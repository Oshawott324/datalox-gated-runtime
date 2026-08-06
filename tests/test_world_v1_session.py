from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest

from datalox_gated_runtime.world_v1 import (
    ActorContext,
    RoleDefinition,
    ToolCatalog,
    ToolDefinition,
    WorldAuthorizationError,
    WorldSession,
    WorldSessionError,
    resolve_actor_context,
)
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.world_v1.verifier_assertions import (
    MutationScopeEquals,
    OperationPresent,
    RequestValueEquals,
    ScheduledEventDeliveryEquals,
    VerifierWorkspace,
    evaluate_assertions,
)


INITIAL_TIME = "2030-01-01T00:00:00+00:00"


def _session(path: Path) -> WorldSession:
    session = WorldSession(path)
    session.reset(
        episode_id="episode-1",
        initial_state={"alpha": {"value": 1}, "beta": [1]},
        initial_time=INITIAL_TIME,
    )
    return session


def test_multi_view_transaction_rolls_back_and_sessions_are_isolated(tmp_path: Path) -> None:
    first = _session(tmp_path / "first.sqlite3")
    with pytest.raises(RuntimeError, match="rollback"):
        with first.transaction(operation_id="test.rollback"):
            first.set_state("alpha", {"value": 2})
            first.set_state("beta", [1, 2])
            raise RuntimeError("rollback")

    assert first.get_state("alpha") == {"value": 1}
    assert first.get_state("beta") == [1]

    second = _session(tmp_path / "second.sqlite3")
    with first.transaction(operation_id="test.commit"):
        assert first.compare_and_set_state("alpha", expected={"value": 1}, value={"value": 3})
    assert first.get_state("alpha") == {"value": 3}
    assert second.get_state("alpha") == {"value": 1}


def test_reset_is_deterministic(tmp_path: Path) -> None:
    first = _session(tmp_path / "first.sqlite3")
    second = _session(tmp_path / "second.sqlite3")

    assert first.export() == second.export()


def test_artifact_revisions_preserve_lineage_and_export(tmp_path: Path) -> None:
    session = _session(tmp_path / "state.sqlite3")
    with session.transaction(operation_id="artifact.create"):
        session.create_artifact(
            artifact_id="draft-1",
            kind="document",
            author_role="owner",
            visibility=["owner", "reviewer"],
            status="draft",
            structured_body={"subject": "First"},
            text_body="First",
            source_artifact_ids=["source-document"],
            evidence_refs=["state:alpha"],
        )
    with session.transaction(operation_id="artifact.finalize"):
        session.revise_artifact(
            "draft-1",
            status="final",
            structured_body={"subject": "Final"},
            text_body="Final",
            source_artifact_ids=["source-document"],
            evidence_refs=["state:alpha", "event:00000001"],
        )

    revisions = session.artifact_revisions("draft-1")
    assert [item["revision"] for item in revisions] == [1, 2]
    assert revisions[0]["snapshot"]["text_body"] == "First"
    exported = session.export()["artifacts"][0]
    assert exported["status"] == "final"
    assert exported["source_artifact_ids"] == ["source-document"]
    assert len(exported["revisions"]) == 2


def test_scheduled_events_deliver_once_at_deterministic_time(tmp_path: Path) -> None:
    session = _session(tmp_path / "state.sqlite3")
    with session.transaction(operation_id="schedule"):
        session.schedule_event(
            event_id="job-1",
            deliver_at="2030-01-01T01:00:00+00:00",
            kind="job.completed",
            payload={"result": 7},
        )
    with session.transaction(operation_id="advance"):
        assert session.advance_clock_by(timedelta(minutes=59)) == ()
    pending_events = {item["id"]: item for item in session.export()["scheduled_events"]}
    assert (
        ScheduledEventDeliveryEquals(
            failure_code="job_delivered_early",
            scheduled_event_id="job-1",
            expected_delivered=False,
        )
        .evaluate(VerifierWorkspace(scheduled_events=pending_events))
        .ok
        is True
    )

    with session.transaction(operation_id="advance"):
        delivered = session.advance_clock_by(
            timedelta(minutes=1),
            handler=lambda current, event: current.set_state("job_result", event.payload),
        )
        assert [event.id for event in delivered] == ["job-1"]
    with session.transaction(operation_id="deliver-again"):
        assert session.deliver_due_events() == ()

    assert session.get_state("job_result") == {"result": 7}
    deliveries = [
        event for event in session.list_events() if event["type"] == "scheduled_event_delivered"
    ]
    clock_advances = [event for event in session.list_events() if event["type"] == "clock_advanced"]
    assert len(deliveries) == 1
    assert len(clock_advances) == 2
    delivered_events = {item["id"]: item for item in session.export()["scheduled_events"]}
    assert (
        ScheduledEventDeliveryEquals(
            failure_code="job_not_delivered",
            scheduled_event_id="job-1",
            expected_delivered=True,
        )
        .evaluate(VerifierWorkspace(scheduled_events=delivered_events))
        .ok
        is True
    )


def test_conversation_export_excludes_simulator_context(tmp_path: Path) -> None:
    session = _session(tmp_path / "state.sqlite3")
    with session.transaction(operation_id="conversation"):
        session.create_conversation(
            conversation_id="thread-1",
            participant_roles=["owner", "counterpart"],
            visibility=["owner", "counterpart"],
            simulator_context={"hidden_secret": "never-export"},
        )
        session.append_message(
            conversation_id="thread-1",
            message_id="message-1",
            sender_role="counterpart",
            visibility=["owner", "counterpart"],
            text_body="Visible reply",
            structured_body={"intent": "confirm"},
        )

    owner_view = session.get_conversation("thread-1", actor=ActorContext("a", "owner"))
    assert owner_view["messages"][0]["text_body"] == "Visible reply"
    assert session.simulator_context("thread-1") == {"hidden_secret": "never-export"}
    exported = session.export()
    assert exported["conversations"][0]["messages"][0]["id"] == "message-1"
    assert "never-export" not in json.dumps(exported)
    assert "simulator" not in json.dumps(exported)


def test_committed_handoff_is_irreversible(tmp_path: Path) -> None:
    session = _session(tmp_path / "state.sqlite3")
    with session.transaction(operation_id="handoff.create"):
        session.create_handoff(
            handoff_id="handoff-1",
            source_role="owner",
            destination_role="reviewer",
            artifact_ids=["draft-1"],
            evidence_refs=["state:alpha"],
        )
        committed = session.commit_handoff("handoff-1")
    assert committed["status"] == "committed"
    assert committed["committed_at"] == committed["updated_at"]
    assert committed["commit_event_ref"] is not None

    with pytest.raises(WorldSessionError) as captured:
        with session.transaction(operation_id="handoff.edit"):
            session.update_handoff(
                "handoff-1",
                destination_role="other",
                artifact_ids=[],
                evidence_refs=[],
            )
    assert captured.value.code == "world_handoff_committed"
    assert session.get_handoff("handoff-1")["destination_role"] == "reviewer"


def test_role_filtering_direct_denial_and_verifier_event_projection(tmp_path: Path) -> None:
    session = _session(tmp_path / "state.sqlite3")
    catalog = ToolCatalog(
        roles=(
            RoleDefinition("owner", "Owns mutations."),
            RoleDefinition("viewer", "Reads only."),
        ),
        tools=(
            ToolDefinition(
                id="state.update",
                description="Update state.",
                list_roles=frozenset({"owner"}),
                invoke_roles=frozenset({"owner"}),
                input_schema={},
            ),
        ),
    )
    viewer = ActorContext("viewer-1", "viewer")
    assert catalog.list_for(viewer) == ()
    with pytest.raises(WorldAuthorizationError) as captured:
        catalog.invoke(
            session=session,
            actor=viewer,
            tool_id="state.update",
            arguments={"value": 5},
            handler=lambda current, tool: current.set_state("alpha", {"value": 5}),
        )
    assert captured.value.code == "world_tool_hidden"

    owner = ActorContext("owner-1", "owner")
    catalog.invoke(
        session=session,
        actor=owner,
        tool_id="state.update",
        arguments={"value": 5},
        handler=lambda current, tool: current.set_state("alpha", {"value": 5}),
    )
    verifier_events = session.export()["verifier_events"]
    denied = next(event for event in verifier_events if event["decision"] == "deny")
    assert denied["actor_role"] == "viewer"
    assert denied["tool_name"] == "state.update"
    assert denied["request"] == {"arguments": {"value": 5}}
    committed = [
        event
        for event in verifier_events
        if event["event_type"] == "transaction_committed"
        and event["operation_id"] == "state.update"
    ][0]
    assert committed["actor_role"] == "owner"
    assert committed["mutation_scope"] == ["state:alpha"]


def test_actor_headers_can_only_select_declared_roles() -> None:
    request = CallRequest(
        method="GET",
        path="/state",
        headers={"X-Datalox-Actor-Id": "actor-1", "X-Datalox-Actor-Role": "admin"},
    )
    with pytest.raises(WorldAuthorizationError) as captured:
        resolve_actor_context(
            request,
            declared_roles=frozenset({"viewer"}),
            default_role="viewer",
        )
    assert captured.value.code == "world_actor_role_unknown"


def test_real_session_commit_events_feed_compositional_assertions(tmp_path: Path) -> None:
    session = _session(tmp_path / "state.sqlite3")
    actor = ActorContext("owner-1", "owner")
    with session.transaction(
        operation_id="state.update",
        actor=actor,
        tool_name="state.update",
        request={"value": 5},
    ):
        session.set_state("alpha", {"value": 5})

    result = evaluate_assertions(
        VerifierWorkspace(
            state=session.list_state(),
            events=session.verifier_events(),
        ),
        (
            OperationPresent(failure_code="operation_missing", operation_id="state.update"),
            RequestValueEquals(
                failure_code="request_wrong",
                operation_id="state.update",
                pointer="/value",
                expected=5,
            ),
            MutationScopeEquals(
                failure_code="scope_wrong",
                operation_id="state.update",
                expected_scope=("state:alpha",),
            ),
        ),
    )

    assert result.passed is True
