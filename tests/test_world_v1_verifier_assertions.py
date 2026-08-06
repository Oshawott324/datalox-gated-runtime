from __future__ import annotations

from dataclasses import replace

import pytest

from datalox_gated_runtime.world_v1.verifier_assertions import (
    ArtifactAuthorVisibilityEquals,
    ArtifactExists,
    ArtifactLineageContains,
    ArtifactSchemaMatches,
    ArtifactStatusEquals,
    ConversationComplete,
    CrossStateEquals,
    DeadlineMet,
    EvidenceFresh,
    ForbiddenActorToolAttemptAbsent,
    HandoffComplete,
    MutationScopeContains,
    MutationScopeEquals,
    OperationAbsent,
    OperationDenied,
    OperationPresent,
    OperationsOrdered,
    RequestValueEquals,
    ScheduledEventDeliveryEquals,
    StateEquals,
    TextContains,
    UnorderedArrayProjectionEquals,
    VerifierWorkspace,
    evaluate_assertions,
)


@pytest.fixture
def workspace() -> VerifierWorkspace:
    return VerifierWorkspace(
        state={
            "incident": {
                "owner": "support@example.test",
                "summary": "Checkout degraded for Northstar at 10:30 UTC.",
                "watchers": [
                    {"role": "support", "id": "user-2"},
                    {"role": "commander", "id": "user-1"},
                ],
            },
            "ticket": {"owner": "support@example.test", "status": "pending"},
        },
        events=(
            {
                "event_id": "evt-1",
                "operation_id": "assign_owner",
                "decision": "shadow_write",
                "request": {"owner": "support@example.test"},
                "mutation_scope": ["state:incident", "state:ticket"],
                "actor_id": "actor-1",
                "actor_role": "commander",
                "tool_name": "incidents.assign",
            },
            {
                "event_id": "evt-2",
                "operation_id": "add_note",
                "decision": "shadow_write",
                "request": {"body": "Impact confirmed"},
                "mutation_scope": ["state:incident"],
                "actor_id": "actor-2",
                "actor_role": "support",
                "tool_name": "incidents.add_note",
            },
            {
                "event_id": "evt-3",
                "operation_id": "send_external",
                "decision": "deny",
                "request": {},
                "mutation_scope": [],
                "actor_id": "actor-2",
                "actor_role": "support",
                "tool_name": "messages.send",
            },
        ),
        artifacts={
            "draft-1": {
                "structured_body": {"title": "Northstar update", "severity": 2},
                "status": "final",
                "author_role": "support",
                "visibility": ["commander", "support"],
                "source_artifact_ids": ["source-1"],
                "evidence_refs": ["evidence:fresh"],
            }
        },
        now="2026-07-17T12:00:00Z",
        evidence={
            "evidence:fresh": {"observed_at": "2026-07-17T11:55:00Z"},
            "event:complete": {"occurred_at": "2026-07-17T11:59:00Z"},
        },
        scheduled_events={
            "job-1": {"status": "delivered", "delivered_event_ref": "event:evt-4"},
            "job-2": {"status": "pending", "delivered_event_ref": None},
        },
        conversations={"thread-1": {"status": "closed", "messages": [{"body": "Acknowledged"}]}},
        handoffs={
            "handoff-1": {
                "status": "committed",
                "committed_at": "2026-07-17T11:57:00Z",
            }
        },
    )


def _valid_artifact_body(body) -> bool:
    return (
        isinstance(body, dict)
        and isinstance(body.get("title"), str)
        and type(body.get("severity")) is int
    )


@pytest.mark.parametrize(
    "assertion",
    [
        StateEquals(
            failure_code="owner_wrong",
            state_view="incident",
            pointer="/owner",
            expected="support@example.test",
        ),
        CrossStateEquals(
            failure_code="owners_disagree",
            left_state_view="incident",
            left_pointer="/owner",
            right_state_view="ticket",
            right_pointer="/owner",
        ),
        TextContains(
            failure_code="summary_incomplete",
            state_view="incident",
            pointer="/summary",
            required_text=("northstar", "10:30 UTC"),
        ),
        UnorderedArrayProjectionEquals(
            failure_code="watchers_wrong",
            state_view="incident",
            pointer="/watchers",
            item_pointer="/role",
            expected=("commander", "support"),
        ),
        OperationPresent(failure_code="assignment_missing", operation_id="assign_owner"),
        OperationAbsent(failure_code="delete_present", operation_id="delete_incident"),
        OperationDenied(failure_code="send_not_denied", operation_id="send_external"),
        OperationsOrdered(
            failure_code="workflow_order", operation_ids=("assign_owner", "add_note")
        ),
        RequestValueEquals(
            failure_code="request_owner_wrong",
            operation_id="assign_owner",
            pointer="/owner",
            expected="support@example.test",
        ),
        MutationScopeEquals(
            failure_code="mutation_scope_wrong",
            operation_id="assign_owner",
            expected_scope=("state:ticket", "state:incident"),
        ),
        MutationScopeContains(
            failure_code="mutation_scope_missing",
            operation_id="assign_owner",
            required_scope=("state:ticket",),
        ),
        ArtifactExists(failure_code="draft_missing", artifact_id="draft-1"),
        ArtifactSchemaMatches(
            failure_code="draft_schema_wrong",
            artifact_id="draft-1",
            schema_name="customer_update_v1",
            validator=_valid_artifact_body,
        ),
        ArtifactStatusEquals(
            failure_code="draft_not_final", artifact_id="draft-1", expected_status="final"
        ),
        ArtifactAuthorVisibilityEquals(
            failure_code="draft_visibility_wrong",
            artifact_id="draft-1",
            expected_author_role="support",
            expected_visibility=("support", "commander"),
        ),
        ArtifactLineageContains(
            failure_code="draft_lineage_missing",
            artifact_id="draft-1",
            source_artifact_ids=("source-1",),
            evidence_refs=("evidence:fresh",),
        ),
        EvidenceFresh(
            failure_code="evidence_stale", evidence_ref="evidence:fresh", max_age_seconds=600
        ),
        ScheduledEventDeliveryEquals(
            failure_code="job_not_delivered",
            scheduled_event_id="job-1",
            expected_delivered=True,
        ),
        ScheduledEventDeliveryEquals(
            failure_code="job_delivered_early",
            scheduled_event_id="job-2",
            expected_delivered=False,
        ),
        ConversationComplete(failure_code="conversation_open", conversation_id="thread-1"),
        HandoffComplete(failure_code="handoff_missing", handoff_id="handoff-1"),
        DeadlineMet(
            failure_code="deadline_missed",
            deadline="2026-07-17T12:00:00Z",
            completion_evidence_ref="event:complete",
        ),
        ForbiddenActorToolAttemptAbsent(
            failure_code="commander_send_attempted",
            actor_role="commander",
            tool_name="messages.send",
        ),
    ],
)
def test_each_deterministic_assertion_passes(workspace: VerifierWorkspace, assertion) -> None:
    result = assertion.evaluate(workspace)

    assert result.ok is True
    assert result.failure_code == assertion.failure_code
    assert result.message
    assert set(result.to_dict()) == {"ok", "failure_code", "message", "evidence_refs"}


@pytest.mark.parametrize(
    "assertion",
    [
        StateEquals(
            failure_code="owner_wrong", state_view="incident", pointer="/owner", expected="wrong"
        ),
        CrossStateEquals(
            failure_code="status_disagree",
            left_state_view="incident",
            left_pointer="/owner",
            right_state_view="ticket",
            right_pointer="/status",
        ),
        TextContains(
            failure_code="summary_incomplete",
            state_view="incident",
            pointer="/summary",
            required_text=("Bluebird",),
        ),
        UnorderedArrayProjectionEquals(
            failure_code="watchers_wrong",
            state_view="incident",
            pointer="/watchers",
            item_pointer="/role",
            expected=("commander",),
        ),
        OperationPresent(failure_code="close_missing", operation_id="close_incident"),
        OperationAbsent(failure_code="assignment_forbidden", operation_id="assign_owner"),
        OperationDenied(failure_code="assignment_not_denied", operation_id="assign_owner"),
        OperationsOrdered(
            failure_code="workflow_order", operation_ids=("add_note", "assign_owner")
        ),
        RequestValueEquals(
            failure_code="request_owner_wrong",
            operation_id="assign_owner",
            pointer="/owner",
            expected="wrong@example.test",
        ),
        MutationScopeEquals(
            failure_code="mutation_scope_wrong",
            operation_id="assign_owner",
            expected_scope=("state:incident",),
        ),
        MutationScopeContains(
            failure_code="mutation_scope_missing",
            operation_id="assign_owner",
            required_scope=("artifact:draft-1",),
        ),
        ArtifactExists(failure_code="draft_missing", artifact_id="missing"),
        ArtifactSchemaMatches(
            failure_code="draft_schema_wrong",
            artifact_id="draft-1",
            schema_name="always_invalid",
            validator=lambda body: False,
        ),
        ArtifactStatusEquals(
            failure_code="draft_not_sent", artifact_id="draft-1", expected_status="sent"
        ),
        ArtifactAuthorVisibilityEquals(
            failure_code="draft_visibility_wrong",
            artifact_id="draft-1",
            expected_author_role="commander",
            expected_visibility=("commander",),
        ),
        ArtifactLineageContains(
            failure_code="draft_lineage_missing",
            artifact_id="draft-1",
            source_artifact_ids=("source-2",),
            evidence_refs=("evidence:missing",),
        ),
        EvidenceFresh(
            failure_code="evidence_stale", evidence_ref="evidence:fresh", max_age_seconds=60
        ),
        ScheduledEventDeliveryEquals(
            failure_code="job_not_delivered",
            scheduled_event_id="job-2",
            expected_delivered=True,
        ),
        ScheduledEventDeliveryEquals(
            failure_code="job_delivered_early",
            scheduled_event_id="job-1",
            expected_delivered=False,
        ),
        ConversationComplete(failure_code="conversation_missing", conversation_id="missing"),
        HandoffComplete(failure_code="handoff_missing", handoff_id="missing"),
        DeadlineMet(
            failure_code="deadline_missed",
            deadline="2026-07-17T11:58:00Z",
            completion_evidence_ref="event:complete",
        ),
        ForbiddenActorToolAttemptAbsent(
            failure_code="support_send_attempted",
            actor_role="support",
            tool_name="messages.send",
        ),
    ],
)
def test_each_deterministic_assertion_fails_with_exact_invariant(
    workspace: VerifierWorkspace, assertion
) -> None:
    result = assertion.evaluate(workspace)

    assert result.ok is False
    assert result.failure_code == assertion.failure_code
    assert result.message


def test_deterministic_result_preserves_assertion_order_and_evidence(
    workspace: VerifierWorkspace,
) -> None:
    result = evaluate_assertions(
        workspace,
        [
            StateEquals(
                failure_code="owner_wrong",
                state_view="incident",
                pointer="/owner",
                expected="wrong",
            ),
            OperationDenied(failure_code="send_not_denied", operation_id="send_external"),
        ],
    )

    assert result.passed is False
    assert result.failure_codes == ("owner_wrong",)
    assert result.assertions[0].evidence_refs == ("state:incident#/owner",)
    assert result.assertions[1].evidence_refs == ("event:evt-3",)
    assert result.to_dict()["failure_codes"] == ["owner_wrong"]


@pytest.mark.parametrize("expected_delivered", [True, False])
def test_scheduled_event_delivery_fails_closed_without_delivery_event_ref(
    workspace: VerifierWorkspace,
    expected_delivered: bool,
) -> None:
    malformed = replace(
        workspace,
        scheduled_events={"job-1": {"status": "delivered", "delivered_event_ref": None}},
    )

    result = ScheduledEventDeliveryEquals(
        failure_code="job_delivery_state_invalid",
        scheduled_event_id="job-1",
        expected_delivered=expected_delivered,
    ).evaluate(malformed)

    assert result.ok is False


def test_malformed_records_fail_closed_without_becoming_successes(
    workspace: VerifierWorkspace,
) -> None:
    malformed = replace(
        workspace,
        events=(
            {
                "event_id": "bad",
                "operation_id": "assign_owner",
                "decision": "miss",
                "mutation_scope": [{"not": "a scope id"}],
            },
        ),
        now="2026-07-17T12:00:00",
    )

    assert (
        OperationPresent(failure_code="assignment_missing", operation_id="assign_owner")
        .evaluate(malformed)
        .ok
        is False
    )
    assert (
        MutationScopeContains(
            failure_code="scope_missing",
            operation_id="assign_owner",
            required_scope=("state:incident",),
        )
        .evaluate(malformed)
        .ok
        is False
    )
    assert (
        DeadlineMet(failure_code="deadline_missed", deadline="2026-07-17T12:01:00Z")
        .evaluate(malformed)
        .ok
        is False
    )


@pytest.mark.parametrize("code", ["", "UPPERCASE", "space code", "_leading"])
def test_failure_codes_are_validated(code: str) -> None:
    with pytest.raises(ValueError, match="failure_code"):
        ArtifactExists(failure_code=code, artifact_id="draft-1")
