from __future__ import annotations

import hashlib
import json
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient
from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    PROVIDER_ID,
    build_stateful_provider_bundle,
)
from test_provider_release_registry import _claims, _profile

from datalox_gated_runtime.data_plane import (
    NoResponseTransportDirective,
    TrackedResponseTransportDirective,
)
from datalox_gated_runtime.interception.gateway import InterceptionGateway
from datalox_gated_runtime.interception.interventions import ProviderBaseBinding
from datalox_gated_runtime.interception.interventions_v2 import (
    DELIVERY_INTERVENTION_V2_TRACE_SCHEMA_VERSION,
    DeliveryInterventionResetConflict,
    DeliveryInterventionSessionV2,
    InterventionDecisionV2,
    NoResponseAction,
    load_delivery_intervention_v2,
    validate_v2_policy_for_operations,
)
from datalox_gated_runtime.interception.server import prepare_admitted_interception_run
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse
from datalox_gated_runtime.provider_runtime import (
    CredentialMapIdentityPolicy,
    CredentialPrincipal,
    CredentialSelector,
    IdentityErrorResponse,
    admit_provider_runtime,
)
from datalox_gated_runtime.provider_runtime.release import (
    ProviderReleaseProfileInput,
    build_provider_release,
)
from datalox_gated_runtime.provider_runtime.state import provider_behavior_state_sha256

ROOT = Path(__file__).resolve().parents[1]
SHA256 = "sha256:" + "1" * 64
PROVIDER = ProviderBaseBinding(
    provider_id="example_provider",
    release_version="2026.09.02",
    profile_id="default",
    bundle_version="1.0.0",
    release_config_sha256=SHA256,
    provider_runtime_sha256=SHA256,
    provider_admission_sha256=SHA256,
    operation_contract_sha256=SHA256,
)


class _Policy:
    policy_id = "write_failures"
    policy_version = "1"
    policy_sha256 = SHA256

    def __init__(self, decisions: dict[int, InterventionDecisionV2]) -> None:
        self.decisions = decisions

    def decide(
        self,
        *,
        seed: str,
        logical_request_index: int,
        operation_id: str,
        request: CallRequest,
    ) -> InterventionDecisionV2 | None:
        del seed, operation_id, request
        return self.decisions.get(logical_request_index)


class _FailingPolicy(_Policy):
    def decide(self, **kwargs) -> InterventionDecisionV2 | None:
        del kwargs
        raise RuntimeError("injected policy failure")


def _decision(phase: str, *, operation_id: str = "counter.write") -> InterventionDecisionV2:
    return InterventionDecisionV2(
        decision_id=f"{phase}_failure",
        operation_id=operation_id,
        action=NoResponseAction(phase),
    )


def _request(*, operation_id: str = "counter.write", method: str = "POST") -> CallRequest:
    return CallRequest(
        method,
        "/counter",
        authority="api.provider.example",
        body={"amount": 2},
        headers={"authorization": "Bearer must-not-enter-the-journal"},
        operation_id=operation_id,
    )


def _response(counter: int, *, status_code: int = 200) -> GateResponse:
    return GateResponse(
        status_code=status_code,
        headers={"content-type": "application/json"},
        body={"counter": counter},
        decision=GateDecision("shadow_write", "provider_base", "Provider base response."),
        event_id=f"evt_counter_{counter}_{status_code}",
    )


def _acknowledge_response(
    outcome: GateResponse | NoResponseTransportDirective | TrackedResponseTransportDirective,
) -> GateResponse:
    assert isinstance(outcome, TrackedResponseTransportDirective)
    body_bytes = len(json.dumps(outcome.response.body, separators=(",", ":")).encode())
    outcome.on_asgi_send_completed(True, body_bytes)
    return outcome.response


def _session(
    tmp_path: Path,
    *,
    phase: str,
    enabled: bool = True,
    operation_id: str = "counter.write",
) -> DeliveryInterventionSessionV2:
    return DeliveryInterventionSessionV2(
        _Policy({1: _decision(phase, operation_id=operation_id)}),
        provider=PROVIDER,
        operation_mutability={"counter.read": "read", "counter.write": "write"},
        seed="episode-1",
        enabled=enabled,
        journal_path=tmp_path / "journal.sqlite3",
    )


def test_pre_dispatch_no_response_never_invokes_write_and_state_is_known_unchanged(
    tmp_path: Path,
) -> None:
    state = {"counter": 1}
    session = _session(tmp_path, phase="pre_dispatch")
    base_calls = 0

    def base() -> GateResponse:
        nonlocal base_calls
        base_calls += 1
        state["counter"] += 2
        return _response(state["counter"])

    outcome = session.handle(
        _request(),
        base,
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )

    assert isinstance(outcome, NoResponseTransportDirective)
    assert base_calls == 0
    assert state == {"counter": 1}
    event = session.export()["events"][0]
    assert event["base"]["invoked"] is False
    assert event["base"]["completion_certainty"] == "not_dispatched"
    assert event["base"]["provider_state_relation"] == "unchanged"
    assert (
        event["base"]["provider_state_before_sha256"]
        == event["base"]["provider_state_after_sha256"]
    )
    assert "must-not-enter-the-journal" not in json.dumps(event)
    assert event["request_sha256"].startswith("sha256:")
    with pytest.raises(DeliveryInterventionResetConflict):
        session.reset()
    outcome.on_disconnect()
    assert session.reset()["events"] == []
    session.shutdown()


def test_post_dispatch_journals_before_one_write_and_binds_committed_outcome(
    tmp_path: Path,
) -> None:
    state = {"counter": 1}
    session = _session(tmp_path, phase="post_dispatch")
    journal = tmp_path / "journal.sqlite3"
    base_calls = 0

    def base() -> GateResponse:
        nonlocal base_calls
        base_calls += 1
        with sqlite3.connect(journal) as observer:
            phase = observer.execute(
                "SELECT phase FROM events WHERE logical_request_index = 1"
            ).fetchone()[0]
        assert phase == "decision_recorded"
        state["counter"] += 2
        return _response(state["counter"])

    outcome = session.handle(
        _request(),
        base,
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )

    assert isinstance(outcome, NoResponseTransportDirective)
    assert base_calls == 1
    assert state == {"counter": 3}
    event = session.export()["events"][0]
    assert event["base"]["completion_certainty"] == "known_completed"
    assert event["base"]["provider_state_relation"] == "changed"
    assert (
        event["base"]["provider_state_before_sha256"]
        != event["base"]["provider_state_after_sha256"]
    )
    assert event["base"]["response"] == {
        "status_code": 200,
        "headers": {"content-type": "application/json"},
        "body": {"counter": 3},
    }
    assert event["delivered"]["response_start_sent"] is False
    assert event["delivered"]["response_body_bytes_sent"] == 0
    assert event["delivered"]["client_completion_certainty"] == "unknown"
    outcome.on_disconnect()
    assert session.export()["events"][0]["outcome"] == "transport_disconnected"
    session.shutdown()


def test_off_evaluates_same_policy_and_returns_exact_base_for_write(tmp_path: Path) -> None:
    state = {"counter": 1}
    session = _session(tmp_path, phase="post_dispatch", enabled=False)
    base_response = _response(3)

    returned = session.handle(
        _request(),
        lambda: (state.update(counter=3), base_response)[1],
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )

    assert _acknowledge_response(returned) is base_response
    event = session.export()["events"][0]
    assert event["decision"]["kind"] == "no_response"
    assert event["applied"] is False
    assert event["outcome"] == "asgi_send_completed"
    assert event["base"]["response_sha256"] == event["delivered"]["response_sha256"]
    on = _session(tmp_path / "on", phase="post_dispatch", enabled=True)
    on_outcome = on.handle(
        _request(),
        lambda: _response(3),
        lambda: canonical_json_sha256({"counter": 3}),
        operation_id="counter.write",
    )
    assert isinstance(on_outcome, NoResponseTransportDirective)
    assert on.export()["events"][0]["event_id"] == event["event_id"]
    assert on.export()["events"][0]["decision"] == event["decision"]
    on_outcome.on_disconnect()
    on.shutdown()
    session.shutdown()


def test_provider_native_http_failure_passes_unchanged_without_scheduled_action(
    tmp_path: Path,
) -> None:
    state = {"counter": 1}
    session = DeliveryInterventionSessionV2(
        _Policy({}),
        provider=PROVIDER,
        operation_mutability={"counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
    )
    failure = _response(1, status_code=409)

    returned = session.handle(
        _request(),
        lambda: failure,
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )

    assert _acknowledge_response(returned) is failure
    event = session.export()["events"][0]
    assert event["base"]["response"]["status_code"] == 409
    assert event["base"]["provider_state_relation"] == "unchanged"
    session.shutdown()


def test_evidence_safe_request_digest_distinguishes_idempotency_headers(
    tmp_path: Path,
) -> None:
    session = DeliveryInterventionSessionV2(
        _Policy({}),
        provider=PROVIDER,
        operation_mutability={"counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
    )
    state = {"counter": 1}
    for value in ("request-one", "request-two"):
        outcome = session.handle(
            CallRequest(
                "POST",
                "/counter",
                authority="api.provider.example",
                body={"amount": 2},
                headers={
                    "authorization": "Bearer redacted",
                    "idempotency-key": value,
                },
            ),
            lambda: _response(1),
            lambda: canonical_json_sha256(state),
            operation_id="counter.write",
        )
        _acknowledge_response(outcome)
    events = session.export()["events"]
    assert events[0]["request_sha256"] != events[1]["request_sha256"]
    assert "request-one" not in json.dumps(events)
    assert "request-two" not in json.dumps(events)
    session.shutdown()


def test_standard_and_declared_credentials_are_absent_and_digest_invariant(
    tmp_path: Path,
) -> None:
    credential_digest = "sha256:" + hashlib.sha256(b"credential-one").hexdigest()
    query_credential_digest = "sha256:" + hashlib.sha256(b"query-one").hexdigest()
    denied = IdentityErrorResponse(401, {"error": "unauthorized"}, {})
    identity_policy = CredentialMapIdentityPolicy(
        principals=(
            CredentialPrincipal(
                principal_context_id="operator",
                actor_id="operator",
                actor_role="operator",
                credentials=(
                    CredentialSelector("header", "x-provider-token", credential_digest),
                    CredentialSelector("query", "access_token", query_credential_digest),
                ),
            ),
        ),
        missing_identity=denied,
        invalid_identity=denied,
    )
    session = DeliveryInterventionSessionV2(
        _Policy({}),
        provider=PROVIDER,
        operation_mutability={"counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
        identity_policy=identity_policy,
    )
    state = {"counter": 1}
    for authorization, declared, query_secret, view in (
        ("Bearer first-secret", "credential-one", "query-one", "full"),
        ("Bearer second-secret", "credential-two", "query-two", "full"),
        ("Bearer third-secret", "credential-three", "query-three", "summary"),
    ):
        outcome = session.handle(
            CallRequest(
                "POST",
                "/counter",
                authority="api.provider.example",
                body={"amount": 2},
                query={"access_token": query_secret, "view": view},
                headers={
                    "authorization": authorization,
                    "x-provider-token": declared,
                    "idempotency-key": "stable-request",
                },
            ),
            lambda: _response(1),
            lambda: canonical_json_sha256(state),
            operation_id="counter.write",
        )
        _acknowledge_response(outcome)
    exported = session.export()
    assert exported["events"][0]["request_sha256"] == exported["events"][1]["request_sha256"]
    assert exported["events"][1]["request_sha256"] != exported["events"][2]["request_sha256"]
    serialized = json.dumps(exported, sort_keys=True)
    for secret in (
        "first-secret",
        "second-secret",
        "credential-one",
        "credential-two",
        "credential-three",
        "query-one",
        "query-two",
        "query-three",
    ):
        assert secret not in serialized
    session.shutdown()


def test_committed_write_journal_failure_latches_and_returns_no_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = {"counter": 1}
    session = _session(tmp_path, phase="post_dispatch", enabled=False)
    original_update = session._journal.update
    calls = 0

    def fail_once(index: int, phase: str, event: dict) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected journal write failure")
        original_update(index, phase, event)

    monkeypatch.setattr(session._journal, "update", fail_once)

    outcome = session.handle(
        _request(),
        lambda: (state.update(counter=3), _response(3))[1],
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )

    assert isinstance(outcome, NoResponseTransportDirective)
    assert state == {"counter": 3}
    exported = session.export()
    assert exported["terminal_failure"]["code"] == (
        "delivery_intervention_v2_base_outcome_record_failed"
    )
    assert exported["events"][0]["outcome"] == "terminal_failure"
    with pytest.raises(DeliveryInterventionResetConflict):
        session.reset()
    outcome.on_disconnect()
    session.shutdown()


def test_pre_dispatch_transition_failure_remains_not_dispatched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = {"counter": 1}
    session = _session(tmp_path, phase="pre_dispatch")
    original_update = session._journal.update
    calls = 0

    def fail_once(index: int, phase: str, event: dict) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("injected pre-dispatch transition failure")
        original_update(index, phase, event)

    monkeypatch.setattr(session._journal, "update", fail_once)
    outcome = session.handle(
        _request(),
        lambda: pytest.fail("pre-dispatch transition failure invoked provider"),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(outcome, NoResponseTransportDirective)
    event = session.export()["events"][0]
    assert event["base"]["invoked"] is False
    assert event["base"]["completion_certainty"] == "not_dispatched"
    assert event["base"]["provider_state_relation"] == "unchanged"
    assert state == {"counter": 1}
    outcome.on_disconnect()
    session.shutdown()


def test_base_exception_after_mutation_is_unknown_completion_and_zero_response(
    tmp_path: Path,
) -> None:
    state = {"counter": 1}
    session = DeliveryInterventionSessionV2(
        _Policy({}),
        provider=PROVIDER,
        operation_mutability={"counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
    )

    def mutate_then_raise() -> GateResponse:
        state["counter"] = 3
        raise OSError("connection ended after dispatch")

    outcome = session.handle(
        _request(),
        mutate_then_raise,
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )

    assert isinstance(outcome, NoResponseTransportDirective)
    event = session.export()["events"][0]
    assert event["base"]["invoked"] is True
    assert event["base"]["completion_certainty"] == "unknown"
    assert event["base"]["provider_state_relation"] == "changed"
    assert event["base"]["response"] is None
    assert event["error"]["code"] == "delivery_intervention_v2_base_completion_unknown"
    outcome.on_disconnect()
    terminal = session.handle(
        _request(),
        lambda: pytest.fail("terminal session dispatched provider"),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(terminal, GateResponse)
    assert terminal.status_code == 503
    assert terminal.body == {
        "error": {
            "code": "delivery_intervention_session_terminal",
            "message": "This provider session requires a trusted reset.",
        }
    }
    session.shutdown()


def test_disconnect_journal_failure_clears_active_pending_and_terminally_latches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = {"counter": 1}
    session = _session(tmp_path, phase="pre_dispatch")
    outcome = session.handle(
        _request(),
        lambda: pytest.fail("pre-dispatch action invoked provider"),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(outcome, NoResponseTransportDirective)
    original_update = session._journal.update

    def fail_disconnect(index: int, phase: str, event: dict) -> None:
        if phase == "transport_disconnected":
            raise OSError("injected disconnect journal failure")
        original_update(index, phase, event)

    monkeypatch.setattr(session._journal, "update", fail_disconnect)
    outcome.on_disconnect()

    exported = session.export()
    assert exported["pending_transport_count"] == 0
    assert exported["terminal_failure"]["code"] == (
        "delivery_intervention_v2_disconnect_record_failed"
    )
    assert session.reset()["events"] == []
    monkeypatch.setattr(session._journal, "update", original_update)
    session.shutdown()


@pytest.mark.parametrize("failure_stage", ("policy", "state_observer", "journal_insert"))
def test_pre_dispatch_control_failures_return_structured_503_without_base_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    policy = (
        _FailingPolicy({})
        if failure_stage == "policy"
        else _Policy({1: _decision("post_dispatch")})
    )
    session = DeliveryInterventionSessionV2(
        policy,
        provider=PROVIDER,
        operation_mutability={"counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
    )
    if failure_stage == "journal_insert":
        original_insert = session._journal.insert_decision
        calls = 0

        def fail_once(index: int, event: dict) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected decision journal failure")
            original_insert(index, event)

        monkeypatch.setattr(session._journal, "insert_decision", fail_once)
    base_calls = 0

    def base() -> GateResponse:
        nonlocal base_calls
        base_calls += 1
        return _response(3)

    def state_observer() -> str:
        if failure_stage == "state_observer":
            raise OSError("injected state observation failure")
        return canonical_json_sha256({"counter": 1})

    response = session.handle(_request(), base, state_observer, operation_id="counter.write")

    assert isinstance(response, GateResponse)
    assert response.status_code == 503
    assert response.body["error"]["code"] == "delivery_intervention_session_terminal"
    assert base_calls == 0
    exported = session.export()
    assert exported["terminal_failure"]["code"] == (
        "delivery_intervention_v2_decision_record_failed"
    )
    if exported["events"]:
        event = exported["events"][0]
        assert event["base"]["invoked"] is False
        assert event["base"]["completion_certainty"] == "not_dispatched"
        assert event["outcome"] == "terminal_failure"
        schema = json.loads(
            (ROOT / "schemas/delivery-intervention-trace-v2.schema.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.Draft202012Validator(schema).validate(exported)
    session.shutdown()


def test_shutdown_aborts_pending_transport_and_closes_durably(tmp_path: Path) -> None:
    state = {"counter": 1}
    session = _session(tmp_path, phase="pre_dispatch")
    outcome = session.handle(
        _request(),
        lambda: pytest.fail("pre-dispatch action invoked the provider"),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(outcome, NoResponseTransportDirective)

    session.shutdown()
    outcome.on_disconnect()

    with sqlite3.connect(tmp_path / "journal.sqlite3") as observer:
        event = json.loads(observer.execute("SELECT event_json FROM events").fetchone()[0])
    assert event["outcome"] == "transport_aborted"
    assert event["delivered"]["transport_status"] == "trusted_shutdown_aborted"


def test_resume_terminalizes_process_lost_pending_transport_until_reset(tmp_path: Path) -> None:
    state = {"counter": 1}
    original = _session(tmp_path, phase="post_dispatch")
    outcome = original.handle(
        _request(),
        lambda: (state.update(counter=3), _response(3))[1],
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(outcome, NoResponseTransportDirective)
    original._journal.close()

    resumed = DeliveryInterventionSessionV2(
        _Policy({1: _decision("post_dispatch")}),
        provider=PROVIDER,
        operation_mutability={"counter.read": "read", "counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
        lifecycle="resume",
    )
    exported = resumed.export()
    assert exported["terminal_failure"]["code"] == "delivery_intervention_v2_process_loss"
    assert exported["events"][0]["outcome"] == "transport_aborted"
    assert exported["events"][0]["delivered"]["transport_status"] == ("process_loss_aborted")
    terminal = resumed.handle(
        _request(),
        lambda: pytest.fail("terminal resume dispatched a provider call"),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(terminal, GateResponse)
    assert terminal.status_code == 503
    assert terminal.decision.reason_code == "delivery_intervention_session_terminal"
    assert resumed.reset()["events"] == []
    resumed.shutdown()


def test_resume_terminalizes_decision_only_record_as_unknown_completion(
    tmp_path: Path,
) -> None:
    class SimulatedProcessLoss(BaseException):
        pass

    state = {"counter": 1}
    original = _session(tmp_path, phase="post_dispatch")

    def commit_then_lose_process() -> GateResponse:
        state["counter"] = 3
        raise SimulatedProcessLoss

    with pytest.raises(SimulatedProcessLoss):
        original.handle(
            _request(),
            commit_then_lose_process,
            lambda: canonical_json_sha256(state),
            operation_id="counter.write",
        )
    assert original.export()["events"][0]["outcome"] == "decision_recorded"
    original._journal.close()

    resumed = DeliveryInterventionSessionV2(
        _Policy({1: _decision("post_dispatch")}),
        provider=PROVIDER,
        operation_mutability={"counter.read": "read", "counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
        lifecycle="resume",
    )
    exported = resumed.export()
    event = exported["events"][0]
    assert state == {"counter": 3}
    assert exported["terminal_failure"]["code"] == "delivery_intervention_v2_process_loss"
    assert event["outcome"] == "transport_aborted"
    assert event["base"]["invoked"] is None
    assert event["base"]["completion_certainty"] == "unknown"
    assert event["base"]["provider_state_after_sha256"] is None
    assert event["base"]["provider_state_relation"] == "unknown"
    trace_schema = json.loads(
        (ROOT / "schemas/delivery-intervention-trace-v2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(trace_schema).validate(exported)
    terminal = resumed.handle(
        _request(),
        lambda: pytest.fail("decision-only resume retried the provider call"),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(terminal, GateResponse)
    assert terminal.status_code == 503
    resumed.shutdown()


def test_resume_terminalizes_response_pending_before_asgi_send(
    tmp_path: Path,
) -> None:
    state = {"counter": 1}
    original = DeliveryInterventionSessionV2(
        _Policy({}),
        provider=PROVIDER,
        operation_mutability={"counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
    )
    outcome = original.handle(
        _request(),
        lambda: (state.update(counter=3), _response(3))[1],
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(outcome, TrackedResponseTransportDirective)
    assert original.export()["events"][0]["outcome"] == "transport_pending"
    original._journal.close()

    resumed = DeliveryInterventionSessionV2(
        _Policy({}),
        provider=PROVIDER,
        operation_mutability={"counter.write": "write"},
        seed="episode-1",
        enabled=True,
        journal_path=tmp_path / "journal.sqlite3",
        lifecycle="resume",
    )
    exported = resumed.export()
    event = exported["events"][0]
    assert exported["terminal_failure"]["code"] == "delivery_intervention_v2_process_loss"
    assert event["outcome"] == "transport_aborted"
    assert event["base"]["invoked"] is True
    assert event["base"]["completion_certainty"] == "known_completed"
    assert event["delivered"]["transport_status"] == "process_loss_aborted"
    assert event["delivered"]["response_start_sent"] is False
    assert event["delivered"]["response_body_bytes_sent"] == 0
    terminal = resumed.handle(
        _request(),
        lambda: pytest.fail("response-pending resume retried the provider call"),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    assert isinstance(terminal, GateResponse)
    assert terminal.status_code == 503
    resumed.shutdown()


def test_v2_config_and_trace_are_strict_and_read_write_operations_are_admitted(
    tmp_path: Path,
) -> None:
    policy = {
        "schema_version": "datalox_delivery_intervention_policy_v2",
        "policy_id": "write_time_failures",
        "policy_version": "1",
        "schedules": [
            {
                "seed": "episode-1",
                "decisions": [
                    {
                        "decision_id": "write_unknown_completion",
                        "request_index": 1,
                        "operation_id": "counter.write",
                        "action": {"kind": "no_response", "phase": "post_dispatch"},
                    }
                ],
            }
        ],
    }
    config = {
        "schema_version": "datalox_delivery_intervention_v2",
        "provider_id": "example_provider",
        "mode": "on",
        "seed": "episode-1",
        "policy": policy,
        "policy_sha256": canonical_json_sha256(policy),
    }
    path = tmp_path / "v2.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    schema = json.loads(
        (ROOT / "schemas/delivery-intervention-v2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(config)
    loaded = load_delivery_intervention_v2(path)
    validate_v2_policy_for_operations(
        loaded.policy,
        operation_mutability={"counter.read": "read", "counter.write": "write"},
    )

    state = {"counter": 1}
    session = DeliveryInterventionSessionV2(
        loaded.policy,
        provider=PROVIDER,
        operation_mutability={"counter.read": "read", "counter.write": "write"},
        seed=loaded.seed,
        enabled=False,
        journal_path=tmp_path / "journal.sqlite3",
    )
    outcome = session.handle(
        _request(),
        lambda: _response(1),
        lambda: canonical_json_sha256(state),
        operation_id="counter.write",
    )
    _acknowledge_response(outcome)
    exported = session.export()
    assert exported["schema_version"] == DELIVERY_INTERVENTION_V2_TRACE_SCHEMA_VERSION
    trace_schema = json.loads(
        (ROOT / "schemas/delivery-intervention-trace-v2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(trace_schema).validate(exported)
    session.shutdown()


def test_two_sessions_have_independent_indexes_state_and_journals(tmp_path: Path) -> None:
    first_state = {"counter": 1}
    second_state = {"counter": 10}
    first = _session(tmp_path / "first", phase="post_dispatch")
    second = _session(tmp_path / "second", phase="post_dispatch")

    first_outcome = first.handle(
        _request(),
        lambda: (first_state.update(counter=3), _response(3))[1],
        lambda: canonical_json_sha256(first_state),
        operation_id="counter.write",
    )
    second_outcome = second.handle(
        _request(),
        lambda: (second_state.update(counter=12), _response(12))[1],
        lambda: canonical_json_sha256(second_state),
        operation_id="counter.write",
    )

    assert first.export()["events"][0]["logical_request_index"] == 1
    assert second.export()["events"][0]["logical_request_index"] == 1
    assert (
        first.export()["events"][0]["base"]["provider_state_after_sha256"]
        != second.export()["events"][0]["base"]["provider_state_after_sha256"]
    )
    assert isinstance(first_outcome, NoResponseTransportDirective)
    assert isinstance(second_outcome, NoResponseTransportDirective)
    first_outcome.on_disconnect()
    second_outcome.on_disconnect()
    first.shutdown()
    second.shutdown()


def _gateway_fixture(tmp_path: Path, *, mode: str) -> tuple[InterceptionGateway, Path]:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release = build_provider_release(
        profiles=(profile,),
        release_version="2026.09.02",
        output_dir=tmp_path / "release",
    )
    release_config = tmp_path / "provider-release.json"
    release_config.write_text(json.dumps(release.config), encoding="utf-8")
    policy = {
        "schema_version": "datalox_delivery_intervention_policy_v2",
        "policy_id": "gateway_write_timeout",
        "policy_version": "1",
        "schedules": [
            {
                "seed": "episode-1",
                "decisions": [
                    {
                        "decision_id": "unknown_write_completion",
                        "request_index": 1,
                        "operation_id": "counter.increment",
                        "action": {"kind": "no_response", "phase": "post_dispatch"},
                    }
                ],
            }
        ],
    }
    config = {
        "schema_version": "datalox_delivery_intervention_v2",
        "provider_id": PROVIDER_ID,
        "mode": mode,
        "seed": "episode-1",
        "policy": policy,
        "policy_sha256": canonical_json_sha256(policy),
    }
    config_path = tmp_path / "intervention.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    gateway = InterceptionGateway.from_admitted_release_bindings(
        bundle_admission_configs=((profile.bundle_dir, profile.admission_path, release_config),),
        run_root=tmp_path / "run",
        control_token="controller-secret",
        delivery_intervention_configs={PROVIDER_ID: config_path},
    )
    return gateway, config_path


def test_gateway_v2_write_is_readable_after_unknown_completion_and_reset_waits_for_disconnect(
    tmp_path: Path,
) -> None:
    gateway, _ = _gateway_fixture(tmp_path, mode="on")
    provider = gateway.providers[PROVIDER_ID]
    assert isinstance(provider.intervention, DeliveryInterventionSessionV2)
    assert provider.intervention.identity_policy is provider.runtime.bundle.identity_policy
    request = CallRequest(
        "POST",
        "/counter",
        authority=PROVIDER_AUTHORITY,
        body={"amount": 2},
    )
    try:
        unchanged_before = provider.runtime.behavior_state_sha256()
        assert unchanged_before == provider_behavior_state_sha256(
            provider.runtime.export()["provider_state"]
        )
        with provider.binding.lock:
            denied_write = provider.binding.handler.handle(
                CallRequest(
                    "POST",
                    "/counter",
                    authority=PROVIDER_AUTHORITY,
                    body={"amount": 2},
                    headers={"x-datalox-actor-role": "viewer"},
                )
            )
        assert isinstance(denied_write, GateResponse)
        assert denied_write.status_code == 400
        assert provider.runtime.behavior_state_sha256() == unchanged_before
        with provider.binding.lock:
            outcome = provider.binding.handler.handle(request)
        assert isinstance(outcome, NoResponseTransportDirective)

        with TestClient(gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as agent:
            readback = agent.get("/counter")
            assert readback.status_code == 200
            assert readback.json()["counter"] == 3
        with TestClient(gateway.control_app) as controller:
            headers = {"x-datalox-control-token": "controller-secret"}
            blocked = controller.post(f"/v1/providers/{PROVIDER_ID}/reset", headers=headers)
            assert blocked.status_code == 409
            trace = controller.get(
                f"/v1/providers/{PROVIDER_ID}/delivery-interventions/export",
                headers=headers,
            ).json()
            assert trace["pending_transport_count"] == 1
            assert trace["events"][0]["operation_mutability"] == "write"
            assert trace["events"][1]["operation_mutability"] == "read"
            assert trace["events"][1]["base"]["provider_state_relation"] == "unchanged"
            outcome.on_disconnect()
            reset = controller.post(f"/v1/providers/{PROVIDER_ID}/reset", headers=headers)
            assert reset.status_code == 200
            provider_export = controller.get(
                f"/v1/providers/{PROVIDER_ID}/export", headers=headers
            ).json()
            assert provider_export["provider_state"]["state"]["counter"] == 1
    finally:
        gateway.close()


def test_gateway_v2_off_returns_exact_base_http_response(tmp_path: Path) -> None:
    baseline, _ = _gateway_fixture(tmp_path / "baseline", mode="off")
    without_policy_profile = _profile(tmp_path / "plain/profile", profile_id="default")
    plain_release = build_provider_release(
        profiles=(without_policy_profile,),
        release_version="2026.09.02",
        output_dir=tmp_path / "plain/release",
    )
    plain_release_config = tmp_path / "plain/provider-release.json"
    plain_release_config.write_text(json.dumps(plain_release.config), encoding="utf-8")
    plain = InterceptionGateway.from_admitted_release_bindings(
        bundle_admission_configs=(
            (
                without_policy_profile.bundle_dir,
                without_policy_profile.admission_path,
                plain_release_config,
            ),
        ),
        run_root=tmp_path / "plain/run",
        control_token="plain-secret",
    )
    try:
        with (
            TestClient(baseline.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as off_agent,
            TestClient(plain.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as plain_agent,
        ):
            off = off_agent.post("/counter", json={"amount": 2})
            exact = plain_agent.post("/counter", json={"amount": 2})
        assert off.status_code == exact.status_code
        assert off.content == exact.content
        assert dict(off.headers) == dict(exact.headers)
        with TestClient(baseline.control_app) as controller:
            trace = controller.get(
                f"/v1/providers/{PROVIDER_ID}/delivery-interventions/export",
                headers={"x-datalox-control-token": "controller-secret"},
            ).json()
        event = trace["events"][0]
        assert event["outcome"] == "asgi_send_completed"
        assert event["delivered"]["transport_status"] == "asgi_send_completed"
        assert event["delivered"]["response_start_sent"] is True
        assert event["delivered"]["response_body_bytes_sent"] == len(off.content)
        assert event["delivered"]["client_completion_certainty"] == "unknown"
    finally:
        baseline.close()
        plain.close()


def test_gateway_pre_dispatch_control_failure_is_structured_and_does_not_mutate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway, _ = _gateway_fixture(tmp_path, mode="on")
    provider = gateway.providers[PROVIDER_ID]
    before = provider.runtime.export()["provider_state"]["state"]["counter"]

    def fail_state_observation() -> str:
        raise OSError("injected controller state observation failure")

    monkeypatch.setattr(provider.runtime, "behavior_state_sha256", fail_state_observation)
    try:
        with TestClient(gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as agent:
            response = agent.post("/counter", json={"amount": 2})
        assert response.status_code == 503
        assert response.json() == {
            "error": {
                "code": "delivery_intervention_session_terminal",
                "message": "This provider session requires a trusted reset.",
            }
        }
        assert provider.runtime.export()["provider_state"]["state"]["counter"] == before
        trace = provider.intervention.export()
        assert trace["events"][0]["base"]["invoked"] is False
        assert trace["events"][0]["base"]["completion_certainty"] == "not_dispatched"
    finally:
        gateway.close()


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl is required for TLS timeout proof")
@pytest.mark.parametrize(
    ("phase", "expected_counter", "expected_relation"),
    (("pre_dispatch", 1, "unchanged"), ("post_dispatch", 3, "changed")),
)
def test_real_tls_exact_provider_url_sends_zero_response_bytes_and_never_retries(
    tmp_path: Path,
    phase: str,
    expected_counter: int,
    expected_relation: str,
) -> None:
    del tmp_path
    tmp_path = Path(tempfile.mkdtemp(prefix="datalox-v2-tls-", dir="/tmp"))
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    authority = f"api.provider.example:{port}"
    profile_root = tmp_path / "profile"
    bundle = build_stateful_provider_bundle(profile_root / "bundle", authority=authority)
    claims_root = profile_root / "claims"
    claims_root.mkdir(parents=True)
    admission = profile_root / "provider-admission.json"
    claims_path = _claims(claims_root)
    claims_path.write_text(
        claims_path.read_text(encoding="utf-8").replace(PROVIDER_AUTHORITY, authority),
        encoding="utf-8",
    )
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims_path,
        output_path=admission,
        admitted_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    profile = ProviderReleaseProfileInput(
        profile_id="default",
        bundle_dir=bundle,
        admission_path=admission,
    )
    release = build_provider_release(
        profiles=(profile,),
        release_version="2026.09.02",
        output_dir=tmp_path / "release",
    )
    release_config = tmp_path / "provider-release.json"
    release_config.write_text(json.dumps(release.config), encoding="utf-8")
    policy = {
        "schema_version": "datalox_delivery_intervention_policy_v2",
        "policy_id": "tls_write_timeout",
        "policy_version": "1",
        "schedules": [
            {
                "seed": "episode-1",
                "decisions": [
                    {
                        "decision_id": f"{phase}_write",
                        "request_index": 1,
                        "operation_id": "counter.increment",
                        "action": {"kind": "no_response", "phase": phase},
                    }
                ],
            }
        ],
    }
    config = {
        "schema_version": "datalox_delivery_intervention_v2",
        "provider_id": PROVIDER_ID,
        "mode": "on",
        "seed": "episode-1",
        "policy": policy,
        "policy_sha256": canonical_json_sha256(policy),
    }
    config_path = tmp_path / "intervention.json"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    run_root = tmp_path / "run"
    prepare_admitted_interception_run(
        bundle_admission_configs=((profile.bundle_dir, profile.admission_path, release_config),),
        run_root=run_root,
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "intercept",
            "serve-admitted",
            "--bundle",
            str(profile.bundle_dir),
            "--admission",
            str(profile.admission_path),
            "--release-config",
            str(release_config),
            "--delivery-intervention",
            f"{PROVIDER_ID}={config_path}",
            "--run",
            str(run_root),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--prepared",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ready = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "datalox_gated_runtime.cli",
                    "intercept",
                    "ready",
                    "--run",
                    str(run_root),
                    "--json",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if ready.returncode == 0:
                break
            if process.poll() is not None:
                pytest.fail(process.stderr.read())
            time.sleep(0.05)
        else:
            pytest.fail("interception gateway did not become ready")

        response_file = tmp_path / "response.bin"
        url = f"https://{authority}/counter"
        timed_out = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--resolve",
                f"{authority}:127.0.0.1",
                "--cacert",
                str(run_root / "certificates/ca.pem"),
                "--max-time",
                "0.5",
                "--output",
                str(response_file),
                "--write-out",
                "%{http_code}",
                "--header",
                "content-type: application/json",
                "--data",
                '{"amount":2}',
                url,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert timed_out.returncode == 28
        assert timed_out.stdout == "000"
        assert not response_file.exists() or response_file.read_bytes() == b""

        readback = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--noproxy",
                "*",
                "--resolve",
                f"{authority}:127.0.0.1",
                "--cacert",
                str(run_root / "certificates/ca.pem"),
                url,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert readback.returncode == 0, readback.stderr
        assert json.loads(readback.stdout)["counter"] == expected_counter

        token = (run_root / "control-token").read_text(encoding="ascii").strip()
        exported = subprocess.run(
            [
                "curl",
                "--silent",
                "--show-error",
                "--unix-socket",
                str(run_root / "control.sock"),
                "--header",
                f"x-datalox-control-token: {token}",
                f"http://localhost/v1/providers/{PROVIDER_ID}/delivery-interventions/export",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert exported.returncode == 0, exported.stderr
        trace = json.loads(exported.stdout)
        event = trace["events"][0]
        assert event["base"]["provider_state_relation"] == expected_relation
        assert event["delivered"]["response_start_sent"] is False
        assert event["delivered"]["response_body_bytes_sent"] == 0
        assert trace["pending_transport_count"] == 0
        if phase == "pre_dispatch":
            assert event["base"]["invoked"] is False
        else:
            assert event["base"]["invoked"] is True
            assert event["base"]["response"]["body"]["counter"] == 3
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        shutil.rmtree(tmp_path)
