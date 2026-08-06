from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import (
    CallRequest,
    GateDecision,
    ResponseCaseStateWorldConfig,
)
from datalox_gated_runtime.world_backend import initialize_world
from datalox_gated_runtime.worlds.response_case_state_v0.verifier import verify_run
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import VerifierAssertion
from datalox_gated_runtime.worlds.response_case_state_v0.verifier import _evaluate
from response_case_state_helpers import EXAMPLE_ROOT, create_world_session


def test_generic_verifier_checks_state_order_requests_and_denials(
    tmp_path: Path, monkeypatch
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    with TestClient(create_app(run_dir)) as client:
        client.patch("/incidents/inc-001/assign", json={"assignee": "owner@example.test"})
        client.post("/incidents/inc-001/notes", json={"note": "Impact confirmed."})
        client.post("/tickets/ticket-001/evidence/fresh", json={})
        client.post("/tickets/ticket-001/copy-assignee", json={})
        client.post("/tickets/ticket-001/send", json={})
        client.post("/incidents/inc-001/resolve", json={})

    result = verify_run(run_dir)

    assert result.passed is True
    assert result.failure_codes == []
    assert {check["name"] for check in result.checks} == {
        "incident_assigned",
        "evidence_fresh",
        "customer_owner_matches",
        "workflow_order",
        "assignment_request_actor",
        "send_denied",
        "resolve_denied",
    }


def test_generic_verifier_fails_wrong_order_and_missing_denials(
    tmp_path: Path, monkeypatch
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    with TestClient(create_app(run_dir)) as client:
        client.post("/incidents/inc-001/notes", json={"note": "Out of order."})
        client.patch("/incidents/inc-001/assign", json={"assignee": "owner@example.test"})
        client.post("/tickets/ticket-001/evidence/fresh", json={})
        client.post("/tickets/ticket-001/copy-assignee", json={})

    result = verify_run(run_dir)

    assert result.passed is False
    assert "workflow_order" in result.failure_codes
    assert "send_denied" in result.failure_codes
    assert "resolve_denied" in result.failure_codes


def test_each_seed_uses_its_own_hidden_expected_assignee(tmp_path: Path, monkeypatch) -> None:
    for seed, incident_id, ticket_id, assignee in (
        (0, "inc-001", "ticket-001", "owner@example.test"),
        (1, "inc-002", "ticket-002", "second-owner@example.test"),
    ):
        run_dir = create_world_session(tmp_path, monkeypatch, name=f"seed-{seed}", seed=seed)
        _complete_workflow(run_dir, incident_id, ticket_id, assignee)

        assert verify_run(run_dir).passed is True


def test_malformed_earlier_request_does_not_mask_later_valid_event(
    tmp_path: Path,
    monkeypatch,
) -> None:
    run_dir = create_world_session(tmp_path, monkeypatch)
    SessionLedger(path=run_dir / "ledger.jsonl").record(
        request=CallRequest(
            method="PATCH",
            path="/incidents/inc-001/assign",
            body={},
            operation_id="assign_incident",
        ),
        decision=GateDecision(
            kind="shadow_write",
            reason_code="synthetic_prior_event",
            message="Synthetic malformed prior event.",
        ),
        response_status_code=200,
        response_body={},
    )
    _complete_workflow(run_dir, "inc-001", "ticket-001", "owner@example.test")

    result = verify_run(run_dir)

    assert result.passed is True
    assert "assignment_request_actor" not in result.failure_codes


def test_operation_not_attempted_passes_with_no_matching_event(tmp_path: Path) -> None:
    run_dir = _create_operation_attempt_session(tmp_path)

    checks = _checks_by_name(verify_run(run_dir))

    assert checks["send_not_attempted"]["ok"] is True
    assert checks["send_operation_absent"]["ok"] is True


@pytest.mark.parametrize("decision_kind", ["replay", "shadow_write", "miss"])
def test_operation_not_attempted_fails_for_any_non_denied_event(
    tmp_path: Path,
    decision_kind: str,
) -> None:
    run_dir = _create_operation_attempt_session(tmp_path)
    _record_send_event(run_dir, decision_kind)

    checks = _checks_by_name(verify_run(run_dir))

    assert checks["send_not_attempted"]["ok"] is False
    assert checks["send_operation_absent"]["ok"] is False


def test_operation_not_attempted_fails_for_denial_while_operation_absent_passes(
    tmp_path: Path,
) -> None:
    run_dir = _create_operation_attempt_session(tmp_path)
    _record_send_event(run_dir, "deny")

    checks = _checks_by_name(verify_run(run_dir))

    assert checks["send_not_attempted"]["ok"] is False
    assert checks["send_operation_absent"]["ok"] is True


def test_semantic_state_assertions_accept_equivalent_prose_and_recipient_order() -> None:
    state = {
        "draft": {
            "body": {
                "content": (
                    "At 10:30 UTC, coordinate checkout-api for Northstar. "
                    "The linked issue is OPS-100."
                )
            },
            "toRecipients": [
                {"emailAddress": {"address": "success@example.test", "name": "Success"}},
                {"emailAddress": {"address": "oncall@example.test", "name": "On Call"}},
            ],
        }
    }
    text_assertion = VerifierAssertion(
        name="draft_facts",
        assertion_type="state_text_contains_all",
        state_key="draft",
        pointer="/body/content",
        expected=["OPS-100", "checkout-api", "10:30 UTC", "Northstar"],
    )
    recipient_assertion = VerifierAssertion(
        name="internal_recipients",
        assertion_type="state_array_projection_equals_unordered",
        state_key="draft",
        pointer="/toRecipients",
        item_pointer="/emailAddress/address",
        expected=["oncall@example.test", "success@example.test"],
    )

    assert _evaluate(text_assertion, state, {}, [])["ok"] is True
    assert _evaluate(recipient_assertion, state, {}, [])["ok"] is True


def test_state_values_equal_compares_current_state_views() -> None:
    assertion = VerifierAssertion(
        name="provider_views_agree",
        assertion_type="state_values_equal",
        state_key="incident",
        pointer="/assignee",
        another_state_key="ticket",
        another_pointer="/owner",
    )
    matching = {
        "incident": {"assignee": "owner@example.test"},
        "ticket": {"owner": "owner@example.test"},
    }
    mismatching = {
        "incident": {"assignee": "owner@example.test"},
        "ticket": {"owner": "queue"},
    }

    assert _evaluate(assertion, matching, {}, [])["ok"] is True
    assert _evaluate(assertion, mismatching, {}, [])["ok"] is False


@pytest.mark.parametrize(
    ("content", "recipients", "failed_assertion"),
    [
        (
            "Coordinate OPS-100 for checkout-api at 09:30 UTC for Northstar.",
            ["oncall@example.test", "success@example.test"],
            "draft_facts",
        ),
        (
            "Coordinate OPS-100 for checkout-api at 10:30 UTC for Bluebird.",
            ["oncall@example.test", "success@example.test"],
            "draft_facts",
        ),
        (
            "Coordinate OPS-100 for checkout-api at 10:30 UTC for Northstar.",
            ["external@example.test", "success@example.test"],
            "internal_recipients",
        ),
    ],
)
def test_semantic_state_assertions_reject_wrong_slot_account_or_recipient(
    content: str,
    recipients: list[str],
    failed_assertion: str,
) -> None:
    state = {
        "draft": {
            "body": {"content": content},
            "toRecipients": [{"emailAddress": {"address": address}} for address in recipients],
        }
    }
    assertions = {
        "draft_facts": VerifierAssertion(
            name="draft_facts",
            assertion_type="state_text_contains_all",
            state_key="draft",
            pointer="/body/content",
            expected=["OPS-100", "checkout-api", "10:30 UTC", "Northstar"],
        ),
        "internal_recipients": VerifierAssertion(
            name="internal_recipients",
            assertion_type="state_array_projection_equals_unordered",
            state_key="draft",
            pointer="/toRecipients",
            item_pointer="/emailAddress/address",
            expected=["oncall@example.test", "success@example.test"],
        ),
    }

    assert _evaluate(assertions[failed_assertion], state, {}, [])["ok"] is False


def _complete_workflow(
    run_dir: Path,
    incident_id: str,
    ticket_id: str,
    assignee: str,
) -> None:
    with TestClient(create_app(run_dir)) as client:
        client.patch(f"/incidents/{incident_id}/assign", json={"assignee": assignee})
        client.post(f"/incidents/{incident_id}/notes", json={"note": "Impact confirmed."})
        client.post(f"/tickets/{ticket_id}/evidence/fresh", json={})
        client.post(f"/tickets/{ticket_id}/copy-assignee", json={})
        client.post(f"/tickets/{ticket_id}/send", json={})
        client.post(f"/incidents/{incident_id}/resolve", json={})


def _create_operation_attempt_session(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    verifier_path = source / "world" / "verifier.json"
    verifier = json.loads(verifier_path.read_text(encoding="utf-8"))
    verifier["assertions"].extend(
        [
            {
                "name": "send_not_attempted",
                "operation_id": "send_customer_draft",
                "type": "operation_not_attempted",
            },
            {
                "name": "send_operation_absent",
                "operation_id": "send_customer_draft",
                "type": "operation_absent",
            },
        ]
    )
    verifier_path.write_text(json.dumps(verifier), encoding="utf-8")
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)
    run_dir = tmp_path / "run"
    initialize_world(run_dir=run_dir, config=config.world, source_dir=source)
    return run_dir


def _record_send_event(run_dir: Path, decision_kind: str) -> None:
    SessionLedger(path=run_dir / "ledger.jsonl").record(
        request=CallRequest(
            method="POST",
            path="/tickets/ticket-001/send",
            operation_id="send_customer_draft",
        ),
        decision=GateDecision(
            kind=decision_kind,
            reason_code="synthetic_event",
            message="Synthetic verifier event.",
        ),
        response_status_code=403 if decision_kind == "deny" else 200,
        response_body={},
    )


def _checks_by_name(result) -> dict[str, dict]:
    return {check["name"]: check for check in result.checks}
