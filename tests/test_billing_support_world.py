import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from datalox_gated_runtime.cli import _session_finalize
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.session import create_session
from datalox_gated_runtime.world_backend import create_world_backend
from datalox_gated_runtime.worlds.billing_support_v0 import BillingSupportWorldBackend


TICKET_ID = "tkt_a13e9e9d3d"
CUSTOMER_ID = "cus_a13e9e9d3d"
INVOICE_ID = "in_a13e9e9d3d_01"
ORIGINAL_PAYMENT_ID = "py_a13e9e9d3d_ok_01"
DUPLICATE_PAYMENT_ID = "py_a13e9e9d3d_dup_02"


def test_load_gate_config_validates_billing_support_world_block(tmp_path: Path) -> None:
    config = load_gate_config(_write_gate_config(tmp_path, _gate_config()))

    assert config.world is not None
    assert config.world.id == "billing_support_v0"
    assert config.world.scenario == "duplicate_payment_refund"
    assert config.world.seed == 1
    assert config.world.state_db == "state.sqlite"
    assert config.world.http_prefixes == ["/support/", "/billing/"]
    assert config.world.verifier == "billing_support_v0"


def test_world_backend_factory_preserves_billing_backend(tmp_path: Path, monkeypatch) -> None:
    run_dir = _create_world_session(tmp_path, monkeypatch)
    config = load_gate_config(run_dir / "gate_config.json")

    backend = create_world_backend(run_dir=run_dir, config=config.world)

    assert isinstance(backend, BillingSupportWorldBackend)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", "unknown_world", "world.id"),
        ("scenario", "refund_not_allowed_policy", "world.scenario"),
        ("seed", "1", "world.seed"),
        ("http_prefixes", ["support/"], "world.http_prefixes"),
        ("http_prefixes", ["/support/"], "world.http_prefixes"),
    ],
)
def test_load_gate_config_rejects_invalid_world_block(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _gate_config()
    assert isinstance(payload["world"], dict)
    payload["world"][field] = value

    with pytest.raises(ValueError, match=message):
        load_gate_config(_write_gate_config(tmp_path, payload))


def test_session_create_initializes_deterministic_billing_world_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    examples_dir = _write_example(tmp_path)
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(examples_dir))
    run_dir = tmp_path / "run"

    create_session(example="billing_support_world_v0", out_dir=run_dir, http_port=8765)

    world_dir = run_dir / "world" / "billing_support_v0"
    metadata = json.loads((world_dir / "run.json").read_text(encoding="utf-8"))
    assert metadata == {
        "world": "billing_support_v0",
        "scenario": "duplicate_payment_refund",
        "seed": 1,
        "state_db": "state.sqlite",
        "verifier": "billing_support_v0",
    }
    db_path = world_dir / "state.sqlite"
    assert db_path.exists()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM tickets").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0] == 2
        expected = conn.execute(
            "SELECT payload_json FROM events WHERE event_type = ? AND visible_to_agent = 0",
            ("expected_resolution.created",),
        ).fetchone()
    assert expected is not None
    assert json.loads(expected[0])["refund_payment_id"] == DUPLICATE_PAYMENT_ID


def test_billing_world_http_reads_writes_and_readback_mutated_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = _create_world_session(tmp_path, monkeypatch)

    with TestClient(create_app(run_dir)) as client:
        ticket = client.get(f"/support/tickets/{TICKET_ID}")
        assert ticket.status_code == 200
        assert ticket.headers["x-datalox-decision"] == "replay"
        assert ticket.json()["data"]["id"] == TICKET_ID

        invoice = client.get(f"/billing/invoices/{INVOICE_ID}")
        assert invoice.status_code == 200
        payment_ids = [payment["id"] for payment in invoice.json()["data"]["payments"]]
        assert payment_ids == [ORIGINAL_PAYMENT_ID, DUPLICATE_PAYMENT_ID]

        payment = client.get(f"/billing/payments/{DUPLICATE_PAYMENT_ID}")
        assert payment.status_code == 200
        assert payment.json()["data"]["refundable_amount"] == 4900

        refund = client.post(
            "/billing/refunds",
            json={
                "payment_id": DUPLICATE_PAYMENT_ID,
                "amount": 4900,
                "reason": "duplicate",
                "ticket_id": TICKET_ID,
            },
        )
        assert refund.status_code == 200
        assert refund.headers["x-datalox-decision"] == "shadow_write"
        assert refund.json()["data"]["payment_id"] == DUPLICATE_PAYMENT_ID

        reply = client.post(
            f"/support/tickets/{TICKET_ID}/reply",
            json={"body": "We found the duplicate charge and issued the refund.", "public": True},
        )
        assert reply.status_code == 200
        close = client.post(f"/support/tickets/{TICKET_ID}/close")
        assert close.status_code == 200

        updated_payment = client.get(f"/billing/payments/{DUPLICATE_PAYMENT_ID}")
        assert updated_payment.json()["data"]["refunded_amount"] == 4900
        assert updated_payment.json()["data"]["refunds"][0]["reason"] == "duplicate"

        updated_ticket = client.get(f"/support/tickets/{TICKET_ID}")
        assert updated_ticket.json()["data"]["status"] == "solved"
        assert any(
            message["author_type"] == "agent" and "refund" in message["body"].lower()
            for message in updated_ticket.json()["data"]["messages"]
        )

    rows = _ledger_rows(run_dir)
    assert rows[0]["decision"]["reason_code"] == "world_state_read"
    assert rows[3]["decision"]["reason_code"] == "world_state_write"
    assert rows[3]["shadow_mutation"]["mode"] == "world_state_write"
    assert rows[3]["shadow_mutation"]["world"] == "billing_support_v0"
    assert rows[3]["shadow_mutation"]["response"]["data"]["payment_id"] == DUPLICATE_PAYMENT_ID


def test_session_finalize_includes_passing_billing_world_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = _create_world_session(tmp_path, monkeypatch)
    _resolve_duplicate_refund(run_dir)

    assert _session_finalize(argparse.Namespace(run=str(run_dir), json=True)) == 0

    audit = json.loads((run_dir / "audit.json").read_text(encoding="utf-8"))
    assert audit["passed"] is True
    assert audit["verifier_type"] == "combined_post_run_audit"
    assert audit["verifiers"]["config"]["passed"] is True
    assert audit["verifiers"]["world"]["passed"] is True
    assert audit["verifiers"]["world"]["scenario"] == "duplicate_payment_refund"
    assert audit["checks"]["world.billing_support_v0.duplicate_payment_refunded"] is True
    assert audit["checks"]["world.billing_support_v0.original_payment_not_refunded"] is True
    assert audit["checks"]["world.billing_support_v0.ticket_reply_mentions_refund"] is True
    assert audit["checks"]["world.billing_support_v0.ticket_closed"] is True


def test_session_finalize_fails_untouched_billing_world(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = _create_world_session(tmp_path, monkeypatch)

    assert _session_finalize(argparse.Namespace(run=str(run_dir), json=True)) == 1

    audit = json.loads((run_dir / "audit.json").read_text(encoding="utf-8"))
    assert audit["passed"] is False
    assert audit["verifiers"]["world"]["passed"] is False
    assert audit["checks"]["world.billing_support_v0.duplicate_payment_refunded"] is False
    assert audit["checks"]["world.billing_support_v0.ticket_reply_mentions_refund"] is False
    assert "world.billing_support_v0.duplicate_payment_refunded" in audit["failure_codes"]


def test_session_finalize_non_json_prints_combined_world_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    run_dir = _create_world_session(tmp_path, monkeypatch)

    assert _session_finalize(argparse.Namespace(run=str(run_dir), json=False)) == 1

    captured = capsys.readouterr()
    assert "Audit result: failed" in captured.out


def test_session_finalize_fails_when_original_payment_is_refunded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_dir = _create_world_session(tmp_path, monkeypatch)

    with TestClient(create_app(run_dir)) as client:
        client.post(
            "/billing/refunds",
            json={
                "payment_id": ORIGINAL_PAYMENT_ID,
                "amount": 4900,
                "reason": "duplicate",
                "ticket_id": TICKET_ID,
            },
        )
        client.post(
            f"/support/tickets/{TICKET_ID}/reply",
            json={"body": "The duplicate refund has been processed.", "public": True},
        )
        client.post(f"/support/tickets/{TICKET_ID}/close")

    assert _session_finalize(argparse.Namespace(run=str(run_dir), json=True)) == 1

    audit = json.loads((run_dir / "audit.json").read_text(encoding="utf-8"))
    assert audit["verifiers"]["world"]["passed"] is False
    assert audit["checks"]["world.billing_support_v0.duplicate_payment_refunded"] is False
    assert audit["checks"]["world.billing_support_v0.original_payment_not_refunded"] is False
    assert "world.billing_support_v0.original_payment_not_refunded" in audit["failure_codes"]


def _create_world_session(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    examples_dir = _write_example(tmp_path)
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(examples_dir))
    run_dir = tmp_path / "run"
    create_session(example="billing_support_world_v0", out_dir=run_dir, http_port=8765)
    return run_dir


def _resolve_duplicate_refund(run_dir: Path) -> None:
    with TestClient(create_app(run_dir)) as client:
        client.get(f"/support/tickets/{TICKET_ID}")
        client.get(f"/billing/invoices/{INVOICE_ID}")
        client.get(f"/billing/payments/{DUPLICATE_PAYMENT_ID}")
        client.post(
            "/billing/refunds",
            json={
                "payment_id": DUPLICATE_PAYMENT_ID,
                "amount": 4900,
                "reason": "duplicate",
                "ticket_id": TICKET_ID,
            },
        )
        client.post(
            f"/support/tickets/{TICKET_ID}/reply",
            json={"body": "We found the duplicate charge and issued the refund.", "public": True},
        )
        client.post(f"/support/tickets/{TICKET_ID}/close")


def _write_example(tmp_path: Path) -> Path:
    examples_dir = tmp_path / "examples"
    example_dir = examples_dir / "billing_support_world_v0"
    example_dir.mkdir(parents=True)
    _write_gate_config(example_dir, _gate_config())
    (example_dir / "task.json").write_text(
        json.dumps(
            {
                "task_id": "billing_support_world_v0",
                "title": "Resolve duplicate payment refund",
                "instructions": f"Refund duplicate payment for ticket {TICKET_ID}.",
                "success_criteria": ["Refund the duplicate payment, reply, and close the ticket."],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return examples_dir


def _gate_config() -> dict[str, Any]:
    return {
        "config_id": "billing_support_world_v0",
        "response_cases": [],
        "audit_rules": [],
        "world": {
            "id": "billing_support_v0",
            "scenario": "duplicate_payment_refund",
            "seed": 1,
            "state_db": "state.sqlite",
            "http_prefixes": ["/support/", "/billing/"],
            "verifier": "billing_support_v0",
        },
    }


def _write_gate_config(directory: Path, payload: dict[str, Any]) -> Path:
    path = directory / "gate_config.json"
    directory.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _ledger_rows(run_dir: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (run_dir / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
