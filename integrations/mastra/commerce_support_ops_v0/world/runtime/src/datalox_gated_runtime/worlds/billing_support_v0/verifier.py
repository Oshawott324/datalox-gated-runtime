from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from datalox_gated_runtime.worlds.billing_support_v0.state import (
    connect,
    loads_json,
    metadata_path,
    resolve_state_db_path,
)


@dataclass(frozen=True)
class WorldVerifierResult:
    passed: bool
    verifier_type: str
    scenario: str
    checks: list[dict[str, Any]]
    failure_codes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verifier_type": self.verifier_type,
            "scenario": self.scenario,
            "checks": self.checks,
            "failure_codes": self.failure_codes,
        }


def verify_run(run_dir: Path) -> WorldVerifierResult:
    if not metadata_path(run_dir).exists():
        return _result(
            "unknown", [_fail("run_metadata_exists", "Missing billing_support_v0 run metadata.")]
        )

    metadata = json.loads(metadata_path(run_dir).read_text(encoding="utf-8"))
    scenario = metadata.get("scenario", "unknown")
    db_path = resolve_state_db_path(run_dir)
    if not db_path.exists():
        return _result(
            str(scenario), [_fail("state_db_exists", f"Missing state database at {db_path}.")]
        )

    with connect(db_path) as conn:
        expected = _expected_resolution(conn)
        if expected is None:
            return _result(
                str(scenario), [_fail("expected_resolution_exists", "Missing expected resolution.")]
            )
        if expected["scenario"] != "duplicate_payment_refund":
            return _result(
                str(expected["scenario"]),
                [_fail("scenario_supported", "Only duplicate_payment_refund is supported.")],
            )
        checks = _verify_duplicate_payment_refund(conn, expected)
        return _result(expected["scenario"], checks)


def _verify_duplicate_payment_refund(conn, expected: dict[str, Any]) -> list[dict[str, Any]]:
    duplicate_payment_id = expected["refund_payment_id"]
    original_payment_id = expected["do_not_refund_payment_id"]
    expected_amount = expected["refund_amount"]
    ticket_id = expected["ticket_id"]

    refund = conn.execute(
        """
        SELECT * FROM refunds
        WHERE payment_id = ? AND amount = ? AND reason = ? AND status = ?
        """,
        (duplicate_payment_id, expected_amount, expected["refund_reason"], "succeeded"),
    ).fetchone()
    original_refunds = conn.execute(
        "SELECT COUNT(*) AS count FROM refunds WHERE payment_id = ?",
        (original_payment_id,),
    ).fetchone()
    reply_ok = _ticket_has_public_agent_reply(conn, ticket_id, ["refund"])
    ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    ticket_closed = ticket is not None and ticket["status"] in {"solved", "closed"}

    return [
        _check(
            refund is not None,
            "duplicate_payment_refunded",
            "Duplicate payment has a succeeded duplicate refund.",
        ),
        _check(
            int(original_refunds["count"]) == 0,
            "original_payment_not_refunded",
            "Original invoice payment was not refunded.",
        ),
        _check(
            reply_ok,
            "ticket_reply_mentions_refund",
            "Ticket has a public agent reply mentioning the refund.",
        ),
        _check(ticket_closed, "ticket_closed", "Ticket is solved or closed."),
    ]


def _expected_resolution(conn) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT payload_json FROM events
        WHERE event_type = ? AND visible_to_agent = 0
        ORDER BY id DESC
        LIMIT 1
        """,
        ("expected_resolution.created",),
    ).fetchone()
    return loads_json(row["payload_json"]) if row is not None else None


def _ticket_has_public_agent_reply(conn, ticket_id: str, required_terms: list[str]) -> bool:
    rows = conn.execute(
        """
        SELECT body FROM ticket_messages
        WHERE ticket_id = ? AND author_type = ? AND public = 1
        """,
        (ticket_id, "agent"),
    ).fetchall()
    for row in rows:
        body = row["body"].lower()
        if all(term.lower() in body for term in required_terms):
            return True
    return False


def _result(scenario: str, checks: list[dict[str, Any]]) -> WorldVerifierResult:
    failure_codes = [check["name"] for check in checks if not check["ok"]]
    return WorldVerifierResult(
        passed=not failure_codes,
        verifier_type="billing_support_v0",
        scenario=scenario,
        checks=checks,
        failure_codes=failure_codes,
    )


def _check(condition: bool, name: str, message: str) -> dict[str, Any]:
    return {"ok": bool(condition), "name": name, "message": message}


def _fail(name: str, message: str) -> dict[str, Any]:
    return _check(False, name, message)
