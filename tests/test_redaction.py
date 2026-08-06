import json
from pathlib import Path

from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import CallRequest, GateDecision


def test_session_ledger_redacts_request_headers_by_default_in_memory_and_on_disk(
    tmp_path: Path,
) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    ledger = SessionLedger(path=ledger_path)
    request = CallRequest(
        method="GET",
        path="/v1/items",
        headers={
            "Authorization": "Bearer real-token",
            "X-Api-Key": "real-api-key",
            "Private-Token": "private-provider-token",
            "X-Access-Token": "provider-access-token",
            "X-Custom-Agent-Secret": "custom-secret",
            "Accept": "application/json",
        },
    )

    event = ledger.record(
        request=request,
        decision=GateDecision(kind="miss", reason_code="no_case", message="no replay case"),
        response_status_code=404,
        response_body={"error": "missing"},
    )

    assert event.request.headers == {
        "Authorization": "[REDACTED]",
        "X-Api-Key": "[REDACTED]",
        "Private-Token": "[REDACTED]",
        "X-Access-Token": "[REDACTED]",
        "X-Custom-Agent-Secret": "[REDACTED]",
        "Accept": "application/json",
    }
    assert ledger.events[0].request.headers == event.request.headers

    row = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert row["request"]["headers"] == event.request.headers


def test_session_ledger_redacts_secret_headers_case_insensitively() -> None:
    ledger = SessionLedger()
    request = CallRequest(
        method="GET",
        path="/v1/items",
        headers={
            "proxy-Authorization": "proxy-secret",
            "COOKIE": "session=secret",
            "set-cookie": "session=secret",
            "x-auth-token": "auth-secret",
            "api-key": "api-secret",
            "Accept": "application/json",
        },
    )

    event = ledger.record(
        request=request,
        decision=GateDecision(kind="miss", reason_code="no_case", message="no replay case"),
        response_status_code=404,
        response_body=None,
    )

    assert event.request.headers == {
        "proxy-Authorization": "[REDACTED]",
        "COOKIE": "[REDACTED]",
        "set-cookie": "[REDACTED]",
        "x-auth-token": "[REDACTED]",
        "api-key": "[REDACTED]",
        "Accept": "application/json",
    }
    assert request.headers["COOKIE"] == "session=secret"
