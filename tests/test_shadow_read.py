from pathlib import Path

import pytest

from datalox_gated_runtime import CallRequest, GatedRuntime, ResponseCase
from datalox_gated_runtime.ledger import SessionLedger


def test_get_after_shadow_write_returns_written_body() -> None:
    runtime = GatedRuntime()

    runtime.handle(
        CallRequest(method="POST", path="/benchling/assay-results", body={"value": 0.82})
    )
    response = runtime.handle(CallRequest(method="GET", path="/benchling/assay-results"))

    assert response.status_code == 200
    assert response.decision.kind == "shadow_read"
    assert response.decision.reason_code == "shadow_state_overlay_v0"
    assert response.body == {"value": 0.82}


def test_ledger_record_snapshots_request_query_and_body() -> None:
    runtime = GatedRuntime()
    query = {"draft": "1"}
    body = {"payload": {"value": "original"}}

    runtime.handle(CallRequest(method="POST", path="/x", query=query, body=body))
    query["draft"] = "2"
    body["payload"]["value"] = "mutated"

    event = runtime.ledger.events[0]
    assert event.request.query == {"draft": "1"}
    assert event.request.body == {"payload": {"value": "original"}}
    assert event.shadow_mutation == {
        "method": "POST",
        "path": "/x",
        "query": {"draft": "1"},
        "body": {"payload": {"value": "original"}},
    }
    assert runtime.export().shadow_state["writes"] == [
        {
            "method": "POST",
            "path": "/x",
            "query": {"draft": "1"},
            "body": {"payload": {"value": "original"}},
        }
    ]


def test_shadow_read_is_query_aware() -> None:
    runtime = GatedRuntime()

    runtime.handle(CallRequest(method="POST", path="/x", query={"draft": "1"}, body={"rev": "new"}))
    bare_response = runtime.handle(CallRequest(method="GET", path="/x"))
    matched_response = runtime.handle(CallRequest(method="GET", path="/x", query={"draft": "1"}))

    assert bare_response.status_code == 404
    assert bare_response.decision.kind == "miss"
    assert matched_response.status_code == 200
    assert matched_response.decision.kind == "shadow_read"
    assert matched_response.body == {"rev": "new"}
    assert runtime.ledger.events[0].shadow_mutation == {
        "method": "POST",
        "path": "/x",
        "query": {"draft": "1"},
        "body": {"rev": "new"},
    }


def test_shadow_read_wins_over_response_case() -> None:
    runtime = GatedRuntime(
        response_cases=[
            ResponseCase(
                case_id="case_old_x",
                method="GET",
                path="/x",
                status_code=200,
                body={"version": "old"},
            )
        ],
    )

    runtime.handle(CallRequest(method="PUT", path="/x", body={"version": "new"}))
    response = runtime.handle(CallRequest(method="GET", path="/x"))

    assert response.status_code == 200
    assert response.decision.kind == "shadow_read"
    assert response.decision.reason_code == "shadow_state_overlay_v0"
    assert response.body == {"version": "new"}


def test_latest_shadow_write_wins() -> None:
    runtime = GatedRuntime()

    runtime.handle(CallRequest(method="POST", path="/x", body={"rev": 1}))
    runtime.handle(CallRequest(method="POST", path="/x", body={"rev": 2}))
    response = runtime.handle(CallRequest(method="GET", path="/x"))

    assert response.status_code == 200
    assert response.decision.kind == "shadow_read"
    assert response.body == {"rev": 2}


def test_unwritten_path_still_misses() -> None:
    runtime = GatedRuntime()

    runtime.handle(CallRequest(method="POST", path="/x", body={"ok": True}))
    response = runtime.handle(CallRequest(method="GET", path="/y"))

    assert response.status_code == 404
    assert response.decision.kind == "miss"


def test_persisted_shadow_write_rehydrates_for_shadow_read(tmp_path: Path) -> None:
    ledger_path = tmp_path / "ledger.jsonl"
    first_runtime = GatedRuntime(ledger=SessionLedger(path=ledger_path))
    first_runtime.handle(CallRequest(method="POST", path="/x", body={"rev": 1}))

    second_runtime = GatedRuntime(ledger=SessionLedger(path=ledger_path))
    response = second_runtime.handle(CallRequest(method="GET", path="/x"))

    assert response.status_code == 200
    assert response.decision.kind == "shadow_read"
    assert response.decision.reason_code == "shadow_state_overlay_v0"
    assert response.body == {"rev": 1}


def test_shadow_read_requires_exact_path() -> None:
    runtime = GatedRuntime()

    runtime.handle(CallRequest(method="POST", path="/x", body={"ok": True}))
    response = runtime.handle(CallRequest(method="GET", path="/x/child"))

    assert response.status_code == 404
    assert response.decision.kind == "miss"


def test_shadow_read_raises_on_missing_writes_list() -> None:
    ledger = SessionLedger()
    ledger.shadow_state = {}
    runtime = GatedRuntime(ledger=ledger)

    with pytest.raises(ValueError, match=r"shadow_state\.writes"):
        runtime.handle(CallRequest(method="GET", path="/x"))


def test_shadow_read_raises_on_matching_write_missing_body() -> None:
    ledger = SessionLedger()
    ledger.shadow_state = {"writes": [{"path": "/x"}]}
    runtime = GatedRuntime(ledger=ledger)

    with pytest.raises(ValueError, match=r"shadow_state\.writes.*body"):
        runtime.handle(CallRequest(method="GET", path="/x"))


def test_latest_shadow_write_ignores_non_dict_entries() -> None:
    ledger = SessionLedger()
    ledger.shadow_state = {"writes": ["bad", {"path": "/x", "body": {"ok": True}}]}
    runtime = GatedRuntime(ledger=ledger)

    response = runtime.handle(CallRequest(method="GET", path="/x"))

    assert response.status_code == 200
    assert response.decision.kind == "shadow_read"
    assert response.body == {"ok": True}


def test_shadow_read_can_return_explicit_none_body() -> None:
    runtime = GatedRuntime()

    runtime.handle(CallRequest(method="POST", path="/x"))
    response = runtime.handle(CallRequest(method="GET", path="/x"))

    assert response.status_code == 200
    assert response.decision.kind == "shadow_read"
    assert response.body is None
