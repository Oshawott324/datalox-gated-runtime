from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.models import LedgerEvent
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import VerifierAssertion
from datalox_gated_runtime.worlds.response_case_state_v0.state import (
    connect,
    load_metadata,
    load_state,
    metadata_path,
    resolve_state_db_path,
)
from datalox_gated_runtime.worlds.response_case_state_v0.transitions import resolve_pointer


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


def verify_run(run_dir: Path, *, ledger: SessionLedger | None = None) -> WorldVerifierResult:
    if not metadata_path(run_dir).exists():
        return _result(
            "unknown", [_check(False, "run_metadata_exists", "Missing world run metadata.")]
        )
    db_path = resolve_state_db_path(run_dir)
    if not db_path.exists():
        return _result(
            "unknown", [_check(False, "state_db_exists", "Missing world state database.")]
        )
    with connect(db_path) as connection:
        state = load_state(connection)
        episode = load_metadata(connection, "episode")
        assertions = [
            VerifierAssertion(**raw) for raw in load_metadata(connection, "verifier_assertions")
        ]
    active_ledger = ledger or SessionLedger(path=run_dir / "ledger.jsonl")
    events = [event for event in active_ledger.events if isinstance(event, LedgerEvent)]
    checks = [_evaluate(assertion, state, episode["expected"], events) for assertion in assertions]
    return _result(episode["episode_id"], checks)


def _evaluate(
    assertion: VerifierAssertion,
    state: dict[str, Any],
    episode_expected: dict[str, Any],
    events: list[LedgerEvent],
) -> dict[str, Any]:
    operation_events = [
        event for event in events if event.request.operation_id == assertion.operation_id
    ]
    try:
        expected = (
            resolve_pointer(episode_expected, assertion.expected_pointer)
            if assertion.expected_pointer is not None
            else assertion.expected
        )
        if assertion.assertion_type == "state_equals":
            actual = resolve_pointer(state[assertion.state_key], assertion.pointer or "")
            ok = actual == expected
        elif assertion.assertion_type == "state_values_equal":
            actual = resolve_pointer(state[assertion.state_key], assertion.pointer or "")
            another_actual = resolve_pointer(
                state[assertion.another_state_key],
                assertion.another_pointer or "",
            )
            ok = actual == another_actual
        elif assertion.assertion_type == "state_text_contains_all":
            actual = resolve_pointer(state[assertion.state_key], assertion.pointer or "")
            ok = _text_contains_all(actual, expected)
        elif assertion.assertion_type == "state_array_projection_equals_unordered":
            actual = resolve_pointer(state[assertion.state_key], assertion.pointer or "")
            ok = _array_projection_equals_unordered(
                actual,
                assertion.item_pointer or "",
                expected,
            )
        elif assertion.assertion_type == "operation_present":
            ok = any(event.decision.kind != "deny" for event in operation_events)
        elif assertion.assertion_type == "operation_absent":
            ok = not any(event.decision.kind != "deny" for event in operation_events)
        elif assertion.assertion_type == "operation_not_attempted":
            ok = not operation_events
        elif assertion.assertion_type == "operation_denied":
            ok = any(event.decision.kind == "deny" for event in operation_events)
        elif assertion.assertion_type == "operation_order":
            indexes = [
                next(
                    (
                        index
                        for index, event in enumerate(events)
                        if event.request.operation_id == operation_id
                        and event.decision.kind != "deny"
                    ),
                    None,
                )
                for operation_id in assertion.operations
            ]
            ok = all(index is not None for index in indexes) and indexes == sorted(indexes)
        elif assertion.assertion_type == "request_value_equals":
            ok = any(
                _event_request_matches(event, assertion.request_pointer or "", expected)
                for event in operation_events
                if event.decision.kind != "deny"
            )
        else:
            ok = False
    except (KeyError, ValueError):
        ok = False
    return _check(ok, assertion.name, f"Verifier assertion {assertion.name}.")


def _event_request_matches(event: LedgerEvent, pointer: str, expected: Any) -> bool:
    try:
        return (
            resolve_pointer(event.request.body, pointer, missing_code="request_value_missing")
            == expected
        )
    except ValueError:
        return False


def _text_contains_all(actual: Any, expected: Any) -> bool:
    if not isinstance(actual, str) or not isinstance(expected, list):
        return False
    normalized = " ".join(actual.casefold().split())
    return bool(expected) and all(
        isinstance(value, str) and " ".join(value.casefold().split()) in normalized
        for value in expected
    )


def _array_projection_equals_unordered(
    actual: Any,
    item_pointer: str,
    expected: Any,
) -> bool:
    if not isinstance(actual, list) or not isinstance(expected, list):
        return False
    projected = [resolve_pointer(item, item_pointer) for item in actual]
    return Counter(_canonical_json(value) for value in projected) == Counter(
        _canonical_json(value) for value in expected
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _result(scenario: str, checks: list[dict[str, Any]]) -> WorldVerifierResult:
    failure_codes = [check["name"] for check in checks if not check["ok"]]
    return WorldVerifierResult(
        passed=not failure_codes,
        verifier_type="response_case_state_v0",
        scenario=scenario,
        checks=checks,
        failure_codes=failure_codes,
    )


def _check(condition: bool, name: str, message: str) -> dict[str, Any]:
    return {"ok": bool(condition), "name": name, "message": message}
