"""Independent audit of V1 intervention and model-visible observation evidence."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

from datalox_dirty_integration.contract import LIST_PRODUCTS_OPERATION


class CalibrationAuditError(ValueError):
    pass


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def audit_episode_export(exported: dict[str, Any]) -> dict[str, Any]:
    trace = _object(exported.get("intervention"), "intervention")
    provider = _object(exported.get("provider"), "provider")
    call_evidence = _object(provider.get("call_evidence"), "provider.call_evidence")
    provider_events: dict[str, dict[str, Any]] = {}
    for provider_event in _array(call_evidence.get("events"), "provider.call_evidence.events"):
        if not isinstance(provider_event, dict) or not isinstance(
            provider_event.get("event_id"), str
        ):
            continue
        provider_event_id = provider_event["event_id"]
        if provider_event_id in provider_events:
            raise CalibrationAuditError("provider evidence contains a duplicate event id")
        provider_events[provider_event_id] = provider_event
    delivered_calls: dict[int, dict[str, Any]] = {}
    for delivered_call in _array(exported.get("delivered_calls"), "delivered_calls"):
        if (
            not isinstance(delivered_call, dict)
            or delivered_call.get("operation_id") != LIST_PRODUCTS_OPERATION
        ):
            continue
        delivered_index = delivered_call.get("intervention_logical_request_index")
        if not isinstance(delivered_index, int):
            raise CalibrationAuditError("provider read call is missing its intervention index")
        if delivered_index in delivered_calls:
            raise CalibrationAuditError("delivered calls contain a duplicate intervention index")
        delivered_calls[delivered_index] = delivered_call
    semantic_events: list[dict[str, Any]] = []
    actions: Counter[str] = Counter()
    applied_count = 0
    changed_count = 0
    observational_noop_count = 0

    events = _array(trace.get("events"), "intervention.events")
    delivered_event_indexes: set[int] = set()
    for expected_index, event in enumerate(events, start=1):
        row = _object(event, "intervention event")
        index = row.get("logical_request_index")
        if index != expected_index:
            raise CalibrationAuditError("intervention events are not a contiguous request sequence")
        for field, expected in (
            ("provider", trace.get("provider")),
            (
                "admitted_read_operation_ids_sha256",
                trace.get("admitted_read_operation_ids_sha256"),
            ),
            ("policy_id", trace.get("policy_id")),
            ("policy_version", trace.get("policy_version")),
            ("policy_sha256", trace.get("policy_sha256")),
            ("seed", trace.get("seed")),
            ("enabled", trace.get("enabled")),
        ):
            if row.get(field) != expected:
                raise CalibrationAuditError(
                    f"intervention event binding mismatch for {field} at request index {index}"
                )
        decision = _object(row.get("decision"), "intervention event decision")
        action = decision.get("action")
        kind = decision.get("kind")
        if not isinstance(kind, str):
            raise CalibrationAuditError(f"decision kind is invalid at request index {index}")
        if (action is None) != (kind == "none"):
            raise CalibrationAuditError(f"decision action mismatch at request index {index}")
        if isinstance(action, dict) and action.get("kind") != kind:
            raise CalibrationAuditError(f"decision action kind mismatch at request index {index}")
        action_sha256 = None if action is None else canonical_sha256(action)
        if decision.get("action_sha256") != action_sha256:
            raise CalibrationAuditError(f"action digest mismatch at request index {index}")
        expected_decision_id = _decision_id(
            policy_sha256=trace.get("policy_sha256"),
            seed=trace.get("seed"),
            logical_request_index=index,
            operation_id=row.get("operation_id"),
            action=action,
        )
        if decision.get("decision_id") != expected_decision_id:
            raise CalibrationAuditError(f"decision identity mismatch at request index {index}")

        base = _object(row.get("base"), "intervention event base")
        delivered = row.get("delivered")
        if row.get("outcome") == "delivered":
            expected_stage = (
                "none"
                if kind == "none"
                else "pre_dispatch"
                if kind == "quota_response"
                else "post_response"
            )
            if row.get("stage") != expected_stage:
                raise CalibrationAuditError(f"delivery stage mismatch at request index {index}")
            expected_applied = trace.get("enabled") is True and action is not None
            if row.get("applied") is not expected_applied:
                raise CalibrationAuditError(
                    f"intervention application mismatch at request index {index}"
                )
            delivered_object = _object(delivered, "intervention event delivered")
            response = _object(delivered_object.get("response"), "delivered response")
            delivered_sha256 = canonical_sha256(response)
            if delivered_object.get("response_sha256") != delivered_sha256:
                raise CalibrationAuditError(
                    f"delivered response digest mismatch at request index {index}"
                )
            if row.get("delivered_sha256") != delivered_sha256:
                raise CalibrationAuditError(
                    f"top-level delivered digest mismatch at request index {index}"
                )
            expected_changed = base.get("response_sha256") != delivered_sha256
            if row.get("observation_changed") is not expected_changed:
                raise CalibrationAuditError(
                    f"observation_changed mismatch at request index {index}"
                )
            call = delivered_calls.get(index)
            if call is None or canonical_sha256(call.get("observation")) != delivered_sha256:
                raise CalibrationAuditError(
                    f"delivered tool observation mismatch at request index {index}"
                )
            delivered_event_indexes.add(index)
        elif row.get("outcome") == "terminal_failure":
            delivered_sha256 = None
            if (
                delivered is not None
                or row.get("delivered_sha256") is not None
                or row.get("observation_changed") is not None
            ):
                raise CalibrationAuditError(
                    f"terminal failure claims a delivered observation at request index {index}"
                )
        else:
            raise CalibrationAuditError(f"unsupported outcome at request index {index}")

        if row.get("base_sha256") != base.get("response_sha256"):
            raise CalibrationAuditError(f"top-level base digest mismatch at request index {index}")

        if base.get("invoked") is True:
            base_event_id = base.get("event_id")
            provider_event = provider_events.get(base_event_id)
            if not isinstance(provider_event, dict):
                raise CalibrationAuditError(
                    f"base provider event is missing at request index {index}"
                )
            if provider_event.get("request", {}).get("operation_id") != row.get("operation_id"):
                raise CalibrationAuditError(
                    f"base provider operation mismatch at request index {index}"
                )
            provider_response = {
                "status_code": provider_event.get("response_status_code"),
                "headers": {},
                "body": provider_event.get("response_body"),
            }
            if canonical_sha256(provider_response) != base.get("response_sha256"):
                raise CalibrationAuditError(
                    f"base provider response mismatch at request index {index}"
                )
        elif base.get("event_id") is not None or base.get("response_sha256") is not None:
            raise CalibrationAuditError(
                f"non-invoked base contains provider evidence at request index {index}"
            )

        actions[kind] += 1
        if row.get("applied") is True:
            applied_count += 1
            if row.get("observation_changed") is False:
                observational_noop_count += 1
        if row.get("observation_changed") is True:
            changed_count += 1
        semantic_events.append(
            {
                "logical_request_index": index,
                "operation_id": row.get("operation_id"),
                "decision_id": decision.get("decision_id"),
                "kind": kind,
                "action_sha256": action_sha256,
                "stage": row.get("stage"),
                "applied": row.get("applied"),
                "observation_changed": row.get("observation_changed"),
                "outcome": row.get("outcome"),
                "base_invoked": base.get("invoked"),
                "base_sha256": row.get("base_sha256"),
                "delivered_sha256": row.get("delivered_sha256"),
            }
        )

    if set(delivered_calls) != delivered_event_indexes:
        raise CalibrationAuditError("delivered read calls and intervention events do not match")
    if trace.get("next_request_index") != len(events) + 1:
        raise CalibrationAuditError("intervention next request index does not match its events")

    semantic = {
        "provider": trace.get("provider"),
        "admitted_read_operation_ids_sha256": trace.get("admitted_read_operation_ids_sha256"),
        "policy_id": trace.get("policy_id"),
        "policy_version": trace.get("policy_version"),
        "policy_sha256": trace.get("policy_sha256"),
        "seed": trace.get("seed"),
        "enabled": trace.get("enabled"),
        "events": semantic_events,
    }
    return {
        "passed": True,
        "event_count": len(semantic_events),
        "semantic_sha256": canonical_sha256(semantic),
        "action_counts": dict(sorted(actions.items())),
        "applied_count": applied_count,
        "observation_changed_count": changed_count,
        "observational_noop_count": observational_noop_count,
        "semantic": semantic,
    }


def audit_pair(off_export: dict[str, Any], on_export: dict[str, Any]) -> dict[str, Any]:
    off = audit_episode_export(off_export)
    on = audit_episode_export(on_export)
    off_trace = _object(off_export.get("intervention"), "off intervention")
    on_trace = _object(on_export.get("intervention"), "on intervention")
    for field in (
        "provider",
        "admitted_read_operation_ids_sha256",
        "policy_id",
        "policy_version",
        "policy_sha256",
        "seed",
    ):
        if off_trace.get(field) != on_trace.get(field):
            raise CalibrationAuditError(f"paired trace binding differs for {field}")
    if off_trace.get("enabled") is not False or on_trace.get("enabled") is not True:
        raise CalibrationAuditError("paired trace modes are not OFF and ON")
    for field in (
        "provider_grounding_sha256",
        "provider_runtime_sha256",
        "provider_admission_sha256",
        "operation_claims_sha256",
        "operation_contract_sha256",
        "provider_release_config_sha256",
        "provider_release_digest",
        "provider_release_version",
        "provider_profile_id",
        "provider_bundle_version",
        "initial_state_fingerprint",
    ):
        if off_export.get(field) != on_export.get(field):
            raise CalibrationAuditError(f"paired provider binding differs for {field}")

    off_events = _array(off_trace.get("events"), "off events")
    on_events = _array(on_trace.get("events"), "on events")
    shared = min(len(off_events), len(on_events))
    for position in range(shared):
        off_event = _object(off_events[position], "off event")
        on_event = _object(on_events[position], "on event")
        for field in ("logical_request_index", "operation_id"):
            if off_event.get(field) != on_event.get(field):
                raise CalibrationAuditError(
                    f"paired policy decision differs at shared position {position + 1}"
                )
        off_decision = _object(off_event.get("decision"), "off decision")
        on_decision = _object(on_event.get("decision"), "on decision")
        for field in ("decision_id", "kind", "action", "action_sha256"):
            if off_decision.get(field) != on_decision.get(field):
                raise CalibrationAuditError(
                    f"paired policy decision differs at shared position {position + 1}"
                )
        if off_event.get("applied") is not False:
            raise CalibrationAuditError(
                f"OFF event applied an intervention at position {position + 1}"
            )
        if off_event.get("outcome") == "delivered" and off_event.get("base", {}).get(
            "response_sha256"
        ) != off_event.get("delivered", {}).get("response_sha256"):
            raise CalibrationAuditError(
                f"OFF event changed the base response at position {position + 1}"
            )
    pair_semantic = {
        "off": off["semantic"],
        "on": on["semantic"],
        "shared_request_count": shared,
    }
    return {
        "passed": True,
        "shared_request_count": shared,
        "semantic_sha256": canonical_sha256(pair_semantic),
        "off": {key: value for key, value in off.items() if key != "semantic"},
        "on": {key: value for key, value in on.items() if key != "semantic"},
    }


def _decision_id(
    *,
    policy_sha256: Any,
    seed: Any,
    logical_request_index: int,
    operation_id: Any,
    action: Any,
) -> str | None:
    if action is None:
        return None
    identity = {
        "policy_sha256": policy_sha256,
        "seed": seed,
        "logical_request_index": logical_request_index,
        "operation_id": operation_id,
        "action": action,
    }
    return f"decision_{canonical_sha256(identity).removeprefix('sha256:')[:24]}"


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CalibrationAuditError(f"{field} must be an object")
    return value


def _array(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise CalibrationAuditError(f"{field} must be an array")
    return value
