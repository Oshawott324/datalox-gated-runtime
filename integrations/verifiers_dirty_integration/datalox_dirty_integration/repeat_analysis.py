"""Pure, descriptive analysis of audited native-agent repeated rollouts.

This consumer-side analysis neither runs a model nor scores a task. It preserves
the existing verifier components and compares provider observations in order.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import statistics
from collections import Counter
from copy import deepcopy
from typing import Any

from datalox_dirty_integration.contract import (
    ADD_LINE_ITEM_OPERATION,
    CREATE_CART_OPERATION,
    DELETE_LINE_ITEM_OPERATION,
    LIST_PRODUCTS_OPERATION,
    UPDATE_LINE_ITEM_OPERATION,
)

WRITE_OPERATIONS = frozenset(
    {
        CREATE_CART_OPERATION,
        ADD_LINE_ITEM_OPERATION,
        UPDATE_LINE_ITEM_OPERATION,
        DELETE_LINE_ITEM_OPERATION,
    }
)
STATUSES = frozenset({"completed", "collection_error", "unstarted"})
IDENTITY_FIELDS = ("slot_id", "profile", "seed", "repetition")


class RepeatAnalysisError(ValueError):
    """The supplied cohort is incomplete or internally inconsistent evidence."""


def _canonical(value: Any) -> str:
    try:
        return json.dumps(
            value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    except (TypeError, ValueError) as exc:
        raise RepeatAnalysisError("evidence must contain finite JSON values") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RepeatAnalysisError(message)


def _number(value: Any, name: str, *, integer: bool = False) -> None:
    _require(
        type(value) is int if integer else type(value) in (int, float),
        f"{name} must be {'an integer' if integer else 'a number'}",
    )
    _require(
        (type(value) is int or math.isfinite(value)) and value >= 0,
        f"{name} must be finite and nonnegative",
    )


def _object(value: Any, fields: tuple[str, ...], name: str) -> None:
    _require(isinstance(value, dict), f"{name} must be an object")
    _require(all(key in value for key in fields), f"{name} is missing required fields")


def first_divergence(left: list[Any], right: list[Any]) -> dict[str, Any] | None:
    """Find the first exact JSON difference, using zero-based index/one-based position.

    Mapping key order is immaterial; array order, duplicates, scalar types,
    provider IDs and values are retained. An inserted call never triggers
    realignment. Presence flags distinguish an ended trace from a JSON null.
    """
    _require(isinstance(left, list) and isinstance(right, list), "traces must be arrays")
    _canonical(left)
    _canonical(right)
    for index in range(max(len(left), len(right))):
        left_present, right_present = index < len(left), index < len(right)
        lvalue = left[index] if left_present else None
        rvalue = right[index] if right_present else None
        if left_present != right_present or _canonical(lvalue) != _canonical(rvalue):
            return {
                "index": index,
                "position": index + 1,
                "kind": "value" if left_present and right_present else "trace_ended",
                "left_present": left_present,
                "right_present": right_present,
                "left": deepcopy(lvalue),
                "right": deepcopy(rvalue),
            }
    return None


def _counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    statuses = Counter(row["status"] for row in rows)
    return {
        "scheduled": len(rows),
        "attempted": statuses["completed"] + statuses["collection_error"],
        "completed": statuses["completed"],
        "audited": sum(
            row["status"] == "completed" and row["audit"]["passed"] is True for row in rows
        ),
        "collection_errors": statuses["collection_error"],
        "unstarted": statuses["unstarted"],
    }


def _stats(values: list[int | float]) -> dict[str, Any]:
    return {
        "n": len(values),
        "min": min(values) if values else None,
        "median": statistics.median(values) if values else None,
        "max": max(values) if values else None,
        "sample_sd": statistics.stdev(values) if len(values) >= 2 else None,
    }


def _success(successes: int, n: int) -> dict[str, Any]:
    if n == 0:
        return {"successes": 0, "n": 0, "proportion": None, "wilson_95": None}
    z = 1.959963984540054
    p = successes / n
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return {
        "successes": successes,
        "n": n,
        "proportion": p,
        "wilson_95": {"low": max(0.0, center - half), "high": min(1.0, center + half)},
    }


def _signatures(row: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    return (
        [
            {"operation_id": call["operation_id"], "request": call["request"]}
            for call in row["provider_calls"]
        ],
        [call["observation"] for call in row["provider_calls"]],
    )


def _validate_completed(row: dict[str, Any]) -> None:
    _object(
        row,
        (
            "task_correctness",
            "request_discipline",
            "provider_calls",
            "interventions",
            "tool_attempts",
            "invalid_tool_attempts",
            "native",
            "audit",
        ),
        f"completed slot {row['slot_id']}",
    )
    task = row["task_correctness"]
    _object(task, ("passed", "score", "checks", "failed_check_ids"), "task_correctness")
    _require(
        type(task["passed"]) is bool and isinstance(task["checks"], list) and bool(task["checks"]),
        "task verdict requires a boolean and named checks",
    )
    for check in task["checks"]:
        _object(check, ("check_id", "passed", "evidence"), "task check")
        _require(
            isinstance(check["check_id"], str) and type(check["passed"]) is bool,
            "task check identity or verdict is invalid",
        )
    check_ids = [check["check_id"] for check in task["checks"]]
    _require(len(set(check_ids)) == len(check_ids), "task check IDs must be unique")
    _require(
        task["passed"] is all(check["passed"] for check in task["checks"])
        and type(task["score"]) in (int, float)
        and task["score"] == float(task["passed"]),
        "task verdict disagrees with checks",
    )
    _require(
        task["failed_check_ids"]
        == [check["check_id"] for check in task["checks"] if not check["passed"]],
        "failed_check_ids disagrees with task checks",
    )
    calls, events = row["provider_calls"], row["interventions"]
    _require(
        isinstance(calls, list) and isinstance(events, list), "calls and events must be arrays"
    )
    indexes: list[int] = []
    for call in calls:
        _object(
            call,
            ("operation_id", "request", "observation", "intervention_logical_request_index"),
            "provider call",
        )
        _require(isinstance(call["operation_id"], str), "operation_id must be a string")
        _object(call["request"], ("method", "authority", "path", "query", "body"), "request")
        _object(call["observation"], ("status_code", "headers", "body"), "observation")
        _number(call["observation"]["status_code"], "status_code", integer=True)
        _require(100 <= call["observation"]["status_code"] <= 599, "invalid HTTP status code")
        index = call["intervention_logical_request_index"]
        if call["operation_id"] == LIST_PRODUCTS_OPERATION:
            _number(index, "logical request index", integer=True)
            indexes.append(index)
        else:
            _require(index is None, "only product reads advance the intervention index")
    _require(indexes == list(range(1, len(indexes) + 1)), "read indexes must be contiguous")
    _require(len(events) == len(indexes), "intervention count disagrees with indexed reads")
    for index, event in enumerate(events, start=1):
        _object(
            event,
            (
                "logical_request_index",
                "operation_id",
                "applied",
                "observation_changed",
                "decision",
                "base",
                "delivered",
                "outcome",
            ),
            "intervention",
        )
        _require(
            type(event["logical_request_index"]) is int
            and event["logical_request_index"] == index
            and event["operation_id"] == LIST_PRODUCTS_OPERATION,
            "intervention identity disagrees with indexed read",
        )
        _require(
            type(event["applied"]) is bool
            and type(event["observation_changed"]) is bool
            and event["outcome"] == "delivered",
            "completed slot has invalid intervention",
        )
        _object(event["decision"], ("kind",), "intervention decision")
        _object(event["base"], ("invoked", "event_id", "response_sha256"), "base receipt")
        _object(event["delivered"], ("response",), "delivered event")
        call = next(call for call in calls if call["intervention_logical_request_index"] == index)
        _require(
            _canonical(event["delivered"]["response"]) == _canonical(call["observation"]),
            "intervention delivered response disagrees with provider call",
        )
    _number(row["tool_attempts"], "tool_attempts", integer=True)
    _number(row["invalid_tool_attempts"], "invalid_tool_attempts", integer=True)
    unexecuted = row.get("unexecuted_tool_attempts", [])
    _require(isinstance(unexecuted, list), "unexecuted_tool_attempts must be an array")
    pending_ids = set()
    for tool in unexecuted:
        _object(tool, ("id", "name", "arguments"), "unexecuted tool call")
        _require(
            isinstance(tool["id"], str)
            and bool(tool["id"])
            and tool["id"] not in pending_ids
            and isinstance(tool["name"], str)
            and isinstance(tool["arguments"], str),
            "unexecuted tool calls require unique native IDs and string name/arguments",
        )
        pending_ids.add(tool["id"])
    _require(
        row["tool_attempts"] == len(calls) + row["invalid_tool_attempts"] + len(unexecuted),
        "tool attempts must account for delivered provider calls, invalid and unexecuted attempts",
    )
    discipline = row["request_discipline"]
    _object(
        discipline,
        (
            "score",
            "minimum_call_count",
            "actual_call_count",
            "failed_call_count",
            "efficiency",
            "failure_factor",
            "reason_codes",
        ),
        "request_discipline",
    )
    for name in ("score", "efficiency", "failure_factor"):
        _number(discipline[name], f"request_discipline.{name}")
        _require(discipline[name] <= 1, f"request_discipline.{name} exceeds one")
    for name in ("actual_call_count", "failed_call_count"):
        _number(discipline[name], name, integer=True)
    _require(discipline["actual_call_count"] == len(calls), "discipline call count mismatch")
    _require(
        discipline["failed_call_count"]
        == sum(
            call["observation"]["status_code"] < 200 or call["observation"]["status_code"] >= 300
            for call in calls
        ),
        "discipline failed call count mismatch",
    )
    if discipline["minimum_call_count"] is not None:
        _number(discipline["minimum_call_count"], "minimum_call_count", integer=True)
    _require(
        isinstance(discipline["reason_codes"], list)
        and all(isinstance(code, str) for code in discipline["reason_codes"]),
        "discipline reason_codes must be strings",
    )
    audit = row["audit"]
    _object(
        audit,
        (
            "passed",
            "event_count",
            "applied_count",
            "observation_changed_count",
            "observational_noop_count",
        ),
        "audit",
    )
    _require(audit["passed"] is True, "completed rollout requires a passing evidence audit")
    expected = {
        "event_count": len(events),
        "applied_count": sum(e["applied"] for e in events),
        "observation_changed_count": sum(e["observation_changed"] for e in events),
        "observational_noop_count": sum(
            e["applied"] and not e["observation_changed"] for e in events
        ),
    }
    for key, value in expected.items():
        _require(type(audit[key]) is int and audit[key] == value, f"audit {key} mismatch")
    native = row["native"]
    _object(
        native,
        (
            "termination_reason",
            "model",
            "backend_fingerprint",
            "usage",
            "duration_seconds",
            "agent_messages",
            "is_truncated",
            "is_completed",
        ),
        "native",
    )
    for key in ("termination_reason", "model", "backend_fingerprint"):
        _require(
            native[key] is None or isinstance(native[key], str),
            f"native.{key} must be text or null",
        )
    for key in ("is_truncated", "is_completed"):
        _require(
            native[key] is None or type(native[key]) is bool,
            f"native.{key} must be boolean or null",
        )
    _require(
        not unexecuted
        or (native["termination_reason"] == "max_turns_reached" and native["is_completed"] is True),
        "unexecuted tool attempts require a completed native max_turns_reached trajectory",
    )
    _require(
        native["usage"] is None or isinstance(native["usage"], dict),
        "native.usage must be object or null",
    )
    _require(isinstance(native["agent_messages"], list), "native.agent_messages must be an array")
    if unexecuted:
        _require(
            bool(native["agent_messages"]), "pending calls require a final native assistant message"
        )
        final_message = native["agent_messages"][-1]
        _object(final_message, ("role", "tool_calls"), "final native assistant message")
        _require(
            final_message["role"] == "assistant"
            and isinstance(final_message["tool_calls"], list)
            and all(isinstance(call, str) for call in final_message["tool_calls"]),
            "pending calls require native serialized assistant tool calls",
        )
        try:
            final_calls = [json.loads(call) for call in final_message["tool_calls"]]
        except json.JSONDecodeError as error:
            raise RepeatAnalysisError("invalid native pending tool-call encoding") from error
        _require(
            _canonical(final_calls) == _canonical(unexecuted),
            "pending calls disagree with the final native assistant message",
        )
    if native["duration_seconds"] is not None:
        _number(native["duration_seconds"], "native.duration_seconds")
    bases = row.get("base_responses", {})
    _require(isinstance(bases, dict), "base_responses must be an object")
    for key, response in bases.items():
        _require(
            key in {str(index) for index in indexes}, "base response has an unknown read index"
        )
        base = events[int(key) - 1]["base"]
        _require(
            base["invoked"] is True and _digest(response) == base["response_sha256"],
            "base response disagrees with its audited receipt",
        )


def _metrics(row: dict[str, Any]) -> dict[str, Any]:
    calls, events = row["provider_calls"], row["interventions"]
    quota_positions = [
        i for i, call in enumerate(calls) if call["observation"]["status_code"] == 429
    ]
    after_quota = [] if not quota_positions else calls[quota_positions[0] + 1 :]
    return {
        "tool_attempts": row["tool_attempts"],
        "invalid_tool_attempts": row["invalid_tool_attempts"],
        "unexecuted_tool_attempts": len(row.get("unexecuted_tool_attempts", [])),
        "provider_calls": len(calls),
        "indexed_reads": len(events),
        "base_provider_invocations": len(calls)
        - len(events)
        + sum(event["base"]["invoked"] is True for event in events),
        "write_calls": sum(call["operation_id"] in WRITE_OPERATIONS for call in calls),
        "discipline_score": row["request_discipline"]["score"],
        "efficiency": row["request_discipline"]["efficiency"],
        "failure_factor": row["request_discipline"]["failure_factor"],
        "failed_provider_calls": row["request_discipline"]["failed_call_count"],
        "applied_interventions": sum(event["applied"] for event in events),
        "changed_observations": sum(event["observation_changed"] for event in events),
        "observational_noops": sum(
            event["applied"] and not event["observation_changed"] for event in events
        ),
        "quota_responses": len(quota_positions),
        "writes_after_first_quota": sum(
            call["operation_id"] in WRITE_OPERATIONS for call in after_quota
        ),
        "ended_on_quota_response": bool(calls and calls[-1]["observation"]["status_code"] == 429),
        "task_incomplete_after_quota": bool(
            quota_positions and not row["task_correctness"]["passed"]
        ),
        "native_truncated": row["native"]["is_truncated"],
    }


def _context(row: dict[str, Any], position: int) -> dict[str, Any] | None:
    if position >= len(row["provider_calls"]):
        return None
    call = row["provider_calls"][position]
    index = call["intervention_logical_request_index"]
    event = row["interventions"][index - 1] if index is not None else None
    return deepcopy(
        {
            "provider_call_position": position + 1,
            "logical_request_index": index,
            "operation_id": call["operation_id"],
            "request": call["request"],
            "base_receipt": event["base"] if event else None,
            "base_response": row.get("base_responses", {}).get(str(index)),
            "decision": event["decision"] if event else None,
            "applied": event["applied"] if event else None,
            "observation_changed": event["observation_changed"] if event else None,
            "delivered_observation": call["observation"],
        }
    )


def _pair(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    lrequests, lobservations = _signatures(left)
    rrequests, robservations = _signatures(right)
    request = first_divergence(lrequests, rrequests)
    observation = first_divergence(lobservations, robservations)
    indexes = [value["index"] for value in (request, observation) if value is not None]
    first_index = min(indexes) if indexes else None
    return {
        "profile": left["profile"],
        "seed": left["seed"],
        "left_slot_id": left["slot_id"],
        "right_slot_id": right["slot_id"],
        "request": request,
        "observation": observation,
        "raw_native_message": first_divergence(
            left["native"]["agent_messages"], right["native"]["agent_messages"]
        ),
        "first_provider_difference_position": first_index + 1 if first_index is not None else None,
        "left_context": _context(left, first_index) if first_index is not None else None,
        "right_context": _context(right, first_index) if first_index is not None else None,
    }


def _distribution(rows: list[dict[str, Any]]) -> dict[str, Any]:
    metrics = [_metrics(row) for row in rows]
    numeric = [
        name
        for name in _metrics_fields()
        if name
        not in {"ended_on_quota_response", "task_incomplete_after_quota", "native_truncated"}
    ]
    signatures = [_signatures(row) for row in rows]
    return {
        "n": len(rows),
        "metrics": {key: _stats([m[key] for m in metrics]) for key in numeric},
        "distinct_request_traces": len({_digest(requests) for requests, _ in signatures}),
        "distinct_observation_traces": len(
            {_digest(observations) for _, observations in signatures}
        ),
        "distinct_provider_traces": len({_digest(pair) for pair in signatures}),
        "quota_exposed_runs": sum(m["quota_responses"] > 0 for m in metrics),
        "ended_on_quota_response_runs": sum(m["ended_on_quota_response"] for m in metrics),
        "task_incomplete_after_quota_runs": sum(m["task_incomplete_after_quota"] for m in metrics),
        "native_truncated_runs": sum(m["native_truncated"] is True for m in metrics),
        "native_truncation_unavailable_runs": sum(m["native_truncated"] is None for m in metrics),
        "termination_reasons": dict(
            sorted(
                Counter(
                    row["native"]["termination_reason"]
                    for row in rows
                    if row["native"]["termination_reason"] is not None
                ).items()
            )
        ),
        "termination_reason_unavailable_runs": sum(
            row["native"]["termination_reason"] is None for row in rows
        ),
        "task_failure_check_counts": dict(
            sorted(
                Counter(
                    check for row in rows for check in row["task_correctness"]["failed_check_ids"]
                ).items()
            )
        ),
    }


def _metrics_fields() -> tuple[str, ...]:
    return (
        "tool_attempts",
        "invalid_tool_attempts",
        "unexecuted_tool_attempts",
        "provider_calls",
        "indexed_reads",
        "base_provider_invocations",
        "write_calls",
        "discipline_score",
        "efficiency",
        "failure_factor",
        "failed_provider_calls",
        "applied_interventions",
        "changed_observations",
        "observational_noops",
        "quota_responses",
        "writes_after_first_quota",
        "ended_on_quota_response",
        "task_incomplete_after_quota",
        "native_truncated",
    )


def analyze_rows(rows: list[dict[str, Any]], schedule: list[dict[str, Any]]) -> dict[str, Any]:
    """Analyze every scheduled slot; malformed or silently omitted slots fail closed."""
    _require(
        isinstance(rows, list) and isinstance(schedule, list) and bool(schedule),
        "rows and a nonempty schedule must be arrays",
    )
    _canonical(rows)
    _canonical(schedule)
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        _object(row, IDENTITY_FIELDS + ("status",), "rollout row")
        _require(
            isinstance(row["slot_id"], str) and row["slot_id"] not in by_id,
            "rollout slot IDs must be strings and unique",
        )
        _require(
            isinstance(row["status"], str) and row["status"] in STATUSES, "unknown rollout status"
        )
        by_id[row["slot_id"]] = row
    ordered: list[dict[str, Any]] = []
    identities: set[tuple[str, str, int]] = set()
    for slot in schedule:
        _object(slot, IDENTITY_FIELDS, "schedule slot")
        _require(
            isinstance(slot["slot_id"], str)
            and bool(slot["slot_id"])
            and isinstance(slot["profile"], str)
            and slot["profile"] in {"clean", "hostile"}
            and isinstance(slot["seed"], str)
            and bool(slot["seed"]),
            "invalid schedule identity",
        )
        _number(slot["repetition"], "repetition", integer=True)
        identity = (slot["profile"], slot["seed"], slot["repetition"])
        _require(identity not in identities, "duplicate profile/seed/repetition")
        identities.add(identity)
        _require(
            slot["slot_id"] in by_id, "scheduled rollout is missing or has a duplicate slot ID"
        )
        row = by_id.pop(slot["slot_id"])
        _require(
            all(_canonical(row[key]) == _canonical(slot[key]) for key in IDENTITY_FIELDS),
            "rollout identity disagrees with schedule",
        )
        if row["status"] == "completed":
            _validate_completed(row)
        ordered.append(row)
    _require(not by_id, "rollout row is absent from schedule")
    groups: list[dict[str, Any]] = []
    pairs: list[dict[str, Any]] = []
    profiles = sorted({row["profile"] for row in ordered})
    for profile in profiles:
        profile_rows = [row for row in ordered if row["profile"] == profile]
        seeds = sorted({row["seed"] for row in profile_rows})
        for seed in [*seeds, None]:
            selected = (
                profile_rows
                if seed is None
                else [row for row in profile_rows if row["seed"] == seed]
            )
            completed = [row for row in selected if row["status"] == "completed"]
            success = [row for row in completed if row["task_correctness"]["passed"]]
            groups.append(
                {
                    "profile": profile,
                    "seed": seed,
                    "scope": "schedule_mixture" if seed is None else "profile_seed",
                    "counts": _counts(selected),
                    "task_success": _success(len(success), len(completed)),
                    "all_completed": _distribution(completed),
                    "success_only": _distribution(success),
                }
            )
            if seed is not None:
                pairs.extend(
                    _pair(left, right) for left, right in itertools.combinations(completed, 2)
                )
    divergent = [pair for pair in pairs if pair["first_provider_difference_position"] is not None]
    slot_order = {row["slot_id"]: index for index, row in enumerate(ordered)}
    example = (
        min(
            divergent,
            key=lambda pair: (
                pair["first_provider_difference_position"],
                slot_order[pair["left_slot_id"]],
                slot_order[pair["right_slot_id"]],
            ),
        )
        if divergent
        else None
    )
    rollout_summaries = []
    for row in ordered:
        report = {key: deepcopy(row[key]) for key in IDENTITY_FIELDS + ("status",)}
        if row["status"] == "completed":
            report.update(
                {
                    "metrics": _metrics(row),
                    "task_correctness": deepcopy(row["task_correctness"]),
                    "request_discipline": deepcopy(row["request_discipline"]),
                    "unexecuted_tool_attempts": deepcopy(row.get("unexecuted_tool_attempts", [])),
                    "native": {
                        key: deepcopy(value)
                        for key, value in row["native"].items()
                        if key != "agent_messages"
                    },
                }
            )
        else:
            for key in ("error", "error_type"):
                if key in row:
                    report[key] = deepcopy(row[key])
        rollout_summaries.append(report)
    counts = _counts(ordered)
    return {
        "schema_version": "datalox_dirty_repeat_analysis_v1",
        "cohort_complete": counts["completed"] == counts["scheduled"],
        "counts": counts,
        "groups": groups,
        "rollouts": rollout_summaries,
        "pairwise_divergences": pairs,
        "divergence_example": deepcopy(example),
        "identical_provider_pair": deepcopy(
            next(
                (pair for pair in pairs if pair["first_provider_difference_position"] is None), None
            )
        ),
        "interpretation": {
            "purpose": "descriptive baseline; no automatic regression threshold",
            "pairwise_comparisons": "dependent descriptions of the same runs, not additional independent samples",
            "clean_seed_labels": "schedule blocks over one no-fault task and tenant state",
            "profile_comparison": "clean versus hostile includes fault exposure and quota; it is not a causal estimate of index coupling alone",
            "quota_indicators": "observed quota exposure and terminal response; causation of task failure is not inferred",
            "missing_values": "null means unavailable; sample SD requires at least two observations",
            "example_selection": "earliest provider divergence, then left and right slot positions in the declared schedule",
            "trace_comparison": "exact ordered provider operations, request values and delivered observations; no realignment or provider-value normalization",
            "raw_native_message": "exact native assistant records, including opaque reasoning and generated response IDs; a difference alone does not establish different visible text or provider actions",
            "provider_counts": "provider_calls counts delivered requests including quota responses; base_provider_invocations excludes pre-dispatch quota interceptions",
        },
    }


def render_summary(summary: dict[str, Any]) -> str:
    """Render the derived report without recomputing or changing component scores."""
    _require(
        summary.get("schema_version") == "datalox_dirty_repeat_analysis_v1",
        "unsupported analysis report",
    )
    counts = summary["counts"]
    lines = [
        "# Repeated-rollout baseline",
        "",
        "Descriptive results; no regression threshold.",
        "",
        "; ".join(f"{key.replace('_', ' ')}: {value}" for key, value in counts.items()) + ".",
        "",
        "| Profile | Policy seed / scope | Audited / scheduled | Task success | Provider calls min / median / max | Discipline min / median / max | Quota-exposed | Truncated |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def cell(value: Any) -> str:
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

    def triplet(stats: dict[str, Any]) -> str:
        return " / ".join(
            "—" if stats[key] is None else f"{stats[key]:.4g}" for key in ("min", "median", "max")
        )

    for group in summary["groups"]:
        distribution, success = group["all_completed"], group["task_success"]
        rate = "—" if success["n"] == 0 else f"{success['successes']}/{success['n']}"
        if success["wilson_95"]:
            interval = success["wilson_95"]
            rate += f" (95% Wilson {interval['low']:.1%}–{interval['high']:.1%})"
        label = "schedule mixture" if group["seed"] is None else group["seed"]
        values = [
            group["profile"],
            label,
            f"{group['counts']['audited']}/{group['counts']['scheduled']}",
            rate,
            triplet(distribution["metrics"]["provider_calls"]),
            triplet(distribution["metrics"]["discipline_score"]),
            distribution["quota_exposed_runs"],
            distribution["native_truncated_runs"],
        ]
        lines.append("| " + " | ".join(cell(value) for value in values) + " |")
    lines.extend(
        [
            "",
            (
                "All completed, audited trajectories are included above, including task failures. "
                "Success-only distributions and every pairwise divergence remain in the JSON report."
            ),
            "",
        ]
    )
    for text in summary["interpretation"].values():
        lines.append(f"- {text}.")
    return "\n".join(lines) + "\n"
