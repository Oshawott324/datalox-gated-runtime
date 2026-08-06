from __future__ import annotations

import json
import re
from copy import deepcopy
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from datalox_gated_runtime.capture import load_captures
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import load_events
from datalox_gated_runtime.mcp_capture import canonical_arguments, load_mcp_captures
from datalox_gated_runtime.models import (
    LedgerEvent,
    McpGateConfig,
    McpLedgerEvent,
    McpResponseCase,
    ResponseCase,
)

PROMOTION_REQUIRED_AUDIT_ERROR = "run must be finalized with a passing audit before promotion"
TARGET_ARTIFACT_NAMES = ("gate_config.json", "task.json", "replay_script.json")


def promote_session(*, run_dir: Path, out_dir: Path) -> dict[str, Any]:
    source_config = load_gate_config(run_dir / "gate_config.json")
    source_task = _load_task(run_dir / "task.json")
    _require_passing_audit(run_dir / "audit.json")
    events = load_events(run_dir / "ledger.jsonl")
    captures = load_captures(run_dir / "captures.jsonl")
    mcp_captures = load_mcp_captures(run_dir / "mcp_captures.jsonl")
    if not captures and not mcp_captures:
        raise ValueError("run has no captures to promote")

    _refuse_existing_target_artifacts(out_dir)

    response_cases = _dedupe_captures(captures)
    mcp_response_cases = _dedupe_mcp_captures(mcp_captures)
    audit_rules = _derive_draft_audit_rules(events)
    replay_script = [_replay_step(event) for event in events]

    out_dir.mkdir(parents=True, exist_ok=True)
    gate_config_payload: dict[str, Any] = {
        "config_id": f"{source_config.config_id}_promoted",
        "metadata": {
            "promoted_from": str(run_dir),
            "verifier_type": "config_post_run_audit",
        },
        "response_cases": [asdict(response_case) for response_case in response_cases],
        "audit_rules": audit_rules,
    }
    if source_config.policy is not None:
        gate_config_payload["policy"] = asdict(
            replace(source_config.policy, live_capture=[]),
        )
    if source_config.mcp is not None:
        gate_config_payload["mcp"] = _promoted_mcp_config(
            source_config.mcp,
            mcp_response_cases=mcp_response_cases,
            schema_snapshot=_load_mcp_tool_schemas(run_dir / "mcp_tool_schemas.json"),
        )
    elif mcp_response_cases:
        raise ValueError("mcp captures require source mcp config")

    (out_dir / "gate_config.json").write_text(
        json.dumps(gate_config_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "task.json").write_text(
        json.dumps(_promoted_task(source_task), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "replay_script.json").write_text(
        json.dumps(replay_script, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    load_gate_config(out_dir / "gate_config.json")
    return {
        "response_case_count": len(response_cases),
        "mcp_response_case_count": len(mcp_response_cases),
        "draft_rule_count": len(audit_rules),
        "replay_step_count": len(replay_script),
        "out_dir": str(out_dir),
    }


def _load_task(path: Path) -> dict[str, Any]:
    try:
        task = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid task json") from exc
    if not isinstance(task, dict):
        raise ValueError("task JSON must be an object")
    return task


def _require_passing_audit(path: Path) -> None:
    if not path.exists():
        raise ValueError(PROMOTION_REQUIRED_AUDIT_ERROR)
    try:
        audit = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid audit json") from exc
    if not isinstance(audit, dict) or audit.get("passed") is not True:
        raise ValueError(PROMOTION_REQUIRED_AUDIT_ERROR)


def _refuse_existing_target_artifacts(out_dir: Path) -> None:
    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError(f"target path is not a directory: {out_dir}")
    for artifact_name in TARGET_ARTIFACT_NAMES:
        artifact_path = out_dir / artifact_name
        if artifact_path.exists():
            raise ValueError(f"target directory already contains {artifact_name}: {out_dir}")


def _dedupe_captures(captures: list[ResponseCase]) -> list[ResponseCase]:
    deduped: dict[tuple[str, str, tuple[tuple[str, str], ...]], ResponseCase] = {}
    for capture in captures:
        key = (
            capture.method.upper(),
            capture.path,
            tuple(sorted(capture.query.items())),
        )
        if key in deduped:
            del deduped[key]
        deduped[key] = capture
    return list(deduped.values())


def _dedupe_mcp_captures(captures: list[McpResponseCase]) -> list[McpResponseCase]:
    deduped: dict[tuple[str, str], McpResponseCase] = {}
    for capture in captures:
        key = (capture.tool_name, canonical_arguments(capture.arguments))
        if key in deduped:
            del deduped[key]
        deduped[key] = capture
    return list(deduped.values())


def _derive_draft_audit_rules(events: list[LedgerEvent | McpLedgerEvent]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    used_failure_codes: set[str] = set()
    read_paths: set[str] = set()
    write_bodies_by_path: dict[str, dict[str, Any]] = {}
    denied_calls: set[tuple[str, str]] = set()

    for event in events:
        if isinstance(event, McpLedgerEvent):
            continue
        method = event.request.normalized_method()
        path = event.request.path
        if (
            method == "GET"
            and event.decision.kind in {"replay", "live_capture", "shadow_read"}
            and 200 <= event.response_status_code < 300
        ):
            read_paths.add(path)

        if event.decision.kind == "shadow_write" and event.shadow_mutation is not None:
            mutation_path = event.shadow_mutation.get("path")
            if isinstance(mutation_path, str) and mutation_path:
                body = event.shadow_mutation.get("body")
                scalar_fields = _scalar_fields(body)
                if scalar_fields:
                    write_bodies_by_path[mutation_path] = scalar_fields

        if event.decision.kind == "deny":
            denied_calls.add((method, path))

    for path in sorted(read_paths):
        rules.append(
            {
                "type": "require_call",
                "method": "GET",
                "path": path,
                "failure_code": _unique_failure_code(
                    f"missing_read_{_path_slug(path)}",
                    used_failure_codes,
                ),
                "draft": True,
            }
        )

    for path in sorted(write_bodies_by_path):
        rules.append(
            {
                "type": "require_shadow_write",
                "path": path,
                "body_contains": write_bodies_by_path[path],
                "failure_code": _unique_failure_code(
                    f"missing_write_{_path_slug(path)}",
                    used_failure_codes,
                ),
                "draft": True,
            }
        )

    for method, path in sorted(denied_calls):
        rules.append(
            {
                "type": "forbid_call",
                "method": method,
                "path": path,
                "failure_code": _unique_failure_code(
                    f"forbidden_{_path_slug(path)}",
                    used_failure_codes,
                ),
                "draft": True,
            }
        )

    return rules


def _scalar_fields(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    return {
        key: value
        for key, value in body.items()
        if isinstance(key, str) and type(value) in {str, int, float, bool}
    }


def _path_slug(path: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    return slug or "root"


def _unique_failure_code(base_code: str, used_codes: set[str]) -> str:
    code = base_code
    suffix = 2
    while code in used_codes:
        code = f"{base_code}_{suffix}"
        suffix += 1
    used_codes.add(code)
    return code


def _replay_step(event: LedgerEvent | McpLedgerEvent) -> dict[str, Any]:
    if isinstance(event, McpLedgerEvent):
        return {
            "surface": "mcp",
            "tool_name": event.tool_name,
            "arguments": dict(event.arguments),
        }
    return {
        "surface": "http",
        "method": event.request.normalized_method(),
        "path": event.request.path,
        "query": dict(event.request.query),
        "body": event.request.body,
    }


def _promoted_task(source_task: dict[str, Any]) -> dict[str, Any]:
    task = dict(source_task)
    task_id = task.get("task_id")
    title = task.get("title")
    if not isinstance(task_id, str) or not task_id.strip():
        raise ValueError("task.task_id must be a non-empty string")
    if not isinstance(title, str) or not title.strip():
        raise ValueError("task.title must be a non-empty string")
    task["task_id"] = f"{task_id}_promoted"
    task["title"] = f"[DRAFT] {title}"
    return task


def _load_mcp_tool_schemas(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid mcp_tool_schemas json") from exc
    if not isinstance(raw, dict):
        raise ValueError("mcp_tool_schemas must be an object")
    parsed: dict[str, dict[str, Any]] = {}
    for tool_name, schema in raw.items():
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("mcp_tool_schemas keys must be non-empty strings")
        if not isinstance(schema, dict):
            raise ValueError(f"mcp_tool_schemas.{tool_name} must be an object")
        if not isinstance(schema.get("inputSchema"), dict):
            raise ValueError(f"mcp_tool_schemas.{tool_name}.inputSchema must be an object")
        description = schema.get("description")
        if description is not None and (
            not isinstance(description, str) or not description.strip()
        ):
            raise ValueError(f"mcp_tool_schemas.{tool_name}.description must be a non-empty string")
        parsed[tool_name] = deepcopy(schema)
    return parsed


def _promoted_mcp_config(
    source_mcp: McpGateConfig,
    *,
    mcp_response_cases: list[McpResponseCase],
    schema_snapshot: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    captured_tool_names = {case.tool_name for case in mcp_response_cases}
    tools = {
        tool_name: "replay" if decision == "live" and tool_name in captured_tool_names else decision
        for tool_name, decision in source_mcp.tools.items()
    }
    remaining_live = {
        tool_name: contract
        for tool_name, contract in source_mcp.live.items()
        if tools.get(tool_name) == "live"
    }
    needed_upstreams = {
        _mcp_upstream_name(tool_name) for tool_name, decision in tools.items() if decision == "live"
    }
    upstreams = {
        upstream_name: asdict(upstream)
        for upstream_name, upstream in source_mcp.upstreams.items()
        if upstream_name in needed_upstreams
    }

    tool_schemas: dict[str, dict[str, Any]] = {}
    for response_case in mcp_response_cases:
        if response_case.input_schema is not None:
            tool_schemas[response_case.tool_name] = {
                "inputSchema": deepcopy(response_case.input_schema)
            }
    tool_schemas.update(deepcopy(source_mcp.generated.tool_schemas))
    tool_schemas.update(deepcopy(schema_snapshot))

    _validate_promoted_mcp_schema_sources(
        tools=tools,
        upstreams=upstreams,
        tool_schemas=tool_schemas,
    )

    payload: dict[str, Any] = {
        "upstreams": upstreams,
        "tools": tools,
        "generated": {
            "tool_schemas": tool_schemas,
            "response_cases": [asdict(response_case) for response_case in mcp_response_cases],
        },
    }
    if remaining_live:
        payload["live"] = {
            tool_name: asdict(contract) for tool_name, contract in remaining_live.items()
        }
    return payload


def _validate_promoted_mcp_schema_sources(
    *,
    tools: dict[str, str],
    upstreams: dict[str, dict[str, Any]],
    tool_schemas: dict[str, dict[str, Any]],
) -> None:
    for tool_name, decision in tools.items():
        if decision == "deny":
            continue
        if _mcp_upstream_name(tool_name) in upstreams or tool_name in tool_schemas:
            continue
        raise ValueError(f"mcp promoted tool schema unavailable: {tool_name}")


def _mcp_upstream_name(tool_name: str) -> str:
    upstream_name, _, _ = tool_name.partition(".")
    return upstream_name
