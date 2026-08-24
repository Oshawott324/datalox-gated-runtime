from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.parse import urlencode

from datalox_gated_runtime.audit import AuditResult, run_config_audit
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger
from datalox_gated_runtime.mcp_capture import canonical_arguments
from datalox_gated_runtime.mcp_runtime import McpGatedRuntime
from datalox_gated_runtime.models import (
    CallRequest,
    McpToolCall,
    _utc_now,
)
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.query import QueryParams, iter_query_items
from datalox_gated_runtime.runtime import GatedRuntime
from datalox_gated_runtime.world_backend import create_world_backend, initialize_world
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import WorldContractError
from datalox_gated_runtime.worlds.response_case_state_v0.mcp_tools import world_tool_request


@dataclass(frozen=True)
class VerifyReplayResult:
    fidelity_passed: bool
    miss_paths: list[str]
    audit: AuditResult


@dataclass(frozen=True)
class HttpReplayStep:
    request: CallRequest


@dataclass(frozen=True)
class McpReplayStep:
    call: McpToolCall


ReplayStep = HttpReplayStep | McpReplayStep
MCP_REPLAY_MISS_REASON_CODES = {
    "mcp_replay_case_missing",
    "mcp_live_disabled",
    "mcp_upstream_unavailable",
    "mcp_tool_not_exposed",
}


def verify_replay(env_dir: Path) -> VerifyReplayResult:
    config = load_gate_config(env_dir / "gate_config.json")
    replay_steps = _load_replay_script(env_dir / "replay_script.json")
    with TemporaryDirectory(prefix="datalox-verify-world-") as temp_dir_name:
        isolated_run_dir = Path(temp_dir_name)
        if config.world is not None:
            initialize_world(run_dir=isolated_run_dir, config=config.world, source_dir=env_dir)
        ledger = SessionLedger()
        world_backend = create_world_backend(run_dir=isolated_run_dir, config=config.world)
        runtime = GatedRuntime(
            policy=GatePolicy.from_config(config.policy),
            response_cases=config.response_cases,
            ledger=ledger,
            world_backend=world_backend,
        )
        mcp_runtime = (
            McpGatedRuntime(config=config.mcp, ledger=ledger) if config.mcp is not None else None
        )

        miss_paths: list[str] = []
        for step in replay_steps:
            if isinstance(step, HttpReplayStep):
                response = runtime.handle(step.request)
                if response.decision.kind == "miss":
                    miss_paths.append(_miss_identifier(step.request))
                continue

            try:
                world_request = world_tool_request(
                    world_backend,
                    step.call.tool_name,
                    step.call.arguments,
                )
            except WorldContractError:
                miss_paths.append(_mcp_miss_identifier(step.call))
                continue
            if world_request is not None:
                response = runtime.handle(world_request)
                if response.decision.kind == "miss":
                    miss_paths.append(_mcp_miss_identifier(step.call))
                continue
            if mcp_runtime is None:
                miss_paths.append(_mcp_miss_identifier(step.call))
                continue
            response = asyncio.run(mcp_runtime.handle(step.call))
            if response.decision.kind == "deny" and (
                response.decision.reason_code in MCP_REPLAY_MISS_REASON_CODES
            ):
                miss_paths.append(_mcp_miss_identifier(step.call))

        audit = run_config_audit(runtime.export(), config.audit_rules)
    result = VerifyReplayResult(
        fidelity_passed=not miss_paths,
        miss_paths=miss_paths,
        audit=audit,
    )
    report_payload = verify_report_payload(result)
    try:
        (env_dir / "verify_report.json").write_text(
            json.dumps(report_payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    except OSError as exc:
        raise ValueError(f"failed to write verify report: {exc}") from exc
    return result


def verify_report_payload(result: VerifyReplayResult) -> dict[str, Any]:
    return {
        **asdict(result),
        "verified_at": _utc_now(),
    }


def _load_replay_script(path: Path) -> list[ReplayStep]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid replay_script json") from exc

    if not isinstance(raw, list):
        raise ValueError("replay_script must be a list")
    return [_parse_replay_step(index, item) for index, item in enumerate(raw)]


def _parse_replay_step(index: int, raw: Any) -> ReplayStep:
    if not isinstance(raw, dict):
        raise ValueError(f"replay_script[{index}] must be an object")
    surface = raw.get("surface", "http")
    if surface == "mcp":
        return _parse_mcp_replay_step(index, raw)
    if surface != "http":
        raise ValueError(f"replay_script[{index}].surface must be http or mcp")
    method = _require_step_str(raw, index, "method")
    path = _require_step_str(raw, index, "path")
    query = _parse_step_query(index, raw.get("query", {}))
    return HttpReplayStep(
        request=CallRequest(
            method=method,
            path=path,
            query=query,
            body=raw.get("body"),
        )
    )


def _require_step_str(raw: dict[str, Any], index: int, key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"replay_script[{index}].{key} must be a non-empty string")
    return value


def _parse_step_query(index: int, raw: Any) -> QueryParams:
    if not isinstance(raw, dict):
        raise ValueError(f"replay_script[{index}].query must be an object")
    query: QueryParams = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            raise ValueError(f"replay_script[{index}].query keys must be strings")
        if isinstance(value, str):
            query[key] = value
            continue
        if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            query[key] = tuple(value)
            continue
        raise ValueError(
            f"replay_script[{index}].query.{key} must be a string or non-empty list of strings"
        )
    return query


def _parse_mcp_replay_step(index: int, raw: dict[str, Any]) -> McpReplayStep:
    tool_name = _require_step_str(raw, index, "tool_name")
    arguments = raw.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError(f"replay_script[{index}].arguments must be an object")
    return McpReplayStep(call=McpToolCall(tool_name=tool_name, arguments=arguments))


def _miss_identifier(request: CallRequest) -> str:
    if not request.query:
        return f"{request.normalized_method()} {request.path}"
    ordered_query = dict(sorted(request.query.items()))
    query = urlencode(list(iter_query_items(ordered_query)))
    return f"{request.normalized_method()} {request.path}?{query}"


def _mcp_miss_identifier(call: McpToolCall) -> str:
    return f"MCP {call.tool_name} {canonical_arguments(call.arguments)}"
