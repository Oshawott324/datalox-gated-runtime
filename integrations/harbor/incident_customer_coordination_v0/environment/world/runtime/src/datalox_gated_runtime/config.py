from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from datalox_gated_runtime.auth import (
    AuthBrokerConfig,
    AuthBrokerError,
    AuthInjection,
    AuthProfile,
    parse_auth_broker_config,
    parse_auth_profile_ref,
)
from datalox_gated_runtime.models import (
    DenyRuleConfig,
    GateConfig,
    LiveAuthHeader,
    LiveGateConfig,
    LiveUpstream,
    McpGateConfig,
    McpGeneratedConfig,
    McpLiveToolContract,
    McpResponseCase,
    McpToolDecision,
    McpUpstreamConfig,
    PolicyConfig,
    ResponseCaseStateWorldConfig,
    ResponseCase,
    RouteRule,
    WorldBundleV1Config,
    WorldConfig,
    WorldConfigValue,
)
from datalox_gated_runtime.query import QueryParams

_MCP_TOOL_DECISIONS = {"live", "replay", "shadow", "deny"}
_MCP_KEYS = {"upstreams", "tools", "live", "generated"}
_MCP_UPSTREAM_KEYS = {"transport", "command", "args"}
_MCP_AUDIT_RULE_TYPES = {
    "require_mcp_call",
    "forbid_mcp_call",
    "require_mcp_shadow",
    "forbid_mcp_shadow_arguments_contains",
}
_BILLING_WORLD_PREFIXES = ["/support/", "/billing/"]
_RESPONSE_CASE_WORLD_KEYS = {
    "kind",
    "seed",
    "state_db",
    "episodes",
    "routes",
    "transitions",
    "verifier",
    "tool_catalog",
    "sources",
}
_WORLD_BUNDLE_V1_KEYS = {"kind", "seed"}
_FORBIDDEN_STATIC_HEADER_NAMES = {"authorization", "cookie", "set-cookie"}
_FORBIDDEN_STATIC_HEADER_SUBSTRINGS = ("secret", "token", "api-key", "apikey")


def load_gate_config(path: Path) -> GateConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("invalid gate config json") from exc

    if not isinstance(raw, dict):
        raise ValueError("gate config must be an object")
    if "ambient_mcp" in raw:
        raise ValueError("ambient_mcp is not supported")
    _require_field(raw, "config_id")
    response_cases = [
        _parse_response_case(index, item)
        for index, item in enumerate(_expect_list(raw, "response_cases"))
    ]
    audit_rules = [
        _parse_audit_rule(index, item)
        for index, item in enumerate(_expect_list(raw, "audit_rules"))
    ]
    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    policy = None
    if "policy" in raw:
        policy = _parse_policy(raw["policy"])
    auth_profiles = _parse_auth_profiles(raw)
    live = None
    if "live" in raw:
        live = _parse_live(raw["live"], auth_profiles)
        auth_profiles = live.auth_profiles
    mcp = None
    if "mcp" in raw:
        mcp = _parse_mcp(raw["mcp"])
    world = None
    if "world" in raw:
        world = _parse_world(raw["world"])
    return GateConfig(
        config_id=raw["config_id"],
        response_cases=response_cases,
        audit_rules=audit_rules,
        metadata=metadata,
        auth_profiles=auth_profiles,
        policy=policy,
        live=live,
        mcp=mcp,
        world=world,
    )


def _parse_world(raw: Any) -> WorldConfigValue:
    if not isinstance(raw, dict):
        raise ValueError("world must be an object")

    kind = raw.get("kind")
    if kind == "world_bundle_v1":
        return _parse_world_bundle_v1(raw)
    if kind == "response_case_state_v0":
        return _parse_response_case_state_world(raw)
    if kind is not None:
        raise ValueError(f"unsupported world.kind: {kind}")
    return _parse_billing_world(raw)


def _parse_world_bundle_v1(raw: dict[str, Any]) -> WorldBundleV1Config:
    unknown = sorted(set(raw) - _WORLD_BUNDLE_V1_KEYS)
    if unknown:
        raise ValueError(f"unknown fields for world_bundle_v1 world: {', '.join(unknown)}")
    missing = sorted(_WORLD_BUNDLE_V1_KEYS - set(raw))
    if missing:
        raise ValueError(f"missing fields for world_bundle_v1 world: {', '.join(missing)}")
    seed = raw["seed"]
    if type(seed) is not int or seed < 0:
        raise ValueError("world.seed must be a non-negative int")
    return WorldBundleV1Config(kind="world_bundle_v1", seed=seed)


def _parse_billing_world(raw: dict[str, Any]) -> WorldConfig:

    world_id = raw.get("id")
    if world_id != "billing_support_v0":
        raise ValueError("world.id must be billing_support_v0")

    scenario = raw.get("scenario")
    if scenario != "duplicate_payment_refund":
        raise ValueError("world.scenario must be duplicate_payment_refund")

    seed = raw.get("seed")
    if type(seed) is not int:
        raise ValueError("world.seed must be an int")

    state_db = raw.get("state_db")
    if not isinstance(state_db, str) or not state_db.strip():
        raise ValueError("world.state_db must be a non-empty file name")
    if "/" in state_db or "\\" in state_db or state_db in {".", ".."}:
        raise ValueError("world.state_db must be a relative file name")

    http_prefixes = raw.get("http_prefixes")
    if not isinstance(http_prefixes, list) or not http_prefixes:
        raise ValueError("world.http_prefixes must be a non-empty list")
    if any(not isinstance(prefix, str) or not prefix.startswith("/") for prefix in http_prefixes):
        raise ValueError("world.http_prefixes must contain absolute prefixes")
    if http_prefixes != _BILLING_WORLD_PREFIXES:
        raise ValueError("world.http_prefixes must be exactly /support/ and /billing/")

    verifier = raw.get("verifier")
    if verifier != "billing_support_v0":
        raise ValueError("world.verifier must be billing_support_v0")

    return WorldConfig(
        id="billing_support_v0",
        scenario="duplicate_payment_refund",
        seed=seed,
        state_db=state_db,
        http_prefixes=list(http_prefixes),
        verifier="billing_support_v0",
    )


def _parse_response_case_state_world(raw: dict[str, Any]) -> ResponseCaseStateWorldConfig:
    unknown = sorted(set(raw) - _RESPONSE_CASE_WORLD_KEYS)
    if unknown:
        raise ValueError(f"unknown fields for response_case_state_v0 world: {', '.join(unknown)}")

    missing = sorted(_RESPONSE_CASE_WORLD_KEYS - set(raw))
    if missing:
        raise ValueError(f"missing fields for response_case_state_v0 world: {', '.join(missing)}")

    seed = raw["seed"]
    if type(seed) is not int:
        raise ValueError("world.seed must be an int")
    if seed < 0:
        raise ValueError("world.seed must be non-negative")

    state_db = raw["state_db"]
    if not isinstance(state_db, str) or not state_db.strip():
        raise ValueError("world.state_db must be a non-empty file name")
    if "/" in state_db or "\\" in state_db or state_db in {".", ".."}:
        raise ValueError("world.state_db must be a relative file name")

    artifacts = {
        name: _parse_world_artifact_path(name, raw[name])
        for name in ("episodes", "routes", "transitions", "verifier", "tool_catalog", "sources")
    }
    return ResponseCaseStateWorldConfig(
        kind="response_case_state_v0",
        seed=seed,
        state_db=state_db,
        **artifacts,
    )


def _parse_world_artifact_path(field: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"world.{field} must be a non-empty relative path")
    if "\\" in value:
        raise ValueError(f"world.{field} must use a strict world/<file> path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.parts != ("world", path.name) or path.name in {"", ".", ".."}:
        raise ValueError(f"world.{field} must use a strict world/<file> path")
    return value


def _parse_response_case(index: int, raw: dict[str, Any]) -> ResponseCase:
    if not isinstance(raw, dict):
        raise ValueError(f"response_cases[{index}] must be an object")
    for field in ("path", "case_id", "method", "status_code"):
        if field not in raw:
            raise ValueError(f"response_cases[{index}].{field} is required")
    _require_non_empty_str(raw, index, "case_id")
    _require_non_empty_str(raw, index, "method")
    _require_non_empty_str(raw, index, "path")
    _require_status_code(raw["status_code"], index)
    if "evidence_ref" in raw and raw["evidence_ref"] is not None:
        if not isinstance(raw["evidence_ref"], str):
            raise ValueError(f"response_cases[{index}].evidence_ref must be a string")
    return ResponseCase(
        case_id=raw["case_id"],
        method=raw["method"],
        path=raw["path"],
        status_code=raw["status_code"],
        body=raw.get("body"),
        evidence_ref=raw.get("evidence_ref"),
        query=_parse_response_case_query(index, raw),
    )


def _parse_response_case_query(index: int, raw: dict[str, Any]) -> QueryParams:
    query = raw.get("query", {})
    if not isinstance(query, dict):
        raise ValueError(f"response_cases[{index}].query must be an object")
    parsed: QueryParams = {}
    for key, value in query.items():
        if not isinstance(key, str):
            raise ValueError(f"response_cases[{index}].query keys must be strings")
        if isinstance(value, str):
            parsed[key] = value
            continue
        if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
            parsed[key] = tuple(value)
            continue
        raise ValueError(
            f"response_cases[{index}].query.{key} must be a string or non-empty list of strings"
        )
    return parsed


def _require_field(raw: dict[str, Any], key: str) -> None:
    if key not in raw:
        raise ValueError(f"{key} is required")


def _require_non_empty_str(raw: dict[str, Any], index: int, key: str) -> None:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"response_cases[{index}].{key} must be a non-empty string")


def _require_status_code(value: Any, index: int) -> None:
    if type(value) is not int:
        raise ValueError(f"response_cases[{index}].status_code must be an int")


def _expect_list(raw: dict[str, Any], key: str) -> list[Any]:
    value = raw.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{key} must be a list")
    return value


def _parse_audit_rule(index: int, raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"audit_rules[{index}] must be an object")
    for field in ("type", "failure_code"):
        if field not in raw:
            raise ValueError(f"audit_rules[{index}].{field} is required")
        if not isinstance(raw[field], str) or not raw[field].strip():
            raise ValueError(f"audit_rules[{index}].{field} must be a non-empty string")
    if "method" in raw and (not isinstance(raw["method"], str) or not raw["method"].strip()):
        raise ValueError(f"audit_rules[{index}].method must be a string")
    if "path" in raw and (not isinstance(raw["path"], str) or not raw["path"].strip()):
        raise ValueError(f"audit_rules[{index}].path must be a string")
    if "path_prefix" in raw and (
        not isinstance(raw["path_prefix"], str) or not raw["path_prefix"].strip()
    ):
        raise ValueError(f"audit_rules[{index}].path_prefix must be a string")
    if "body_contains" in raw and not isinstance(raw["body_contains"], dict):
        raise ValueError(f"audit_rules[{index}].body_contains must be an object")
    if "arguments_contains" in raw and not isinstance(raw["arguments_contains"], dict):
        raise ValueError(f"audit_rules[{index}].arguments_contains must be an object")
    if raw["type"] == "forbid_call":
        _validate_forbid_call_rule(index, raw)
    if raw["type"] in _MCP_AUDIT_RULE_TYPES:
        _validate_mcp_audit_rule(index, raw)
    return raw


def _validate_forbid_call_rule(index: int, raw: dict[str, Any]) -> None:
    if "method" not in raw:
        raise ValueError(f"audit_rules[{index}].method is required for forbid_call")
    has_path = "path" in raw
    has_path_prefix = "path_prefix" in raw
    if has_path == has_path_prefix:
        raise ValueError(
            f"audit_rules[{index}] forbid_call requires exactly one of path or path_prefix"
        )


def _validate_mcp_audit_rule(index: int, raw: dict[str, Any]) -> None:
    if "tool_name" not in raw:
        raise ValueError(f"audit_rules[{index}].tool_name is required")
    if not isinstance(raw["tool_name"], str) or not raw["tool_name"].strip():
        raise ValueError(f"audit_rules[{index}].tool_name must be a non-empty string")


def _parse_policy(raw: Any) -> PolicyConfig:
    if not isinstance(raw, dict):
        raise ValueError("policy must be an object")
    return PolicyConfig(
        deny=[
            _parse_deny_rule(index, item)
            for index, item in enumerate(_expect_optional_policy_list(raw, "deny"))
        ],
        shadow_write=[
            _parse_route_rule("policy.shadow_write", index, item)
            for index, item in enumerate(_expect_optional_policy_list(raw, "shadow_write"))
        ],
        live_capture=[
            _parse_live_capture_rule(index, item)
            for index, item in enumerate(_expect_optional_policy_list(raw, "live_capture"))
        ],
    )


def _parse_auth_profiles(raw: dict[str, Any]) -> AuthBrokerConfig:
    try:
        return parse_auth_broker_config(raw)
    except AuthBrokerError as exc:
        raise ValueError(exc.message) from exc


def _parse_live(raw: Any, auth_profiles: AuthBrokerConfig) -> LiveGateConfig:
    if not isinstance(raw, dict):
        raise ValueError("live must be an object")
    upstreams = raw.get("upstreams")
    if not isinstance(upstreams, dict) or not upstreams:
        raise ValueError("live.upstreams must be a non-empty object")

    parsed: dict[str, LiveUpstream] = {}
    profiles = dict(auth_profiles.profiles)
    for name, upstream in upstreams.items():
        if not isinstance(name, str) or not name.strip() or "/" in name:
            raise ValueError("live.upstreams key must be a non-empty single segment")
        if not isinstance(upstream, dict):
            raise ValueError(f"live.upstreams.{name} must be an object")
        base_url = _require_live_str(upstream, f"live.upstreams.{name}.base_url")
        _require_http_url(base_url, f"live.upstreams.{name}.base_url")
        auth_env = _optional_live_str(upstream, f"live.upstreams.{name}.auth_env")
        auth_header = _optional_live_str(upstream, f"live.upstreams.{name}.auth_header")
        auth_scheme = _optional_live_auth_scheme(upstream, f"live.upstreams.{name}.auth_scheme")
        extra_auth = _parse_extra_auth(upstream.get("extra_auth", []), f"live.upstreams.{name}")
        try:
            auth_profile = parse_auth_profile_ref(
                upstream,
                path=f"live.upstreams.{name}.auth_profile",
            )
        except AuthBrokerError as exc:
            raise ValueError(exc.message) from exc
        if auth_profile is not None and _has_legacy_live_auth(upstream):
            raise ValueError(
                f"live.upstreams.{name}.auth_profile must not be mixed with legacy auth fields"
            )
        if auth_profile is not None and auth_profile not in profiles:
            raise ValueError(f"live.upstreams.{name}.auth_profile references unknown profile")
        normalized_auth_header = auth_header or "Authorization"
        normalized_auth_scheme = "Bearer" if auth_scheme is None else auth_scheme
        if auth_profile is None and (auth_env is not None or extra_auth):
            auth_profile = f"legacy_{name}_auth"
            profiles[auth_profile] = _legacy_auth_profile(
                auth_env=auth_env,
                auth_header=normalized_auth_header,
                auth_scheme=normalized_auth_scheme,
                extra_auth=extra_auth,
            )
        static_headers = _parse_static_headers(
            upstream.get("static_headers", {}),
            f"live.upstreams.{name}",
        )
        parsed[name] = LiveUpstream(
            base_url=base_url,
            auth_env=auth_env,
            auth_header=normalized_auth_header,
            auth_scheme=normalized_auth_scheme,
            extra_auth=extra_auth,
            static_headers=static_headers,
            auth_profile=auth_profile,
        )
    return LiveGateConfig(
        upstreams=parsed,
        auth_profiles=AuthBrokerConfig(profiles=profiles),
    )


def _has_legacy_live_auth(upstream: dict[str, Any]) -> bool:
    return any(
        key in upstream and upstream[key] not in (None, [], "")
        for key in ("auth_env", "auth_header", "auth_scheme", "extra_auth")
    )


def _legacy_auth_profile(
    *,
    auth_env: str | None,
    auth_header: str,
    auth_scheme: str,
    extra_auth: list[LiveAuthHeader],
) -> AuthProfile:
    inject: list[AuthInjection] = []
    if auth_env is not None:
        inject.append(
            AuthInjection(
                target="header",
                name=auth_header,
                env=auth_env,
                scheme=auth_scheme,
            )
        )
    inject.extend(
        AuthInjection(target="header", name=auth.header, env=auth.env, scheme=auth.scheme)
        for auth in extra_auth
    )
    return AuthProfile(kind="env_static", inject=tuple(inject))


def _parse_extra_auth(raw: Any, path: str) -> list[LiveAuthHeader]:
    if not isinstance(raw, list):
        raise ValueError(f"{path}.extra_auth must be a list")
    parsed: list[LiveAuthHeader] = []
    for index, item in enumerate(raw):
        item_path = f"{path}.extra_auth[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{item_path} must be an object")
        header = _require_live_str(item, f"{item_path}.header")
        env = _require_live_str(item, f"{item_path}.env")
        scheme = _optional_live_auth_scheme(item, f"{item_path}.scheme")
        parsed.append(
            LiveAuthHeader(
                header=header,
                env=env,
                scheme="Bearer" if scheme is None else scheme,
            )
        )
    return parsed


def _parse_static_headers(raw: Any, path: str) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}.static_headers must be an object")
    parsed: dict[str, str] = {}
    for header, value in raw.items():
        header_path = f"{path}.static_headers.{header}"
        if not isinstance(header, str) or not header.strip():
            raise ValueError(f"{path}.static_headers keys must be non-empty strings")
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{header_path} must be a non-empty string")
        _reject_secret_static_header(header, header_path)
        parsed[header] = value
    return parsed


def _reject_secret_static_header(header: str, path: str) -> None:
    normalized = header.lower()
    if normalized in _FORBIDDEN_STATIC_HEADER_NAMES or any(
        item in normalized for item in _FORBIDDEN_STATIC_HEADER_SUBSTRINGS
    ):
        raise ValueError(f"{path} must not contain static credentials")


def _parse_mcp(raw: Any) -> McpGateConfig:
    if not isinstance(raw, dict):
        raise ValueError("mcp must be an object")
    for key in raw:
        if key not in _MCP_KEYS:
            if key == "ambient_mcp":
                raise ValueError("mcp.ambient_mcp is not supported")
            raise ValueError(f"mcp.{key} is not allowed")
    upstreams = _parse_mcp_upstreams(raw.get("upstreams", {}))
    tools = _parse_mcp_tools(raw)
    generated = _parse_mcp_generated(raw.get("generated", {}))
    live = _parse_mcp_live(raw.get("live", {}))
    _validate_mcp_schema_sources(tools, upstreams, generated)
    _validate_mcp_live_tools(tools, live)
    return McpGateConfig(
        upstreams=upstreams,
        tools=tools,
        live=live,
        generated=generated,
    )


def _parse_mcp_upstreams(raw: Any) -> dict[str, McpUpstreamConfig]:
    if not isinstance(raw, dict):
        raise ValueError("mcp.upstreams must be an object")
    parsed: dict[str, McpUpstreamConfig] = {}
    for name, upstream in raw.items():
        if not isinstance(name, str) or not name.strip() or "/" in name or "." in name:
            raise ValueError("mcp.upstreams key must be a non-empty single segment")
        if not isinstance(upstream, dict):
            raise ValueError(f"mcp.upstreams.{name} must be an object")
        for key in upstream:
            if key not in _MCP_UPSTREAM_KEYS:
                raise ValueError(f"mcp.upstreams.{name}.{key} is not allowed")
        transport = upstream.get("transport")
        if transport != "stdio":
            raise ValueError(f"mcp.upstreams.{name}.transport must be stdio")
        command = upstream.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"mcp.upstreams.{name}.command must be a non-empty string")
        args = upstream.get("args", [])
        if not isinstance(args, list) or any(not isinstance(arg, str) for arg in args):
            raise ValueError(f"mcp.upstreams.{name}.args must be a list of strings")
        parsed[name] = McpUpstreamConfig(transport="stdio", command=command, args=args)
    return parsed


def _parse_mcp_tools(raw: dict[str, Any]) -> dict[str, McpToolDecision]:
    tools = raw.get("tools")
    if not isinstance(tools, dict):
        raise ValueError("mcp.tools must be an object")
    parsed: dict[str, McpToolDecision] = {}
    for tool_name, decision in tools.items():
        _validate_mcp_tool_name(tool_name, "mcp.tools")
        if not isinstance(decision, str) or decision not in _MCP_TOOL_DECISIONS:
            raise ValueError(f"mcp.tools.{tool_name} must be one of live, replay, shadow, deny")
        parsed[tool_name] = decision
    return parsed


def _parse_mcp_generated(raw: Any) -> McpGeneratedConfig:
    if not isinstance(raw, dict):
        raise ValueError("mcp.generated must be an object")
    tool_schemas = _parse_mcp_generated_tool_schemas(raw.get("tool_schemas", {}))
    response_cases = _parse_mcp_response_cases(raw.get("response_cases", []))
    return McpGeneratedConfig(tool_schemas=tool_schemas, response_cases=response_cases)


def _parse_mcp_generated_tool_schemas(raw: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ValueError("mcp.generated.tool_schemas must be an object")
    parsed: dict[str, dict[str, Any]] = {}
    for tool_name, schema in raw.items():
        _validate_mcp_tool_name(tool_name, "mcp.generated.tool_schemas")
        if not isinstance(schema, dict):
            raise ValueError(f"mcp.generated.tool_schemas.{tool_name} must be an object")
        unknown = sorted(set(schema) - {"inputSchema", "description"})
        if unknown:
            raise ValueError(f"mcp.generated.tool_schemas.{tool_name}.{unknown[0]} is not allowed")
        input_schema = schema.get("inputSchema")
        if not isinstance(input_schema, dict):
            raise ValueError(
                f"mcp.generated.tool_schemas.{tool_name}.inputSchema must be an object"
            )
        description = schema.get("description")
        if description is not None and (
            not isinstance(description, str) or not description.strip()
        ):
            raise ValueError(
                f"mcp.generated.tool_schemas.{tool_name}.description must be a non-empty string"
            )
        parsed[tool_name] = schema
    return parsed


def _parse_mcp_response_cases(raw: Any) -> list[McpResponseCase]:
    if not isinstance(raw, list):
        raise ValueError("mcp.generated.response_cases must be a list")
    return [_parse_mcp_response_case(index, item) for index, item in enumerate(raw)]


def _parse_mcp_response_case(index: int, raw: Any) -> McpResponseCase:
    path = f"mcp.generated.response_cases[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must be an object")
    case_id = _require_mcp_non_empty_str(raw, f"{path}.case_id")
    tool_name = _require_mcp_non_empty_str(raw, f"{path}.tool_name")
    _validate_mcp_tool_name(tool_name, path)
    arguments = raw.get("arguments")
    if not isinstance(arguments, dict):
        raise ValueError(f"{path}.arguments must be an object")
    result = raw.get("result")
    if not isinstance(result, dict):
        raise ValueError(f"{path}.result must be an object")
    evidence_ref = _optional_mcp_str(raw, f"{path}.evidence_ref")
    input_schema = None
    if "input_schema" in raw:
        input_schema = raw["input_schema"]
        if not isinstance(input_schema, dict):
            raise ValueError(f"{path}.input_schema must be an object")
    return McpResponseCase(
        case_id=case_id,
        tool_name=tool_name,
        arguments=arguments,
        result=result,
        evidence_ref=evidence_ref,
        input_schema=input_schema,
    )


def _parse_mcp_live(raw: Any) -> dict[str, McpLiveToolContract]:
    if not isinstance(raw, dict):
        raise ValueError("mcp.live must be an object")
    parsed: dict[str, McpLiveToolContract] = {}
    for tool_name, entry in raw.items():
        _validate_mcp_tool_name(tool_name, "mcp.live")
        if not isinstance(entry, dict):
            raise ValueError(f"mcp.live.{tool_name} must be an object")
        contract = entry.get("contract")
        if contract != "safe_read":
            raise ValueError(f"mcp.live.{tool_name}.contract must be safe_read")
        evidence_ref = entry.get("evidence_ref")
        if not isinstance(evidence_ref, str) or not evidence_ref.strip():
            raise ValueError(f"mcp.live.{tool_name}.evidence_ref must be a non-empty string")
        parsed[tool_name] = McpLiveToolContract(contract="safe_read", evidence_ref=evidence_ref)
    return parsed


def _validate_mcp_schema_sources(
    tools: dict[str, McpToolDecision],
    upstreams: dict[str, McpUpstreamConfig],
    generated: McpGeneratedConfig,
) -> None:
    for tool_name, decision in tools.items():
        if decision == "deny":
            continue
        upstream_name, _ = _split_mcp_tool_name(tool_name)
        if upstream_name in upstreams or tool_name in generated.tool_schemas:
            continue
        raise ValueError(f"mcp tool schema unavailable: {tool_name}")


def _validate_mcp_live_tools(
    tools: dict[str, McpToolDecision],
    live: dict[str, McpLiveToolContract],
) -> None:
    for tool_name in live:
        if tools.get(tool_name) != "live":
            raise ValueError(f"mcp.live.{tool_name} requires mcp.tools decision live")
    for tool_name, decision in tools.items():
        if decision == "live" and tool_name not in live:
            raise ValueError(f"mcp.live.{tool_name} is required")


def _validate_mcp_tool_name(tool_name: Any, path: str) -> None:
    if not isinstance(tool_name, str):
        raise ValueError(f"{path} key must be a string")
    _split_mcp_tool_name(tool_name)


def _split_mcp_tool_name(tool_name: str) -> tuple[str, str]:
    upstream_name, separator, upstream_tool_name = tool_name.partition(".")
    if (
        not separator
        or not upstream_name.strip()
        or not upstream_tool_name.strip()
        or "/" in upstream_name
        or any(not segment for segment in upstream_tool_name.split("."))
    ):
        raise ValueError("mcp tool keys must be <upstream>.<tool>")
    return upstream_name, upstream_tool_name


def _require_mcp_non_empty_str(raw: dict[str, Any], path: str) -> str:
    key = path.rsplit(".", 1)[1]
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _optional_mcp_str(raw: dict[str, Any], path: str) -> str | None:
    key = path.rsplit(".", 1)[1]
    if key not in raw:
        return None
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    return value


def _require_live_str(raw: dict[str, Any], path: str) -> str:
    key = path.rsplit(".", 1)[1]
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _optional_live_str(raw: dict[str, Any], path: str) -> str | None:
    key = path.rsplit(".", 1)[1]
    if key not in raw:
        return None
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _optional_live_auth_scheme(raw: dict[str, Any], path: str) -> str | None:
    key = path.rsplit(".", 1)[1]
    if key not in raw:
        return None
    value = raw.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    return value


def _require_http_url(value: str, path: str) -> None:
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{path} must be a non-empty http(s) URL")


def _expect_optional_policy_list(raw: dict[str, Any], key: str) -> list[Any]:
    value = raw.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"policy.{key} must be a list")
    return value


def _parse_deny_rule(index: int, raw: Any) -> DenyRuleConfig:
    path = f"policy.deny[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must be an object")
    method = _require_policy_str(raw, f"{path}.method")
    path_prefix = _require_policy_path_prefix(raw, f"{path}.path_prefix")
    reason_code = _require_policy_str(raw, f"{path}.reason_code")
    message = _require_policy_str(raw, f"{path}.message")
    return DenyRuleConfig(
        method=method,
        path_prefix=path_prefix,
        reason_code=reason_code,
        message=message,
    )


def _parse_route_rule(base_path: str, index: int, raw: Any) -> RouteRule:
    path = f"{base_path}[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must be an object")
    path_prefix = _require_policy_path_prefix(raw, f"{path}.path_prefix")
    method = None
    if "method" in raw:
        method = _require_policy_str(raw, f"{path}.method")
    exact = False
    if "exact" in raw:
        exact_value = raw["exact"]
        if type(exact_value) is not bool:
            raise ValueError(f"{path}.exact must be a boolean")
        exact = exact_value
    return RouteRule(path_prefix=path_prefix, method=method, exact=exact)


def _parse_live_capture_rule(index: int, raw: Any) -> RouteRule:
    path = f"policy.live_capture[{index}]"
    rule = _parse_route_rule("policy.live_capture", index, raw)
    if rule.method is not None and rule.method.upper() != "GET":
        raise ValueError(f"{path} must be GET-only")
    if not _has_non_empty_first_segment(rule.path_prefix):
        raise ValueError(f"{path}.path_prefix must include a non-empty first segment")
    return RouteRule(path_prefix=rule.path_prefix, method="GET", exact=rule.exact)


def _require_policy_str(raw: dict[str, Any], path: str) -> str:
    key = path.rsplit(".", 1)[1]
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _require_policy_path_prefix(raw: dict[str, Any], path: str) -> str:
    value = _require_policy_str(raw, path)
    if not value.startswith("/"):
        raise ValueError(f"{path} must start with /")
    return value


def _has_non_empty_first_segment(path_prefix: str) -> bool:
    segments = path_prefix.split("/")
    return len(segments) > 1 and bool(segments[1])
