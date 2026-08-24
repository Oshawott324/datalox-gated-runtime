from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from datalox_gated_runtime.auth import AuthBrokerConfig
from datalox_gated_runtime.query import QueryParams, normalize_query

DecisionKind = Literal["replay", "shadow_read", "shadow_write", "live_capture", "deny", "miss"]
McpToolDecision = Literal["live", "replay", "shadow", "deny"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def path_prefix_matches(path: str, path_prefix: str) -> bool:
    if path_prefix == "/":
        return True
    if path_prefix.endswith("/"):
        return path.startswith(path_prefix)
    return path == path_prefix or path.startswith(f"{path_prefix}/")


@dataclass(frozen=True)
class CallRequest:
    method: str
    path: str
    query: QueryParams = field(default_factory=dict)
    body: dict[str, Any] | list[Any] | str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    operation_id: str | None = None
    scheme: str = "https"
    authority: str = ""
    raw_body_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "query", normalize_query(self.query))

    def normalized_method(self) -> str:
        return self.method.upper()


@dataclass(frozen=True)
class ResponseCase:
    case_id: str
    method: str
    path: str
    status_code: int
    body: dict[str, Any] | list[Any] | str | None
    evidence_ref: str | None = None
    query: QueryParams = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "query", normalize_query(self.query))

    def matches(self, request: CallRequest) -> bool:
        return (
            self.method.upper() == request.normalized_method()
            and self.path == request.path
            and self.query == request.query
        )


@dataclass(frozen=True)
class RouteRule:
    path_prefix: str
    method: str | None = None
    exact: bool = False

    def matches(self, request: CallRequest) -> bool:
        if self.method is not None and self.method.upper() != request.normalized_method():
            return False
        if self.exact:
            return request.path == self.path_prefix
        return path_prefix_matches(request.path, self.path_prefix)


@dataclass(frozen=True)
class DenyRuleConfig:
    method: str
    path_prefix: str
    reason_code: str
    message: str


@dataclass(frozen=True)
class PolicyConfig:
    deny: list[DenyRuleConfig] = field(default_factory=list)
    shadow_write: list[RouteRule] = field(default_factory=list)
    live_capture: list[RouteRule] = field(default_factory=list)


@dataclass(frozen=True)
class LiveAuthHeader:
    header: str
    env: str
    scheme: str = "Bearer"


@dataclass(frozen=True)
class LiveUpstream:
    base_url: str
    auth_env: str | None = None
    auth_header: str = "Authorization"
    auth_scheme: str = "Bearer"
    extra_auth: list[LiveAuthHeader] = field(default_factory=list)
    static_headers: dict[str, str] = field(default_factory=dict)
    auth_profile: str | None = None


@dataclass(frozen=True)
class LiveGateConfig:
    upstreams: dict[str, LiveUpstream]
    auth_profiles: AuthBrokerConfig = field(default_factory=AuthBrokerConfig)


@dataclass(frozen=True)
class McpUpstreamConfig:
    transport: Literal["stdio"]
    command: str
    args: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class McpLiveToolContract:
    contract: Literal["safe_read"]
    evidence_ref: str


@dataclass(frozen=True)
class McpResponseCase:
    case_id: str
    tool_name: str
    arguments: dict[str, Any]
    result: dict[str, Any]
    evidence_ref: str | None = None
    input_schema: dict[str, Any] | None = None


@dataclass(frozen=True)
class McpGeneratedConfig:
    tool_schemas: dict[str, dict[str, Any]] = field(default_factory=dict)
    response_cases: list[McpResponseCase] = field(default_factory=list)


@dataclass(frozen=True)
class McpGateConfig:
    upstreams: dict[str, McpUpstreamConfig] = field(default_factory=dict)
    tools: dict[str, McpToolDecision] = field(default_factory=dict)
    live: dict[str, McpLiveToolContract] = field(default_factory=dict)
    generated: McpGeneratedConfig = field(default_factory=McpGeneratedConfig)


@dataclass(frozen=True)
class WorldConfig:
    id: Literal["billing_support_v0"]
    scenario: Literal["duplicate_payment_refund"]
    seed: int
    state_db: str
    http_prefixes: list[str]
    verifier: Literal["billing_support_v0"]


@dataclass(frozen=True)
class ResponseCaseStateWorldConfig:
    kind: Literal["response_case_state_v0"]
    seed: int
    state_db: str
    episodes: str
    routes: str
    transitions: str
    verifier: str
    tool_catalog: str
    sources: str

    @property
    def id(self) -> Literal["response_case_state_v0"]:
        return self.kind

    def artifact_paths(self) -> tuple[str, ...]:
        return (
            self.episodes,
            self.routes,
            self.transitions,
            self.verifier,
            self.tool_catalog,
            self.sources,
        )


@dataclass(frozen=True)
class WorldBundleV1Config:
    kind: Literal["world_bundle_v1"]
    seed: int

    @property
    def id(self) -> Literal["world_bundle_v1"]:
        return self.kind


WorldConfigValue = WorldConfig | ResponseCaseStateWorldConfig | WorldBundleV1Config


@dataclass(frozen=True)
class McpToolCall:
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GateConfig:
    config_id: str
    response_cases: list[ResponseCase]
    audit_rules: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    auth_profiles: AuthBrokerConfig = field(default_factory=AuthBrokerConfig)
    policy: PolicyConfig | None = None
    live: LiveGateConfig | None = None
    mcp: McpGateConfig | None = None
    world: WorldConfigValue | None = None


@dataclass(frozen=True)
class TaskBrief:
    task_id: str
    title: str
    instructions: str
    success_criteria: list[str]


@dataclass(frozen=True)
class GateDecision:
    kind: DecisionKind
    reason_code: str
    message: str
    rule_id: str | None = None


@dataclass(frozen=True)
class GateResponse:
    status_code: int
    body: dict[str, Any] | list[Any] | str | None
    decision: GateDecision
    event_id: str
    response_case_id: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class McpDecision:
    kind: McpToolDecision
    reason_code: str
    message: str


@dataclass(frozen=True)
class McpGateResponse:
    result: dict[str, Any]
    decision: McpDecision
    event_id: str
    response_case_id: str | None = None


@dataclass(frozen=True)
class SessionManifest:
    session_id: str
    run_dir: str
    task_path: str
    gate_config_path: str
    ledger_path: str
    run_export_path: str
    audit_path: str
    http_base_url: str
    commands: dict[str, str]
    expected_surfaces: list[str]


@dataclass(frozen=True)
class LedgerEvent:
    event_id: str
    created_at: str
    request: CallRequest
    decision: GateDecision
    response_status_code: int
    response_body: dict[str, Any] | list[Any] | str | None
    surface: Literal["http"] = "http"
    response_case_id: str | None = None
    shadow_mutation: dict[str, Any] | None = None


@dataclass(frozen=True)
class McpLedgerEvent:
    surface: Literal["mcp"]
    event_id: str
    created_at: str
    tool_name: str
    upstream_name: str
    upstream_tool_name: str
    arguments: dict[str, Any]
    decision: McpDecision
    result: dict[str, Any]
    response_case_id: str | None = None
    shadow_mutation: dict[str, Any] | None = None


@dataclass(frozen=True)
class RunExport:
    run_id: str
    created_at: str
    events: list[LedgerEvent | McpLedgerEvent]
    shadow_state: dict[str, Any]

    @classmethod
    def from_parts(
        cls,
        events: list[LedgerEvent | McpLedgerEvent],
        shadow_state: dict[str, Any],
    ) -> RunExport:
        return cls(
            run_id=f"run_{uuid4().hex}",
            created_at=_utc_now(),
            events=events,
            shadow_state=shadow_state,
        )
