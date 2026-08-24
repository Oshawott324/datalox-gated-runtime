from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse, WorldVerifierResult
from datalox_gated_runtime.world_v1.errors import WorldAuthorizationError

if False:  # pragma: no cover - imported only for type checking without a runtime cycle
    from datalox_gated_runtime.world_v1.session import WorldSession

T = TypeVar("T")


def _require_identifier(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ValueError(f"{field_name} must be a non-empty, trimmed string")
    return value


@dataclass(frozen=True)
class ActorContext:
    actor_id: str
    role: str

    def __post_init__(self) -> None:
        _require_identifier(self.actor_id, field_name="actor_id")
        _require_identifier(self.role, field_name="role")


@dataclass(frozen=True)
class RoleDefinition:
    id: str
    description: str

    def __post_init__(self) -> None:
        _require_identifier(self.id, field_name="role id")
        if not isinstance(self.description, str):
            raise ValueError("role description must be a string")


@dataclass(frozen=True)
class ToolDefinition:
    id: str
    description: str
    list_roles: frozenset[str]
    invoke_roles: frozenset[str]
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    source_refs: tuple[str, ...] = ()
    operation_family: str | None = None

    def __post_init__(self) -> None:
        _require_identifier(self.id, field_name="tool id")
        if not isinstance(self.description, str):
            raise ValueError("tool description must be a string")
        if not self.invoke_roles.issubset(self.list_roles):
            raise ValueError("tool invoke_roles must be a subset of list_roles")
        if len(set(self.source_refs)) != len(self.source_refs) or any(
            not isinstance(source_ref, str) or not source_ref for source_ref in self.source_refs
        ):
            raise ValueError("tool source_refs must contain unique, non-empty strings")
        if self.operation_family is not None:
            _require_identifier(self.operation_family, field_name="operation_family")


class ToolCatalog:
    """Immutable role-filtered tool catalog with fail-closed direct invocation."""

    def __init__(
        self,
        *,
        roles: tuple[RoleDefinition, ...],
        tools: tuple[ToolDefinition, ...],
    ) -> None:
        self._roles = {role.id: role for role in roles}
        self._tools = {tool.id: tool for tool in tools}
        if len(self._roles) != len(roles):
            raise ValueError("role ids must be unique")
        if len(self._tools) != len(tools):
            raise ValueError("tool ids must be unique")
        for tool in tools:
            unknown = (tool.list_roles | tool.invoke_roles) - self._roles.keys()
            if unknown:
                raise ValueError(
                    f"tool {tool.id!r} references unknown roles: {', '.join(sorted(unknown))}"
                )

    @property
    def role_ids(self) -> frozenset[str]:
        return frozenset(self._roles)

    def require_actor(self, actor: ActorContext) -> None:
        if actor.role not in self._roles:
            raise WorldAuthorizationError(
                "world_actor_role_unknown",
                f"Actor role {actor.role!r} is not declared by this world.",
                actor_id=actor.actor_id,
                role=actor.role,
            )

    def list_for(self, actor: ActorContext) -> tuple[ToolDefinition, ...]:
        self.require_actor(actor)
        return tuple(tool for tool in self._tools.values() if actor.role in tool.list_roles)

    def require_invocation(self, actor: ActorContext, tool_id: str) -> ToolDefinition:
        self.require_actor(actor)
        tool = self._tools.get(tool_id)
        if tool is None:
            raise WorldAuthorizationError(
                "world_tool_unknown",
                f"Tool {tool_id!r} is not declared by this world.",
                actor_id=actor.actor_id,
                actor_role=actor.role,
                tool_id=tool_id,
            )
        if actor.role not in tool.list_roles:
            raise WorldAuthorizationError(
                "world_tool_hidden",
                f"Tool {tool_id!r} is hidden from role {actor.role!r}.",
                actor_id=actor.actor_id,
                actor_role=actor.role,
                tool_id=tool_id,
            )
        if actor.role not in tool.invoke_roles:
            raise WorldAuthorizationError(
                "world_tool_invocation_forbidden",
                f"Role {actor.role!r} may list but may not invoke tool {tool_id!r}.",
                actor_id=actor.actor_id,
                actor_role=actor.role,
                tool_id=tool_id,
            )
        return tool

    def invoke(
        self,
        *,
        session: WorldSession,
        actor: ActorContext,
        tool_id: str,
        arguments: Mapping[str, Any],
        handler: Callable[[WorldSession, ToolDefinition], T],
    ) -> T:
        try:
            tool = self.require_invocation(actor, tool_id)
        except WorldAuthorizationError as exc:
            session.record_denied_tool_attempt(
                actor=actor,
                tool_id=tool_id,
                arguments=arguments,
                reason_code=exc.code,
                request={"arguments": dict(arguments)},
            )
            raise

        with session.transaction(
            operation_id=tool.id,
            actor=actor,
            tool_name=tool.id,
            request={"arguments": dict(arguments)},
        ):
            session.append_event(
                "tool_invocation_started",
                {
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "tool_id": tool.id,
                    "arguments": dict(arguments),
                },
            )
            result = handler(session, tool)
            session.append_event(
                "tool_invocation_completed",
                {
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "tool_id": tool.id,
                },
            )
            return result


def resolve_actor_context(
    request: CallRequest,
    *,
    declared_roles: frozenset[str],
    default_role: str,
    configured_actor: ActorContext | None = None,
) -> ActorContext:
    """Resolve non-secret actor headers without allowing undeclared privilege."""

    headers = {key.lower(): value for key, value in request.headers.items()}
    actor_id = headers.get("x-datalox-actor-id")
    actor_role = headers.get("x-datalox-actor-role")

    if actor_id is None:
        actor_id = configured_actor.actor_id if configured_actor is not None else "agent"
    if actor_role is None:
        actor_role = configured_actor.role if configured_actor is not None else default_role

    actor = ActorContext(actor_id=actor_id, role=actor_role)
    if actor.role not in declared_roles:
        raise WorldAuthorizationError(
            "world_actor_role_unknown",
            f"Actor role {actor.role!r} is not declared by this world.",
            actor_id=actor.actor_id,
            role=actor.role,
            declared_roles=sorted(declared_roles),
        )
    return actor


class WorldImplementationV1(ABC):
    """Exact code-first protocol implemented by a compiled world bundle."""

    schema_version = "datalox_world_bundle_v1"

    @abstractmethod
    def initialize_episode(
        self,
        *,
        session: WorldSession,
        episode: Mapping[str, Any],
    ) -> None:
        """Reset authoritative state from one validated episode."""

    @abstractmethod
    def handle(
        self,
        request: CallRequest,
        *,
        actor: ActorContext,
        session: WorldSession,
    ) -> WorldResponse | None:
        """Handle one provider-shaped HTTP request against session state."""

    def tool_for_request(self, request: CallRequest) -> str | None:
        """Map a protected HTTP operation to a declared tool id.

        Bundles should override this for direct HTTP routes. The default supports
        requests produced by :class:`WorldBundleBackend.request_for_tool`.
        """

        headers = {key.lower(): value for key, value in request.headers.items()}
        return headers.get("x-datalox-tool-name")

    @abstractmethod
    def tool_schemas(self, *, actor: ActorContext) -> dict[str, dict[str, Any]]:
        """Return role-filtered MCP argument schemas."""

    @abstractmethod
    def request_for_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        actor: ActorContext,
    ) -> CallRequest:
        """Project one declared MCP tool call onto the HTTP-shaped operation."""

    @abstractmethod
    def operation_for_tool(self, tool_name: str) -> str | None:
        """Return the stable operation id for an MCP tool."""

    @abstractmethod
    def verify(
        self,
        *,
        session: WorldSession,
        episode: Mapping[str, Any],
    ) -> WorldVerifierResult:
        """Verify the current session using deterministic bundle logic."""

    @abstractmethod
    def task(self, *, episode: Mapping[str, Any]) -> TaskBrief | None:
        """Return the agent-visible task for the selected episode."""
