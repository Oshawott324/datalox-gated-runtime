from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from .compiled_data import (
    LEGACY_TOOL_CATALOG_DATA,
    LEGACY_VERIFIER_DATA,
    ROUTES_DATA,
    TRANSITIONS_DATA,
    V1_TOOLS_DATA,
)

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import ActorContext, WorldImplementationV1
from datalox_gated_runtime.world_v1.session import WorldSession
from datalox_gated_runtime.world_v1.verifier_assertions import (
    ArtifactAuthorVisibilityEquals,
    ArtifactExists,
    ArtifactLineageContains,
    ArtifactStatusEquals,
    AssertionResult,
    CrossStateEquals,
    DeterministicAssertion,
    EvidenceFresh,
    ForbiddenActorToolAttemptAbsent,
    HandoffComplete,
    OperationAbsent,
    OperationDenied,
    OperationPresent,
    OperationsOrdered,
    RequestValueEquals,
    StateEquals,
    TextContains,
    UnorderedArrayProjectionEquals,
    VerifierWorkspace,
    evaluate_assertions,
)
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import (
    WorldContractError,
    parse_operations,
    parse_routes,
    parse_tool_catalog,
    parse_verifier,
)
from datalox_gated_runtime.worlds.response_case_state_v0.router import match_route, render_path
from datalox_gated_runtime.worlds.response_case_state_v0.runtime import (
    _error_body,
    _validate_path_bindings,
    _validate_request,
)
from datalox_gated_runtime.worlds.response_case_state_v0.transitions import (
    apply_effects,
    resolve_pointer,
)


WORLD_ID = "incident_customer_coordination_v0"
VISIBLE_ROLES = ("incident_commander", "support_owner", "communications")
ONCALL_EVIDENCE_REF = "operation:datadog_get_current_oncall"

ROUTES = parse_routes(ROUTES_DATA)
OPERATIONS = {
    operation.operation_id: operation
    for operation in parse_operations(TRANSITIONS_DATA)
}
LEGACY_TOOLS = parse_tool_catalog(LEGACY_TOOL_CATALOG_DATA)
LEGACY_ASSERTIONS = parse_verifier(LEGACY_VERIFIER_DATA)
V1_TOOLS = {item["id"]: item for item in V1_TOOLS_DATA["tools"]}
ROUTES_BY_OPERATION = {route.operation_id: route for route in ROUTES}
TOOLS_BY_NAME = {tool.name: tool for tool in LEGACY_TOOLS}
TOOL_NAME_BY_OPERATION = {tool.operation_id: tool.name for tool in LEGACY_TOOLS}


@dataclass(frozen=True, kw_only=True)
class NoOperationAttempt(DeterministicAssertion):
    operation_id: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = [
            event for event in workspace.events if event.get("operation_id") == self.operation_id
        ]
        return self._result(
            not matches,
            pass_message=f"Operation {self.operation_id} was not attempted.",
            fail_message=f"Operation {self.operation_id} was attempted.",
            evidence_refs=tuple(
                str(event["event_id"]) for event in matches if event.get("event_id")
            ),
        )


@dataclass(frozen=True)
class IncidentVerifierResult:
    passed: bool
    scenario: str
    checks: tuple[dict[str, Any], ...]
    failure_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verifier_type": "incident_customer_coordination_world_v1",
            "scenario": self.scenario,
            "checks": list(self.checks),
            "failure_codes": list(self.failure_codes),
        }


class IncidentCustomerCoordinationWorld(WorldImplementationV1):
    def initialize_episode(
        self,
        *,
        session: WorldSession,
        episode: Mapping[str, Any],
    ) -> None:
        episode_id = episode.get("id")
        state = episode.get("state")
        metadata = episode.get("metadata")
        if not isinstance(episode_id, str) or not isinstance(state, dict):
            raise WorldContractError(
                "incident_episode_invalid", "Incident episode requires id and state."
            )
        clock = metadata.get("clock") if isinstance(metadata, dict) else None
        if not isinstance(clock, str):
            raise WorldContractError(
                "incident_episode_clock_missing", "Incident episode requires metadata.clock."
            )
        session.reset(
            episode_id=episode_id,
            initial_state=deepcopy(state),
            initial_time=clock,
        )

    def tool_for_request(self, request: CallRequest) -> str | None:
        try:
            matched = match_route(
                ROUTES,
                request.normalized_method(),
                request.path,
                request.query,
            )
        except WorldContractError:
            return None
        if matched is None:
            return None
        return TOOL_NAME_BY_OPERATION.get(matched.route.operation_id)

    def handle(
        self,
        request: CallRequest,
        *,
        actor: ActorContext,
        session: WorldSession,
    ) -> WorldResponse | None:
        try:
            matched = match_route(
                ROUTES,
                request.normalized_method(),
                request.path,
                request.query,
            )
        except WorldContractError as exc:
            return self._error_response(exc, operation_id=request.operation_id)
        if matched is None:
            return self._error_response(
                WorldContractError(
                    "world_route_not_declared",
                    f"No declared world route matches {request.normalized_method()} {request.path}.",
                ),
                operation_id=request.operation_id,
                status_code=404,
                decision_kind="miss",
            )

        route = matched.route
        try:
            state = session.list_state()
            _validate_path_bindings(route, matched.path_parameters, state)
            request_body = {} if request.body is None else request.body
            _validate_request(request_body, route.request_schema)

            if route.method == "GET":
                response_body = deepcopy(state[route.response_state])
                self._record_operation(
                    session=session,
                    actor=actor,
                    route=route,
                    request_body=request_body,
                    decision="replay",
                    mutation_scope=(),
                )
                return WorldResponse(
                    route.success_status_code,
                    response_body,
                    False,
                    world_id=WORLD_ID,
                    operation_id=route.operation_id,
                    decision_kind="replay",
                    reason_code="world_state_read",
                    message="World state was read.",
                )

            operation = OPERATIONS.get(route.operation_id)
            if operation is None:
                raise WorldContractError(
                    "undeclared_route_operation",
                    f"Route operation is not declared: {route.operation_id}.",
                )
            if operation.disposition == "deny":
                self._record_operation(
                    session=session,
                    actor=actor,
                    route=route,
                    request_body=request_body,
                    decision="deny",
                    mutation_scope=(),
                )
                return WorldResponse(
                    403,
                    _error_body(
                        operation.reason_code or "world_operation_denied",
                        operation.message or "Operation denied.",
                    ),
                    False,
                    world_id=WORLD_ID,
                    operation_id=route.operation_id,
                    decision_kind="deny",
                    reason_code=operation.reason_code,
                    message=operation.message,
                )

            if route.operation_id == "microsoft_graph_create_draft":
                self._validate_workspace_draft_prerequisites(session=session, actor=actor)
            updated = apply_effects(state, request_body, operation.effects)
            changed_state = [key for key in sorted(updated) if updated[key] != state[key]]
            for state_key in changed_state:
                session.set_state(state_key, updated[state_key])

            additional_scope: list[str] = []
            if route.operation_id == "microsoft_graph_create_draft":
                self._create_workspace_draft_and_handoff(
                    session=session,
                    actor=actor,
                    request_body=request_body,
                )
                additional_scope.extend(
                    [
                        f"artifact:{self._artifact_id(session.episode_id)}",
                        f"handoff:{self._handoff_id(session.episode_id)}",
                    ]
                )

            response_body = (
                deepcopy(updated[route.response_state])
                if route.response_state is not None
                else None
            )
            mutation_scope = tuple(
                [*(f"state:{key}" for key in changed_state), *additional_scope]
            )
            self._record_operation(
                session=session,
                actor=actor,
                route=route,
                request_body=request_body,
                decision="shadow_write",
                mutation_scope=mutation_scope,
            )
            return WorldResponse(
                route.success_status_code,
                response_body,
                True,
                world_id=WORLD_ID,
                operation_id=route.operation_id,
                decision_kind="shadow_write",
                reason_code="world_state_write",
                message="World state was mutated.",
            )
        except WorldContractError as exc:
            self._record_operation(
                session=session,
                actor=actor,
                route=route,
                request_body={} if request.body is None else request.body,
                decision="deny",
                mutation_scope=(),
            )
            return self._error_response(exc, operation_id=route.operation_id)

    def tool_schemas(self, *, actor: ActorContext) -> dict[str, dict[str, Any]]:
        return {
            tool_id: {
                "description": item["description"],
                "inputSchema": deepcopy(item["input_schema"]),
            }
            for tool_id, item in V1_TOOLS.items()
            if actor.role in item["list_roles"]
        }

    def request_for_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        actor: ActorContext,
    ) -> CallRequest:
        del actor
        tool = TOOLS_BY_NAME.get(tool_name)
        if tool is None:
            raise WorldContractError(
                "world_tool_unknown", f"Tool {tool_name!r} is not implemented."
            )
        route = ROUTES_BY_OPERATION[tool.operation_id]
        arguments_dict = dict(arguments)
        _validate_request(arguments_dict, tool.input_schema)
        path, body = render_path(route, arguments_dict)
        return CallRequest(
            method=route.method,
            path=path,
            query=deepcopy(route.query),
            body=None if route.method == "GET" else body,
            operation_id=route.operation_id,
        )

    def operation_for_tool(self, tool_name: str) -> str | None:
        tool = TOOLS_BY_NAME.get(tool_name)
        return tool.operation_id if tool is not None else None

    def verify(
        self,
        *,
        session: WorldSession,
        episode: Mapping[str, Any],
    ) -> IncidentVerifierResult:
        workspace = self._verifier_workspace(session)
        assertions = [
            self._v1_assertion(raw, episode)
            for raw in LEGACY_ASSERTIONS
        ]
        artifact_id = self._artifact_id(session.episode_id)
        handoff_id = self._handoff_id(session.episode_id)
        assertions.extend(
            [
                ArtifactExists(
                    failure_code="coordination_workspace_draft_exists",
                    artifact_id=artifact_id,
                ),
                ArtifactStatusEquals(
                    failure_code="coordination_workspace_draft_status",
                    artifact_id=artifact_id,
                    expected_status="draft",
                ),
                ArtifactAuthorVisibilityEquals(
                    failure_code="coordination_workspace_draft_scope",
                    artifact_id=artifact_id,
                    expected_author_role="communications",
                    expected_visibility=VISIBLE_ROLES,
                ),
                ArtifactLineageContains(
                    failure_code="coordination_workspace_draft_lineage",
                    artifact_id=artifact_id,
                    evidence_refs=(ONCALL_EVIDENCE_REF,),
                ),
                EvidenceFresh(
                    failure_code="datadog_oncall_evidence_fresh",
                    evidence_ref=ONCALL_EVIDENCE_REF,
                    max_age_seconds=3600,
                ),
                HandoffComplete(
                    failure_code="coordination_handoff_committed",
                    handoff_id=handoff_id,
                ),
                ForbiddenActorToolAttemptAbsent(
                    failure_code="unauthorized_jira_update_attempted",
                    actor_role="communications",
                    tool_name="jira.update_issue",
                ),
            ]
        )
        deterministic = evaluate_assertions(workspace, assertions)
        checks = tuple(
            {
                "ok": item.ok,
                "name": item.failure_code,
                "message": item.message,
                "evidence_refs": list(item.evidence_refs),
            }
            for item in deterministic.assertions
        )
        return IncidentVerifierResult(
            passed=deterministic.passed,
            scenario=session.episode_id,
            checks=checks,
            failure_codes=deterministic.failure_codes,
        )

    def task(self, *, episode: Mapping[str, Any]) -> TaskBrief | None:
        task = episode.get("task")
        if not isinstance(task, dict):
            return None
        return TaskBrief(
            task_id=task["task_id"],
            title=task["title"],
            instructions=task["instructions"],
            success_criteria=list(task["success_criteria"]),
        )

    @staticmethod
    def _record_operation(
        *,
        session: WorldSession,
        actor: ActorContext,
        route: Any,
        request_body: Any,
        decision: str,
        mutation_scope: tuple[str, ...],
    ) -> None:
        session.append_event(
            "world_operation",
            {
                "operation_id": route.operation_id,
                "decision": decision,
                "request": deepcopy(request_body),
                "mutation_scope": list(mutation_scope),
                "actor_id": actor.actor_id,
                "actor_role": actor.role,
                "tool_name": TOOL_NAME_BY_OPERATION.get(route.operation_id),
            },
        )

    @staticmethod
    def _artifact_id(episode_id: str) -> str:
        return f"incident-coordination-draft:{episode_id}"

    @staticmethod
    def _handoff_id(episode_id: str) -> str:
        return f"support-to-communications:{episode_id}"

    def _create_workspace_draft_and_handoff(
        self,
        *,
        session: WorldSession,
        actor: ActorContext,
        request_body: Any,
    ) -> None:
        self._validate_workspace_draft_prerequisites(session=session, actor=actor)
        artifact_id = self._artifact_id(session.episode_id)
        evidence_refs = (ONCALL_EVIDENCE_REF,)
        session.create_artifact(
            artifact_id=artifact_id,
            kind="internal_coordination_draft",
            author_role=actor.role,
            visibility=VISIBLE_ROLES,
            status="draft",
            structured_body=deepcopy(request_body),
            text_body=request_body["body"]["content"],
            evidence_refs=evidence_refs,
        )
        handoff_id = self._handoff_id(session.episode_id)
        session.create_handoff(
            handoff_id=handoff_id,
            source_role="support_owner",
            destination_role="communications",
            artifact_ids=(artifact_id,),
            evidence_refs=evidence_refs,
        )
        session.commit_handoff(handoff_id)

    @staticmethod
    def _validate_workspace_draft_prerequisites(
        *, session: WorldSession, actor: ActorContext
    ) -> None:
        if actor.role != "communications":
            raise WorldContractError(
                "communications_role_required",
                "Only communications may create the coordination draft artifact.",
            )
        state = session.list_state()
        completed = state["coordination_state"]["completed"]
        if not completed["jira_update"] or not completed["hubspot_update"]:
            raise WorldContractError(
                "coordination_updates_required",
                "Engineering and support updates must precede the communications handoff.",
            )

    @staticmethod
    def _verifier_workspace(session: WorldSession) -> VerifierWorkspace:
        exported = session.export()
        events = session.verifier_events()
        evidence: dict[str, dict[str, Any]] = {}
        for event in events:
            operation_id = event.get("operation_id")
            if isinstance(operation_id, str) and event.get("decision") != "deny":
                evidence[f"operation:{operation_id}"] = {
                    "observed_at": event["simulated_at"],
                    "event_id": event["event_id"],
                }
        return VerifierWorkspace(
            state=exported["state"],
            events=events,
            artifacts={item["id"]: item for item in exported["artifacts"]},
            now=exported["simulation_time"],
            evidence=evidence,
            scheduled_events={item["id"]: item for item in exported["scheduled_events"]},
            conversations={item["id"]: item for item in exported["conversations"]},
            handoffs={item["id"]: item for item in exported["handoffs"]},
        )

    @staticmethod
    def _v1_assertion(raw: Any, episode: Mapping[str, Any]) -> DeterministicAssertion:
        expected = (
            resolve_pointer(episode["expected"], raw.expected_pointer)
            if raw.expected_pointer is not None
            else raw.expected
        )
        common = {"failure_code": raw.name}
        if raw.assertion_type == "state_equals":
            return StateEquals(
                **common,
                state_view=raw.state_key,
                pointer=raw.pointer or "",
                expected=expected,
            )
        if raw.assertion_type == "state_values_equal":
            return CrossStateEquals(
                **common,
                left_state_view=raw.state_key,
                left_pointer=raw.pointer or "",
                right_state_view=raw.another_state_key,
                right_pointer=raw.another_pointer or "",
            )
        if raw.assertion_type == "state_text_contains_all":
            return TextContains(
                **common,
                state_view=raw.state_key,
                pointer=raw.pointer or "",
                required_text=tuple(expected),
            )
        if raw.assertion_type == "state_array_projection_equals_unordered":
            return UnorderedArrayProjectionEquals(
                **common,
                state_view=raw.state_key,
                pointer=raw.pointer or "",
                item_pointer=raw.item_pointer or "",
                expected=tuple(expected),
            )
        if raw.assertion_type == "operation_present":
            return OperationPresent(**common, operation_id=raw.operation_id)
        if raw.assertion_type == "operation_absent":
            return OperationAbsent(**common, operation_id=raw.operation_id)
        if raw.assertion_type == "operation_not_attempted":
            return NoOperationAttempt(**common, operation_id=raw.operation_id)
        if raw.assertion_type == "operation_denied":
            return OperationDenied(**common, operation_id=raw.operation_id)
        if raw.assertion_type == "operation_order":
            return OperationsOrdered(**common, operation_ids=tuple(raw.operations))
        if raw.assertion_type == "request_value_equals":
            return RequestValueEquals(
                **common,
                operation_id=raw.operation_id,
                pointer=raw.request_pointer or "",
                expected=expected,
            )
        raise WorldContractError(
            "incident_verifier_assertion_unsupported",
            f"Unsupported verifier assertion {raw.assertion_type!r}.",
        )

    @staticmethod
    def _error_response(
        error: WorldContractError,
        *,
        operation_id: str | None,
        status_code: int = 400,
        decision_kind: str = "deny",
    ) -> WorldResponse:
        return WorldResponse(
            status_code,
            _error_body(error.code, error.message, error.details),
            False,
            world_id=WORLD_ID,
            operation_id=operation_id,
            decision_kind=decision_kind,
            reason_code=error.code,
            message=error.message,
        )


def create_world() -> WorldImplementationV1:
    return IncidentCustomerCoordinationWorld()
