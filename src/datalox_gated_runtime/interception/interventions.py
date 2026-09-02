"""Controller-owned delivery interventions around provider-grounded behavior."""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Protocol, TypeAlias

from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse

DELIVERY_INTERVENTION_SCHEMA_VERSION = "datalox_delivery_intervention_v1"
DELIVERY_INTERVENTION_POLICY_SCHEMA_VERSION = "datalox_delivery_intervention_policy_v1"
DELIVERY_INTERVENTION_TRACE_SCHEMA_VERSION = "datalox_delivery_intervention_trace_v1"
DELIVERY_INTERVENTION_MAX_JSON_BYTES = 2 * 1024 * 1024

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_JSON_TYPES = frozenset({"array", "boolean", "integer", "null", "number", "object", "string"})

JsonValue: TypeAlias = dict[str, Any] | list[Any] | str | int | float | bool | None


class DeliveryInterventionError(ValueError):
    """A fixed intervention policy or its application failed closed."""


@dataclass(frozen=True)
class QuotaResponseAction:
    status_code: int
    headers: Mapping[str, str]
    body: JsonValue


@dataclass(frozen=True)
class JsonTypeDriftAction:
    pointer: str
    from_type: str
    to_type: str
    value: JsonValue


@dataclass(frozen=True)
class RepeatPageAction:
    source_request_index: int


InterventionAction: TypeAlias = QuotaResponseAction | JsonTypeDriftAction | RepeatPageAction


@dataclass(frozen=True)
class InterventionDecision:
    decision_id: str
    operation_id: str
    action: InterventionAction


class DeliveryInterventionPolicy(Protocol):
    """A consumer-owned deterministic decision policy.

    Datalox calls this exactly once for each logical request. The policy owns the
    distribution; the runtime only validates and applies its returned decision.
    """

    policy_id: str
    policy_version: str
    policy_sha256: str

    def decide(
        self,
        *,
        seed: str,
        logical_request_index: int,
        operation_id: str,
        request: CallRequest,
    ) -> InterventionDecision | None: ...


@dataclass(frozen=True)
class ScheduledDeliveryInterventionPolicy:
    policy_id: str
    policy_version: str
    policy_sha256: str
    schedules: Mapping[str, Mapping[int, InterventionDecision]]

    def decide(
        self,
        *,
        seed: str,
        logical_request_index: int,
        operation_id: str,
        request: CallRequest,
    ) -> InterventionDecision | None:
        del operation_id, request
        schedule = self.schedules.get(seed)
        if schedule is None:
            raise DeliveryInterventionError("the intervention policy does not declare this seed")
        return schedule.get(logical_request_index)


@dataclass(frozen=True)
class LoadedDeliveryIntervention:
    provider_id: str
    enabled: bool
    seed: str
    policy: ScheduledDeliveryInterventionPolicy
    path: Path


@dataclass(frozen=True)
class ProviderBaseBinding:
    provider_id: str
    release_version: str
    profile_id: str
    bundle_version: str
    release_config_sha256: str
    provider_runtime_sha256: str
    provider_admission_sha256: str
    operation_contract_sha256: str


@dataclass(frozen=True)
class _BaseResponse:
    operation_id: str
    response: GateResponse


class DeliveryInterventionSession:
    """One isolated, fixed-mode intervention session.

    The session is outside ``ProviderRuntime``. Provider calls and their ledger
    remain the base truth; this object writes a separate delivery trace.
    """

    def __init__(
        self,
        policy: DeliveryInterventionPolicy,
        *,
        provider: ProviderBaseBinding,
        allowed_read_operation_ids: frozenset[str],
        seed: str,
        enabled: bool,
        trace_path: Path | None = None,
    ) -> None:
        _validate_policy_identity(policy)
        _validate_provider_binding(provider)
        if (
            not isinstance(allowed_read_operation_ids, frozenset)
            or not allowed_read_operation_ids
            or any(
                not isinstance(operation_id, str) or not _IDENTIFIER.fullmatch(operation_id)
                for operation_id in allowed_read_operation_ids
            )
        ):
            raise DeliveryInterventionError(
                "allowed_read_operation_ids must be a non-empty identifier frozenset"
            )
        if not isinstance(seed, str) or not seed or len(seed) > 256:
            raise DeliveryInterventionError("intervention seed must be a bounded non-empty string")
        if type(enabled) is not bool:
            raise DeliveryInterventionError("intervention enabled mode must be a boolean")
        self.policy = policy
        self.provider = provider
        self.allowed_read_operation_ids = allowed_read_operation_ids
        self.allowed_read_operation_ids_sha256 = canonical_json_sha256(
            sorted(allowed_read_operation_ids)
        )
        self.seed = seed
        self.enabled = enabled
        self.trace_path = trace_path
        self._lock = threading.Lock()
        self._next_request_index = 1
        self._base_responses: dict[int, _BaseResponse] = {}
        self._events: list[dict[str, Any]] = []
        self._terminal_failure: dict[str, Any] | None = None
        if trace_path is not None:
            _create_empty_trace(trace_path)

    def handle(
        self,
        request: CallRequest,
        invoke_base: Callable[[], GateResponse],
        *,
        operation_id: str | None = None,
    ) -> GateResponse:
        """Apply one exact decision without retrying or normalizing either layer."""

        with self._lock:
            resolved_operation = operation_id or request.operation_id
            if not isinstance(resolved_operation, str) or not _IDENTIFIER.fullmatch(
                resolved_operation
            ):
                raise DeliveryInterventionError(
                    "a declared provider operation_id is required before intervention"
                )
            if resolved_operation not in self.allowed_read_operation_ids:
                raise DeliveryInterventionError(
                    "operation is outside the session's admitted read operation set"
                )
            if self._terminal_failure is not None:
                raise DeliveryInterventionError(
                    "intervention session is terminally failed; trusted reset is required"
                )
            index = self._next_request_index
            self._next_request_index += 1
            decision: InterventionDecision | None = None
            try:
                decision = self.policy.decide(
                    seed=self.seed,
                    logical_request_index=index,
                    operation_id=resolved_operation,
                    request=request,
                )
                if decision is not None:
                    _validate_decision(decision, index=index, operation_id=resolved_operation)
            except Exception as exc:
                failure = self._latch_failure(
                    code="delivery_intervention_policy_failed",
                    message="The consumer-owned intervention policy failed.",
                    stage="policy_decision",
                    index=index,
                    operation_id=resolved_operation,
                    decision=decision,
                    base_invoked=False,
                    base=None,
                )
                raise failure from exc

            if (
                self.enabled
                and decision is not None
                and isinstance(decision.action, QuotaResponseAction)
            ):
                delivered = _quota_response(
                    decision.action,
                    event_id=_event_id(self, index, operation_id=resolved_operation),
                )
                try:
                    self._record(
                        index=index,
                        operation_id=resolved_operation,
                        decision=decision,
                        base=None,
                        delivered=delivered,
                        applied=True,
                    )
                except Exception as exc:
                    failure = self._latch_evidence_failure(
                        index=index,
                        operation_id=resolved_operation,
                        stage="evidence_write",
                    )
                    raise failure from exc
                return delivered

            try:
                base = invoke_base()
            except Exception as exc:
                failure = self._latch_failure(
                    code="delivery_intervention_base_dispatch_failed",
                    message="The base provider invocation failed before returning evidence.",
                    stage="base_dispatch",
                    index=index,
                    operation_id=resolved_operation,
                    decision=decision,
                    base_invoked=True,
                    base=None,
                )
                raise failure from exc
            if not isinstance(base, GateResponse):
                failure = self._latch_failure(
                    code="delivery_intervention_base_response_invalid",
                    message="The base provider invocation returned an invalid response.",
                    stage="base_dispatch",
                    index=index,
                    operation_id=resolved_operation,
                    decision=decision,
                    base_invoked=True,
                    base=None,
                )
                raise failure
            self._base_responses[index] = _BaseResponse(
                operation_id=resolved_operation,
                response=deepcopy(base),
            )
            delivered = base
            applied = False
            if self.enabled and decision is not None:
                try:
                    delivered = self._apply_post_response(
                        decision=decision,
                        base=base,
                        operation_id=resolved_operation,
                        index=index,
                    )
                except Exception as exc:
                    failure = self._latch_failure(
                        code="delivery_intervention_application_failed",
                        message="The declared intervention could not be applied exactly.",
                        stage="post_response",
                        index=index,
                        operation_id=resolved_operation,
                        decision=decision,
                        base_invoked=True,
                        base=base,
                    )
                    raise failure from exc
                applied = True
            try:
                self._record(
                    index=index,
                    operation_id=resolved_operation,
                    decision=decision,
                    base=base,
                    delivered=delivered,
                    applied=applied,
                )
            except Exception as exc:
                failure = self._latch_evidence_failure(
                    index=index,
                    operation_id=resolved_operation,
                    stage="evidence_write",
                )
                raise failure from exc
            return delivered

    def reset(self) -> dict[str, Any]:
        """Reset only intervention state while preserving operator-fixed mode and seed."""

        with self._lock:
            self._next_request_index = 1
            self._base_responses.clear()
            self._events.clear()
            self._terminal_failure = None
            if self.trace_path is not None:
                _replace_with_empty_trace(self.trace_path)
            return self._export_unlocked()

    def export(self) -> dict[str, Any]:
        with self._lock:
            return self._export_unlocked()

    def _export_unlocked(self) -> dict[str, Any]:
        return {
            "schema_version": DELIVERY_INTERVENTION_TRACE_SCHEMA_VERSION,
            "provider": _provider_binding_payload(self.provider),
            "admitted_read_operation_ids": sorted(self.allowed_read_operation_ids),
            "admitted_read_operation_ids_sha256": self.allowed_read_operation_ids_sha256,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "policy_sha256": self.policy.policy_sha256,
            "seed": self.seed,
            "enabled": self.enabled,
            "next_request_index": self._next_request_index,
            "terminal_failure": deepcopy(self._terminal_failure),
            "events": deepcopy(self._events),
        }

    def _apply_post_response(
        self,
        *,
        decision: InterventionDecision,
        base: GateResponse,
        operation_id: str,
        index: int,
    ) -> GateResponse:
        action = decision.action
        if isinstance(action, QuotaResponseAction):
            raise DeliveryInterventionError("quota_response must execute before base dispatch")
        if isinstance(action, JsonTypeDriftAction):
            body = _replace_json_type(base.body, action)
            return replace(base, body=body)
        if isinstance(action, RepeatPageAction):
            source = self._base_responses.get(action.source_request_index)
            if source is None:
                raise DeliveryInterventionError("repeat_page source base response is unavailable")
            if action.source_request_index >= index:
                raise DeliveryInterventionError("repeat_page must reference an earlier request")
            if source.operation_id != operation_id:
                raise DeliveryInterventionError(
                    "repeat_page source must use the same provider operation"
                )
            return replace(base, body=deepcopy(source.response.body))
        raise DeliveryInterventionError("unsupported intervention action")

    def _record(
        self,
        *,
        index: int,
        operation_id: str,
        decision: InterventionDecision | None,
        base: GateResponse | None,
        delivered: GateResponse,
        applied: bool,
    ) -> None:
        action = None if decision is None else decision.action
        kind = _action_kind(action)
        stage = (
            "none"
            if action is None
            else "pre_dispatch"
            if isinstance(action, QuotaResponseAction)
            else "post_response"
        )
        response_payload = _response_payload(delivered)
        action_payload = _action_payload(action)
        source_base = _source_base_payload(self._base_responses, action)
        event = {
            "event_id": _event_id(self, index, operation_id=operation_id),
            "provider": _provider_binding_payload(self.provider),
            "admitted_read_operation_ids_sha256": self.allowed_read_operation_ids_sha256,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "policy_sha256": self.policy.policy_sha256,
            "seed": self.seed,
            "logical_request_index": index,
            "operation_id": operation_id,
            "enabled": self.enabled,
            "decision": {
                "decision_id": None if decision is None else decision.decision_id,
                "kind": kind,
                "action": action_payload,
                "action_sha256": (
                    None if action_payload is None else canonical_json_sha256(action_payload)
                ),
                "source_base": source_base,
            },
            "stage": stage,
            "applied": applied,
            "outcome": "delivered",
            "base": {
                "invoked": base is not None,
                "event_id": None if base is None else base.event_id,
                "response_sha256": None if base is None else _response_sha256(base),
            },
            "delivered": {
                "kind": "response",
                "response_sha256": canonical_json_sha256(response_payload),
                "response": response_payload,
            },
            "error": None,
        }
        if self.trace_path is not None:
            _append_trace_event(self.trace_path, event)
        self._events.append(event)

    def _latch_failure(
        self,
        *,
        code: str,
        message: str,
        stage: str,
        index: int,
        operation_id: str,
        decision: InterventionDecision | None,
        base_invoked: bool,
        base: GateResponse | None,
    ) -> DeliveryInterventionError:
        event_id = _event_id(self, index, operation_id=operation_id)
        safe_decision = (
            decision
            if isinstance(decision, InterventionDecision)
            and isinstance(
                decision.action,
                (QuotaResponseAction, JsonTypeDriftAction, RepeatPageAction),
            )
            else None
        )
        action = None if safe_decision is None else safe_decision.action
        action_payload = _action_payload(action)
        event = {
            "event_id": event_id,
            "provider": _provider_binding_payload(self.provider),
            "admitted_read_operation_ids_sha256": self.allowed_read_operation_ids_sha256,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "policy_sha256": self.policy.policy_sha256,
            "seed": self.seed,
            "logical_request_index": index,
            "operation_id": operation_id,
            "enabled": self.enabled,
            "decision": {
                "decision_id": None if safe_decision is None else safe_decision.decision_id,
                "kind": _action_kind(action),
                "action": action_payload,
                "action_sha256": (
                    None if action_payload is None else canonical_json_sha256(action_payload)
                ),
                "source_base": _source_base_payload(self._base_responses, action),
            },
            "stage": stage,
            "applied": False,
            "outcome": "terminal_failure",
            "base": {
                "invoked": base_invoked,
                "event_id": None if base is None else base.event_id,
                "response_sha256": None if base is None else _safe_response_sha256(base),
            },
            "delivered": None,
            "error": {"code": code, "message": message},
        }
        terminal = {
            "event_id": event_id,
            "logical_request_index": index,
            "stage": stage,
            "code": code,
            "message": message,
        }
        try:
            if self.trace_path is not None:
                _append_trace_event(self.trace_path, event)
            self._events.append(event)
            self._terminal_failure = terminal
        except Exception:  # noqa: BLE001
            self._terminal_failure = {
                **terminal,
                "stage": "evidence_write",
                "code": "delivery_intervention_evidence_write_failed",
                "message": "The intervention trace could not be written.",
            }
        return DeliveryInterventionError(self._terminal_failure["message"])

    def _latch_evidence_failure(
        self, *, index: int, operation_id: str, stage: str
    ) -> DeliveryInterventionError:
        self._terminal_failure = {
            "event_id": _event_id(self, index, operation_id=operation_id),
            "logical_request_index": index,
            "stage": stage,
            "code": "delivery_intervention_evidence_write_failed",
            "message": "The intervention trace could not be written.",
        }
        return DeliveryInterventionError(self._terminal_failure["message"])


class DeliveryInterventionHandler:
    """Bind one ProviderRuntime-like handler to one intervention session."""

    def __init__(
        self,
        *,
        base_handler: Any,
        session: DeliveryInterventionSession,
        resolve_operation_id: Callable[[CallRequest], str | None],
    ) -> None:
        self.base_handler = base_handler
        self.session = session
        self.resolve_operation_id = resolve_operation_id

    def handle(self, request: CallRequest) -> GateResponse:
        operation_id = self.resolve_operation_id(request)
        if (
            operation_id is None
            or operation_id not in self.session.allowed_read_operation_ids
            or any(name.lower().startswith("x-datalox-") for name in request.headers)
        ):
            return self.base_handler.handle(request)
        return self.session.handle(
            request,
            lambda: self.base_handler.handle(request),
            operation_id=operation_id,
        )


def load_delivery_intervention(path: Path) -> LoadedDeliveryIntervention:
    raw, resolved = _load_config_object(path)
    _require_fields(
        raw,
        {
            "schema_version",
            "provider_id",
            "mode",
            "seed",
            "policy",
            "policy_sha256",
        },
        "delivery intervention config",
    )
    if raw["schema_version"] != DELIVERY_INTERVENTION_SCHEMA_VERSION:
        raise DeliveryInterventionError("unsupported delivery intervention schema")
    provider_id = _identifier(raw["provider_id"], "provider_id")
    mode = raw["mode"]
    if mode not in {"off", "on"}:
        raise DeliveryInterventionError("delivery intervention mode must be off or on")
    seed = raw["seed"]
    if not isinstance(seed, str) or not seed or len(seed) > 256:
        raise DeliveryInterventionError("delivery intervention seed is invalid")
    policy_raw = raw["policy"]
    if not isinstance(policy_raw, dict):
        raise DeliveryInterventionError("delivery intervention policy must be an object")
    digest = raw["policy_sha256"]
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise DeliveryInterventionError("delivery intervention policy digest is invalid")
    if canonical_json_sha256(policy_raw) != digest:
        raise DeliveryInterventionError("delivery intervention policy digest does not match")
    policy = _parse_scheduled_policy(policy_raw, digest=digest)
    if seed not in policy.schedules:
        raise DeliveryInterventionError("selected seed is absent from the intervention policy")
    return LoadedDeliveryIntervention(
        provider_id=provider_id,
        enabled=mode == "on",
        seed=seed,
        policy=policy,
        path=resolved,
    )


def validate_policy_for_operations(
    policy: ScheduledDeliveryInterventionPolicy,
    *,
    operation_mutability: Mapping[str, str],
) -> None:
    """Require every v1 intervention to target an admitted read operation."""

    for schedule in policy.schedules.values():
        for decision in schedule.values():
            mutability = operation_mutability.get(decision.operation_id)
            if mutability is None:
                raise DeliveryInterventionError(
                    f"intervention operation is not admitted: {decision.operation_id}"
                )
            if mutability != "read":
                raise DeliveryInterventionError(
                    "delivery intervention v1 supports read operations only"
                )


def _parse_scheduled_policy(
    raw: dict[str, Any], *, digest: str
) -> ScheduledDeliveryInterventionPolicy:
    _require_fields(
        raw,
        {"schema_version", "policy_id", "policy_version", "schedules"},
        "delivery intervention policy",
    )
    if raw["schema_version"] != DELIVERY_INTERVENTION_POLICY_SCHEMA_VERSION:
        raise DeliveryInterventionError("unsupported delivery intervention policy schema")
    policy_id = _identifier(raw["policy_id"], "policy_id")
    version = _identifier(raw["policy_version"], "policy_version")
    schedules_raw = raw["schedules"]
    if not isinstance(schedules_raw, list) or not schedules_raw:
        raise DeliveryInterventionError("intervention policy requires schedules")
    schedules: dict[str, dict[int, InterventionDecision]] = {}
    for raw_schedule in schedules_raw:
        if not isinstance(raw_schedule, dict):
            raise DeliveryInterventionError("intervention schedule must be an object")
        _require_fields(raw_schedule, {"seed", "decisions"}, "intervention schedule")
        seed = raw_schedule["seed"]
        if not isinstance(seed, str) or not seed or len(seed) > 256 or seed in schedules:
            raise DeliveryInterventionError("intervention schedule seed is invalid or duplicated")
        raw_decisions = raw_schedule["decisions"]
        if not isinstance(raw_decisions, list):
            raise DeliveryInterventionError("intervention decisions must be an array")
        decisions: dict[int, InterventionDecision] = {}
        decision_ids: set[str] = set()
        for raw_decision in raw_decisions:
            decision, request_index = _parse_decision(raw_decision)
            if request_index in decisions or decision.decision_id in decision_ids:
                raise DeliveryInterventionError(
                    "intervention request indexes and decision ids must be unique per seed"
                )
            decisions[request_index] = decision
            decision_ids.add(decision.decision_id)
        _validate_repeat_sources(decisions)
        schedules[seed] = decisions
    return ScheduledDeliveryInterventionPolicy(
        policy_id=policy_id,
        policy_version=version,
        policy_sha256=digest,
        schedules=schedules,
    )


def _parse_decision(raw: Any) -> tuple[InterventionDecision, int]:
    if not isinstance(raw, dict):
        raise DeliveryInterventionError("intervention decision must be an object")
    _require_fields(
        raw,
        {"decision_id", "request_index", "operation_id", "action"},
        "intervention decision",
    )
    decision_id = _identifier(raw["decision_id"], "decision_id")
    operation_id = _identifier(raw["operation_id"], "operation_id")
    request_index = raw["request_index"]
    if type(request_index) is not int or request_index < 1:
        raise DeliveryInterventionError("intervention request_index must be a positive integer")
    action = _parse_action(raw["action"])
    return InterventionDecision(decision_id, operation_id, action), request_index


def _parse_action(raw: Any) -> InterventionAction:
    if not isinstance(raw, dict) or not isinstance(raw.get("kind"), str):
        raise DeliveryInterventionError("intervention action must declare a kind")
    kind = raw["kind"]
    if kind == "quota_response":
        _require_fields(raw, {"kind", "response"}, "quota response action")
        response = raw["response"]
        if not isinstance(response, dict):
            raise DeliveryInterventionError("quota response must be an object")
        _require_fields(response, {"status_code", "headers", "body"}, "quota response")
        action = QuotaResponseAction(
            status_code=response["status_code"],
            headers=response["headers"],
            body=deepcopy(response["body"]),
        )
        _validate_action(action)
        return action
    if kind == "json_type_drift":
        _require_fields(
            raw,
            {"kind", "pointer", "from_type", "to_type", "value"},
            "JSON type drift action",
        )
        action = JsonTypeDriftAction(
            pointer=raw["pointer"],
            from_type=raw["from_type"],
            to_type=raw["to_type"],
            value=deepcopy(raw["value"]),
        )
        _validate_action(action)
        return action
    if kind == "repeat_page":
        _require_fields(raw, {"kind", "source_request_index"}, "repeat page action")
        action = RepeatPageAction(source_request_index=raw["source_request_index"])
        _validate_action(action)
        return action
    raise DeliveryInterventionError(f"unsupported intervention action: {kind}")


def _validate_decision(decision: InterventionDecision, *, index: int, operation_id: str) -> None:
    if not isinstance(decision, InterventionDecision):
        raise DeliveryInterventionError("intervention policy returned an invalid decision")
    _identifier(decision.decision_id, "decision_id")
    _identifier(decision.operation_id, "operation_id")
    if decision.operation_id != operation_id:
        raise DeliveryInterventionError(
            f"decision {decision.decision_id!r} targets {decision.operation_id!r} "
            f"at request {index}, not {operation_id!r}"
        )
    _validate_action(decision.action)


def _validate_action(action: InterventionAction) -> None:
    if isinstance(action, QuotaResponseAction):
        if action.status_code != 429:
            raise DeliveryInterventionError("quota response status must be 429")
        _validate_headers(action.headers)
        canonical_json_sha256(action.body)
        return
    if isinstance(action, JsonTypeDriftAction):
        _parse_json_pointer(action.pointer)
        if action.from_type not in _JSON_TYPES or action.to_type not in _JSON_TYPES:
            raise DeliveryInterventionError("JSON type drift declares an unsupported JSON type")
        if action.from_type == action.to_type:
            raise DeliveryInterventionError("JSON type drift must change the JSON type")
        canonical_json_sha256(action.value)
        if _json_type(action.value) != action.to_type:
            raise DeliveryInterventionError("JSON type drift value does not match to_type")
        return
    if isinstance(action, RepeatPageAction):
        if type(action.source_request_index) is not int or action.source_request_index < 1:
            raise DeliveryInterventionError("repeat_page source index must be positive")
        return
    raise DeliveryInterventionError("intervention policy returned an unsupported action")


def _validate_repeat_sources(decisions: Mapping[int, InterventionDecision]) -> None:
    for request_index, decision in decisions.items():
        action = decision.action
        if not isinstance(action, RepeatPageAction):
            continue
        if action.source_request_index >= request_index:
            raise DeliveryInterventionError("repeat_page must reference an earlier request")
        source = decisions.get(action.source_request_index)
        if source is not None and isinstance(source.action, QuotaResponseAction):
            raise DeliveryInterventionError(
                "repeat_page source cannot be a request suppressed by quota_response"
            )


def _quota_response(action: QuotaResponseAction, *, event_id: str) -> GateResponse:
    _validate_action(action)
    return GateResponse(
        status_code=action.status_code,
        headers=dict(action.headers),
        body=deepcopy(action.body),
        decision=GateDecision(
            kind="deny",
            reason_code="delivery_intervention_quota",
            message="The controller-owned intervention delivered its declared quota response.",
        ),
        event_id=event_id,
    )


def _replace_json_type(body: JsonValue, action: JsonTypeDriftAction) -> JsonValue:
    _validate_action(action)
    result = deepcopy(body)
    tokens = _parse_json_pointer(action.pointer)
    if not tokens:
        if _json_type(result) != action.from_type:
            raise DeliveryInterventionError("JSON type drift root does not match from_type")
        return deepcopy(action.value)
    parent: Any = result
    for token in tokens[:-1]:
        parent = _pointer_child(parent, token)
    final = tokens[-1]
    current = _pointer_child(parent, final)
    if _json_type(current) != action.from_type:
        raise DeliveryInterventionError("JSON type drift target does not match from_type")
    if isinstance(parent, dict):
        parent[final] = deepcopy(action.value)
    elif isinstance(parent, list):
        parent[_list_index(final, len(parent))] = deepcopy(action.value)
    else:
        raise DeliveryInterventionError("JSON pointer parent is not a container")
    return result


def _parse_json_pointer(pointer: Any) -> list[str]:
    if not isinstance(pointer, str):
        raise DeliveryInterventionError("JSON pointer must be a string")
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise DeliveryInterventionError("JSON pointer must be empty or start with slash")
    tokens: list[str] = []
    for encoded in pointer[1:].split("/"):
        decoded = ""
        index = 0
        while index < len(encoded):
            if encoded[index] != "~":
                decoded += encoded[index]
                index += 1
                continue
            if index + 1 >= len(encoded) or encoded[index + 1] not in {"0", "1"}:
                raise DeliveryInterventionError("JSON pointer contains an invalid escape")
            decoded += "~" if encoded[index + 1] == "0" else "/"
            index += 2
        tokens.append(decoded)
    return tokens


def _pointer_child(parent: Any, token: str) -> Any:
    if isinstance(parent, dict):
        if token not in parent:
            raise DeliveryInterventionError("JSON pointer does not exist")
        return parent[token]
    if isinstance(parent, list):
        return parent[_list_index(token, len(parent))]
    raise DeliveryInterventionError("JSON pointer traverses a non-container")


def _list_index(token: str, length: int) -> int:
    if not token or (token != "0" and token.startswith("0")) or not token.isdigit():
        raise DeliveryInterventionError("JSON pointer array index is invalid")
    index = int(token)
    if index >= length:
        raise DeliveryInterventionError("JSON pointer array index is out of bounds")
    return index


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        return "array"
    if type(value) is dict:
        return "object"
    raise DeliveryInterventionError("value is not JSON")


def _response_payload(response: GateResponse) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "headers": deepcopy(dict(response.headers)),
        "body": deepcopy(response.body),
    }


def _response_sha256(response: GateResponse) -> str:
    return canonical_json_sha256(_response_payload(response))


def _safe_response_sha256(response: GateResponse) -> str | None:
    try:
        return _response_sha256(response)
    except (TypeError, ValueError):
        return None


def _action_kind(action: InterventionAction | None) -> str:
    if action is None:
        return "none"
    if isinstance(action, QuotaResponseAction):
        return "quota_response"
    if isinstance(action, JsonTypeDriftAction):
        return "json_type_drift"
    if isinstance(action, RepeatPageAction):
        return "repeat_page"
    raise DeliveryInterventionError("unsupported intervention action")


def _action_payload(action: InterventionAction | None) -> dict[str, Any] | None:
    if action is None:
        return None
    if isinstance(action, QuotaResponseAction):
        return {
            "kind": "quota_response",
            "response": {
                "status_code": action.status_code,
                "headers": deepcopy(dict(action.headers)),
                "body": deepcopy(action.body),
            },
        }
    if isinstance(action, JsonTypeDriftAction):
        return {
            "kind": "json_type_drift",
            "pointer": action.pointer,
            "from_type": action.from_type,
            "to_type": action.to_type,
            "value": deepcopy(action.value),
        }
    if isinstance(action, RepeatPageAction):
        return {
            "kind": "repeat_page",
            "source_request_index": action.source_request_index,
        }
    raise DeliveryInterventionError("unsupported intervention action")


def _source_base_payload(
    base_responses: Mapping[int, _BaseResponse],
    action: InterventionAction | None,
) -> dict[str, Any] | None:
    if not isinstance(action, RepeatPageAction):
        return None
    source = base_responses.get(action.source_request_index)
    if source is None:
        return None
    return {
        "logical_request_index": action.source_request_index,
        "event_id": source.response.event_id,
        "response_sha256": _response_sha256(source.response),
    }


def _event_id(session: DeliveryInterventionSession, index: int, *, operation_id: str) -> str:
    digest = canonical_json_sha256(
        {
            "provider": _provider_binding_payload(session.provider),
            "admitted_read_operation_ids_sha256": (session.allowed_read_operation_ids_sha256),
            "policy_sha256": session.policy.policy_sha256,
            "seed": session.seed,
            "logical_request_index": index,
            "operation_id": operation_id,
        }
    )
    return f"intv_{digest.removeprefix('sha256:')[:24]}"


def _validate_provider_binding(provider: ProviderBaseBinding) -> None:
    if not isinstance(provider, ProviderBaseBinding):
        raise DeliveryInterventionError("provider base binding is required")
    _identifier(provider.provider_id, "provider_id")
    _identifier(provider.release_version, "release_version")
    _identifier(provider.profile_id, "profile_id")
    if not isinstance(provider.bundle_version, str) or not provider.bundle_version:
        raise DeliveryInterventionError("bundle_version is invalid")
    for name, value in (
        ("release_config_sha256", provider.release_config_sha256),
        ("provider_runtime_sha256", provider.provider_runtime_sha256),
        ("provider_admission_sha256", provider.provider_admission_sha256),
        ("operation_contract_sha256", provider.operation_contract_sha256),
    ):
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise DeliveryInterventionError(f"{name} is invalid")


def _provider_binding_payload(provider: ProviderBaseBinding) -> dict[str, Any]:
    return {
        "provider_id": provider.provider_id,
        "release_version": provider.release_version,
        "profile_id": provider.profile_id,
        "bundle_version": provider.bundle_version,
        "release_config_sha256": provider.release_config_sha256,
        "provider_runtime_sha256": provider.provider_runtime_sha256,
        "provider_admission_sha256": provider.provider_admission_sha256,
        "operation_contract_sha256": provider.operation_contract_sha256,
    }


def _validate_policy_identity(policy: DeliveryInterventionPolicy) -> None:
    _identifier(getattr(policy, "policy_id", None), "policy_id")
    _identifier(getattr(policy, "policy_version", None), "policy_version")
    digest = getattr(policy, "policy_sha256", None)
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        raise DeliveryInterventionError("policy_sha256 is invalid")
    if not callable(getattr(policy, "decide", None)):
        raise DeliveryInterventionError("intervention policy must implement decide")


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise DeliveryInterventionError(f"{name} is invalid")
    return value


def _validate_headers(headers: Any) -> None:
    if not isinstance(headers, Mapping):
        raise DeliveryInterventionError("intervention response headers must be an object")
    seen: set[str] = set()
    for name, value in headers.items():
        if (
            not isinstance(name, str)
            or not _HEADER_NAME.fullmatch(name)
            or not isinstance(value, str)
            or "\r" in value
            or "\n" in value
        ):
            raise DeliveryInterventionError("intervention response header is invalid")
        lowered = name.lower()
        if lowered in seen or lowered.startswith("x-datalox-"):
            raise DeliveryInterventionError(
                "intervention response headers must be unique and provider-shaped"
            )
        seen.add(lowered)


def _require_fields(value: dict[str, Any], expected: set[str], name: str) -> None:
    if set(value) != expected:
        raise DeliveryInterventionError(f"{name} fields do not match the strict v1 contract")


def _load_config_object(path: Path) -> tuple[dict[str, Any], Path]:
    if path.is_symlink():
        raise DeliveryInterventionError("delivery intervention config must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size > DELIVERY_INTERVENTION_MAX_JSON_BYTES:
            raise DeliveryInterventionError(
                "delivery intervention config must be a bounded regular file"
            )
        payload = resolved.read_bytes()
        if len(payload) > DELIVERY_INTERVENTION_MAX_JSON_BYTES:
            raise DeliveryInterventionError("delivery intervention config is too large")
        value = json.loads(payload.decode("utf-8"))
    except DeliveryInterventionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DeliveryInterventionError("delivery intervention config is invalid") from exc
    if not isinstance(value, dict):
        raise DeliveryInterventionError("delivery intervention config must contain an object")
    canonical_json_sha256(value)
    return value, resolved


def _create_empty_trace(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise DeliveryInterventionError("intervention trace path already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_with_empty_trace(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise DeliveryInterventionError("intervention trace path is invalid")
    path.unlink()
    _create_empty_trace(path)


def _append_trace_event(path: Path, event: Mapping[str, Any]) -> None:
    if path.is_symlink() or not path.is_file():
        raise DeliveryInterventionError("intervention trace path is invalid")
    payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("intervention trace append made no progress")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
