"""Executable provider-mediated behavior for one admitted provider session.

The session executes only causal edges declared by an admitted Composition Pack.
Calls that an agent makes across providers remain ordinary agent actions; the
session never infers a hidden integration from a task, payload, or provider pair.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.parse import quote

from datalox_gated_runtime.composition.events import (
    MAX_SESSION_DELIVERIES,
    DeliveryCommand,
    DeliveryOutcome,
    DeliveryRequest,
    DeliveryRunResult,
    DeliveryState,
    ExistingSourceDeliveryRequest,
    PostOutcomeEffect,
    SessionEventEngine,
    SourceFanoutRequest,
)
from datalox_gated_runtime.composition.pack import (
    CompensationContract,
    DeliveryEdge,
    LoadedCompositionPack,
    SourceEventContract,
    evaluate_request_template,
    evaluate_source_match,
    evaluate_string_template,
    evaluate_string_template_map,
    evaluate_template,
)
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse
from datalox_gated_runtime.provider_runtime.identity import redact_external_request
from datalox_gated_runtime.provider_runtime.release import (
    LoadedProviderRelease,
)
from datalox_gated_runtime.provider_runtime.runtime import ProviderRuntime

if TYPE_CHECKING:
    from datalox_gated_runtime.rollout.provider_set import AdmittedRolloutProviderBinding

COMPOSITION_SESSION_EXPORT_SCHEMA_VERSION = "datalox_composition_session_export_v1"
_PATH_PARAMETER = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_SECRET_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
    }
)


@dataclass(frozen=True)
class CompositionSessionError(ValueError):
    """Stable controller-readable session failure."""

    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __str__(self) -> str:
        return self.message


@runtime_checkable
class AdmissionProviderProfileCapability(Protocol):
    provider_id: str
    profile_id: str
    release_manifest_sha256: str
    provider_runtime_sha256: str
    provider_admission_sha256: str
    operation_contract_sha256: str


@runtime_checkable
class CompositionAdmissionCapability(Protocol):
    """Trusted result returned by the strict Composition Admission loader."""

    canonical_sha256: str
    pack_id: str
    pack_version: str
    composition_pack_sha256: str
    distribution_label: str
    time_scope: str
    provider_profiles: tuple[AdmissionProviderProfileCapability, ...]
    required_coverage: tuple[Any, ...]
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class _CompositionExecutionAuthority:
    """Private capability consumed by the shared composition execution core."""

    authority_kind: str
    canonical_sha256: str
    pack_id: str
    pack_version: str
    composition_pack_sha256: str
    distribution_label: str
    time_scope: str
    provider_profiles: tuple[AdmissionProviderProfileCapability, ...]


@dataclass(frozen=True)
class CompositionRuntimeRelease:
    """OCI-independent capability for one verified materialized release profile."""

    provider_id: str
    profile_id: str
    release_manifest_sha256: str
    release_config_sha256: str
    provider_runtime_sha256: str
    provider_admission_sha256: str
    operation_contract_sha256: str
    release_config: Mapping[str, Any] = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        frozen = _freeze_json(self.release_config)
        if not isinstance(frozen, Mapping):
            raise TypeError("release_config must be a finite JSON object")
        object.__setattr__(self, "release_config", frozen)

    @classmethod
    def from_loaded_release(
        cls, release: LoadedProviderRelease, *, profile_id: str
    ) -> CompositionRuntimeRelease:
        profiles = [item for item in release.profiles if item.profile_id == profile_id]
        if len(profiles) != 1:
            _fail(
                "composition_session_profile_unknown",
                "The selected provider release profile does not exist.",
                provider_id=release.provider_id,
                profile_id=profile_id,
            )
        profile = profiles[0]
        return cls(
            provider_id=release.provider_id,
            profile_id=profile.profile_id,
            release_manifest_sha256=release.manifest_descriptor["digest"],
            release_config_sha256=canonical_json_sha256(release.config),
            provider_runtime_sha256=profile.provider_runtime_sha256,
            provider_admission_sha256=profile.provider_admission_sha256,
            operation_contract_sha256=release.config["operation_contract_sha256"],
            release_config=release.config,
        )

    @classmethod
    def from_admitted_rollout_binding(
        cls, binding: AdmittedRolloutProviderBinding
    ) -> CompositionRuntimeRelease:
        """Project a strict materialized Provider Set v2 binding into execution."""

        from datalox_gated_runtime.rollout.provider_set import AdmittedRolloutProviderBinding

        if not isinstance(binding, AdmittedRolloutProviderBinding):
            raise TypeError("binding must be an AdmittedRolloutProviderBinding")
        provider = binding.provider
        return cls(
            provider_id=provider.provider_id,
            profile_id=provider.profile_id,
            release_manifest_sha256=provider.release_manifest_sha256,
            release_config_sha256=binding.release_config_sha256,
            provider_runtime_sha256=provider.provider_runtime_sha256,
            provider_admission_sha256=provider.provider_admission_sha256,
            operation_contract_sha256=provider.operation_contract_sha256,
            release_config=binding.release_config,
        )


@dataclass(frozen=True)
class CompositionProviderSession:
    """One exact runtime release capability and its isolated runtime instance."""

    release: CompositionRuntimeRelease
    runtime: ProviderRuntime


@dataclass(frozen=True)
class _Operation:
    provider_id: str
    operation_id: str
    scheme: str
    authority: str
    method: str
    path_template: str
    path_segments: tuple[str, ...]
    mutability: str


@dataclass(frozen=True)
class _DeliveryDefinition:
    edge_id: str
    target_provider_id: str
    target_operation_id: str
    principal_context_id: str
    delivered_statuses: frozenset[int]
    retryable_statuses: frozenset[int]
    compensation: CompensationContract | None
    is_compensation: bool


@dataclass(frozen=True)
class _CompletedDelivery:
    request: CallRequest
    response: GateResponse


class _CompositionExecutionCore:
    """Shared execution core for admitted runtime and isolated authoring probes.

    The public :class:`CompositionSession` is the only runtime constructor. The
    authoring runner creates this private core from exact provider admissions and
    release-profile digests; no candidate authority enters the runtime surface.
    """

    def __init__(
        self,
        *,
        pack: LoadedCompositionPack,
        execution_authority: _CompositionExecutionAuthority,
        providers: Mapping[str, CompositionProviderSession],
        event_engine: SessionEventEngine,
    ) -> None:
        if not isinstance(pack, LoadedCompositionPack):
            _fail("composition_session_pack_invalid", "A loaded Composition Pack is required.")
        if not isinstance(execution_authority, _CompositionExecutionAuthority):
            raise TypeError("execution_authority must be a private composition capability")
        if not isinstance(event_engine, SessionEventEngine):
            _fail(
                "composition_session_event_engine_invalid",
                "A SessionEventEngine is required.",
            )
        self.pack = pack
        self._execution_authority = execution_authority
        self.event_engine = event_engine
        self._lock = threading.RLock()
        self._latched_failure: dict[str, Any] | None = None
        self._finalized = False
        self._providers = self._bind_providers(providers)
        self._operations = self._build_operations()
        self._source_contracts = self._build_source_contracts()
        self._edges_by_source = self._build_edges_by_source()
        self._deliveries = self._build_delivery_definitions()
        self._source_events: dict[str, dict[str, Any]] = {}
        self._next_source_sequence = 0
        self.event_engine.apply_pending_effects()
        self._restore_event_contexts()

    @property
    def composition_delivery_time(self) -> str:
        with self._lock:
            return self.event_engine.logical_time

    def handle_agent_request(self, request: CallRequest) -> GateResponse:
        """Handle one unchanged provider request and queue only explicit source effects."""

        return self._handle_request(request)

    def _handle_authoring_request_as_principal(
        self,
        request: CallRequest,
        *,
        provider_id: str,
        operation_id: str,
        principal_context_id: str,
    ) -> GateResponse:
        """Execute one candidate probe through a provider-owned local principal."""

        return self._handle_request(
            request,
            expected_provider_id=provider_id,
            expected_operation_id=operation_id,
            trusted_principal_context_id=principal_context_id,
        )

    def _handle_request(
        self,
        request: CallRequest,
        *,
        expected_provider_id: str | None = None,
        expected_operation_id: str | None = None,
        trusted_principal_context_id: str | None = None,
    ) -> GateResponse:
        """Run the common exact routing, provider execution, and source scheduling path."""

        with self._lock:
            if self._finalized:
                return _session_denial(
                    "composition_session_finalized",
                    "The provider session has already been finalized.",
                )
            if self._latched_failure is not None:
                return _session_denial(
                    "composition_session_invalid",
                    "The composed provider session is invalid until a trusted reset succeeds.",
                )
            try:
                self._drain_due_locked()
            except Exception as exc:
                self._latch("composition_delivery_drain_failed", exc)
                return _session_denial(
                    "composition_session_invalid",
                    "The composed provider session is invalid until a trusted reset succeeds.",
                )
            operation = self._match_operation(request)
            if operation is None:
                return _session_denial(
                    "composition_operation_not_admitted",
                    "This native provider operation is outside the composed admitted surface.",
                )
            if expected_provider_id is not None and operation.provider_id != expected_provider_id:
                _fail(
                    "composition_authoring_provider_mismatch",
                    "The candidate probe provider does not own the exact native request surface.",
                    expected_provider_id=expected_provider_id,
                    actual_provider_id=operation.provider_id,
                )
            if (
                expected_operation_id is not None
                and operation.operation_id != expected_operation_id
            ):
                _fail(
                    "composition_authoring_operation_mismatch",
                    "The candidate probe operation does not match the exact native request surface.",
                    expected_operation_id=expected_operation_id,
                    actual_operation_id=operation.operation_id,
                )
            runtime = self._providers[operation.provider_id].runtime
            bound_request = replace(request, operation_id=None)
            try:
                response = (
                    runtime.handle(bound_request)
                    if trusted_principal_context_id is None
                    else runtime.handle_as_principal(
                        bound_request,
                        principal_context_id=trusted_principal_context_id,
                    )
                )
            except Exception as exc:
                self._latch("composition_provider_execution_failed", exc)
                return _session_denial(
                    "composition_session_invalid",
                    "The composed provider session is invalid until a trusted reset succeeds.",
                )
            try:
                self._record_matching_source(
                    provider_id=operation.provider_id,
                    operation_id=operation.operation_id,
                    request=bound_request,
                    response=response,
                )
            except Exception as exc:
                self._latch("composition_source_scheduling_failed", exc)
            return response

    def advance_delivery_time_to(self, value: datetime | str) -> str:
        """Advance only the composition delivery scheduler clock."""

        with self._lock:
            self._require_controller_ready()
            return self.event_engine.advance_to(value)

    def drain_due(self) -> tuple[DeliveryRunResult, ...]:
        """Execute every currently due delivery in deterministic queue order."""

        with self._lock:
            self._require_controller_ready()
            try:
                return self._drain_due_locked()
            except Exception as exc:
                self._latch("composition_delivery_drain_failed", exc)
                raise

    def resolve_unknown(self, delivery_id: str, outcome: DeliveryOutcome) -> DeliveryRunResult:
        """Apply one trusted completion resolution and its declared failure policy."""

        with self._lock:
            self._require_controller_ready()
            try:
                result = self.event_engine.resolve_unknown(
                    delivery_id,
                    outcome,
                    effect_factory=lambda command, normalized, state: self._post_outcome_effects(
                        command=command,
                        outcome=normalized,
                        delivery_state=state,
                        completed=None,
                        staged_sources={},
                    ),
                )
                self.event_engine.apply_pending_effects()
            except Exception as exc:
                self._latch("composition_post_delivery_policy_failed", exc)
                raise
            return result

    def reset(self) -> dict[str, Any]:
        """Reset all modules and event state; expose partial failure only as a latch."""

        with self._lock:
            if self._finalized:
                _fail(
                    "composition_session_finalized",
                    "A finalized provider session cannot be reset.",
                )
            failures: list[dict[str, str]] = []
            for provider_id in sorted(self._providers):
                try:
                    self._providers[provider_id].runtime.reset()
                except Exception as exc:
                    failures.append(_stable_failure(provider_id, exc))
            try:
                self.event_engine.reset()
            except Exception as exc:
                failures.append(_stable_failure("event_engine", exc))
            if failures:
                self._latched_failure = {
                    "code": "composition_session_reset_failed",
                    "components": failures,
                }
                _fail(
                    "composition_session_reset_failed",
                    "The composed provider session remains unavailable because reset failed.",
                    components=failures,
                )
            self._latched_failure = None
            self._source_events.clear()
            self._next_source_sequence = 0
            return self.export()

    def export(self) -> dict[str, Any]:
        """Export provider state, event receipts, and exact admission bindings."""

        with self._lock:
            providers = {
                provider_id: binding.runtime.export()
                for provider_id, binding in sorted(self._providers.items())
            }
            events = self.event_engine.export()
            result = {
                "schema_version": COMPOSITION_SESSION_EXPORT_SCHEMA_VERSION,
                "pack": {
                    "pack_id": self.pack.pack_id,
                    "pack_version": self.pack.pack_version,
                    "composition_pack_sha256": self.pack.canonical_sha256,
                    "composition_admission_sha256": self._execution_authority.canonical_sha256,
                    "distribution_label": self._execution_authority.distribution_label,
                    "time_scope": self._execution_authority.time_scope,
                },
                "provider_profiles": [
                    {
                        **_profile_capability_payload(item),
                        "release_config_sha256": self._providers[
                            item.provider_id
                        ].release.release_config_sha256,
                    }
                    for item in sorted(
                        self._execution_authority.provider_profiles,
                        key=lambda item: item.provider_id,
                    )
                ],
                "composition_delivery_time": self.event_engine.logical_time,
                "providers": providers,
                "events": events,
                "status": "invalid" if self._latched_failure is not None else "valid",
                "failure": deepcopy(self._latched_failure),
                "finalized": self._finalized,
            }
            result["content_sha256"] = canonical_json_sha256(result)
            return result

    def finalize(self) -> dict[str, Any]:
        """Drain due work, export evidence, and close all session-owned resources."""

        with self._lock:
            if self._finalized:
                _fail(
                    "composition_session_finalized",
                    "The composed provider session was already finalized.",
                )
            if self._latched_failure is None:
                try:
                    self._drain_due_locked()
                except Exception as exc:
                    self._latch("composition_delivery_drain_failed", exc)
            self._finalized = True
            exported = self.export()
            for provider_id in sorted(self._providers):
                self._providers[provider_id].runtime.close()
            self.event_engine.close()
            return exported

    def _bind_providers(
        self, providers: Mapping[str, CompositionProviderSession]
    ) -> dict[str, CompositionProviderSession]:
        if not isinstance(providers, Mapping):
            _fail(
                "composition_session_provider_bindings_invalid",
                "Provider sessions must be supplied as a provider-id mapping.",
            )
        pack_provider_ids = {item.provider_id for item in self.pack.providers}
        if set(providers) != pack_provider_ids:
            _fail(
                "composition_session_provider_bindings_invalid",
                "Provider sessions must exactly match the Composition Pack.",
                expected=sorted(pack_provider_ids),
                actual=sorted(providers),
            )
        admission_profiles = {
            item.provider_id: item for item in self._execution_authority.provider_profiles
        }
        if set(admission_profiles) != pack_provider_ids or len(admission_profiles) != len(
            self._execution_authority.provider_profiles
        ):
            _fail(
                "composition_session_admission_binding_invalid",
                "Composition Admission provider profiles do not exactly match the pack.",
            )
        if (
            self._execution_authority.pack_id != self.pack.pack_id
            or self._execution_authority.pack_version != self.pack.pack_version
            or self._execution_authority.composition_pack_sha256 != self.pack.canonical_sha256
            or self._execution_authority.time_scope != self.pack.time_scope
        ):
            _fail(
                "composition_session_admission_binding_invalid",
                "Composition Admission does not admit this exact Composition Pack.",
            )

        pack_bindings = {item.provider_id: item for item in self.pack.providers}
        result: dict[str, CompositionProviderSession] = {}
        authority_owners: dict[str, str] = {}
        for provider_id in sorted(pack_provider_ids):
            binding = providers[provider_id]
            if not isinstance(binding, CompositionProviderSession):
                _fail(
                    "composition_session_provider_binding_invalid",
                    "Every provider requires an exact CompositionProviderSession binding.",
                    provider_id=provider_id,
                )
            release = binding.release
            if not isinstance(release, CompositionRuntimeRelease):
                _fail(
                    "composition_session_release_capability_invalid",
                    "Every provider requires an immutable runtime release capability.",
                    provider_id=provider_id,
                )
            if not isinstance(binding.runtime, ProviderRuntime):
                _fail(
                    "composition_session_provider_runtime_invalid",
                    "Every provider session requires an admitted ProviderRuntime.",
                    provider_id=provider_id,
                )
            config = release.release_config
            config_profiles = [
                item
                for item in config.get("profiles", ())
                if item.get("profile_id") == release.profile_id
            ]
            if (
                len(config_profiles) != 1
                or config.get("provider_id") != release.provider_id
                or config.get("authorities") != tuple(binding.runtime.authorities)
                or config.get("operation_contract_sha256") != release.operation_contract_sha256
                or canonical_json_sha256(_thaw_json(config.get("operations", ())))
                != release.operation_contract_sha256
                or canonical_json_sha256(_thaw_json(config)) != release.release_config_sha256
            ):
                _fail(
                    "composition_session_release_capability_invalid",
                    "Runtime release metadata does not match its exact release config.",
                    provider_id=provider_id,
                )
            config_profile = config_profiles[0]
            pack_binding = pack_bindings[provider_id]
            admitted = admission_profiles[provider_id]
            runtime_digest = _sha256_file(binding.runtime.bundle.root / "provider-runtime.json")
            assurance = binding.runtime.export().get("provider_assurance")
            if not isinstance(assurance, dict) or assurance.get("status") != "valid":
                _fail(
                    "composition_session_provider_not_admitted",
                    "Every provider runtime must have valid provider admission assurance.",
                    provider_id=provider_id,
                )
            actual = {
                "provider_id": release.provider_id,
                "profile_id": release.profile_id,
                "release_manifest_sha256": release.release_manifest_sha256,
                "provider_runtime_sha256": runtime_digest,
                "provider_admission_sha256": assurance.get("provider_admission_sha256"),
                "operation_contract_sha256": release.operation_contract_sha256,
            }
            expected = _profile_capability_payload(admitted)
            if (
                provider_id != release.provider_id
                or actual != expected
                or release.provider_runtime_sha256 != runtime_digest
                or release.provider_admission_sha256 != actual["provider_admission_sha256"]
                or config_profile.get("provider_runtime_sha256") != runtime_digest
                or config_profile.get("provider_admission_sha256")
                != actual["provider_admission_sha256"]
                or pack_binding.release_manifest_sha256 != actual["release_manifest_sha256"]
                or pack_binding.operation_contract_sha256 != actual["operation_contract_sha256"]
            ):
                _fail(
                    "composition_session_provider_binding_mismatch",
                    "A provider runtime does not match its admitted release profile.",
                    provider_id=provider_id,
                )
            for authority in config["authorities"]:
                owner = authority_owners.setdefault(authority, provider_id)
                if owner != provider_id:
                    _fail(
                        "composition_session_authority_ambiguous",
                        "One provider authority cannot belong to multiple composed modules.",
                        authority=authority,
                    )
            result[provider_id] = binding
        return result

    def _build_operations(self) -> tuple[_Operation, ...]:
        operations: list[_Operation] = []
        for provider_id, binding in sorted(self._providers.items()):
            for raw in binding.release.release_config["operations"]:
                surface = raw["native_surface"]
                operations.append(
                    _Operation(
                        provider_id=provider_id,
                        operation_id=raw["operation_id"],
                        scheme=surface["scheme"],
                        authority=surface["authority"],
                        method=surface["method"],
                        path_template=surface["path_template"],
                        path_segments=_template_segments(surface["path_template"]),
                        mutability=raw["mutability"],
                    )
                )
        for index, left in enumerate(operations):
            for right in operations[index + 1 :]:
                if (
                    left.scheme == right.scheme
                    and left.authority == right.authority
                    and left.method == right.method
                    and _templates_overlap(left.path_segments, right.path_segments)
                ):
                    _fail(
                        "composition_session_operation_surface_ambiguous",
                        "Composed admitted operation surfaces overlap.",
                        operation_ids=sorted((left.operation_id, right.operation_id)),
                    )
        return tuple(operations)

    def _build_source_contracts(
        self,
    ) -> dict[tuple[str, str], tuple[SourceEventContract, ...]]:
        result: dict[tuple[str, str], list[SourceEventContract]] = {}
        for contract in self.pack.source_event_contracts:
            result.setdefault((contract.provider_id, contract.source_operation_id), []).append(
                contract
            )
        return {key: tuple(value) for key, value in result.items()}

    def _build_edges_by_source(self) -> dict[str, tuple[DeliveryEdge, ...]]:
        result: dict[str, list[DeliveryEdge]] = {}
        for edge in self.pack.delivery_edges:
            result.setdefault(edge.source_contract_id, []).append(edge)
        return {key: tuple(value) for key, value in result.items()}

    def _build_delivery_definitions(self) -> dict[str, _DeliveryDefinition]:
        result: dict[str, _DeliveryDefinition] = {}
        for edge in self.pack.delivery_edges:
            result[edge.edge_id] = _DeliveryDefinition(
                edge_id=edge.edge_id,
                target_provider_id=edge.target_provider_id,
                target_operation_id=edge.target_operation_id,
                principal_context_id=edge.principal_context_id,
                delivered_statuses=frozenset(edge.delivered_statuses),
                retryable_statuses=frozenset(edge.retryable_statuses),
                compensation=edge.compensation,
                is_compensation=False,
            )
            if edge.compensation is not None:
                compensation = edge.compensation
                result[compensation.compensation_id] = _DeliveryDefinition(
                    edge_id=compensation.compensation_id,
                    target_provider_id=compensation.target_provider_id,
                    target_operation_id=compensation.target_operation_id,
                    principal_context_id=compensation.principal_context_id,
                    delivered_statuses=frozenset(compensation.delivered_statuses),
                    retryable_statuses=frozenset(),
                    compensation=None,
                    is_compensation=True,
                )
        return result

    def _match_operation(self, request: CallRequest) -> _Operation | None:
        matches = [
            operation
            for operation in self._operations
            if request.scheme == operation.scheme
            and request.authority == operation.authority
            and request.normalized_method() == operation.method
            and _path_matches(request.path, operation.path_segments)
        ]
        if len(matches) > 1:
            raise RuntimeError("ambiguous admitted composition surface escaped validation")
        return matches[0] if matches else None

    def _record_matching_source(
        self,
        *,
        provider_id: str,
        operation_id: str,
        request: CallRequest,
        response: GateResponse,
    ) -> None:
        prepared = self._prepare_matching_source_fanout(
            provider_id=provider_id,
            operation_id=operation_id,
            request=request,
            response=response,
            staged_sources={},
        )
        if prepared is None:
            return
        effect, event_id, source_context = prepared
        is_new = event_id not in self._source_events
        recorded_event_id, delivery_ids = self.event_engine.record_source_event_with_deliveries(
            source_provider_id=effect.source_provider_id,
            provider_event_id=effect.provider_event_id,
            event_type=effect.event_type,
            payload=effect.payload,
            deliveries=effect.deliveries,
            correlation_ids=effect.correlation_ids,
            idempotency_key=effect.idempotency_key,
        )
        if recorded_event_id != event_id or len(delivery_ids) != len(effect.deliveries):
            raise RuntimeError("atomic source fan-out returned inconsistent identities")
        if is_new:
            self._source_events[event_id] = source_context
            self._next_source_sequence += 1

    def _prepare_edge(
        self, edge: DeliveryEdge, *, source_context: Mapping[str, Any]
    ) -> DeliveryRequest:
        contexts = {"source_event": source_context}
        request = evaluate_request_template(
            edge.request,
            contexts=contexts,
            field_name=f"{edge.edge_id}.request",
        )
        request["path"] = self._render_path(
            edge.target_provider_id,
            edge.target_operation_id,
            request.pop("path_params"),
        )
        idempotency_key = evaluate_string_template(
            edge.idempotency_key,
            contexts=contexts,
            field_name=f"{edge.edge_id}.idempotency_key",
        )
        ordering_key = evaluate_string_template(
            edge.ordering_key,
            contexts=contexts,
            field_name=f"{edge.edge_id}.ordering_key",
        )
        correlations = evaluate_string_template_map(
            edge.correlations,
            contexts=contexts,
            field_name=f"{edge.edge_id}.correlations",
        )
        return DeliveryRequest(
            edge_id=edge.edge_id,
            ordering_key=ordering_key,
            target_provider_id=edge.target_provider_id,
            target_operation_id=edge.target_operation_id,
            target_principal_context_id=edge.principal_context_id,
            request=request,
            available_at=_add_seconds(self.event_engine.logical_time, edge.logical_delay_seconds),
            retry_delays_seconds=edge.retry_delays_seconds,
            correlation_ids=correlations,
            idempotency_key=idempotency_key,
        )

    def _prepare_compensation(
        self,
        compensation: CompensationContract,
        *,
        source_context: Mapping[str, Any],
        delivery_outcome: Mapping[str, Any],
    ) -> DeliveryRequest:
        contexts = {
            "source_event": source_context,
            "delivery_outcome": delivery_outcome,
        }
        request = evaluate_request_template(
            compensation.request,
            contexts=contexts,
            field_name=f"{compensation.compensation_id}.request",
        )
        request["path"] = self._render_path(
            compensation.target_provider_id,
            compensation.target_operation_id,
            request.pop("path_params"),
        )
        idempotency_key = evaluate_string_template(
            compensation.idempotency_key,
            contexts=contexts,
            field_name=f"{compensation.compensation_id}.idempotency_key",
        )
        ordering_key = evaluate_string_template(
            compensation.ordering_key,
            contexts=contexts,
            field_name=f"{compensation.compensation_id}.ordering_key",
        )
        correlations = evaluate_string_template_map(
            compensation.correlations,
            contexts=contexts,
            field_name=f"{compensation.compensation_id}.correlations",
        )
        return DeliveryRequest(
            edge_id=compensation.compensation_id,
            ordering_key=ordering_key,
            target_provider_id=compensation.target_provider_id,
            target_operation_id=compensation.target_operation_id,
            target_principal_context_id=compensation.principal_context_id,
            request=request,
            available_at=_add_seconds(
                self.event_engine.logical_time, compensation.logical_delay_seconds
            ),
            retry_delays_seconds=(),
            correlation_ids=correlations,
            idempotency_key=idempotency_key,
        )

    def _render_path(
        self, provider_id: str, operation_id: str, path_params: Mapping[str, str]
    ) -> str:
        operation = next(
            (
                item
                for item in self._operations
                if item.provider_id == provider_id and item.operation_id == operation_id
            ),
            None,
        )
        if operation is None:
            raise RuntimeError("admitted pack operation escaped provider binding validation")
        parts: list[str] = []
        for segment in operation.path_segments:
            parameter = _PATH_PARAMETER.fullmatch(segment)
            if parameter is None:
                parts.append(segment)
                continue
            value = path_params[parameter.group(1)]
            if not value or value in {".", ".."}:
                _fail(
                    "composition_session_path_parameter_invalid",
                    "A rendered path parameter is not a safe provider path segment.",
                    operation_id=operation_id,
                )
            parts.append(quote(value, safe="-._~"))
        return "/" + "/".join(parts) if parts else "/"

    def _drain_due_locked(self) -> tuple[DeliveryRunResult, ...]:
        results: list[DeliveryRunResult] = []
        for _ in range(MAX_SESSION_DELIVERIES):
            completed: dict[str, _CompletedDelivery] = {}
            staged_sources: dict[str, dict[str, Any]] = {}

            def execute(command: DeliveryCommand) -> DeliveryOutcome:
                outcome, completion = self._execute_delivery(command)
                completed[command.delivery_id] = completion
                return outcome

            def effects(
                command: DeliveryCommand,
                outcome: DeliveryOutcome,
                delivery_state: DeliveryState,
            ) -> Sequence[PostOutcomeEffect]:
                return self._post_outcome_effects(
                    command=command,
                    outcome=outcome,
                    delivery_state=delivery_state,
                    completed=completed.get(command.delivery_id),
                    staged_sources=staged_sources,
                )

            result = self.event_engine.run_due(execute, effect_factory=effects)
            if result is None:
                return tuple(results)
            self.event_engine.apply_pending_effects()
            for event_id, context in staged_sources.items():
                if event_id not in self._source_events:
                    self._source_events[event_id] = context
                    self._next_source_sequence += 1
            results.append(result)
        export = self.event_engine.export()
        now = export["logical_time"]
        if any(
            delivery["state"] in {"queued", "retry_scheduled"} and delivery["available_at"] <= now
            for delivery in export["deliveries"]
        ):
            self._latched_failure = {"code": "composition_session_drain_limit_reached"}
            _fail(
                "composition_session_drain_limit_reached",
                "The bounded delivery drain did not reach a stable due queue.",
            )
        return tuple(results)

    def _execute_delivery(
        self, command: DeliveryCommand
    ) -> tuple[DeliveryOutcome, _CompletedDelivery]:
        definition = self._deliveries.get(command.edge_id)
        if definition is None:
            raise RuntimeError("unknown admitted delivery edge")
        if (
            command.target_provider_id != definition.target_provider_id
            or command.target_operation_id != definition.target_operation_id
            or command.target_principal_context_id != definition.principal_context_id
        ):
            raise RuntimeError("persisted delivery does not match its admitted edge")
        operation = next(
            (
                item
                for item in self._operations
                if item.provider_id == definition.target_provider_id
                and item.operation_id == definition.target_operation_id
            ),
            None,
        )
        if operation is None or operation.mutability != "write":
            raise RuntimeError("delivery target is not an admitted write operation")
        request = CallRequest(
            scheme=operation.scheme,
            authority=operation.authority,
            method=operation.method,
            path=command.request["path"],
            query=command.request["query"],
            headers=command.request["headers"],
            body=deepcopy(command.request["body"]),
            operation_id=None,
        )
        runtime = self._providers[definition.target_provider_id].runtime
        response = runtime.handle_as_principal(
            request,
            principal_context_id=definition.principal_context_id,
        )
        receipt = _response_receipt(response)
        if response.status_code in definition.delivered_statuses:
            kind = "delivered"
            error_code = None
            error_message = None
        elif response.status_code in definition.retryable_statuses:
            kind = "retryable_failure"
            error_code = "composition_delivery_retryable"
            error_message = "The declared target response is retryable."
        else:
            kind = "terminal_failure"
            error_code = "composition_delivery_terminal"
            error_message = "The declared target response is terminal."
        return (
            DeliveryOutcome(
                kind=kind,
                receipt=receipt,
                status_code=response.status_code,
                error_code=error_code,
                error_message=error_message,
            ),
            _CompletedDelivery(request=request, response=response),
        )

    def _post_outcome_effects(
        self,
        *,
        command: DeliveryCommand,
        outcome: DeliveryOutcome,
        delivery_state: DeliveryState,
        completed: _CompletedDelivery | None,
        staged_sources: dict[str, dict[str, Any]],
    ) -> tuple[PostOutcomeEffect, ...]:
        """Prepare causal follow-ups before the parent outcome is committed.

        The event engine persists the returned effects in the same transaction as
        the delivery outcome. Applying the effects later is idempotent, so a process
        loss cannot leave a committed provider write without its declared fan-out or
        compensation.
        """

        definition = self._deliveries.get(command.edge_id)
        if definition is None:
            raise RuntimeError("persisted delivery has no admitted definition")
        if (
            command.target_provider_id != definition.target_provider_id
            or command.target_operation_id != definition.target_operation_id
            or command.target_principal_context_id != definition.principal_context_id
        ):
            raise RuntimeError("persisted delivery does not match its admitted edge")

        effects: list[PostOutcomeEffect] = []
        if outcome.kind == "delivered" and completed is not None:
            prepared = self._prepare_matching_source_fanout(
                provider_id=definition.target_provider_id,
                operation_id=definition.target_operation_id,
                request=completed.request,
                response=completed.response,
                staged_sources=staged_sources,
            )
            if prepared is not None:
                effect, event_id, source_context = prepared
                effects.append(effect)
                if event_id not in self._source_events:
                    staged_sources[event_id] = source_context

        compensation = definition.compensation
        if compensation is None or delivery_state != "terminal_failure":
            return tuple(effects)
        trigger: str | None = None
        if outcome.kind == "terminal_failure":
            trigger = "terminal_failure"
        elif outcome.kind == "retryable_failure":
            trigger = "retry_exhausted"
        if trigger is None or trigger not in compensation.triggers:
            return tuple(effects)
        source_context = self._source_events.get(command.source_event_id)
        if source_context is None:
            raise RuntimeError("persisted delivery references an unavailable source event")
        delivery_outcome = {
            "delivery_id": command.delivery_id,
            "edge_id": definition.edge_id,
            "source_event_id": command.source_event_id,
            "target_provider_id": definition.target_provider_id,
            "target_operation_id": definition.target_operation_id,
            "attempt_number": command.attempt_number,
            "kind": outcome.kind,
            "status_code": outcome.status_code,
            "receipt": deepcopy(outcome.receipt),
            "error_code": outcome.error_code,
            "error_message": outcome.error_message,
        }
        effects.append(
            ExistingSourceDeliveryRequest(
                source_event_id=command.source_event_id,
                delivery=self._prepare_compensation(
                    compensation,
                    source_context=source_context,
                    delivery_outcome=delivery_outcome,
                ),
            )
        )
        return tuple(effects)

    def _prepare_matching_source_fanout(
        self,
        *,
        provider_id: str,
        operation_id: str,
        request: CallRequest,
        response: GateResponse,
        staged_sources: Mapping[str, Mapping[str, Any]],
    ) -> tuple[SourceFanoutRequest, str, dict[str, Any]] | None:
        safe_request = redact_external_request(
            request,
            self._providers[provider_id].runtime.bundle.identity_policy,
        )
        provider_export = self._providers[provider_id].runtime.export()
        provider_state = provider_export.get("provider_state")
        if not isinstance(provider_state, Mapping):
            _fail(
                "composition_source_provider_state_invalid",
                "The source provider did not export finite provider state.",
                provider_id=provider_id,
            )
        contexts = {
            "request": _request_context(safe_request),
            "response": _response_context(response),
            "provider_state": deepcopy(provider_state),
        }
        candidates = self._source_contracts.get((provider_id, operation_id), ())
        matches = [
            contract
            for contract in candidates
            if any(
                accepted.status_code == response.status_code
                and accepted.decision_kind == response.decision.kind
                for accepted in contract.accepted_outcomes
            )
            and evaluate_source_match(contract.match, contexts=contexts)
        ]
        if len(matches) > 1:
            _fail(
                "composition_source_match_ambiguous",
                "Multiple admitted source contracts matched one provider operation outcome.",
                provider_id=provider_id,
                operation_id=operation_id,
                source_contract_ids=sorted(item.source_contract_id for item in matches),
            )
        if not matches:
            return None
        contract = matches[0]
        provider_event_id = evaluate_string_template(
            contract.provider_event_id,
            contexts=contexts,
            field_name=f"{contract.source_contract_id}.provider_event_id",
        )
        payload = evaluate_template(
            contract.payload,
            contexts=contexts,
            expected_type="object",
            field_name=f"{contract.source_contract_id}.payload",
        )
        correlations = evaluate_string_template_map(
            contract.correlations,
            contexts=contexts,
            field_name=f"{contract.source_contract_id}.correlations",
        )
        event_id = self.event_engine.source_event_identity(
            source_provider_id=provider_id,
            provider_event_id=provider_event_id,
        )
        existing = self._source_events.get(event_id) or staged_sources.get(event_id)
        if existing is None:
            source_context = {
                "source_event_id": event_id,
                "source_provider_id": provider_id,
                "provider_event_id": provider_event_id,
                "event_type": contract.event_type,
                "payload": deepcopy(payload),
                "correlation_ids": deepcopy(correlations),
                "idempotency_key": provider_event_id,
                "sequence": self._next_source_sequence + len(staged_sources),
                "recorded_at": self.event_engine.logical_time,
            }
        else:
            source_context = deepcopy(dict(existing))
        edges = self._edges_by_source.get(contract.source_contract_id, ())
        deliveries = tuple(
            self._prepare_edge(edge, source_context=source_context) for edge in edges
        )
        if not deliveries:
            raise RuntimeError("an admitted source contract has no declared delivery edge")
        return (
            SourceFanoutRequest(
                source_provider_id=provider_id,
                provider_event_id=provider_event_id,
                event_type=contract.event_type,
                payload=payload,
                deliveries=deliveries,
                correlation_ids=correlations,
                idempotency_key=provider_event_id,
            ),
            event_id,
            source_context,
        )

    def _restore_event_contexts(self) -> None:
        exported = self.event_engine.export()
        for event in exported["source_events"]:
            self._source_events[event["source_event_id"]] = {
                key: deepcopy(event[key])
                for key in (
                    "source_event_id",
                    "source_provider_id",
                    "provider_event_id",
                    "event_type",
                    "payload",
                    "correlation_ids",
                    "idempotency_key",
                    "sequence",
                    "recorded_at",
                )
            }
        self._next_source_sequence = len(self._source_events)

    def _require_controller_ready(self) -> None:
        if self._finalized:
            _fail(
                "composition_session_finalized",
                "The composed provider session was already finalized.",
            )
        if self._latched_failure is not None:
            _fail(
                "composition_session_invalid",
                "The composed provider session is invalid until a trusted reset succeeds.",
            )

    def _latch(self, code: str, exc: Exception) -> None:
        self._latched_failure = {
            "code": code,
            "cause_code": getattr(exc, "code", type(exc).__name__),
        }


class CompositionSession(_CompositionExecutionCore):
    """A deterministic runtime session bound to a derived Composition Admission.

    Agent-facing code may call :meth:`handle_agent_request` only. Reset, time,
    delivery, resolution, export, and finalization belong to a trusted controller.
    Candidate packs have no constructor path through this public runtime class.
    """

    def __init__(
        self,
        *,
        pack: LoadedCompositionPack,
        admission: CompositionAdmissionCapability,
        providers: Mapping[str, CompositionProviderSession],
        event_engine: SessionEventEngine,
    ) -> None:
        if (
            not isinstance(admission, CompositionAdmissionCapability)
            or admission.payload.get("admitted") is not True
        ):
            _fail(
                "composition_session_admission_invalid",
                "A trusted successful Composition Admission capability is required.",
            )
        self.admission = admission
        super().__init__(
            pack=pack,
            execution_authority=_CompositionExecutionAuthority(
                authority_kind="derived_admission",
                canonical_sha256=admission.canonical_sha256,
                pack_id=admission.pack_id,
                pack_version=admission.pack_version,
                composition_pack_sha256=admission.composition_pack_sha256,
                distribution_label=admission.distribution_label,
                time_scope=admission.time_scope,
                provider_profiles=admission.provider_profiles,
            ),
            providers=providers,
            event_engine=event_engine,
        )


def _profile_capability_payload(item: AdmissionProviderProfileCapability) -> dict[str, str]:
    return {
        "provider_id": item.provider_id,
        "profile_id": item.profile_id,
        "release_manifest_sha256": item.release_manifest_sha256,
        "provider_runtime_sha256": item.provider_runtime_sha256,
        "provider_admission_sha256": item.provider_admission_sha256,
        "operation_contract_sha256": item.operation_contract_sha256,
    }


def _request_context(request: CallRequest) -> dict[str, Any]:
    return {
        "scheme": request.scheme,
        "authority": request.authority,
        "method": request.normalized_method(),
        "path": request.path,
        "query": deepcopy(request.query),
        "headers": _redact_headers(request.headers),
        "body": deepcopy(request.body),
    }


def _response_context(response: GateResponse) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "decision_kind": response.decision.kind,
        "headers": _redact_headers(response.headers),
        "body": deepcopy(response.body),
    }


def _response_receipt(response: GateResponse) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "decision_kind": response.decision.kind,
        "reason_code": response.decision.reason_code,
        "response_event_id": response.event_id,
        "response_body_sha256": canonical_json_sha256(response.body),
        "headers": _redact_headers(response.headers),
    }


def _redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in _SECRET_HEADERS and not name.lower().startswith("x-datalox-")
    }


def _template_segments(path_template: str) -> tuple[str, ...]:
    if path_template == "/":
        return ()
    return tuple(path_template[1:].split("/"))


def _templates_overlap(left: Sequence[str], right: Sequence[str]) -> bool:
    if len(left) != len(right):
        return False
    return all(
        _PATH_PARAMETER.fullmatch(left_item) is not None
        or _PATH_PARAMETER.fullmatch(right_item) is not None
        or left_item == right_item
        for left_item, right_item in zip(left, right)
    )


def _path_matches(path: str, template: Sequence[str]) -> bool:
    if path == "/":
        parts: tuple[str, ...] = ()
    elif not path.startswith("/") or path.endswith("/"):
        return False
    else:
        parts = tuple(path[1:].split("/"))
    if len(parts) != len(template):
        return False
    return all(
        part not in {"", ".", ".."}
        and (_PATH_PARAMETER.fullmatch(pattern) is not None or part == pattern)
        for part, pattern in zip(parts, template)
    )


def _add_seconds(value: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    return (
        (parsed.astimezone(UTC) + timedelta(seconds=seconds))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _stable_failure(component: str, exc: Exception) -> dict[str, str]:
    return {
        "component": component,
        "code": str(getattr(exc, "code", type(exc).__name__)),
    }


def _freeze_json(value: Any) -> Any:
    try:
        normalized = json.loads(
            json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError) as exc:
        raise TypeError("release_config must be finite JSON data") from exc

    def freeze(item: Any) -> Any:
        if isinstance(item, dict):
            return MappingProxyType({key: freeze(child) for key, child in item.items()})
        if isinstance(item, list):
            return tuple(freeze(child) for child in item)
        return item

    return freeze(normalized)


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _session_denial(code: str, message: str) -> GateResponse:
    event_id = "evt_" + hashlib.sha256(code.encode("utf-8")).hexdigest()[:32]
    return GateResponse(
        status_code=500 if code != "composition_operation_not_admitted" else 403,
        body={"error": {"code": code, "message": message, "details": {}}},
        decision=GateDecision(kind="deny", reason_code=code, message=message),
        event_id=event_id,
    )


def _fail(code: str, message: str, **details: Any) -> None:
    raise CompositionSessionError(
        code=code,
        message=message,
        details=MappingProxyType(deepcopy(details)),
    )
