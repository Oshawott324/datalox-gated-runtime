"""Derived admission for provider-mediated Composition Packs.

An authored Composition Pack is a claim.  This module admits that claim only
after a trusted runner executes an exact, finite probe program twice across a
functional reset.  The derived admission binds the pack and every selected
Provider Release profile by digest; it contains no executable behavior.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol, TypeAlias

from datalox_gated_runtime.json_digest import canonical_json_bytes
from datalox_gated_runtime.composition.pack import LoadedCompositionPack, load_composition_pack
from datalox_gated_runtime.provider_runtime.release import (
    LoadedProviderRelease,
    load_provider_release,
    load_provider_release_from_descriptor,
)

COMPOSITION_OPERATION_CLAIMS_SCHEMA_VERSION = "datalox_composition_operation_claims_v1"
COMPOSITION_ADMISSION_SCHEMA_VERSION = "datalox_composition_admission_v1"
COMPOSITION_ADMISSION_MAX_JSON_BYTES = 8 * 1024 * 1024
COMPOSITION_ADMISSION_MAX_PROBES = 256
COMPOSITION_ADMISSION_MAX_STEPS = 8_192
COMPOSITION_ADMISSION_MAX_ASSERTIONS = 32_768
COMPOSITION_ADMISSION_MAX_HEADERS = 256
COMPOSITION_ADMISSION_MAX_QUERY_KEYS = 256

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_PATH_PARAMETER = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$")
_DISTRIBUTION_ORDER = {"public": 0, "restricted": 1, "private": 2}
_DECISION_KINDS = {"replay", "shadow_read", "shadow_write", "deny", "miss"}
_FORBIDDEN_PROBE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
    }
)
_ACTIONS = {"agent_http", "controller_advance", "controller_drain"}
_ASSERTION_SOURCES = {"action_result", "exported_evidence"}
_JSON_TYPES = {"object", "array", "string", "number", "integer", "boolean", "null"}
_EDGE_CORE_BEHAVIORS = {
    "delivery_success",
    "read_after_write",
    "duplicate_idempotency",
    "ordering",
    "terminal_failure",
}
_EDGE_RETRY_BEHAVIORS = {"retryable_failure", "retry_exhaustion"}

FrozenJson: TypeAlias = (
    None | bool | int | float | str | tuple["FrozenJson", ...] | Mapping[str, "FrozenJson"]
)


@dataclass(frozen=True)
class CompositionAdmissionError(ValueError):
    """Stable controller-readable Composition Admission failure."""

    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class AdmissionProviderProfile:
    provider_id: str
    profile_id: str
    release_manifest_sha256: str
    provider_runtime_sha256: str
    provider_admission_sha256: str
    operation_contract_sha256: str


@dataclass(frozen=True, order=True)
class CoverageAtom:
    subject_kind: Literal["source_contract", "delivery_edge", "compensation"]
    subject_id: str
    behavior: str


@dataclass(frozen=True)
class LoadedCompositionAdmission:
    path: Path
    canonical_sha256: str
    pack_id: str
    pack_version: str
    composition_pack_sha256: str
    distribution_label: str
    time_scope: Literal["delivery_scheduler_only_v1"]
    provider_profiles: tuple[AdmissionProviderProfile, ...]
    required_coverage: tuple[CoverageAtom, ...]
    payload: Mapping[str, FrozenJson]


@dataclass(frozen=True)
class ValidatedCompositionAuthoringInputs:
    """Strict candidate inputs ready for isolated composition probe execution."""

    pack: LoadedCompositionPack
    claims_path: Path
    claims_sha256: str
    admitted_at: datetime
    provider_profiles: tuple[AdmissionProviderProfile, ...]
    required_coverage: tuple[CoverageAtom, ...]
    probe_count: int
    step_count: int


class CompositionProbeRunner(Protocol):
    """Trusted execution boundary used by the admission builder.

    Implementations may call a local composed session, but provider access is
    outside this interface.  Every returned value must be a finite JSON object.
    """

    def reset(self) -> Mapping[str, Any]: ...

    def agent_http(
        self,
        *,
        provider_id: str,
        operation_id: str,
        principal_context_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...

    def advance_delivery_time(self, *, seconds: int) -> Mapping[str, Any]: ...

    def drain(self) -> Mapping[str, Any]: ...

    def export_evidence(self) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class _BoundInputs:
    profiles: tuple[dict[str, str], ...]
    operations: Mapping[str, Mapping[str, Mapping[str, Any]]]


@dataclass(frozen=True)
class _AdmissionReleaseContract:
    provider_id: str
    release_manifest_sha256: str
    config: Mapping[str, Any]
    allowed_profile_ids: frozenset[str]


@dataclass(frozen=True)
class _ValidatedAdmissionInputs:
    pack: LoadedCompositionPack
    claims_file: Path
    claims: Mapping[str, Any]
    admitted_at: datetime
    bound: _BoundInputs
    required: tuple[CoverageAtom, ...]
    probes: tuple[dict[str, Any], ...]
    reset_probe: dict[str, Any]


def _revalidate_pack(
    pack: LoadedCompositionPack,
    *,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
) -> LoadedCompositionPack:
    """Re-read all pack/evidence bytes so a stale loaded object cannot be admitted."""

    if not isinstance(pack, LoadedCompositionPack):
        _fail(
            "composition_admission_pack_invalid",
            "Admission requires a strictly loaded authored Composition Pack.",
        )
    try:
        current = load_composition_pack(pack.root, provider_releases=provider_releases)
    except Exception as exc:
        if isinstance(exc, CompositionAdmissionError):
            raise
        raise CompositionAdmissionError(
            "composition_admission_pack_revalidation_failed",
            "The authored Composition Pack no longer passes strict loading.",
            MappingProxyType({"exception_type": type(exc).__name__}),
        ) from exc
    if current.canonical_sha256 != pack.canonical_sha256:
        _fail(
            "composition_admission_pack_changed",
            "Composition Pack bytes changed after the supplied pack was loaded.",
            supplied_sha256=pack.canonical_sha256,
            current_sha256=current.canonical_sha256,
        )
    return current


def admit_composition_pack(
    *,
    pack: LoadedCompositionPack,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
    claims_path: Path,
    runner: CompositionProbeRunner,
    output_path: Path,
    admitted_at: datetime | None = None,
) -> LoadedCompositionAdmission:
    """Execute exact probes twice and write one immutable derived admission."""

    if output_path.exists() or output_path.is_symlink():
        _fail(
            "composition_admission_output_exists",
            "Composition admission output already exists.",
            path=str(output_path),
        )
    validated = _validate_authoring_inputs(
        pack=pack,
        provider_releases=provider_releases,
        claims_path=claims_path,
        admitted_at=admitted_at,
    )
    _validate_runner(runner)

    first = _execute_suite(
        runner,
        reset_probe=validated.reset_probe,
        probes=validated.probes,
    )
    second = _execute_suite(
        runner,
        reset_probe=validated.reset_probe,
        probes=validated.probes,
    )
    if first["behavior_sha256"] != second["behavior_sha256"]:
        _fail(
            "composition_admission_reset_not_equivalent",
            "Reset did not restore equivalent observable composition behavior.",
            first_run_sha256=first["behavior_sha256"],
            second_run_sha256=second["behavior_sha256"],
        )

    pack = validated.pack
    distribution = _derived_distribution(pack)
    payload: dict[str, Any] = {
        "schema_version": COMPOSITION_ADMISSION_SCHEMA_VERSION,
        "admitted": True,
        "task_free": True,
        "pack_id": pack.pack_id,
        "pack_version": pack.pack_version,
        "composition_pack_sha256": pack.canonical_sha256,
        "composition_operation_claims_sha256": _sha256_file(validated.claims_file),
        "admitted_at": _format_utc(validated.admitted_at),
        "distribution_label": distribution,
        "time_scope": pack.time_scope,
        "provider_profiles": [deepcopy(item) for item in validated.bound.profiles],
        "evidence_sources": _admitted_evidence(pack),
        "grounded_claims": _admitted_grounded_claims(pack),
        "required_coverage": [_coverage_payload(item) for item in validated.required],
        "functional_reset": {
            "passed": True,
            "first_run_sha256": first["behavior_sha256"],
            "second_run_sha256": second["behavior_sha256"],
            "reset_result_sha256": first["reset_result_sha256"],
            "baseline_evidence_sha256": first["baseline_evidence_sha256"],
        },
        "behavior_probes": _probe_results(validated.probes, first, second),
    }
    _write_json_exclusive(output_path, payload)
    return load_composition_admission(
        output_path,
        pack=pack,
        provider_releases=provider_releases,
    )


def validate_composition_authoring_inputs(
    *,
    pack: LoadedCompositionPack,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
    claims_path: Path,
    admitted_at: datetime | None = None,
) -> ValidatedCompositionAuthoringInputs:
    """Validate exact authoring claims without creating a runtime admission."""

    validated = _validate_authoring_inputs(
        pack=pack,
        provider_releases=provider_releases,
        claims_path=claims_path,
        admitted_at=admitted_at,
    )
    return ValidatedCompositionAuthoringInputs(
        pack=validated.pack,
        claims_path=validated.claims_file,
        claims_sha256=_sha256_file(validated.claims_file),
        admitted_at=validated.admitted_at,
        provider_profiles=tuple(_profile_model(item) for item in validated.bound.profiles),
        required_coverage=validated.required,
        probe_count=len(validated.probes),
        step_count=sum(len(probe["steps"]) for probe in validated.probes),
    )


def _validate_authoring_inputs(
    *,
    pack: LoadedCompositionPack,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
    claims_path: Path,
    admitted_at: datetime | None,
) -> _ValidatedAdmissionInputs:
    if not isinstance(pack, LoadedCompositionPack):
        _fail(
            "composition_admission_pack_invalid",
            "Admission requires a strictly loaded authored Composition Pack.",
        )
    current_pack = _revalidate_pack(pack, provider_releases=provider_releases)
    claims_file = _resolve_regular_file(
        claims_path,
        code="composition_admission_claims_unreadable",
    )
    claims = _load_json_object(claims_file, code="composition_admission_claims_invalid")
    now = _admission_time(admitted_at)
    bound = _validate_claims(
        claims,
        pack=current_pack,
        provider_releases=provider_releases,
        admitted_at=now,
    )
    required = _required_coverage(current_pack)
    probes = _validate_probes(
        claims["behavior_probes"],
        required=required,
        bound=bound,
        pack=current_pack,
    )
    reset_probe = _validate_reset_probe(claims["reset_probe"])
    _require_exact_coverage(probes, required=required)
    return _ValidatedAdmissionInputs(
        pack=current_pack,
        claims_file=claims_file,
        claims=claims,
        admitted_at=now,
        bound=bound,
        required=required,
        probes=probes,
        reset_probe=reset_probe,
    )


def load_composition_admission(
    path: Path,
    *,
    pack: LoadedCompositionPack,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
) -> LoadedCompositionAdmission:
    """Load an admission and re-bind it to exact current pack/release inputs."""

    pack = _revalidate_pack(pack, provider_releases=provider_releases)
    contracts = _load_admission_release_contracts(provider_releases)
    return _load_composition_admission_from_contracts(
        path,
        pack=pack,
        provider_contracts=contracts,
    )


def _load_composition_admission_from_contracts(
    path: Path,
    *,
    pack: LoadedCompositionPack,
    provider_contracts: Mapping[str, _AdmissionReleaseContract],
) -> LoadedCompositionAdmission:
    """Internal runtime loader over already strict selected release contracts."""

    admission_path = _resolve_regular_file(path, code="composition_admission_unreadable")
    raw = _load_json_object(admission_path, code="composition_admission_invalid")
    fields = {
        "schema_version",
        "admitted",
        "task_free",
        "pack_id",
        "pack_version",
        "composition_pack_sha256",
        "composition_operation_claims_sha256",
        "admitted_at",
        "distribution_label",
        "time_scope",
        "provider_profiles",
        "evidence_sources",
        "grounded_claims",
        "required_coverage",
        "functional_reset",
        "behavior_probes",
    }
    _exact_object(raw, fields, field="composition admission")
    if raw["schema_version"] != COMPOSITION_ADMISSION_SCHEMA_VERSION:
        _fail("composition_admission_schema_unsupported", "Unsupported admission schema.")
    if raw["admitted"] is not True or raw["task_free"] is not True:
        _fail(
            "composition_admission_not_successful",
            "Composition admission must be successful and task-free.",
        )
    if (
        raw["pack_id"] != pack.pack_id
        or raw["pack_version"] != pack.pack_version
        or raw["composition_pack_sha256"] != pack.canonical_sha256
    ):
        _fail(
            "composition_admission_pack_binding_invalid",
            "Composition admission does not bind the supplied pack exactly.",
        )
    _sha256(raw["composition_operation_claims_sha256"], field="claims digest")
    admitted_at = _utc_timestamp(raw["admitted_at"], field="admitted_at")
    _validate_pack_evidence_freshness(pack, admitted_at=admitted_at)
    if raw["distribution_label"] != _derived_distribution(pack):
        _fail(
            "composition_admission_distribution_invalid",
            "Admission distribution does not match its Composition Pack.",
        )
    if raw["time_scope"] != pack.time_scope:
        _fail(
            "composition_admission_time_scope_invalid",
            "Admission time scope does not match its Composition Pack.",
        )
    bound = _bind_provider_profiles_from_contracts(
        raw["provider_profiles"],
        pack=pack,
        provider_contracts=provider_contracts,
    )
    if raw["evidence_sources"] != _admitted_evidence(pack):
        _fail(
            "composition_admission_evidence_binding_invalid",
            "Admission evidence metadata does not exactly match the bound pack.",
        )
    if raw["grounded_claims"] != _admitted_grounded_claims(pack):
        _fail(
            "composition_admission_grounding_binding_invalid",
            "Admission grounding and rights do not exactly match the bound pack.",
        )
    required = _required_coverage(pack)
    if raw["required_coverage"] != [_coverage_payload(item) for item in required]:
        _fail(
            "composition_admission_coverage_binding_invalid",
            "Admission coverage does not exactly match the bound pack.",
        )
    _validate_derived_reset(raw["functional_reset"])
    _validate_derived_probe_results(raw["behavior_probes"], required=required)
    frozen = _freeze(raw)
    if not isinstance(frozen, Mapping):
        raise AssertionError("composition admission must freeze to an object")
    return LoadedCompositionAdmission(
        path=admission_path,
        canonical_sha256=_sha256_file(admission_path),
        pack_id=pack.pack_id,
        pack_version=pack.pack_version,
        composition_pack_sha256=pack.canonical_sha256,
        distribution_label=raw["distribution_label"],
        time_scope=raw["time_scope"],
        provider_profiles=tuple(_profile_model(item) for item in bound.profiles),
        required_coverage=required,
        payload=frozen,
    )


def _validate_claims(
    raw: Any,
    *,
    pack: LoadedCompositionPack,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
    admitted_at: datetime,
) -> _BoundInputs:
    fields = {
        "schema_version",
        "pack_id",
        "pack_version",
        "composition_pack_sha256",
        "provider_profiles",
        "reset_probe",
        "behavior_probes",
    }
    _exact_object(raw, fields, field="composition operation claims")
    if raw["schema_version"] != COMPOSITION_OPERATION_CLAIMS_SCHEMA_VERSION:
        _fail("composition_admission_claims_schema_unsupported", "Unsupported claims schema.")
    if (
        raw["pack_id"] != pack.pack_id
        or raw["pack_version"] != pack.pack_version
        or raw["composition_pack_sha256"] != pack.canonical_sha256
    ):
        _fail(
            "composition_admission_pack_binding_invalid",
            "Claims do not bind the supplied Composition Pack exactly.",
        )
    _validate_pack_evidence_freshness(pack, admitted_at=admitted_at)
    return _bind_provider_profiles(
        raw["provider_profiles"],
        pack=pack,
        provider_releases=provider_releases,
    )


def _bind_provider_profiles(
    value: Any,
    *,
    pack: LoadedCompositionPack,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
) -> _BoundInputs:
    contracts = _load_admission_release_contracts(provider_releases)
    return _bind_provider_profiles_from_contracts(
        value,
        pack=pack,
        provider_contracts=contracts,
    )


def _bind_provider_profiles_from_contracts(
    value: Any,
    *,
    pack: LoadedCompositionPack,
    provider_contracts: Mapping[str, _AdmissionReleaseContract],
) -> _BoundInputs:
    if not isinstance(value, list) or not value:
        _fail(
            "composition_admission_provider_profiles_invalid",
            "provider_profiles must be a non-empty list.",
        )
    expected_provider_ids = [item.provider_id for item in pack.providers]
    actual_provider_ids = sorted(provider_contracts)
    if actual_provider_ids != expected_provider_ids:
        _fail(
            "composition_admission_provider_release_set_invalid",
            "Exactly the pack's sorted provider releases must be supplied.",
            expected=expected_provider_ids,
            actual=actual_provider_ids,
        )
    fields = {
        "provider_id",
        "profile_id",
        "release_manifest_sha256",
        "provider_runtime_sha256",
        "provider_admission_sha256",
        "operation_contract_sha256",
    }
    normalized: list[dict[str, str]] = []
    ids: list[str] = []
    for index, item in enumerate(value):
        _exact_object(item, fields, field=f"provider_profiles[{index}]")
        provider_id = _identifier(item["provider_id"], field="provider_id")
        profile_id = _identifier(item["profile_id"], field="profile_id")
        for field_name in fields - {"provider_id", "profile_id"}:
            _sha256(item[field_name], field=field_name)
        if provider_id in ids:
            _fail(
                "composition_admission_provider_profile_duplicate",
                "Each provider must select exactly one profile.",
            )
        if provider_id not in provider_contracts:
            _fail(
                "composition_admission_provider_profile_unknown",
                "A selected profile belongs to an undeclared provider.",
                provider_id=provider_id,
            )
        release = provider_contracts[provider_id]
        if profile_id not in release.allowed_profile_ids:
            _fail(
                "composition_admission_provider_profile_unknown",
                "The selected Provider Release profile is unavailable to this runtime.",
                provider_id=provider_id,
                profile_id=profile_id,
            )
        profile = next(
            (
                candidate
                for candidate in release.config["profiles"]
                if candidate["profile_id"] == profile_id
            ),
            None,
        )
        if profile is None:
            _fail(
                "composition_admission_provider_profile_unknown",
                "The selected Provider Release profile does not exist.",
                provider_id=provider_id,
                profile_id=profile_id,
            )
        expected = {
            "provider_id": provider_id,
            "profile_id": profile_id,
            "release_manifest_sha256": release.release_manifest_sha256,
            "provider_runtime_sha256": profile["provider_runtime_sha256"],
            "provider_admission_sha256": profile["provider_admission_sha256"],
            "operation_contract_sha256": release.config["operation_contract_sha256"],
        }
        if item != expected:
            _fail(
                "composition_admission_provider_profile_binding_invalid",
                "A selected provider profile digest binding is not exact.",
                provider_id=provider_id,
                profile_id=profile_id,
            )
        normalized.append(expected)
        ids.append(provider_id)
    if ids != sorted(ids) or ids != expected_provider_ids:
        _fail(
            "composition_admission_provider_profile_set_invalid",
            "Provider profiles must exactly cover the pack in provider-id order.",
            expected=expected_provider_ids,
            actual=ids,
        )
    operations = {
        provider_id: MappingProxyType(
            {item["operation_id"]: deepcopy(item) for item in release.config["operations"]}
        )
        for provider_id, release in provider_contracts.items()
    }
    return _BoundInputs(
        profiles=tuple(normalized),
        operations=MappingProxyType(operations),
    )


def _load_admission_release_contracts(
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
) -> dict[str, _AdmissionReleaseContract]:
    if not isinstance(provider_releases, Mapping):
        _fail(
            "composition_admission_provider_releases_invalid",
            "provider_releases must map provider ids to strict Provider Releases.",
        )
    result: dict[str, _AdmissionReleaseContract] = {}
    for provider_id, supplied in provider_releases.items():
        if not isinstance(provider_id, str):
            _fail(
                "composition_admission_provider_release_invalid",
                "Provider release mapping keys must be provider ids.",
            )
        if isinstance(supplied, Path):
            release = load_provider_release(supplied)
        elif isinstance(supplied, LoadedProviderRelease):
            release = load_provider_release_from_descriptor(
                root=supplied.root,
                manifest_descriptor=supplied.manifest_descriptor,
            )
        else:
            _fail(
                "composition_admission_provider_release_invalid",
                "A provider binding requires a release path or LoadedProviderRelease.",
                provider_id=provider_id,
            )
        if release.provider_id != provider_id:
            _fail(
                "composition_admission_provider_release_invalid",
                "A supplied release provider id does not match its mapping key.",
                provider_id=provider_id,
            )
        result[provider_id] = _AdmissionReleaseContract(
            provider_id=provider_id,
            release_manifest_sha256=release.manifest_descriptor["digest"],
            config=release.config,
            allowed_profile_ids=frozenset(profile.profile_id for profile in release.profiles),
        )
    return result


def _validate_pack_evidence_freshness(
    pack: LoadedCompositionPack, *, admitted_at: datetime
) -> None:
    for source in pack.evidence_sources:
        observed = _utc_timestamp(source.observed_at, field="observed_at")
        valid_through = _utc_timestamp(source.valid_through, field="valid_through")
        if not (observed <= admitted_at <= valid_through):
            _fail(
                "composition_admission_evidence_not_current",
                "Every Composition Pack evidence source must be current at admission.",
                evidence_id=source.evidence_id,
                admitted_at=_format_utc(admitted_at),
                observed_at=source.observed_at,
                valid_through=source.valid_through,
            )


def _required_coverage(pack: LoadedCompositionPack) -> tuple[CoverageAtom, ...]:
    required: list[CoverageAtom] = []
    for source in pack.source_event_contracts:
        required.append(
            CoverageAtom("source_contract", source.source_contract_id, "source_emission")
        )
    for edge in pack.delivery_edges:
        for behavior in sorted(_EDGE_CORE_BEHAVIORS):
            required.append(CoverageAtom("delivery_edge", edge.edge_id, behavior))
        if edge.retryable_statuses:
            for behavior in sorted(_EDGE_RETRY_BEHAVIORS):
                required.append(CoverageAtom("delivery_edge", edge.edge_id, behavior))
        if edge.compensation is not None:
            for trigger in edge.compensation.triggers:
                required.append(
                    CoverageAtom(
                        "compensation",
                        edge.compensation.compensation_id,
                        f"compensation_{trigger}",
                    )
                )
    return tuple(sorted(required))


def _validate_reset_probe(value: Any) -> dict[str, Any]:
    _exact_object(value, {"expected_result", "assertions"}, field="reset_probe")
    expected = _json_object(value["expected_result"], field="reset_probe.expected_result")
    assertions = _validate_assertions(value["assertions"], field="reset_probe.assertions")
    _require_evidence_assertion(assertions, field="reset_probe.assertions")
    return {"expected_result": expected, "assertions": assertions}


def _validate_probes(
    value: Any,
    *,
    required: tuple[CoverageAtom, ...],
    bound: _BoundInputs,
    pack: LoadedCompositionPack,
) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not value or len(value) > COMPOSITION_ADMISSION_MAX_PROBES:
        _fail(
            "composition_admission_probes_invalid",
            f"behavior_probes must contain 1 through {COMPOSITION_ADMISSION_MAX_PROBES} probes.",
        )
    required_set = set(required)
    source_map = {item.source_contract_id: item for item in pack.source_event_contracts}
    edge_map = {item.edge_id: item for item in pack.delivery_edges}
    compensation_map = {
        item.compensation.compensation_id: item.compensation
        for item in pack.delivery_edges
        if item.compensation is not None
    }
    result: list[dict[str, Any]] = []
    probe_ids: list[str] = []
    step_count = 0
    assertion_count = 0
    step_ids: set[str] = set()
    for probe_index, probe in enumerate(value):
        _exact_object(probe, {"probe_id", "steps"}, field=f"behavior_probes[{probe_index}]")
        probe_id = _identifier(probe["probe_id"], field="probe_id")
        if probe_id in probe_ids:
            _fail("composition_admission_probe_duplicate", "Probe ids must be unique.")
        steps = probe["steps"]
        if not isinstance(steps, list) or not steps:
            _fail("composition_admission_probe_steps_invalid", "Every probe needs ordered steps.")
        normalized_steps: list[dict[str, Any]] = []
        for step_index, step in enumerate(steps):
            step_count += 1
            if step_count > COMPOSITION_ADMISSION_MAX_STEPS:
                _fail("composition_admission_steps_too_many", "Probe suite has too many steps.")
            normalized = _validate_step(
                step,
                field=f"behavior_probes[{probe_index}].steps[{step_index}]",
                bound=bound,
                required=required_set,
                source_map=source_map,
                edge_map=edge_map,
                compensation_map=compensation_map,
            )
            if normalized["step_id"] in step_ids:
                _fail("composition_admission_step_duplicate", "Step ids must be globally unique.")
            step_ids.add(normalized["step_id"])
            assertion_count += len(normalized["assertions"])
            if assertion_count > COMPOSITION_ADMISSION_MAX_ASSERTIONS:
                _fail(
                    "composition_admission_assertions_too_many",
                    "Probe suite has too many assertions.",
                )
            normalized_steps.append(normalized)
        result.append({"probe_id": probe_id, "steps": normalized_steps})
        probe_ids.append(probe_id)
    if probe_ids != sorted(probe_ids):
        _fail("composition_admission_probe_order_invalid", "Probes must be sorted by probe_id.")
    return tuple(result)


def _validate_step(
    value: Any,
    *,
    field: str,
    bound: _BoundInputs,
    required: set[CoverageAtom],
    source_map: Mapping[str, Any],
    edge_map: Mapping[str, Any],
    compensation_map: Mapping[str, Any],
) -> dict[str, Any]:
    common = {"step_id", "action", "expected_result", "assertions", "covers"}
    if not isinstance(value, Mapping):
        _fail("composition_admission_step_invalid", "Probe steps must be objects.", field=field)
    action = value.get("action")
    if action not in _ACTIONS:
        _fail("composition_admission_action_invalid", "Unsupported probe action.", field=field)
    action_fields = {
        "agent_http": {"provider_id", "operation_id", "principal_context_id", "request"},
        "controller_advance": {"seconds"},
        "controller_drain": set(),
    }[action]
    _exact_object(value, common | action_fields, field=field)
    normalized: dict[str, Any] = {
        "step_id": _identifier(value["step_id"], field="step_id"),
        "action": action,
        "expected_result": _json_object(value["expected_result"], field=f"{field}.expected_result"),
        "assertions": _validate_assertions(value["assertions"], field=f"{field}.assertions"),
        "covers": _validate_covers(value["covers"], required=required, field=f"{field}.covers"),
    }
    _require_evidence_assertion(normalized["assertions"], field=f"{field}.assertions")
    if action == "agent_http":
        provider_id = _identifier(value["provider_id"], field="provider_id")
        operation_id = _identifier(value["operation_id"], field="operation_id")
        principal_context_id = _identifier(
            value["principal_context_id"], field="principal_context_id"
        )
        try:
            operation = bound.operations[provider_id][operation_id]
        except KeyError:
            _fail(
                "composition_admission_probe_operation_unknown",
                "An agent HTTP step references an operation outside the selected releases.",
                provider_id=provider_id,
                operation_id=operation_id,
            )
        request = _validate_http_request(
            value["request"], operation=operation, field=f"{field}.request"
        )
        normalized["expected_result"] = _validate_http_result(
            normalized["expected_result"], field=f"{field}.expected_result"
        )
        normalized.update(
            {
                "provider_id": provider_id,
                "operation_id": operation_id,
                "principal_context_id": principal_context_id,
                "request": request,
            }
        )
    elif action == "controller_advance":
        seconds = value["seconds"]
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, int)
            or not (1 <= seconds <= 2_592_000)
        ):
            _fail(
                "composition_admission_advance_invalid",
                "Logical-time advances must be integers from 1 through 2592000 seconds.",
            )
        normalized["seconds"] = seconds

    _validate_cover_action(
        normalized,
        source_map=source_map,
        edge_map=edge_map,
        compensation_map=compensation_map,
        operations=bound.operations,
    )
    return normalized


def _validate_http_request(
    value: Any, *, operation: Mapping[str, Any], field: str
) -> dict[str, Any]:
    fields = {"scheme", "authority", "method", "path", "query", "headers", "body"}
    _exact_object(value, fields, field=field)
    surface = operation["native_surface"]
    for name in ("scheme", "authority", "method"):
        if value[name] != surface[name]:
            _fail(
                "composition_admission_probe_surface_mismatch",
                "Probe request does not match its admitted provider operation.",
                field=name,
                operation_id=operation["operation_id"],
            )
    path = value["path"]
    if not isinstance(path, str) or not path.startswith("/") or "?" in path or "#" in path:
        _fail("composition_admission_probe_path_invalid", "Probe request path is invalid.")
    if not _path_matches(surface["path_template"], path):
        _fail(
            "composition_admission_probe_surface_mismatch",
            "Probe request path does not match its admitted path template.",
            operation_id=operation["operation_id"],
        )
    query = value["query"]
    if not isinstance(query, Mapping) or len(query) > COMPOSITION_ADMISSION_MAX_QUERY_KEYS:
        _fail("composition_admission_probe_query_invalid", "Probe query is invalid or too large.")
    normalized_query: dict[str, str | list[str]] = {}
    for key, item in query.items():
        if not isinstance(key, str) or not key:
            _fail(
                "composition_admission_probe_query_invalid",
                "Probe query keys must be non-empty strings.",
            )
        if isinstance(item, str):
            normalized_query[key] = item
        elif isinstance(item, list) and all(isinstance(part, str) for part in item):
            normalized_query[key] = list(item)
        else:
            _fail(
                "composition_admission_probe_query_invalid",
                "Probe query values must be strings or arrays of strings.",
            )
    headers = value["headers"]
    if not isinstance(headers, Mapping) or len(headers) > COMPOSITION_ADMISSION_MAX_HEADERS:
        _fail(
            "composition_admission_probe_headers_invalid", "Probe headers are invalid or too large."
        )
    normalized_headers: dict[str, str] = {}
    lowered: set[str] = set()
    for name, header_value in headers.items():
        if (
            not isinstance(name, str)
            or _HEADER_NAME.fullmatch(name) is None
            or not isinstance(header_value, str)
        ):
            _fail(
                "composition_admission_probe_headers_invalid",
                "Probe headers must be valid string pairs.",
            )
        lower = name.lower()
        if lower in lowered:
            _fail(
                "composition_admission_probe_headers_invalid",
                "Probe header names must be unique case-insensitively.",
            )
        if lower in _FORBIDDEN_PROBE_HEADERS or lower.startswith("x-datalox-"):
            _fail(
                "composition_admission_probe_credentials_forbidden",
                "Probe claims cannot contain credentials or Datalox control headers.",
                header=name,
            )
        lowered.add(lower)
        normalized_headers[name] = header_value
    return {
        "scheme": value["scheme"],
        "authority": value["authority"],
        "method": value["method"],
        "path": path,
        "query": normalized_query,
        "headers": normalized_headers,
        "body": _finite_json(value["body"], field=f"{field}.body"),
    }


def _validate_http_result(value: Any, *, field: str) -> dict[str, Any]:
    _exact_object(value, {"status_code", "decision_kind", "headers", "body"}, field=field)
    status = value["status_code"]
    if isinstance(status, bool) or not isinstance(status, int) or not (100 <= status <= 599):
        _fail(
            "composition_admission_probe_result_invalid",
            "An HTTP probe status_code must be an integer from 100 through 599.",
            field=field,
        )
    if value["decision_kind"] not in _DECISION_KINDS:
        _fail(
            "composition_admission_probe_result_invalid",
            "An HTTP probe decision_kind is invalid.",
            field=field,
        )
    headers = value["headers"]
    if not isinstance(headers, Mapping) or len(headers) > COMPOSITION_ADMISSION_MAX_HEADERS:
        _fail(
            "composition_admission_probe_result_invalid",
            "HTTP result headers must be a bounded string mapping.",
            field=field,
        )
    normalized_headers: dict[str, str] = {}
    lowered: set[str] = set()
    for name, header_value in headers.items():
        if (
            not isinstance(name, str)
            or _HEADER_NAME.fullmatch(name) is None
            or not isinstance(header_value, str)
            or name.lower() in lowered
        ):
            _fail(
                "composition_admission_probe_result_invalid",
                "HTTP result headers must be valid and unique case-insensitively.",
                field=field,
            )
        lower = name.lower()
        if lower in _FORBIDDEN_PROBE_HEADERS or lower.startswith("x-datalox-"):
            _fail(
                "composition_admission_probe_credentials_forbidden",
                "Probe results must omit credentials and Datalox control headers.",
                header=name,
            )
        lowered.add(lower)
        normalized_headers[name] = header_value
    return {
        "status_code": status,
        "decision_kind": value["decision_kind"],
        "headers": normalized_headers,
        "body": _finite_json(value["body"], field=f"{field}.body"),
    }


def _validate_covers(
    value: Any, *, required: set[CoverageAtom], field: str
) -> tuple[CoverageAtom, ...]:
    if not isinstance(value, list):
        _fail("composition_admission_coverage_invalid", "covers must be an array.", field=field)
    result: list[CoverageAtom] = []
    for index, item in enumerate(value):
        _exact_object(item, {"subject_kind", "subject_id", "behavior"}, field=f"{field}[{index}]")
        kind = item["subject_kind"]
        if kind not in {"source_contract", "delivery_edge", "compensation"}:
            _fail("composition_admission_coverage_invalid", "Coverage subject kind is invalid.")
        atom = CoverageAtom(
            kind,
            _identifier(item["subject_id"], field="subject_id"),
            _identifier(item["behavior"], field="behavior"),
        )
        if atom not in required:
            _fail(
                "composition_admission_coverage_extra",
                "Probe coverage contains an undeclared or unnecessary atom.",
                atom=_coverage_payload(atom),
            )
        result.append(atom)
    if len(set(result)) != len(result):
        _fail("composition_admission_coverage_ambiguous", "A step repeats one coverage atom.")
    return tuple(sorted(result))


def _validate_cover_action(
    step: Mapping[str, Any],
    *,
    source_map: Mapping[str, Any],
    edge_map: Mapping[str, Any],
    compensation_map: Mapping[str, Any],
    operations: Mapping[str, Mapping[str, Mapping[str, Any]]],
) -> None:
    for atom in step["covers"]:
        if atom.subject_kind == "source_contract":
            source = source_map[atom.subject_id]
            accepted = {(item.status_code, item.decision_kind) for item in source.accepted_outcomes}
            expected_result = step["expected_result"]
            if (
                step["action"] != "agent_http"
                or step.get("provider_id") != source.provider_id
                or step.get("operation_id") != source.source_operation_id
                or (
                    expected_result.get("status_code"),
                    expected_result.get("decision_kind"),
                )
                not in accepted
            ):
                _fail(
                    "composition_admission_coverage_action_invalid",
                    "Source-emission coverage must prove an accepted outcome on its exact source HTTP operation.",
                    subject_id=atom.subject_id,
                )
        elif atom.subject_kind == "delivery_edge" and atom.behavior == "read_after_write":
            edge = edge_map[atom.subject_id]
            provider_id = step.get("provider_id")
            operation_id = step.get("operation_id")
            operation = operations.get(provider_id, {}).get(operation_id)
            if (
                step["action"] != "agent_http"
                or provider_id != edge.target_provider_id
                or operation is None
                or operation["mutability"] != "read"
            ):
                _fail(
                    "composition_admission_coverage_action_invalid",
                    "Read-after-write coverage must be an admitted read on the target provider.",
                    edge_id=atom.subject_id,
                )
        elif atom.subject_kind == "delivery_edge":
            if step["action"] != "controller_drain":
                _fail(
                    "composition_admission_coverage_action_invalid",
                    "Delivery behavior coverage must be attached to a deterministic drain.",
                    edge_id=atom.subject_id,
                    behavior=atom.behavior,
                )
        elif atom.subject_kind == "compensation":
            if atom.subject_id not in compensation_map or step["action"] != "controller_drain":
                _fail(
                    "composition_admission_coverage_action_invalid",
                    "Compensation coverage must be attached to a deterministic drain.",
                    compensation_id=atom.subject_id,
                )


def _validate_assertions(value: Any, *, field: str) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not value:
        _fail(
            "composition_admission_assertions_invalid",
            "Assertions must be a non-empty array.",
            field=field,
        )
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            _fail("composition_admission_assertion_invalid", "Assertions must be objects.")
        operator = item.get("operator")
        common = {"assertion_id", "source", "pointer", "operator"}
        operator_fields = {
            "equals": {"expected_value"},
            "type": {"expected_type"},
            "exists": {"expected_exists"},
        }.get(operator)
        if operator_fields is None:
            _fail(
                "composition_admission_assertion_operator_invalid",
                "Unsupported assertion operator.",
            )
        _exact_object(item, common | operator_fields, field=f"{field}[{index}]")
        assertion_id = _identifier(item["assertion_id"], field="assertion_id")
        if assertion_id in ids:
            _fail(
                "composition_admission_assertion_duplicate",
                "Assertion ids must be unique within a step.",
            )
        source = item["source"]
        if source not in _ASSERTION_SOURCES:
            _fail("composition_admission_assertion_source_invalid", "Assertion source is invalid.")
        pointer = _json_pointer(item["pointer"], field="pointer")
        normalized = {
            "assertion_id": assertion_id,
            "source": source,
            "pointer": pointer,
            "operator": operator,
        }
        if operator == "equals":
            normalized["expected_value"] = _finite_json(
                item["expected_value"], field="expected_value"
            )
        elif operator == "type":
            if item["expected_type"] not in _JSON_TYPES:
                _fail(
                    "composition_admission_assertion_type_invalid",
                    "Assertion JSON type is invalid.",
                )
            normalized["expected_type"] = item["expected_type"]
        else:
            if not isinstance(item["expected_exists"], bool):
                _fail(
                    "composition_admission_assertion_exists_invalid",
                    "expected_exists must be boolean.",
                )
            normalized["expected_exists"] = item["expected_exists"]
        result.append(normalized)
        ids.add(assertion_id)
    return tuple(result)


def _require_evidence_assertion(assertions: Sequence[Mapping[str, Any]], *, field: str) -> None:
    if not any(item["source"] == "exported_evidence" for item in assertions):
        _fail(
            "composition_admission_evidence_assertion_missing",
            "Every reset or behavior step must assert exported composition evidence.",
            field=field,
        )


def _require_exact_coverage(
    probes: Sequence[Mapping[str, Any]], *, required: tuple[CoverageAtom, ...]
) -> None:
    actual = [atom for probe in probes for step in probe["steps"] for atom in step["covers"]]
    counts = Counter(actual)
    missing = [item for item in required if counts[item] == 0]
    ambiguous = [item for item, count in counts.items() if count > 1]
    if missing:
        _fail(
            "composition_admission_coverage_missing",
            "Probe coverage is missing required provider-mediated behavior.",
            missing=[_coverage_payload(item) for item in missing],
        )
    if ambiguous:
        _fail(
            "composition_admission_coverage_ambiguous",
            "Each required behavior must have exactly one proof point.",
            ambiguous=[_coverage_payload(item) for item in sorted(ambiguous)],
        )
    if set(actual) != set(required):
        _fail("composition_admission_coverage_extra", "Probe coverage is not exact.")


def _execute_suite(
    runner: CompositionProbeRunner,
    *,
    reset_probe: Mapping[str, Any],
    probes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    reset_result = _invoke_runner("reset", runner.reset)
    baseline = _invoke_runner("export_evidence", runner.export_evidence)
    _expect_exact(reset_result, reset_probe["expected_result"], field="reset_probe.expected_result")
    _evaluate_assertions(
        reset_probe["assertions"], action_result=reset_result, exported_evidence=baseline
    )
    observations: list[dict[str, Any]] = []
    for probe in probes:
        step_observations: list[dict[str, Any]] = []
        for step in probe["steps"]:
            action = step["action"]
            if action == "agent_http":
                result = _invoke_runner(
                    "agent_http",
                    runner.agent_http,
                    provider_id=step["provider_id"],
                    operation_id=step["operation_id"],
                    principal_context_id=step["principal_context_id"],
                    request=deepcopy(step["request"]),
                )
            elif action == "controller_advance":
                result = _invoke_runner(
                    "advance_delivery_time",
                    runner.advance_delivery_time,
                    seconds=step["seconds"],
                )
            else:
                result = _invoke_runner("drain", runner.drain)
            evidence = _invoke_runner("export_evidence", runner.export_evidence)
            _expect_exact(
                result, step["expected_result"], field=f"step {step['step_id']} expected_result"
            )
            _evaluate_assertions(
                step["assertions"], action_result=result, exported_evidence=evidence
            )
            step_observations.append(
                {
                    "step_id": step["step_id"],
                    "action": action,
                    "result": result,
                    "exported_evidence": evidence,
                }
            )
        observations.append({"probe_id": probe["probe_id"], "steps": step_observations})
    final = _invoke_runner("export_evidence", runner.export_evidence)
    behavior = {
        "reset_result": reset_result,
        "baseline_evidence": baseline,
        "probes": observations,
        "final_evidence": final,
    }
    return {
        "behavior_sha256": _canonical_sha256(behavior),
        "reset_result_sha256": _canonical_sha256(reset_result),
        "baseline_evidence_sha256": _canonical_sha256(baseline),
        "probes": observations,
    }


def _validate_runner(runner: Any) -> None:
    required = ("reset", "agent_http", "advance_delivery_time", "drain", "export_evidence")
    if any(not callable(getattr(runner, name, None)) for name in required):
        _fail(
            "composition_admission_probe_runner_invalid",
            "The trusted composition probe runner does not implement the required closed interface.",
        )


def _invoke_runner(name: str, function: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        value = function(**kwargs)
    except CompositionAdmissionError:
        raise
    except Exception as exc:
        raise CompositionAdmissionError(
            "composition_admission_probe_runner_failed",
            "The trusted composition probe runner failed.",
            MappingProxyType({"action": name, "exception_type": type(exc).__name__}),
        ) from exc
    return _json_object(value, field=f"runner.{name}")


def _expect_exact(actual: Any, expected: Any, *, field: str) -> None:
    if canonical_json_bytes(actual) != canonical_json_bytes(expected):
        _fail(
            "composition_admission_probe_result_mismatch",
            "A probe action did not return its exact expected result.",
            field=field,
            actual_sha256=_canonical_sha256(actual),
            expected_sha256=_canonical_sha256(expected),
        )


def _evaluate_assertions(
    assertions: Sequence[Mapping[str, Any]],
    *,
    action_result: Mapping[str, Any],
    exported_evidence: Mapping[str, Any],
) -> None:
    sources = {"action_result": action_result, "exported_evidence": exported_evidence}
    for assertion in assertions:
        exists, actual = _resolve_pointer(sources[assertion["source"]], assertion["pointer"])
        operator = assertion["operator"]
        passed = False
        if operator == "exists":
            passed = exists is assertion["expected_exists"]
        elif operator == "equals":
            passed = exists and canonical_json_bytes(actual) == canonical_json_bytes(
                assertion["expected_value"]
            )
        elif operator == "type":
            passed = exists and _matches_json_type(actual, assertion["expected_type"])
        if not passed:
            _fail(
                "composition_admission_assertion_failed",
                "A composition evidence assertion failed.",
                assertion_id=assertion["assertion_id"],
                actual_exists=exists,
            )


def _probe_results(
    probes: Sequence[Mapping[str, Any]],
    first: Mapping[str, Any],
    second: Mapping[str, Any],
) -> list[dict[str, Any]]:
    first_by_id = {item["probe_id"]: item for item in first["probes"]}
    second_by_id = {item["probe_id"]: item for item in second["probes"]}
    results: list[dict[str, Any]] = []
    for probe in probes:
        probe_id = probe["probe_id"]
        first_steps = {item["step_id"]: item for item in first_by_id[probe_id]["steps"]}
        second_steps = {item["step_id"]: item for item in second_by_id[probe_id]["steps"]}
        steps: list[dict[str, Any]] = []
        for step in probe["steps"]:
            step_id = step["step_id"]
            first_observed = first_steps[step_id]
            second_observed = second_steps[step_id]
            steps.append(
                {
                    "step_id": step_id,
                    "action": step["action"],
                    "covers": [_coverage_payload(item) for item in step["covers"]],
                    "assertions_passed": [item["assertion_id"] for item in step["assertions"]],
                    "first_result_sha256": _canonical_sha256(first_observed["result"]),
                    "second_result_sha256": _canonical_sha256(second_observed["result"]),
                    "first_evidence_sha256": _canonical_sha256(first_observed["exported_evidence"]),
                    "second_evidence_sha256": _canonical_sha256(
                        second_observed["exported_evidence"]
                    ),
                }
            )
        results.append({"probe_id": probe_id, "steps": steps})
    return results


def _admitted_evidence(pack: LoadedCompositionPack) -> list[dict[str, Any]]:
    return [
        {
            "evidence_id": item.evidence_id,
            "artifact_path": item.artifact_path,
            "artifact_sha256": item.artifact_sha256,
            "grounding_level": item.grounding_level,
            "observed_at": item.observed_at,
            "valid_through": item.valid_through,
            "distribution_label": item.distribution_label,
            "rights_basis": item.rights_basis,
            "current_at_admission": True,
        }
        for item in pack.evidence_sources
    ]


def _admitted_grounded_claims(pack: LoadedCompositionPack) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for source in pack.source_event_contracts:
        claims.append(
            {
                "claim_kind": "source_contract",
                "claim_id": source.source_contract_id,
                "grounding": {
                    "level": source.grounding.level,
                    "evidence_refs": list(source.grounding.evidence_refs),
                },
                "rights": {
                    "distribution_label": source.rights.distribution_label,
                    "behavior_distribution_basis": source.rights.behavior_distribution_basis,
                },
            }
        )
    for edge in pack.delivery_edges:
        claims.append(
            {
                "claim_kind": "delivery_edge",
                "claim_id": edge.edge_id,
                "grounding": {
                    "level": edge.grounding.level,
                    "evidence_refs": list(edge.grounding.evidence_refs),
                },
                "rights": {
                    "distribution_label": edge.rights.distribution_label,
                    "behavior_distribution_basis": edge.rights.behavior_distribution_basis,
                },
            }
        )
        if edge.compensation is not None:
            claims.append(
                {
                    "claim_kind": "compensation",
                    "claim_id": edge.compensation.compensation_id,
                    "grounding": {
                        "level": edge.compensation.grounding.level,
                        "evidence_refs": list(edge.compensation.grounding.evidence_refs),
                    },
                    "rights": {
                        "distribution_label": edge.compensation.rights.distribution_label,
                        "behavior_distribution_basis": edge.compensation.rights.behavior_distribution_basis,
                    },
                }
            )
    return sorted(claims, key=lambda item: (item["claim_kind"], item["claim_id"]))


def _derived_distribution(pack: LoadedCompositionPack) -> str:
    labels = [pack.distribution_label]
    labels.extend(item.distribution_label for item in pack.evidence_sources)
    labels.extend(item.rights.distribution_label for item in pack.source_event_contracts)
    for edge in pack.delivery_edges:
        labels.append(edge.rights.distribution_label)
        if edge.compensation is not None:
            labels.append(edge.compensation.rights.distribution_label)
    return max(labels, key=_DISTRIBUTION_ORDER.__getitem__)


def _validate_derived_reset(value: Any) -> None:
    fields = {
        "passed",
        "first_run_sha256",
        "second_run_sha256",
        "reset_result_sha256",
        "baseline_evidence_sha256",
    }
    _exact_object(value, fields, field="functional_reset")
    if value["passed"] is not True or value["first_run_sha256"] != value["second_run_sha256"]:
        _fail("composition_admission_reset_invalid", "Admission functional reset proof is invalid.")
    for field_name in fields - {"passed"}:
        _sha256(value[field_name], field=field_name)


def _validate_derived_probe_results(value: Any, *, required: tuple[CoverageAtom, ...]) -> None:
    if not isinstance(value, list) or not value:
        _fail("composition_admission_probe_results_invalid", "Admission probe results are invalid.")
    seen_probes: list[str] = []
    seen_steps: set[str] = set()
    coverage: list[CoverageAtom] = []
    for probe in value:
        _exact_object(probe, {"probe_id", "steps"}, field="behavior_probes[]")
        probe_id = _identifier(probe["probe_id"], field="probe_id")
        if probe_id in seen_probes or not isinstance(probe["steps"], list) or not probe["steps"]:
            _fail(
                "composition_admission_probe_results_invalid",
                "Admission probe grouping is invalid.",
            )
        for step in probe["steps"]:
            fields = {
                "step_id",
                "action",
                "covers",
                "assertions_passed",
                "first_result_sha256",
                "second_result_sha256",
                "first_evidence_sha256",
                "second_evidence_sha256",
            }
            _exact_object(step, fields, field="behavior_probes[].steps[]")
            step_id = _identifier(step["step_id"], field="step_id")
            if step_id in seen_steps or step["action"] not in _ACTIONS:
                _fail(
                    "composition_admission_probe_results_invalid",
                    "Admission probe step is invalid.",
                )
            seen_steps.add(step_id)
            if not isinstance(step["assertions_passed"], list) or not step["assertions_passed"]:
                _fail(
                    "composition_admission_probe_results_invalid",
                    "Admission assertions are invalid.",
                )
            for assertion_id in step["assertions_passed"]:
                _identifier(assertion_id, field="assertion_id")
            for name in fields & {
                "first_result_sha256",
                "second_result_sha256",
                "first_evidence_sha256",
                "second_evidence_sha256",
            }:
                _sha256(step[name], field=name)
            if (
                step["first_result_sha256"] != step["second_result_sha256"]
                or step["first_evidence_sha256"] != step["second_evidence_sha256"]
            ):
                _fail(
                    "composition_admission_probe_results_invalid",
                    "Admission probe replay is not equivalent.",
                )
            coverage.extend(_coverage_from_payload(step["covers"]))
        seen_probes.append(probe_id)
    if seen_probes != sorted(seen_probes) or Counter(coverage) != Counter(required):
        _fail("composition_admission_probe_results_invalid", "Admission probe coverage is invalid.")


def _coverage_from_payload(value: Any) -> list[CoverageAtom]:
    if not isinstance(value, list):
        _fail("composition_admission_probe_results_invalid", "Admission covers is invalid.")
    result = []
    for item in value:
        _exact_object(item, {"subject_kind", "subject_id", "behavior"}, field="covers[]")
        kind = item["subject_kind"]
        if kind not in {"source_contract", "delivery_edge", "compensation"}:
            _fail(
                "composition_admission_probe_results_invalid", "Admission coverage kind is invalid."
            )
        result.append(
            CoverageAtom(
                kind,
                _identifier(item["subject_id"], field="subject_id"),
                _identifier(item["behavior"], field="behavior"),
            )
        )
    return result


def _profile_model(value: Mapping[str, Any]) -> AdmissionProviderProfile:
    return AdmissionProviderProfile(
        **{name: value[name] for name in AdmissionProviderProfile.__dataclass_fields__}
    )


def _coverage_payload(value: CoverageAtom) -> dict[str, str]:
    return {
        "subject_kind": value.subject_kind,
        "subject_id": value.subject_id,
        "behavior": value.behavior,
    }


def _path_matches(template: str, path: str) -> bool:
    template_parts = template.split("/")
    path_parts = path.split("/")
    if len(template_parts) != len(path_parts):
        return False
    for expected, actual in zip(template_parts, path_parts, strict=True):
        if _PATH_PARAMETER.fullmatch(expected) is not None:
            if (
                not actual
                or "/" in actual
                or "{" in actual
                or "}" in actual
                or actual in {".", ".."}
            ):
                return False
        elif expected != actual:
            return False
    return True


def _json_pointer(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or (value and not value.startswith("/")):
        _fail(
            "composition_admission_pointer_invalid",
            "JSON pointers must be empty or begin with '/'.",
            field=field,
        )
    for token in value.split("/")[1:]:
        index = 0
        while index < len(token):
            if token[index] == "~":
                if index + 1 >= len(token) or token[index + 1] not in {"0", "1"}:
                    _fail(
                        "composition_admission_pointer_invalid",
                        "JSON pointer escape is invalid.",
                        field=field,
                    )
                index += 2
            else:
                index += 1
    return value


def _resolve_pointer(value: Any, pointer: str) -> tuple[bool, Any]:
    current = value
    if pointer == "":
        return True, current
    for encoded in pointer.split("/")[1:]:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                return False, None
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                return False, None
            index = int(token)
            if index >= len(current):
                return False, None
            current = current[index]
        else:
            return False, None
    return True, current


def _matches_json_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return False


def _json_object(value: Any, *, field: str) -> dict[str, Any]:
    normalized = _finite_json(value, field=field)
    if not isinstance(normalized, dict):
        _fail(
            "composition_admission_json_object_required",
            "A finite JSON object is required.",
            field=field,
        )
    return normalized


def _finite_json(value: Any, *, field: str) -> Any:
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CompositionAdmissionError(
            "composition_admission_json_invalid",
            "Probe claims and runner results must be finite JSON.",
            MappingProxyType({"field": field}),
        ) from exc
    if len(encoded) > COMPOSITION_ADMISSION_MAX_JSON_BYTES:
        _fail(
            "composition_admission_json_too_large",
            "JSON value exceeds the admission limit.",
            field=field,
        )
    return json.loads(encoded)


def _admission_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        _fail("composition_admission_time_invalid", "admitted_at must be an aware UTC datetime.")
    return value.astimezone(UTC)


def _utc_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        _fail(
            "composition_admission_timestamp_invalid",
            "Timestamp must be RFC 3339 UTC.",
            field=field,
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CompositionAdmissionError(
            "composition_admission_timestamp_invalid",
            "Timestamp must be a valid RFC 3339 UTC value.",
            MappingProxyType({"field": field}),
        ) from exc
    return parsed.astimezone(UTC)


def _format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _identifier(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _fail("composition_admission_identifier_invalid", "Identifier is invalid.", field=field)
    return value


def _sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail("composition_admission_digest_invalid", "SHA-256 digest is invalid.", field=field)
    return value


def _canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _resolve_regular_file(path: Path, *, code: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        stat_result = path.lstat()
    except OSError as exc:
        raise CompositionAdmissionError(code, "Required admission file is unreadable.") from exc
    if (
        path.is_symlink()
        or not path.is_file()
        or not resolved.is_file()
        or stat_result.st_size > COMPOSITION_ADMISSION_MAX_JSON_BYTES
    ):
        _fail(code, "Required admission file must be a bounded regular file.", path=str(path))
    return resolved


def _load_json_object(path: Path, *, code: str) -> dict[str, Any]:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise CompositionAdmissionError(
                    "composition_admission_json_duplicate_key",
                    "Composition admission JSON contains a duplicate object key.",
                    MappingProxyType({"key": key}),
                )
            result[key] = value
        return result

    try:
        raw = json.loads(path.read_bytes(), object_pairs_hook=strict_object)
    except CompositionAdmissionError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompositionAdmissionError(code, "Admission JSON is unreadable or invalid.") from exc
    if not isinstance(raw, dict):
        _fail(code, "Admission JSON must be an object.")
    return raw


def _exact_object(value: Any, fields: set[str], *, field: str) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        _fail(
            "composition_admission_fields_invalid",
            "Object fields must match the strict composition admission contract.",
            field=field,
            missing=sorted(fields - set(value)) if isinstance(value, Mapping) else sorted(fields),
            extra=sorted(set(value) - fields) if isinstance(value, Mapping) else [],
        )


def _write_json_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        _fail("composition_admission_output_parent_invalid", "Admission output parent is invalid.")
    encoded = canonical_json_bytes(payload) + b"\n"
    scratch: str | None = None
    try:
        descriptor, scratch = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=parent)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(scratch, 0o444)
        try:
            os.link(scratch, path)
        except FileExistsError:
            _fail(
                "composition_admission_output_exists",
                "Composition admission output already exists.",
            )
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if scratch is not None:
            try:
                os.unlink(scratch)
            except FileNotFoundError:
                pass


def _freeze(value: Any) -> FrozenJson:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _fail(code: str, message: str, **details: Any) -> None:
    raise CompositionAdmissionError(code, message, MappingProxyType(details))
