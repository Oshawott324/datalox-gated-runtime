"""Authoring-only execution of candidate Composition Packs.

This module materializes exact admitted Provider Release profiles and executes a
candidate pack in an isolated local directory. It never contacts a provider and
never creates a capability accepted by the public CompositionSession runtime.
"""

from __future__ import annotations

import shutil
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any

from datalox_gated_runtime.composition.admission import (
    AdmissionProviderProfile,
    LoadedCompositionAdmission,
    ValidatedCompositionAuthoringInputs,
    admit_composition_pack,
    validate_composition_authoring_inputs,
)
from datalox_gated_runtime.composition.events import SessionEventEngine
from datalox_gated_runtime.composition.pack import LoadedCompositionPack
from datalox_gated_runtime.composition.session import (
    CompositionProviderSession,
    CompositionRuntimeRelease,
    _CompositionExecutionAuthority,
    _CompositionExecutionCore,
    _redact_headers,
)
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest, GateResponse
from datalox_gated_runtime.provider_runtime.release import (
    LoadedProviderRelease,
    load_provider_release,
    load_provider_release_from_descriptor,
    materialize_provider_release_profile,
)
from datalox_gated_runtime.provider_runtime.runtime import ProviderRuntime

CANDIDATE_COMPOSITION_EVIDENCE_SCHEMA_VERSION = "datalox_candidate_composition_evidence_v1"
DEFAULT_CANDIDATE_INITIAL_TIME = "2030-01-01T00:00:00.000000Z"
DEFAULT_CANDIDATE_EPISODE_SEED = "composition-admission"


@dataclass(frozen=True)
class CompositionAuthoringError(ValueError):
    """Stable authoring-only candidate execution failure."""

    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __str__(self) -> str:
        return self.message


class CandidateCompositionRunner:
    """Closed local implementation of the CompositionProbeRunner protocol."""

    def __init__(
        self,
        *,
        validated: ValidatedCompositionAuthoringInputs,
        provider_releases: Mapping[str, Path | LoadedProviderRelease],
        work_dir: Path,
        initial_time: str = DEFAULT_CANDIDATE_INITIAL_TIME,
        episode_seed: str = DEFAULT_CANDIDATE_EPISODE_SEED,
    ) -> None:
        if not isinstance(validated, ValidatedCompositionAuthoringInputs):
            raise TypeError("validated must be ValidatedCompositionAuthoringInputs")
        self.validated = validated
        self.work_dir = _create_private_work_dir(work_dir)
        self._closed = False
        runtimes: list[ProviderRuntime] = []
        event_engine: SessionEventEngine | None = None
        try:
            releases = _strict_releases(provider_releases)
            profiles = {item.provider_id: item for item in validated.provider_profiles}
            if set(releases) != set(profiles):
                _fail(
                    "composition_authoring_provider_set_invalid",
                    "Candidate releases must exactly match the validated provider profiles.",
                    expected=sorted(profiles),
                    actual=sorted(releases),
                )
            providers: dict[str, CompositionProviderSession] = {}
            for provider_id in sorted(profiles):
                profile = profiles[provider_id]
                release = releases[provider_id]
                _require_exact_profile(release, profile)
                materialized = materialize_provider_release_profile(
                    release=release,
                    profile_id=profile.profile_id,
                    output_dir=self.work_dir / "providers" / provider_id / "materialized",
                )
                runtime = ProviderRuntime(
                    bundle_dir=materialized.bundle_dir,
                    admission_path=materialized.admission_path,
                    run_dir=self.work_dir / "providers" / provider_id / "run",
                    lifecycle="create",
                )
                runtimes.append(runtime)
                providers[provider_id] = CompositionProviderSession(
                    release=CompositionRuntimeRelease.from_loaded_release(
                        release,
                        profile_id=profile.profile_id,
                    ),
                    runtime=runtime,
                )
            event_engine = SessionEventEngine(
                self.work_dir / "events" / "events.sqlite3",
                episode_seed=episode_seed,
                initial_time=initial_time,
            )
            authority_payload = {
                "authority_kind": "candidate_authoring",
                "claims_sha256": validated.claims_sha256,
                "composition_pack_sha256": validated.pack.canonical_sha256,
                "provider_profiles": [_profile_payload(item) for item in profiles.values()],
            }
            self._session = _CompositionExecutionCore(
                pack=validated.pack,
                execution_authority=_CompositionExecutionAuthority(
                    authority_kind="candidate_authoring",
                    canonical_sha256=canonical_json_sha256(authority_payload),
                    pack_id=validated.pack.pack_id,
                    pack_version=validated.pack.pack_version,
                    composition_pack_sha256=validated.pack.canonical_sha256,
                    distribution_label=validated.pack.distribution_label,
                    time_scope=validated.pack.time_scope,
                    provider_profiles=tuple(
                        profiles[provider_id] for provider_id in sorted(profiles)
                    ),
                ),
                providers=providers,
                event_engine=event_engine,
            )
        except BaseException:
            for runtime in reversed(runtimes):
                runtime.close()
            if event_engine is not None:
                event_engine.close()
            shutil.rmtree(self.work_dir, ignore_errors=True)
            raise

    def __enter__(self) -> CandidateCompositionRunner:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        for provider_id in sorted(self._session._providers):
            self._session._providers[provider_id].runtime.close()
        self._session.event_engine.close()
        self._closed = True

    def reset(self) -> Mapping[str, Any]:
        self._require_open()
        self._session.reset()
        return {
            "composition_delivery_time": self._session.composition_delivery_time,
            "reset": True,
        }

    def agent_http(
        self,
        *,
        provider_id: str,
        operation_id: str,
        principal_context_id: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self._require_open()
        response = self._session._handle_authoring_request_as_principal(
            _call_request(request),
            provider_id=provider_id,
            operation_id=operation_id,
            principal_context_id=principal_context_id,
        )
        return _http_observation(response)

    def advance_delivery_time(self, *, seconds: int) -> Mapping[str, Any]:
        self._require_open()
        if isinstance(seconds, bool) or not isinstance(seconds, int) or seconds < 1:
            _fail(
                "composition_authoring_advance_invalid",
                "Delivery-time advance must be a positive integer number of seconds.",
            )
        current = _parse_time(self._session.composition_delivery_time)
        delivery_time = self._session.advance_delivery_time_to(current + timedelta(seconds=seconds))
        return {"composition_delivery_time": delivery_time}

    def drain(self) -> Mapping[str, Any]:
        self._require_open()
        results = self._session.drain_due()
        return {
            "deliveries": [
                {
                    "attempt_number": item.attempt_number,
                    "attempt_outcome": item.attempt_outcome,
                    "delivery_state": item.delivery_state,
                    "next_available_at": item.next_available_at,
                }
                for item in results
            ],
            "drained": len(results),
        }

    def export_evidence(self) -> Mapping[str, Any]:
        self._require_open()
        providers = {
            provider_id: _canonical_provider_evidence(binding.runtime.export())
            for provider_id, binding in sorted(self._session._providers.items())
        }
        return {
            "schema_version": CANDIDATE_COMPOSITION_EVIDENCE_SCHEMA_VERSION,
            "pack": {
                "pack_id": self.validated.pack.pack_id,
                "pack_version": self.validated.pack.pack_version,
                "composition_pack_sha256": self.validated.pack.canonical_sha256,
                "claims_sha256": self.validated.claims_sha256,
                "time_scope": self.validated.pack.time_scope,
            },
            "provider_profiles": [
                _profile_payload(item) for item in self.validated.provider_profiles
            ],
            "composition_delivery_time": self._session.composition_delivery_time,
            "providers": providers,
            "events": _canonical_event_evidence(self._session.event_engine.export()),
        }

    def _require_open(self) -> None:
        if self._closed:
            _fail(
                "composition_authoring_runner_closed",
                "The candidate composition runner is closed.",
            )


def admit_candidate_composition_pack(
    *,
    pack: LoadedCompositionPack,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
    claims_path: Path,
    output_path: Path,
    work_dir: Path,
    admitted_at: datetime | None = None,
) -> LoadedCompositionAdmission:
    """Validate, execute, and derive one Composition Admission locally."""

    validated = validate_composition_authoring_inputs(
        pack=pack,
        provider_releases=provider_releases,
        claims_path=claims_path,
        admitted_at=admitted_at,
    )
    with CandidateCompositionRunner(
        validated=validated,
        provider_releases=provider_releases,
        work_dir=work_dir,
    ) as runner:
        return admit_composition_pack(
            pack=validated.pack,
            provider_releases=provider_releases,
            claims_path=claims_path,
            runner=runner,
            output_path=output_path,
            admitted_at=validated.admitted_at,
        )


def _strict_releases(
    values: Mapping[str, Path | LoadedProviderRelease],
) -> dict[str, LoadedProviderRelease]:
    if not isinstance(values, Mapping):
        _fail(
            "composition_authoring_provider_releases_invalid",
            "Provider releases must be supplied as a provider-id mapping.",
        )
    result: dict[str, LoadedProviderRelease] = {}
    for provider_id, supplied in values.items():
        if not isinstance(provider_id, str):
            _fail(
                "composition_authoring_provider_release_invalid",
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
                "composition_authoring_provider_release_invalid",
                "Each provider requires a strict Provider Release path or capability.",
                provider_id=provider_id,
            )
        if release.provider_id != provider_id:
            _fail(
                "composition_authoring_provider_release_invalid",
                "A provider release mapping key does not match the loaded release.",
                provider_id=provider_id,
            )
        result[provider_id] = release
    return result


def _require_exact_profile(
    release: LoadedProviderRelease,
    expected: AdmissionProviderProfile,
) -> None:
    profile = next(
        (item for item in release.profiles if item.profile_id == expected.profile_id),
        None,
    )
    actual = (
        None
        if profile is None
        else {
            "provider_id": release.provider_id,
            "profile_id": profile.profile_id,
            "release_manifest_sha256": release.manifest_descriptor["digest"],
            "provider_runtime_sha256": profile.provider_runtime_sha256,
            "provider_admission_sha256": profile.provider_admission_sha256,
            "operation_contract_sha256": release.config["operation_contract_sha256"],
        }
    )
    if actual != _profile_payload(expected):
        _fail(
            "composition_authoring_provider_profile_binding_invalid",
            "A candidate provider profile no longer matches its validated exact digests.",
            provider_id=expected.provider_id,
            profile_id=expected.profile_id,
        )


def _profile_payload(value: AdmissionProviderProfile) -> dict[str, str]:
    return {
        "provider_id": value.provider_id,
        "profile_id": value.profile_id,
        "release_manifest_sha256": value.release_manifest_sha256,
        "provider_runtime_sha256": value.provider_runtime_sha256,
        "provider_admission_sha256": value.provider_admission_sha256,
        "operation_contract_sha256": value.operation_contract_sha256,
    }


def _call_request(value: Mapping[str, Any]) -> CallRequest:
    if not isinstance(value, Mapping) or set(value) != {
        "scheme",
        "authority",
        "method",
        "path",
        "query",
        "headers",
        "body",
    }:
        _fail(
            "composition_authoring_request_invalid",
            "An authoring HTTP request must use the exact validated request fields.",
        )
    return CallRequest(
        scheme=value["scheme"],
        authority=value["authority"],
        method=value["method"],
        path=value["path"],
        query=deepcopy(value["query"]),
        headers=deepcopy(value["headers"]),
        body=deepcopy(value["body"]),
        operation_id=None,
    )


def _http_observation(response: GateResponse) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "decision_kind": response.decision.kind,
        "headers": _redact_headers(response.headers),
        "body": deepcopy(response.body),
    }


def _canonical_provider_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    call_evidence = value["call_evidence"]
    return {
        "schema_version": value["schema_version"],
        "provider_id": value["provider_id"],
        "bundle_version": value["bundle_version"],
        "authorities": deepcopy(value["authorities"]),
        "provider_state": deepcopy(value["provider_state"]),
        "call_evidence": {
            "events": [_canonical_call_event(item) for item in call_evidence["events"]],
            "shadow_state": deepcopy(call_evidence["shadow_state"]),
        },
        "provider_assurance": deepcopy(value["provider_assurance"]),
    }


def _canonical_call_event(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("surface", "http") == "http":
        fields = {
            "surface",
            "request",
            "decision",
            "response_status_code",
            "response_body",
            "response_case_id",
            "shadow_mutation",
        }
    else:
        fields = {
            "surface",
            "tool_name",
            "upstream_name",
            "upstream_tool_name",
            "arguments",
            "decision",
            "result",
            "response_case_id",
            "shadow_mutation",
        }
    return {field: deepcopy(value[field]) for field in sorted(fields) if field in value}


def _canonical_event_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    result = deepcopy(dict(value))
    result["composition_delivery_time"] = result.pop("logical_time")
    result["initial_composition_delivery_time"] = result.pop("initial_time")
    result.pop("content_sha256", None)
    result.pop("state_digest", None)
    for delivery in result["deliveries"]:
        for attempt in delivery["attempts"]:
            _remove_runtime_response_id(attempt.get("receipt"))
        for resolution in delivery["resolutions"]:
            _remove_runtime_response_id(resolution.get("receipt"))
    return result


def _remove_runtime_response_id(value: Any) -> None:
    if isinstance(value, dict):
        value.pop("response_event_id", None)


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError) as exc:
        _fail(
            "composition_authoring_delivery_time_invalid",
            "The composition delivery time is not a valid UTC timestamp.",
        )
        raise AssertionError from exc
    return parsed.astimezone(UTC)


def _create_private_work_dir(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("work_dir must be a Path")
    destination = path.expanduser().resolve(strict=False)
    if destination.exists() or destination.is_symlink():
        _fail(
            "composition_authoring_work_dir_exists",
            "Candidate composition work directory must be a fresh path.",
            path=str(destination),
        )
    destination.mkdir(parents=True, mode=0o700)
    destination.chmod(0o700)
    return destination


def _fail(code: str, message: str, **details: Any) -> None:
    raise CompositionAuthoringError(code, message, MappingProxyType(deepcopy(details)))
