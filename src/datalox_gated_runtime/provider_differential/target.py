"""Execute an offline differential against one immutable Provider Release."""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_differential.errors import ProviderDifferentialError
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.provider_runtime.runtime import ProviderRuntime
from datalox_gated_runtime.reference import JsonValue, ObservationRequest, ObservedResponse
from datalox_gated_runtime.reference.contracts import ReferenceCall, thaw_json


class ProviderReleaseTarget:
    """One materialized release profile with exact provider-shaped requests."""

    def __init__(
        self,
        *,
        registry: FilesystemProviderReleaseRegistry,
        release_reference: str,
        profile_id: str,
        authority: str,
        principal_bindings: Mapping[str, str],
    ) -> None:
        if not isinstance(registry, FilesystemProviderReleaseRegistry):
            _fail("provider_differential_registry_invalid", "registry is invalid.")
        if type(release_reference) is not str or not release_reference:
            _fail(
                "provider_differential_release_reference_invalid",
                "release_reference must be non-empty.",
            )
        if type(profile_id) is not str or not profile_id:
            _fail("provider_differential_profile_invalid", "profile_id must be non-empty.")
        if type(authority) is not str or not authority or authority.strip() != authority:
            _fail("provider_differential_authority_invalid", "authority must be canonical.")
        if not isinstance(principal_bindings, Mapping) or not principal_bindings:
            _fail(
                "provider_differential_principal_bindings_invalid",
                "principal_bindings must be a non-empty object.",
            )
        bindings: dict[str, str] = {}
        for auth_context_id, principal_context_id in principal_bindings.items():
            if (
                type(auth_context_id) is not str
                or not auth_context_id
                or auth_context_id.strip() != auth_context_id
                or type(principal_context_id) is not str
                or not principal_context_id
                or principal_context_id.strip() != principal_context_id
            ):
                _fail(
                    "provider_differential_principal_bindings_invalid",
                    "Principal bindings require canonical string keys and values.",
                )
            bindings[auth_context_id] = principal_context_id

        release = registry.resolve(release_reference)
        if authority not in release.config["authorities"]:
            _fail(
                "provider_differential_authority_not_released",
                "authority is absent from the immutable Provider Release.",
                authority=authority,
                release_reference=release_reference,
            )
        profile = next((item for item in release.profiles if item.profile_id == profile_id), None)
        if profile is None:
            _fail(
                "provider_differential_profile_unknown",
                "profile_id is absent from the immutable Provider Release.",
                profile_id=profile_id,
            )

        self.release_reference = release_reference
        self.profile_id = profile_id
        self.authority = authority
        self.provider_id = release.provider_id
        self.manifest_sha256 = release.manifest_descriptor["digest"]
        self.provider_runtime_sha256 = profile.provider_runtime_sha256
        self.provider_admission_sha256 = profile.provider_admission_sha256
        self.target_id = self.manifest_sha256
        self.target_version = release_reference
        self._principal_bindings = bindings
        self._temporary = tempfile.TemporaryDirectory(prefix="datalox-release-differential-")
        self._runtime: ProviderRuntime | None = None
        self._transcript: list[dict[str, Any]] = []
        self._reset_generation = 0
        self._last_reset_state_sha256: str | None = None
        try:
            materialized = registry.materialize(
                reference=release_reference,
                profile_id=profile_id,
                output_dir=Path(self._temporary.name) / "profile",
            )
            self._runtime = ProviderRuntime(
                bundle_dir=materialized.bundle_dir,
                admission_path=materialized.admission_path,
                run_dir=Path(self._temporary.name) / "run",
            )
        except BaseException:
            self._temporary.cleanup()
            raise

    def __enter__(self) -> ProviderReleaseTarget:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    @property
    def reset_generation(self) -> int:
        return self._reset_generation

    @property
    def last_reset_state_sha256(self) -> str | None:
        return self._last_reset_state_sha256

    def reset(self, seed: int) -> None:
        if type(seed) is not int:
            _fail("provider_differential_seed_invalid", "target seed must be an integer.")
        runtime = self._require_runtime()
        runtime.reset()
        self._transcript = []
        self._reset_generation += 1
        self._last_reset_state_sha256 = runtime.behavior_state_sha256()

    def execute(
        self,
        call: ReferenceCall,
        *,
        principal_context_id: str,
    ) -> ObservedResponse:
        if not isinstance(call, ReferenceCall):
            _fail("provider_differential_call_invalid", "call must be a ReferenceCall.")
        if self._reset_generation == 0:
            _fail(
                "provider_differential_reset_required",
                "Provider Release target must be reset before execution.",
            )
        try:
            provider_principal = self._principal_bindings[principal_context_id]
        except KeyError as error:
            raise ProviderDifferentialError(
                "provider_differential_principal_unbound",
                "Reference auth context has no explicit provider principal binding.",
                {"auth_context_id": principal_context_id},
            ) from error
        request = CallRequest(
            scheme="https",
            authority=self.authority,
            method=call.method,
            path=call.path,
            query=thaw_json(call.query),
            body=thaw_json(call.body),
            headers=dict(call.headers),
            operation_id=call.operation_id,
        )
        response = self._require_runtime().handle_as_principal(
            request,
            principal_context_id=provider_principal,
        )
        self._transcript.append(
            {
                "request": {
                    "scheme": request.scheme,
                    "authority": request.authority,
                    "method": request.normalized_method(),
                    "path": request.path,
                    "query": dict(request.query),
                    "body": request.body,
                    "headers": dict(sorted(request.headers.items())),
                    "operation_id": call.operation_id,
                    "auth_context_id": principal_context_id,
                    "provider_principal_context_id": provider_principal,
                },
                "response": {
                    "status_code": response.status_code,
                    "body": response.body,
                    "headers": dict(sorted(response.headers.items())),
                },
            }
        )
        return ObservedResponse(
            status_code=response.status_code,
            body=response.body,
            headers=response.headers,
        )

    def observe(self, request: ObservationRequest) -> JsonValue:
        del request
        _fail(
            "provider_differential_observation_unsupported",
            "Provider Release differential observations require a declared adapter.",
        )

    def behavior_state_sha256(self) -> str:
        return self._require_runtime().behavior_state_sha256()

    def behavioral_fingerprint(self) -> str:
        payload = json.dumps(
            self._transcript,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def transcript(self) -> tuple[dict[str, Any], ...]:
        return tuple(json.loads(json.dumps(item)) for item in self._transcript)

    def close(self) -> None:
        runtime = self._runtime
        self._runtime = None
        if runtime is not None:
            runtime.close()
        self._temporary.cleanup()

    def _require_runtime(self) -> ProviderRuntime:
        if self._runtime is None:
            _fail(
                "provider_differential_target_closed",
                "Provider Release differential target is closed.",
            )
        return self._runtime


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderDifferentialError(code, message, details)
