"""Multi-provider transparent gateway and separately authenticated control plane."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from datalox_gated_runtime.data_plane import ProviderBinding, create_data_plane_app
from datalox_gated_runtime.interception.interventions import (
    DELIVERY_INTERVENTION_SCHEMA_VERSION,
    DeliveryInterventionHandler,
    DeliveryInterventionSession,
    ProviderBaseBinding,
    load_delivery_intervention,
    validate_policy_for_operations,
)
from datalox_gated_runtime.interception.interventions_v2 import (
    DELIVERY_INTERVENTION_V2_SCHEMA_VERSION,
    DeliveryInterventionHandlerV2,
    DeliveryInterventionResetConflict,
    DeliveryInterventionSessionV2,
    intervention_schema_version,
    load_delivery_intervention_v2,
    validate_v2_policy_for_operations,
)
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    load_provider_admission,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.release import (
    PROVIDER_RELEASE_MAX_JSON_BYTES,
    PROVIDER_RELEASE_SCHEMA_VERSION,
)


@dataclass(frozen=True)
class GatewayProvider:
    runtime: ProviderRuntime
    binding: ProviderBinding
    release_config: dict[str, object] | None = None
    intervention: DeliveryInterventionSession | DeliveryInterventionSessionV2 | None = None


class InterceptionGateway:
    def __init__(
        self,
        *,
        providers: dict[str, GatewayProvider],
        control_token: str,
    ) -> None:
        if not providers:
            raise ValueError("at least one provider runtime is required")
        if not control_token:
            raise ValueError("control token must be non-empty")
        self.providers = providers
        self._control_token = control_token
        authority_bindings: dict[str, ProviderBinding] = {}
        for provider in providers.values():
            for authority in provider.runtime.authorities:
                if authority in authority_bindings:
                    raise ValueError(f"duplicate provider authority: {authority}")
                authority_bindings[authority] = provider.binding
        self.data_app = create_data_plane_app(authority_bindings)
        self.control_app = self._create_control_app()

    @classmethod
    def from_bundles(
        cls,
        *,
        bundle_dirs: tuple[Path, ...],
        run_root: Path,
        control_token: str | None = None,
    ) -> InterceptionGateway:
        return cls._from_bundle_bindings(
            bundle_admission_configs=tuple((bundle_dir, None, None) for bundle_dir in bundle_dirs),
            run_root=run_root,
            control_token=control_token,
            delivery_intervention_configs=None,
        )

    @classmethod
    def from_admitted_bundles(
        cls,
        *,
        bundle_admissions: tuple[tuple[Path, Path], ...],
        run_root: Path,
        control_token: str | None = None,
    ) -> InterceptionGateway:
        """Create a gateway from explicit bundle/admission bindings."""

        if not bundle_admissions:
            raise ValueError("at least one provider bundle/admission binding is required")
        return cls._from_bundle_bindings(
            bundle_admission_configs=tuple(
                (bundle_dir, admission_path, None)
                for bundle_dir, admission_path in bundle_admissions
            ),
            run_root=run_root,
            control_token=control_token,
            delivery_intervention_configs=None,
        )

    @classmethod
    def from_admitted_release_bindings(
        cls,
        *,
        bundle_admission_configs: tuple[tuple[Path, Path, Path], ...],
        run_root: Path,
        control_token: str | None = None,
        delivery_intervention_configs: Mapping[str, Path] | None = None,
    ) -> InterceptionGateway:
        """Create a gateway with admitted runtimes and exact release operation metadata."""

        if not bundle_admission_configs:
            raise ValueError("at least one admitted provider release binding is required")
        return cls._from_bundle_bindings(
            bundle_admission_configs=bundle_admission_configs,
            run_root=run_root,
            control_token=control_token,
            delivery_intervention_configs=delivery_intervention_configs,
        )

    @classmethod
    def _from_bundle_bindings(
        cls,
        *,
        bundle_admission_configs: tuple[tuple[Path, Path | None, Path | None], ...],
        run_root: Path,
        control_token: str | None,
        delivery_intervention_configs: Mapping[str, Path] | None,
    ) -> InterceptionGateway:
        providers: dict[str, GatewayProvider] = {}
        v2_sessions: list[DeliveryInterventionSessionV2] = []
        pending_interventions = dict(delivery_intervention_configs or {})
        try:
            for index, (bundle_dir, admission_path, release_config_path) in enumerate(
                bundle_admission_configs
            ):
                release_config = (
                    _load_release_config(
                        release_config_path=release_config_path,
                        admission_path=admission_path,
                    )
                    if release_config_path is not None and admission_path is not None
                    else None
                )
                runtime = ProviderRuntime(
                    bundle_dir=bundle_dir,
                    run_dir=run_root / f"{index:04d}",
                    admission_path=admission_path,
                )
                provider_id = runtime.bundle.manifest.provider_id
                if release_config is not None and (
                    release_config.get("provider_id") != provider_id
                    or release_config.get("authorities") != list(runtime.authorities)
                ):
                    runtime.close()
                    raise ValueError("provider release config does not match its provider runtime")
                if provider_id in providers:
                    runtime.close()
                    raise ValueError(f"duplicate provider id: {provider_id}")
                providers[provider_id] = GatewayProvider(
                    runtime=runtime,
                    binding=ProviderBinding(runtime),
                    release_config=release_config,
                )
                intervention: DeliveryInterventionSession | DeliveryInterventionSessionV2 | None = (
                    None
                )
                handler: Any = runtime
                intervention_config_path = pending_interventions.pop(provider_id, None)
                if intervention_config_path is not None:
                    if release_config is None:
                        raise ValueError(
                            "delivery interventions require an admitted provider release"
                        )
                    if admission_path is None:
                        raise ValueError(
                            "delivery interventions require an exact provider admission"
                        )
                    operations = _release_operations(release_config)
                    provider_runtime_sha256 = _sha256_file(
                        runtime.bundle.root / "provider-runtime.json"
                    )
                    provider_admission_sha256 = _sha256_file(admission_path)
                    profile_id = _selected_profile_id(
                        release_config,
                        provider_runtime_sha256=provider_runtime_sha256,
                        provider_admission_sha256=provider_admission_sha256,
                    )
                    operation_mutability = {
                        operation["operation_id"]: operation["mutability"]
                        for operation in operations
                    }
                    provider_binding = ProviderBaseBinding(
                        provider_id=provider_id,
                        release_version=release_config["release_version"],
                        profile_id=profile_id,
                        bundle_version=runtime.bundle.manifest.bundle_version,
                        release_config_sha256=_sha256_file(release_config_path),
                        provider_runtime_sha256=provider_runtime_sha256,
                        provider_admission_sha256=provider_admission_sha256,
                        operation_contract_sha256=release_config["operation_contract_sha256"],
                    )
                    schema_version = intervention_schema_version(intervention_config_path)
                    if schema_version == DELIVERY_INTERVENTION_SCHEMA_VERSION:
                        loaded = load_delivery_intervention(intervention_config_path)
                        if loaded.provider_id != provider_id:
                            raise ValueError(
                                "delivery intervention provider_id does not match its runtime"
                            )
                        validate_policy_for_operations(
                            loaded.policy,
                            operation_mutability=operation_mutability,
                        )
                        intervention = DeliveryInterventionSession(
                            loaded.policy,
                            provider=provider_binding,
                            allowed_read_operation_ids=frozenset(
                                operation_id
                                for operation_id, mutability in operation_mutability.items()
                                if mutability == "read"
                            ),
                            seed=loaded.seed,
                            enabled=loaded.enabled,
                            trace_path=runtime.run_dir / "delivery-interventions.jsonl",
                        )
                        handler = DeliveryInterventionHandler(
                            base_handler=runtime,
                            session=intervention,
                            resolve_operation_id=_operation_resolver(operations),
                        )
                    elif schema_version == DELIVERY_INTERVENTION_V2_SCHEMA_VERSION:
                        loaded_v2 = load_delivery_intervention_v2(intervention_config_path)
                        if loaded_v2.provider_id != provider_id:
                            raise ValueError(
                                "delivery intervention provider_id does not match its runtime"
                            )
                        validate_v2_policy_for_operations(
                            loaded_v2.policy,
                            operation_mutability=operation_mutability,
                        )
                        intervention = DeliveryInterventionSessionV2(
                            loaded_v2.policy,
                            provider=provider_binding,
                            operation_mutability=operation_mutability,
                            seed=loaded_v2.seed,
                            enabled=loaded_v2.enabled,
                            journal_path=runtime.run_dir / "delivery-interventions-v2.sqlite3",
                            identity_policy=runtime.bundle.identity_policy,
                        )
                        v2_sessions.append(intervention)
                        handler = DeliveryInterventionHandlerV2(
                            base_handler=runtime,
                            session=intervention,
                            resolve_operation_id=_operation_resolver(operations),
                        )
                    else:
                        raise ValueError("unsupported delivery intervention schema")
                providers[provider_id] = GatewayProvider(
                    runtime=runtime,
                    binding=ProviderBinding(handler),
                    release_config=release_config,
                    intervention=intervention,
                )
            if pending_interventions:
                raise ValueError(
                    "delivery intervention configs reference unknown providers: "
                    + ", ".join(sorted(pending_interventions))
                )
        except Exception:
            for session in v2_sessions:
                try:
                    session.shutdown()
                except Exception:  # noqa: BLE001, S110 - preserve the construction failure
                    pass
            for provider in providers.values():
                provider.runtime.close()
            raise
        return cls(
            providers=providers,
            control_token=control_token or secrets.token_urlsafe(32),
        )

    @property
    def authorities(self) -> tuple[str, ...]:
        return tuple(
            authority
            for provider in self.providers.values()
            for authority in provider.runtime.authorities
        )

    def close(self) -> None:
        failures: list[Exception] = []
        for provider in self.providers.values():
            try:
                if isinstance(provider.intervention, DeliveryInterventionSessionV2):
                    provider.intervention.shutdown()
            except Exception as exc:  # noqa: BLE001 - close all independently owned resources
                failures.append(exc)
            try:
                provider.runtime.close()
            except Exception as exc:  # noqa: BLE001 - close all independently owned resources
                failures.append(exc)
        if failures:
            raise RuntimeError("one or more gateway resources failed to close") from failures[0]

    def _create_control_app(self) -> FastAPI:
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        def authorize(x_datalox_control_token: str | None = Header(default=None)) -> None:
            if x_datalox_control_token is None or not secrets.compare_digest(
                x_datalox_control_token, self._control_token
            ):
                raise HTTPException(status_code=401, detail="invalid control token")

        @app.get("/health")
        def health(_: None = Depends(authorize)) -> dict[str, object]:
            return {"ok": True, "providers": sorted(self.providers)}

        @app.get("/v1/providers/{provider_id}/export")
        def export(
            provider_id: str,
            _: None = Depends(authorize),
        ) -> dict[str, object]:
            provider = self._provider(provider_id)
            with provider.binding.lock:
                return provider.runtime.export()

        @app.get("/v1/providers/{provider_id}/time")
        def provider_time(
            provider_id: str,
            _: None = Depends(authorize),
        ) -> dict[str, object]:
            provider = self._provider(provider_id)
            with provider.binding.lock:
                try:
                    return provider.runtime.provider_time()
                except ProviderRuntimeError as exc:
                    raise _provider_time_http_error(exc) from exc

        @app.post("/v1/providers/{provider_id}/time/advance")
        async def advance_provider_time(
            provider_id: str,
            request: Request,
            _: None = Depends(authorize),
        ) -> dict[str, object]:
            target = await _provider_time_target(request)
            provider = self._provider(provider_id)
            with provider.binding.lock:
                try:
                    return provider.runtime.advance_provider_time(target)
                except ProviderRuntimeError as exc:
                    raise _provider_time_http_error(exc) from exc

        @app.get("/v1/providers/{provider_id}/delivery-interventions/export")
        def export_delivery_interventions(
            provider_id: str,
            _: None = Depends(authorize),
        ) -> dict[str, object]:
            provider = self._provider(provider_id)
            if provider.intervention is None:
                raise HTTPException(
                    status_code=404,
                    detail="provider delivery intervention is not configured",
                )
            with provider.binding.lock:
                return provider.intervention.export()

        @app.post("/v1/providers/{provider_id}/reset")
        def reset(
            provider_id: str,
            _: None = Depends(authorize),
        ) -> dict[str, object]:
            provider = self._provider(provider_id)
            with provider.binding.lock:
                try:
                    if isinstance(provider.intervention, DeliveryInterventionSessionV2):
                        provider.intervention.ensure_resettable()
                    result = provider.runtime.reset()
                    if provider.intervention is not None:
                        provider.intervention.reset()
                    return result
                except DeliveryInterventionResetConflict as exc:
                    raise HTTPException(status_code=409, detail=str(exc)) from exc
                except Exception as exc:
                    if isinstance(provider.intervention, DeliveryInterventionSessionV2):
                        try:
                            provider.intervention.latch_reset_failure(
                                "Provider state and intervention journal reset did not complete "
                                "as one trusted control operation."
                            )
                        except Exception as latch_exc:
                            raise HTTPException(
                                status_code=500,
                                detail=(
                                    "provider reset failed and the terminal latch could not "
                                    "be persisted"
                                ),
                            ) from latch_exc
                    raise HTTPException(
                        status_code=500,
                        detail="provider reset failed and the session is terminally latched",
                    ) from exc

        return app

    def _provider(self, provider_id: str) -> GatewayProvider:
        provider = self.providers.get(provider_id)
        if provider is None:
            raise HTTPException(status_code=404, detail="provider runtime not found")
        return provider


async def _provider_time_target(request: Request) -> str:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail={
                "code": "provider_time_control_content_type_invalid",
                "message": "Provider time advance requires Content-Type: application/json.",
            },
        )
    payload = await request.body()
    if len(payload) > 4096:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "provider_time_control_body_too_large",
                "message": "Provider time advance body exceeds the control-plane limit.",
            },
        )
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "provider_time_control_body_invalid",
                "message": "Provider time advance body must be valid JSON.",
            },
        ) from exc
    if (
        not isinstance(decoded, dict)
        or set(decoded) != {"target"}
        or not isinstance(decoded["target"], str)
    ):
        raise HTTPException(
            status_code=400,
            detail={
                "code": "provider_time_control_fields_invalid",
                "message": "Provider time advance requires exactly one string target field.",
            },
        )
    return decoded["target"]


def _provider_time_http_error(error: ProviderRuntimeError) -> HTTPException:
    if error.code == "world_clock_reverse_forbidden":
        status_code = 409
    elif error.code == "provider_runtime_time_invalid":
        status_code = 400
    else:
        status_code = 422
    return HTTPException(
        status_code=status_code,
        detail={"code": error.code, "message": error.message, "details": error.details},
    )


def _load_release_config(
    *,
    release_config_path: Path,
    admission_path: Path,
) -> dict[str, object]:
    if release_config_path.is_symlink():
        raise ValueError("provider release config must not be a symbolic link")
    try:
        resolved = release_config_path.resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size > PROVIDER_RELEASE_MAX_JSON_BYTES:
            raise ValueError("provider release config is not a bounded regular file")
        payload = resolved.read_bytes()
        if len(payload) > PROVIDER_RELEASE_MAX_JSON_BYTES:
            raise ValueError("provider release config exceeds its size limit")
        config = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"provider release config is invalid: {exc}") from exc
    if not isinstance(config, dict):
        raise TypeError("provider release config must contain an object")
    admission = load_provider_admission(admission_path)
    operations = sorted(admission["operations"], key=lambda operation: operation["operation_id"])
    if (
        config.get("schema_version") != PROVIDER_RELEASE_SCHEMA_VERSION
        or config.get("provider_id") != admission["provider_id"]
        or config.get("operations") != operations
        or config.get("operation_contract_sha256") != canonical_json_sha256(operations)
    ):
        raise ValueError("provider release config does not match its provider admission")
    return config


def _release_operations(release_config: Mapping[str, object]) -> tuple[dict[str, Any], ...]:
    value = release_config.get("operations")
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(item, dict) for item in value)
    ):
        raise ValueError("provider release operations are invalid")
    return tuple(value)


def _operation_resolver(
    operations: tuple[dict[str, Any], ...],
) -> Any:
    surfaces = tuple(
        (
            operation["operation_id"],
            operation["native_surface"]["authority"],
            operation["native_surface"]["method"],
            tuple(operation["native_surface"]["path_template"].strip("/").split("/")),
        )
        for operation in operations
    )

    def resolve(request: CallRequest) -> str | None:
        request_segments = tuple(request.path.strip("/").split("/"))
        matches = [
            operation_id
            for operation_id, authority, method, path_segments in surfaces
            if request.authority == authority
            and request.normalized_method() == method
            and len(request_segments) == len(path_segments)
            and all(
                declared == actual
                or (
                    declared.startswith("{")
                    and declared.endswith("}")
                    and len(declared) > 2
                    and bool(actual)
                )
                for declared, actual in zip(path_segments, request_segments, strict=True)
            )
        ]
        if len(matches) > 1:
            raise ValueError("request resolves to multiple admitted provider operations")
        return matches[0] if matches else None

    return resolve


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _selected_profile_id(
    release_config: Mapping[str, object],
    *,
    provider_runtime_sha256: str,
    provider_admission_sha256: str,
) -> str:
    profiles = release_config.get("profiles")
    if not isinstance(profiles, list):
        raise TypeError("provider release profiles are invalid")
    matches = [
        profile["profile_id"]
        for profile in profiles
        if isinstance(profile, dict)
        and profile.get("provider_runtime_sha256") == provider_runtime_sha256
        and profile.get("provider_admission_sha256") == provider_admission_sha256
    ]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise ValueError("provider runtime does not match exactly one release profile")
    return matches[0]
