"""Multi-provider transparent gateway and separately authenticated control plane."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

from datalox_gated_runtime.data_plane import ProviderBinding, create_data_plane_app
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    load_provider_admission,
)
from datalox_gated_runtime.provider_runtime.release import (
    PROVIDER_RELEASE_MAX_JSON_BYTES,
    PROVIDER_RELEASE_SCHEMA_VERSION,
)


@dataclass(frozen=True)
class GatewayProvider:
    runtime: ProviderRuntime
    binding: ProviderBinding
    release_config: dict[str, object] | None = None


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
        )

    @classmethod
    def from_admitted_release_bindings(
        cls,
        *,
        bundle_admission_configs: tuple[tuple[Path, Path, Path], ...],
        run_root: Path,
        control_token: str | None = None,
    ) -> InterceptionGateway:
        """Create a gateway with admitted runtimes and exact release operation metadata."""

        if not bundle_admission_configs:
            raise ValueError("at least one admitted provider release binding is required")
        return cls._from_bundle_bindings(
            bundle_admission_configs=bundle_admission_configs,
            run_root=run_root,
            control_token=control_token,
        )

    @classmethod
    def _from_bundle_bindings(
        cls,
        *,
        bundle_admission_configs: tuple[tuple[Path, Path | None, Path | None], ...],
        run_root: Path,
        control_token: str | None,
    ) -> InterceptionGateway:
        providers: dict[str, GatewayProvider] = {}
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
        except Exception:
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
        for provider in self.providers.values():
            provider.runtime.close()

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

        @app.post("/v1/providers/{provider_id}/reset")
        def reset(
            provider_id: str,
            _: None = Depends(authorize),
        ) -> dict[str, object]:
            provider = self._provider(provider_id)
            with provider.binding.lock:
                return provider.runtime.reset()

        return app

    def _provider(self, provider_id: str) -> GatewayProvider:
        provider = self.providers.get(provider_id)
        if provider is None:
            raise HTTPException(status_code=404, detail="provider runtime not found")
        return provider


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
        raise ValueError("provider release config must contain an object")
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
