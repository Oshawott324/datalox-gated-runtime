"""Multi-provider transparent gateway and separately authenticated control plane."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException

from datalox_gated_runtime.data_plane import ProviderBinding, create_data_plane_app
from datalox_gated_runtime.provider_runtime import ProviderRuntime


@dataclass(frozen=True)
class GatewayProvider:
    runtime: ProviderRuntime
    binding: ProviderBinding


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
        providers: dict[str, GatewayProvider] = {}
        try:
            for bundle_dir in bundle_dirs:
                runtime = ProviderRuntime(
                    bundle_dir=bundle_dir,
                    run_dir=run_root / bundle_dir.name,
                )
                provider_id = runtime.bundle.manifest.provider_id
                if provider_id in providers:
                    runtime.close()
                    raise ValueError(f"duplicate provider id: {provider_id}")
                providers[provider_id] = GatewayProvider(
                    runtime=runtime,
                    binding=ProviderBinding(runtime),
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
