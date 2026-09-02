"""One downstream task episode over the task-free Medusa provider runtime."""

from __future__ import annotations

import hashlib
import json
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Self

from datalox_dirty_integration.policy import LIST_PRODUCTS_OPERATION, SeededCommercePolicy
from datalox_gated_runtime.interception.interventions import (
    DeliveryInterventionSession,
    ProviderBaseBinding,
)
from datalox_gated_runtime.models import CallRequest, GateResponse
from datalox_gated_runtime.provider_runtime import ProviderRuntime
from datalox_gated_runtime.provider_runtime.release import load_provider_release


def sha256_file(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


class CommerceEpisode:
    """Owns a clean provider instance plus one switchable intervention session."""

    def __init__(
        self,
        *,
        provider_config: Path,
        policy: SeededCommercePolicy,
        intervention_seed: str,
        intervention_enabled: bool,
        provider_admission: Path,
        provider_runtime_bundle: Path,
        provider_release: Path,
        provider_profile_id: str = "default",
    ) -> None:
        self.provider_config = provider_config.resolve()
        self.provider_admission = provider_admission.resolve()
        self.provider_runtime_bundle = provider_runtime_bundle.resolve()
        self.provider_release_path = provider_release.resolve()
        if not self.provider_config.is_file():
            raise FileNotFoundError(f"provider config does not exist: {self.provider_config}")
        if not self.provider_admission.is_file():
            raise FileNotFoundError(f"provider admission does not exist: {self.provider_admission}")
        if not self.provider_runtime_bundle.is_dir():
            raise FileNotFoundError(
                f"provider runtime bundle does not exist: {self.provider_runtime_bundle}"
            )
        if not self.provider_release_path.is_dir():
            raise FileNotFoundError(
                f"provider release does not exist: {self.provider_release_path}"
            )
        release = load_provider_release(self.provider_release_path)
        profile = next(
            (item for item in release.profiles if item.profile_id == provider_profile_id), None
        )
        if profile is None:
            raise ValueError(
                f"provider release has no profile {provider_profile_id!r}: "
                f"{self.provider_release_path}"
            )
        runtime_sha256 = sha256_file(self.provider_runtime_bundle / "provider-runtime.json")
        admission_sha256 = sha256_file(self.provider_admission)
        if runtime_sha256 != profile.provider_runtime_sha256:
            raise ValueError("provider runtime bundle does not match the selected release profile")
        if admission_sha256 != profile.provider_admission_sha256:
            raise ValueError("provider admission does not match the selected release profile")
        self._temporary = tempfile.TemporaryDirectory(prefix="datalox-verifiers-pair-")
        root = Path(self._temporary.name)
        self.provider = ProviderRuntime(
            bundle_dir=self.provider_runtime_bundle,
            admission_path=self.provider_admission,
            run_dir=root / "provider-run",
        )
        assurance = self.provider.export()["provider_assurance"]
        if assurance["status"] != "valid":
            raise RuntimeError("provider runtime admission is not valid")
        if assurance["operation_claims_sha256"] != profile.operation_claims_sha256:
            raise ValueError("provider operation claims do not match the selected release profile")
        release_config_sha256 = release.manifest["config"]["digest"]
        self.interventions = DeliveryInterventionSession(
            policy,
            provider=ProviderBaseBinding(
                provider_id=release.provider_id,
                release_version=release.release_version,
                profile_id=profile.profile_id,
                bundle_version=release.config["bundle_version"],
                release_config_sha256=release_config_sha256,
                provider_runtime_sha256=profile.provider_runtime_sha256,
                provider_admission_sha256=assurance["provider_admission_sha256"],
                operation_contract_sha256=release.config["operation_contract_sha256"],
            ),
            allowed_read_operation_ids=frozenset({LIST_PRODUCTS_OPERATION}),
            seed=intervention_seed,
            enabled=intervention_enabled,
        )
        self.submitted: dict[str, Any] | None = None
        self.delivered_calls: list[dict[str, Any]] = []
        self.rate_limited_calls = 0
        self.provider_config_sha256 = sha256_file(self.provider_config)
        self.provider_runtime_sha256 = runtime_sha256
        self.provider_admission_sha256 = admission_sha256
        self.operation_claims_sha256 = assurance["operation_claims_sha256"]
        self.operation_contract_sha256 = release.config["operation_contract_sha256"]
        self.provider_release_config_sha256 = release_config_sha256
        self.provider_release_digest = release.manifest_descriptor["digest"]
        self.provider_release_version = release.release_version
        self.provider_profile_id = profile.profile_id
        self.provider_bundle_version = release.config["bundle_version"]
        self.initial_state_fingerprint = self._initial_state_fingerprint()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def close(self) -> None:
        self.provider.close()
        self._temporary.cleanup()

    def reset(self) -> None:
        self.provider.reset()
        self.interventions.reset()
        self.submitted = None
        self.delivered_calls.clear()
        self.rate_limited_calls = 0

    def list_products(self, *, offset: int, limit: int = 10) -> GateResponse:
        if type(offset) is not int or offset < 0:
            raise ValueError("offset must be a non-negative integer")
        if limit != 10:
            raise ValueError("this admitted slice requires limit=10")
        request = CallRequest(
            method="GET",
            scheme="https",
            authority="api.medusa.local",
            path="/store/products",
            query={"limit": str(limit), "offset": str(offset)},
            operation_id=LIST_PRODUCTS_OPERATION,
        )
        response = self.interventions.handle(
            request,
            lambda: self.provider.handle(request),
            operation_id=LIST_PRODUCTS_OPERATION,
        )
        if response.status_code == 429:
            self.rate_limited_calls += 1
        self.delivered_calls.append(
            {
                "request": {
                    "method": request.method,
                    "authority": request.authority,
                    "path": request.path,
                    "query": deepcopy(request.query),
                },
                "observation": {
                    "status_code": response.status_code,
                    "headers": deepcopy(response.headers),
                    "body": deepcopy(response.body),
                },
            }
        )
        return response

    def submit_products(self, raw: str, *, reported_count: Any) -> dict[str, Any]:
        try:
            submitted = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("products_json must be a JSON array") from exc
        if not isinstance(submitted, list):
            raise TypeError("products_json must be a JSON array")
        self.submitted = {"products": submitted, "reported_count": reported_count}
        return {"received": True}

    def export(self) -> dict[str, Any]:
        return {
            "provider_config_sha256": self.provider_config_sha256,
            "provider_runtime_sha256": self.provider_runtime_sha256,
            "provider_admission_sha256": self.provider_admission_sha256,
            "operation_claims_sha256": self.operation_claims_sha256,
            "operation_contract_sha256": self.operation_contract_sha256,
            "provider_release_config_sha256": self.provider_release_config_sha256,
            "provider_release_digest": self.provider_release_digest,
            "provider_release_version": self.provider_release_version,
            "provider_profile_id": self.provider_profile_id,
            "provider_bundle_version": self.provider_bundle_version,
            "initial_state_fingerprint": self.initial_state_fingerprint,
            "provider": self.provider.export(),
            "intervention": self.interventions.export(),
            "delivered_calls": deepcopy(self.delivered_calls),
            "request_discipline": {
                "rate_limited_calls": self.rate_limited_calls,
                "delivered_call_count": len(self.delivered_calls),
            },
        }

    def _initial_state_fingerprint(self) -> str:
        export = self.provider.export()
        provider_state = export.get("provider_state")
        canonical = json.dumps(
            {
                "provider_config_sha256": self.provider_config_sha256,
                "provider_admission_sha256": self.provider_admission_sha256,
                "operation_claims_sha256": self.operation_claims_sha256,
                "operation_contract_sha256": self.operation_contract_sha256,
                "provider_release_config_sha256": self.provider_release_config_sha256,
                "provider_release_digest": self.provider_release_digest,
                "provider_release_version": self.provider_release_version,
                "provider_profile_id": self.provider_profile_id,
                "provider_bundle_version": self.provider_bundle_version,
                "provider_state": provider_state,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return f"sha256:{hashlib.sha256(canonical).hexdigest()}"
