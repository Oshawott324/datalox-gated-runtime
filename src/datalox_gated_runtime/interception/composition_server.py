"""TLS and Unix-socket delivery for admitted composition sessions."""

from __future__ import annotations

import json
import re
import secrets
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

from datalox_gated_runtime.composition.runtime_binding import (
    LoadedRuntimeComposition,
    load_runtime_composition,
)
from datalox_gated_runtime.interception.certificates import generate_run_certificates
from datalox_gated_runtime.interception.composition_gateway import (
    CompositionInterceptionGateway,
)
from datalox_gated_runtime.interception.server import _exclusive_write, _serve_gateway_process
from datalox_gated_runtime.rollout.provider_set import LoadedMaterializedRolloutProviderSetV2

PREPARED_COMPOSITION_RUN_SCHEMA = "datalox_interception_prepared_composition_v1"
_EPISODE_SEED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")


def prepare_composition_interception_run(
    *,
    provider_set: LoadedMaterializedRolloutProviderSetV2,
    composition_pack_dir: Path,
    composition_admission_path: Path,
    run_root: Path,
    episode_seed: str,
    initial_time: str,
    trust_dir: Path | None = None,
) -> Path:
    """Prepare one exact admitted composition without starting its data plane."""

    loaded = load_runtime_composition(
        provider_set=provider_set,
        pack_dir=composition_pack_dir,
        admission_path=composition_admission_path,
    )
    seed = _episode_seed(episode_seed)
    logical_time = _logical_time(initial_time)
    if run_root.exists() or run_root.is_symlink():
        raise ValueError("composition interception run directory must not already exist")
    if trust_dir is not None and (trust_dir.exists() or trust_dir.is_symlink()):
        raise ValueError("composition trust directory must not already exist")
    run_root.mkdir(parents=True, mode=0o700)
    run_root.chmod(0o700)
    trust_created = False
    try:
        token = secrets.token_urlsafe(32)
        _exclusive_write(run_root / "control-token", (token + "\n").encode("ascii"), 0o600)
        certificates = generate_run_certificates(
            output_dir=run_root / "certificates",
            authorities=_authorities(loaded),
        )
        if trust_dir is not None:
            trust_dir.mkdir(parents=True, mode=0o755)
            trust_created = True
            _exclusive_write(
                trust_dir / "ca.pem",
                certificates.ca_certificate.read_bytes(),
                0o644,
            )

        path = run_root / "prepared.json"
        _exclusive_write(
            path,
            (
                json.dumps(
                    _prepared_payload(loaded, episode_seed=seed, initial_time=logical_time),
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode("utf-8"),
            0o644,
        )
        return path
    except BaseException:
        shutil.rmtree(run_root, ignore_errors=True)
        if trust_created and trust_dir is not None:
            shutil.rmtree(trust_dir, ignore_errors=True)
        raise


def serve_composition_interception_gateway(
    *,
    provider_set: LoadedMaterializedRolloutProviderSetV2,
    composition_pack_dir: Path,
    composition_admission_path: Path,
    run_root: Path,
    episode_seed: str,
    initial_time: str,
    host: str,
    port: int,
    prepared: bool = False,
) -> None:
    """Serve an exact admitted composition through unchanged provider authorities."""

    seed = _episode_seed(episode_seed)
    logical_time = _logical_time(initial_time)
    loaded = load_runtime_composition(
        provider_set=provider_set,
        pack_dir=composition_pack_dir,
        admission_path=composition_admission_path,
    )
    if prepared:
        _validate_prepared_composition_run(
            loaded=loaded,
            run_root=run_root,
            episode_seed=seed,
            initial_time=logical_time,
        )
    else:
        prepare_composition_interception_run(
            provider_set=loaded.provider_set,
            composition_pack_dir=composition_pack_dir,
            composition_admission_path=composition_admission_path,
            run_root=run_root,
            episode_seed=seed,
            initial_time=logical_time,
        )
        loaded = load_runtime_composition(
            provider_set=loaded.provider_set,
            pack_dir=composition_pack_dir,
            admission_path=composition_admission_path,
        )

    try:
        token_path = run_root / "control-token"
        if token_path.is_symlink() or not token_path.is_file():
            raise ValueError("composition control token is unavailable")
        control_token = token_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError("composition control token is unavailable") from exc
    if not control_token:
        raise ValueError("composition control token is empty")

    gateway = CompositionInterceptionGateway.from_materialized_provider_set(
        provider_set=loaded.provider_set,
        composition_pack_dir=composition_pack_dir,
        composition_admission_path=composition_admission_path,
        session_root=run_root / "session",
        episode_seed=seed,
        initial_time=logical_time,
        control_token=control_token,
    )
    _serve_gateway_process(
        gateway=gateway,  # type: ignore[arg-type]
        run_root=run_root,
        host=host,
        port=port,
    )


def _validate_prepared_composition_run(
    *,
    loaded: LoadedRuntimeComposition,
    run_root: Path,
    episode_seed: str,
    initial_time: str,
) -> None:
    prepared_path = run_root / "prepared.json"
    if prepared_path.is_symlink():
        raise ValueError("prepared composition interception run is invalid")
    try:
        prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("prepared composition interception run is missing or invalid") from exc
    expected = _prepared_payload(
        loaded,
        episode_seed=episode_seed,
        initial_time=initial_time,
    )
    if prepared != expected:
        raise ValueError("prepared composition run does not match its admitted artifacts")
    required = (
        run_root / "control-token",
        run_root / "certificates/ca.pem",
        run_root / "certificates/gateway.pem",
        run_root / "certificates/gateway-key.pem",
    )
    if any(path.is_symlink() or not path.is_file() for path in required):
        raise ValueError("prepared composition interception run is incomplete")


def _prepared_payload(
    loaded: LoadedRuntimeComposition,
    *,
    episode_seed: str,
    initial_time: str,
) -> dict[str, object]:
    return {
        "schema_version": PREPARED_COMPOSITION_RUN_SCHEMA,
        "provider_set_sha256": loaded.provider_set.source_manifest_sha256,
        "providers": [
            {
                "provider_id": binding.provider.provider_id,
                "profile_id": binding.provider.profile_id,
                "release_manifest_sha256": binding.provider.release_manifest_sha256,
                "release_config_sha256": binding.release_config_sha256,
                "provider_runtime_sha256": binding.provider.provider_runtime_sha256,
                "provider_admission_sha256": binding.provider.provider_admission_sha256,
                "operation_contract_sha256": binding.provider.operation_contract_sha256,
                "authorities": list(binding.provider.authorities),
            }
            for binding in loaded.provider_set.bindings
        ],
        "composition": {
            "pack_id": loaded.pack.pack_id,
            "pack_version": loaded.pack.pack_version,
            "composition_pack_sha256": loaded.pack.canonical_sha256,
            "composition_admission_sha256": loaded.admission.canonical_sha256,
        },
        "authorities": list(_authorities(loaded)),
        "episode_seed": episode_seed,
        "initial_time": initial_time,
    }


def _authorities(loaded: LoadedRuntimeComposition) -> tuple[str, ...]:
    return tuple(
        authority
        for binding in loaded.provider_set.bindings
        for authority in binding.provider.authorities
    )


def _episode_seed(value: str) -> str:
    if not isinstance(value, str) or _EPISODE_SEED.fullmatch(value) is None:
        raise ValueError("composition episode seed is invalid")
    return value


def _logical_time(value: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("composition initial time must be an RFC 3339 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("composition initial time must be an RFC 3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("composition initial time must use UTC")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
