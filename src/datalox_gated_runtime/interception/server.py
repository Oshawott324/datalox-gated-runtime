"""TLS data-plane process with a Unix-socket control plane."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import uvicorn

from datalox_gated_runtime.interception.certificates import generate_run_certificates
from datalox_gated_runtime.interception.gateway import InterceptionGateway
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.provider_runtime import (
    load_provider_admission,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.release import (
    PROVIDER_RELEASE_MAX_JSON_BYTES,
    PROVIDER_RELEASE_SCHEMA_VERSION,
)

PREPARED_RUN_SCHEMA = "datalox_interception_prepared_v1"
PREPARED_ADMITTED_RUN_SCHEMA = "datalox_interception_prepared_admitted_v1"


@dataclass(frozen=True)
class _AdmittedServerBinding:
    provider_id: str
    bundle_dir: Path
    admission_path: Path
    release_config_path: Path
    manifest_sha256: str
    admission_sha256: str
    release_config_sha256: str
    authorities: tuple[str, ...]


def prepare_interception_run(
    *,
    bundle_dirs: tuple[Path, ...],
    run_root: Path,
    trust_dir: Path | None = None,
) -> Path:
    if run_root.exists():
        raise ValueError("interception run directory must not already exist")
    run_root.mkdir(parents=True)
    bundles = [load_provider_runtime_bundle(path) for path in bundle_dirs]
    authorities = tuple(
        authority for bundle in bundles for authority in bundle.manifest.authorities
    )
    if len(set(authorities)) != len(authorities):
        raise ValueError("provider runtime authorities must be unique across bundles")
    control_token = secrets.token_urlsafe(32)
    _exclusive_write(run_root / "control-token", (control_token + "\n").encode("ascii"), 0o600)
    certificates = generate_run_certificates(
        output_dir=run_root / "certificates",
        authorities=authorities,
    )
    if trust_dir is not None:
        trust_dir.mkdir(parents=True, exist_ok=True)
        _exclusive_write(trust_dir / "ca.pem", certificates.ca_certificate.read_bytes(), 0o644)
    prepared = {
        "schema_version": PREPARED_RUN_SCHEMA,
        "bundles": [
            {
                "provider_id": bundle.manifest.provider_id,
                "manifest_sha256": _sha256(bundle.root / "provider-runtime.json"),
            }
            for bundle in bundles
        ],
        "authorities": list(authorities),
    }
    path = run_root / "prepared.json"
    _exclusive_write(
        path,
        (json.dumps(prepared, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        0o644,
    )
    return path


def prepare_admitted_interception_run(
    *,
    bundle_admission_configs: tuple[tuple[Path, Path, Path], ...],
    run_root: Path,
    trust_dir: Path | None = None,
) -> Path:
    """Prepare TLS and control state bound to explicit admitted provider runtimes."""

    bindings = _load_admitted_bindings(bundle_admission_configs)
    return _prepare_run(
        bindings=bindings,
        schema_version=PREPARED_ADMITTED_RUN_SCHEMA,
        run_root=run_root,
        trust_dir=trust_dir,
    )


def check_interception_ready(*, run_root: Path) -> dict[str, object]:
    """Query the private control socket without exposing its token to the agent."""

    try:
        token = (run_root / "control-token").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise ValueError("interception control token is unavailable") from exc
    if not token:
        raise ValueError("interception control token is empty")
    request = (
        "GET /health HTTP/1.1\r\n"
        "Host: localhost\r\n"
        f"x-datalox-control-token: {token}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    response = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(str(run_root / "control.sock"))
            client.sendall(request)
            while chunk := client.recv(64 * 1024):
                response.extend(chunk)
    except OSError as exc:
        raise ValueError("interception control plane is unavailable") from exc
    header, separator, body = bytes(response).partition(b"\r\n\r\n")
    status_line = header.split(b"\r\n", 1)[0] if header else b""
    if separator != b"\r\n\r\n" or status_line != b"HTTP/1.1 200 OK":
        raise ValueError("interception control plane is not ready")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("interception control plane returned an invalid health response") from exc
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise ValueError("interception control plane reported an unhealthy runtime")
    return payload


def serve_interception_gateway(
    *,
    bundle_dirs: tuple[Path, ...],
    run_root: Path,
    host: str,
    port: int,
    prepared: bool = False,
) -> None:
    if prepared:
        _validate_prepared_run(bundle_dirs=bundle_dirs, run_root=run_root)
    else:
        prepare_interception_run(bundle_dirs=bundle_dirs, run_root=run_root)
    control_token = (run_root / "control-token").read_text(encoding="ascii").strip()

    gateway = InterceptionGateway.from_bundles(
        bundle_dirs=bundle_dirs,
        run_root=run_root / "providers",
        control_token=control_token,
    )
    _serve_gateway_process(gateway=gateway, run_root=run_root, host=host, port=port)


def serve_admitted_interception_gateway(
    *,
    bundle_admission_configs: tuple[tuple[Path, Path, Path], ...],
    run_root: Path,
    host: str,
    port: int,
    prepared: bool = False,
) -> None:
    """Serve a gateway whose providers all carry exact admission bindings."""

    bindings = _load_admitted_bindings(bundle_admission_configs)
    if prepared:
        _validate_admitted_prepared_run(bindings=bindings, run_root=run_root)
    else:
        _prepare_run(
            bindings=bindings,
            schema_version=PREPARED_ADMITTED_RUN_SCHEMA,
            run_root=run_root,
            trust_dir=None,
        )
    control_token = (run_root / "control-token").read_text(encoding="ascii").strip()
    gateway = InterceptionGateway.from_admitted_release_bindings(
        bundle_admission_configs=tuple(
            (
                binding.bundle_dir,
                binding.admission_path,
                binding.release_config_path,
            )
            for binding in bindings
        ),
        run_root=run_root / "providers",
        control_token=control_token,
    )
    _serve_gateway_process(gateway=gateway, run_root=run_root, host=host, port=port)


def _exclusive_write(path: Path, content: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _wait_for_socket(path: Path, thread: threading.Thread) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            return
        if not thread.is_alive():
            raise ValueError("control server exited before creating its Unix socket")
        time.sleep(0.05)
    raise ValueError("control server did not create its Unix socket")


def _validate_prepared_run(*, bundle_dirs: tuple[Path, ...], run_root: Path) -> None:
    try:
        prepared = json.loads((run_root / "prepared.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("prepared interception run is missing or invalid") from exc
    bundles = [load_provider_runtime_bundle(path) for path in bundle_dirs]
    expected = {
        "schema_version": PREPARED_RUN_SCHEMA,
        "bundles": [
            {
                "provider_id": bundle.manifest.provider_id,
                "manifest_sha256": _sha256(bundle.root / "provider-runtime.json"),
            }
            for bundle in bundles
        ],
        "authorities": [
            authority for bundle in bundles for authority in bundle.manifest.authorities
        ],
    }
    if prepared != expected:
        raise ValueError("prepared interception run does not match provider bundles")
    required = (
        run_root / "control-token",
        run_root / "certificates/ca.pem",
        run_root / "certificates/gateway.pem",
        run_root / "certificates/gateway-key.pem",
    )
    if any(not path.is_file() for path in required):
        raise ValueError("prepared interception run is incomplete")


def _load_admitted_bindings(
    bundle_admission_configs: tuple[tuple[Path, Path, Path], ...],
) -> tuple[_AdmittedServerBinding, ...]:
    if not bundle_admission_configs:
        raise ValueError("at least one admitted provider release binding is required")
    bindings: list[_AdmittedServerBinding] = []
    provider_ids: set[str] = set()
    authorities: set[str] = set()
    for index, binding in enumerate(bundle_admission_configs):
        if not isinstance(binding, tuple) or len(binding) != 3:
            raise ValueError(f"admitted provider release binding {index} is invalid")
        bundle_dir, admission_path, release_config_path = binding
        bundle = load_provider_runtime_bundle(bundle_dir)
        admission = load_provider_admission(admission_path)
        release_config, resolved_release_config_path = _load_release_config(release_config_path)
        runtime_digest = _sha256(bundle.root / "provider-runtime.json")
        admission_digest = _sha256(admission_path.resolve(strict=True))
        release_config_digest = _sha256(resolved_release_config_path)
        operations = sorted(
            admission["operations"], key=lambda operation: operation["operation_id"]
        )
        if (
            admission["provider_id"] != bundle.manifest.provider_id
            or admission["bundle_version"] != bundle.manifest.bundle_version
            or admission["provider_runtime_sha256"] != runtime_digest
            or release_config.get("schema_version") != PROVIDER_RELEASE_SCHEMA_VERSION
            or release_config.get("provider_id") != bundle.manifest.provider_id
            or release_config.get("authorities") != list(bundle.manifest.authorities)
            or release_config.get("operations") != operations
            or release_config.get("operation_contract_sha256") != canonical_json_sha256(operations)
        ):
            raise ValueError(f"admitted provider release binding {index} is inconsistent")
        if bundle.manifest.provider_id in provider_ids:
            raise ValueError(f"duplicate provider id: {bundle.manifest.provider_id}")
        provider_ids.add(bundle.manifest.provider_id)
        for authority in bundle.manifest.authorities:
            if authority in authorities:
                raise ValueError(f"duplicate provider authority: {authority}")
            authorities.add(authority)
        bindings.append(
            _AdmittedServerBinding(
                provider_id=bundle.manifest.provider_id,
                bundle_dir=bundle.root,
                admission_path=admission_path.resolve(strict=True),
                release_config_path=resolved_release_config_path,
                manifest_sha256=runtime_digest,
                admission_sha256=admission_digest,
                release_config_sha256=release_config_digest,
                authorities=bundle.manifest.authorities,
            )
        )
    return tuple(bindings)


def _prepare_run(
    *,
    bindings: tuple[_AdmittedServerBinding, ...],
    schema_version: str,
    run_root: Path,
    trust_dir: Path | None,
) -> Path:
    if run_root.exists() or run_root.is_symlink():
        raise ValueError("interception run directory must not already exist")
    run_root.mkdir(parents=True)
    authorities = tuple(authority for binding in bindings for authority in binding.authorities)
    control_token = secrets.token_urlsafe(32)
    _exclusive_write(run_root / "control-token", (control_token + "\n").encode("ascii"), 0o600)
    certificates = generate_run_certificates(
        output_dir=run_root / "certificates",
        authorities=authorities,
    )
    if trust_dir is not None:
        trust_dir.mkdir(parents=True, exist_ok=True)
        _exclusive_write(trust_dir / "ca.pem", certificates.ca_certificate.read_bytes(), 0o644)
    prepared = {
        "schema_version": schema_version,
        "bundles": [
            {
                "provider_id": binding.provider_id,
                "manifest_sha256": binding.manifest_sha256,
                **(
                    {
                        "admission_sha256": binding.admission_sha256,
                        "release_config_sha256": binding.release_config_sha256,
                    }
                    if schema_version == PREPARED_ADMITTED_RUN_SCHEMA
                    else {}
                ),
            }
            for binding in bindings
        ],
        "authorities": list(authorities),
    }
    path = run_root / "prepared.json"
    _exclusive_write(
        path,
        (json.dumps(prepared, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        0o644,
    )
    return path


def _validate_admitted_prepared_run(
    *,
    bindings: tuple[_AdmittedServerBinding, ...],
    run_root: Path,
) -> None:
    try:
        prepared = json.loads((run_root / "prepared.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("prepared admitted interception run is missing or invalid") from exc
    expected = {
        "schema_version": PREPARED_ADMITTED_RUN_SCHEMA,
        "bundles": [
            {
                "provider_id": binding.provider_id,
                "manifest_sha256": binding.manifest_sha256,
                "admission_sha256": binding.admission_sha256,
                "release_config_sha256": binding.release_config_sha256,
            }
            for binding in bindings
        ],
        "authorities": [authority for binding in bindings for authority in binding.authorities],
    }
    if prepared != expected:
        raise ValueError("prepared interception run does not match admitted provider bindings")
    required = (
        run_root / "control-token",
        run_root / "certificates/ca.pem",
        run_root / "certificates/gateway.pem",
        run_root / "certificates/gateway-key.pem",
    )
    if any(path.is_symlink() or not path.is_file() for path in required):
        raise ValueError("prepared admitted interception run is incomplete")


def _serve_gateway_process(
    *,
    gateway: InterceptionGateway,
    run_root: Path,
    host: str,
    port: int,
) -> None:
    certificate_root = run_root / "certificates"
    control_socket = run_root / "control.sock"
    control_config = uvicorn.Config(
        gateway.control_app,
        uds=str(control_socket),
        log_level="warning",
        access_log=False,
        server_header=False,
        date_header=False,
    )
    control_server = uvicorn.Server(control_config)
    control_thread = threading.Thread(target=control_server.run, daemon=True)
    control_thread.start()
    try:
        _wait_for_socket(control_socket, control_thread)
        control_socket.chmod(0o600)
        uvicorn.run(
            gateway.data_app,
            host=host,
            port=port,
            ssl_certfile=str(certificate_root / "gateway.pem"),
            ssl_keyfile=str(certificate_root / "gateway-key.pem"),
            server_header=False,
            date_header=False,
        )
    finally:
        control_server.should_exit = True
        control_thread.join(timeout=5)
        gateway.close()
        control_socket.unlink(missing_ok=True)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _load_release_config(path: Path) -> tuple[dict[str, object], Path]:
    if path.is_symlink():
        raise ValueError("provider release config must not be a symbolic link")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size > PROVIDER_RELEASE_MAX_JSON_BYTES:
            raise ValueError("provider release config is not a bounded regular file")
        payload = resolved.read_bytes()
        if len(payload) > PROVIDER_RELEASE_MAX_JSON_BYTES:
            raise ValueError("provider release config exceeds its size limit")
        raw = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"provider release config is invalid: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("provider release config must contain an object")
    return raw, resolved
