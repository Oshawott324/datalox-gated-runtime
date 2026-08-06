#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import signal
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT = (
    ROOT / "envs/probed_opentrons_local_v0/evidence/behavior_harvest/functional_reset_evidence.json"
)
EXPECTED_ARCHIVE_SHA256 = "sha256:dbd3e2d7213a0f5eddffdfac1560b72cd4b0ac509d48a1a158b0d1920aa61273"
EXPECTED_COMMIT = "ad074b80e267084f08065b6d559b791140dfa671"
HEADERS = {"opentrons-version": "*"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _verify_extracted_source(*, archive: Path, source_root: Path) -> dict[str, Any]:
    archive_prefix = f"opentrons-{EXPECTED_COMMIT}/"
    selected_prefixes = ("hardware/", "hardware-testing/", "robot-server/", "server-utils/")
    archive_selected_prefixes = tuple(archive_prefix + item for item in selected_prefixes)
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = {
            member.name[len(archive_prefix) :]: member
            for member in bundle.getmembers()
            if member.isfile() and member.name.startswith(archive_selected_prefixes)
        }
        local_paths = {
            path.relative_to(source_root).as_posix(): path
            for path in source_root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        }
        if set(local_paths) != set(members):
            raise RuntimeError(
                "archive-extracted source file set mismatch: "
                f"missing={sorted(set(members) - set(local_paths))[:5]}, "
                f"extra={sorted(set(local_paths) - set(members))[:5]}"
            )
        inventory = hashlib.sha256()
        python_files = 0
        for relative_path in sorted(local_paths):
            local_digest = _sha256(local_paths[relative_path])
            extracted = bundle.extractfile(members[relative_path])
            if extracted is None:
                raise RuntimeError(f"archive member cannot be read: {relative_path}")
            archive_digest = f"sha256:{hashlib.sha256(extracted.read()).hexdigest()}"
            if local_digest != archive_digest:
                raise RuntimeError(f"archive-extracted source differs: {relative_path}")
            inventory.update(f"{relative_path}\t{local_digest}\n".encode())
            if relative_path.endswith(".py"):
                python_files += 1
    return {
        "all_files_byte_identical": True,
        "file_count": len(local_paths),
        "inventory_sha256": f"sha256:{inventory.hexdigest()}",
        "python_file_count": python_files,
    }


def _request(port: int, method: str, path: str, body: Any = None) -> dict[str, Any]:
    headers = dict(HEADERS)
    payload = None
    if body is not None:
        payload = json.dumps(
            body,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        headers["content-type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.getheader("content-type")
        parsed = json.loads(raw) if raw else None
        return {
            "request": {"body": body, "method": method, "path": path},
            "response": {
                "body": parsed,
                "body_sha256": f"sha256:{hashlib.sha256(raw).hexdigest()}",
                "content_type": content_type,
                "status_code": response.status,
            },
        }
    finally:
        connection.close()


def _wait_for_health(process: subprocess.Popen[bytes], port: int) -> dict[str, Any]:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"official simulator exited early with {process.returncode}")
        try:
            observed = _request(port, "GET", "/health")
        except (ConnectionError, OSError, TimeoutError):
            time.sleep(0.05)
            continue
        if observed["response"]["status_code"] == 200:
            body = observed["response"]["body"]
            expected = {
                "api_version": "9.1.1",
                "fw_version": "Virtual Smoothie",
                "robot_model": "OT-2 Standard",
                "robot_serial": "simulator",
            }
            actual = {key: body.get(key) for key in expected}
            if actual != expected:
                raise RuntimeError(f"unexpected simulator identity: {actual}")
            return observed
        time.sleep(0.05)
    raise RuntimeError("official simulator health preflight timed out")


def _launch(
    *,
    source_root: Path,
    venv: Path,
    port: int,
    api_config: Path,
    log_path: Path,
) -> tuple[subprocess.Popen[bytes], Any]:
    prefixes = ("robot-server", "hardware", "hardware-testing", "server-utils")
    python_path = ":".join(str(source_root / item) for item in prefixes)
    environment = {
        **os.environ,
        "PYTHONPATH": python_path,
        "OT_ROBOT_SERVER_DOT_ENV_PATH": str(source_root / "robot-server/dev.env"),
        "OT_ROBOT_SERVER_simulator_configuration_file_path": str(
            source_root / "robot-server/simulators/test.json"
        ),
        "OT_API_CONFIG_DIR": str(api_config),
    }
    log_handle = log_path.open("wb")
    process = subprocess.Popen(
        [
            str(venv / "bin/python"),
            "-m",
            "uvicorn",
            "robot_server.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--ws",
            "wsproto",
        ],
        cwd=source_root / "robot-server",
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
    )
    return process, log_handle


def _stop(process: subprocess.Popen[bytes], log_handle: Any) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("official simulator did not stop after SIGINT") from error
    log_handle.close()
    if process.returncode != 0:
        raise RuntimeError(f"official simulator shutdown returned {process.returncode}")


def _empty_observations(port: int) -> list[dict[str, Any]]:
    observations = [
        _request(port, "GET", path) for path in ("/protocols", "/runs", "/labwareOffsets")
    ]
    for item in observations:
        response = item["response"]
        if response["status_code"] != 200 or response["body"].get("data") != []:
            raise RuntimeError(f"simulator state is not empty: {item}")
    return observations


def capture(*, source_root: Path, archive: Path, venv: Path, port: int) -> dict[str, Any]:
    if _sha256(archive) != EXPECTED_ARCHIVE_SHA256:
        raise RuntimeError("official source archive digest mismatch")
    required = (
        source_root / "robot-server/robot_server/app.py",
        source_root / "robot-server/dev.env",
        source_root / "robot-server/simulators/test.json",
    )
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(f"archive-extracted source is incomplete: {missing}")
    source_comparison = _verify_extracted_source(archive=archive, source_root=source_root)

    with tempfile.TemporaryDirectory(prefix="datalox-opentrons-reset-") as temporary:
        temp = Path(temporary)
        api_config = temp / "api-config"
        first, first_log = _launch(
            source_root=source_root,
            venv=venv,
            port=port,
            api_config=api_config,
            log_path=temp / "first.log",
        )
        try:
            first_health = _wait_for_health(first, port)
            before = _empty_observations(port)
            create = _request(
                port,
                "POST",
                "/runs",
                {"data": {"protocolId": None}},
            )
            if create["response"]["status_code"] != 201:
                raise RuntimeError(f"virtual run mutation failed: {create}")
            mutated = _request(port, "GET", "/runs")
            if mutated["response"]["body"].get("meta", {}).get("totalLength") != 1:
                raise RuntimeError(f"virtual run mutation was not observable: {mutated}")
        finally:
            _stop(first, first_log)

        second, second_log = _launch(
            source_root=source_root,
            venv=venv,
            port=port,
            api_config=api_config,
            log_path=temp / "second.log",
        )
        try:
            second_health = _wait_for_health(second, port)
            after = _empty_observations(port)
        finally:
            _stop(second, second_log)

    return {
        "archive_sha256": EXPECTED_ARCHIVE_SHA256,
        "before_mutation": before,
        "claim_boundary": (
            "Observed only for process restart with auto-created temporary persistence in the "
            "official disposable simulator; tenant or physical-robot reset is not claimed."
        ),
        "functional_reset_passed": True,
        "health_before_restart": first_health,
        "health_after_restart": second_health,
        "mutation": create,
        "mutation_observation": mutated,
        "observations_after_restart": after,
        "provider_id": "opentrons_robot_server",
        "provider_version": "9.1.1",
        "reset_action": "terminate process and launch a new process with temporary persistence",
        "schema_id": "datalox_opentrons_functional_reset_evidence_v1",
        "source_comparison": source_comparison,
        "source_commit": EXPECTED_COMMIT,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--venv", type=Path, required=True)
    parser.add_argument("--port", type=int, default=31951)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--execute-reviewed-simulator-restart", action="store_true")
    args = parser.parse_args()
    if not args.execute_reviewed_simulator_restart:
        parser.error("capture requires --execute-reviewed-simulator-restart")
    if os.environ.get("DATALOX_OPENTRONS_VIRTUAL_AUTHORING_APPROVED") != "1":
        parser.error("set DATALOX_OPENTRONS_VIRTUAL_AUTHORING_APPROVED=1 after review")
    result = capture(
        source_root=args.source_root.resolve(strict=True),
        archive=args.archive.resolve(strict=True),
        venv=args.venv.resolve(strict=True),
        port=args.port,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(json.dumps({"output": str(args.output), "functional_reset_passed": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
