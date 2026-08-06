#!/usr/bin/env python3
"""Re-harvest the reviewed GS1 EPCIS slice from pinned disposable FasTnT."""

from __future__ import annotations

import argparse
import http.client
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
ENV = ROOT / "envs/gs1_epcis_2_0_1_v0"
EVIDENCE = ENV / "evidence/behavior_harvest"
CAPTURES = EVIDENCE / "captures"
RESET_EVIDENCE = EVIDENCE / "reset_equivalence.v1.json"
EMPTY_SNAPSHOT = EVIDENCE / "restricted/fastnt-v2.8.2-migrated-empty.sqlite3"
BUILDER_PATH = ROOT / "scripts/providers/build-gs1-epcis-behavior-evidence.py"
DOCKER_CONTEXT = os.environ.get("DATALOX_GS1_DOCKER_CONTEXT", "colima")
CONTAINER = "datalox-gs1-epcis-authoring"
ORIGIN = "http://127.0.0.1:17882"
IMAGE_MANIFEST = "sha256:118a410f91b6f25cf858ca314b92c420a51a9e063b030d115e409ffa271a483b"
IMAGE = f"ghcr.io/louisaxel-ambroise/epcis@{IMAGE_MANIFEST}"
IMAGE_ID = IMAGE_MANIFEST
CONFIG_SHA256 = "sha256:a317a87d5800a2a862bd3c94a7d522c4ae444f8a25bc86d95c243730cf73c04b"
ROOTFS_LAYERS_SHA256 = "sha256:6756215f2453a6012eef280b94d1883946ef58ebae9391079e03d61fd7200152"
EMPTY_SNAPSHOT_SHA256 = "sha256:17cfa60b5dfa36c8fcf06d25e7f16704f55ca28db61c83d82460f44e0c1f4f7d"
MIGRATION_ID = "20250421102751_InitialV2_8_0"
PROVIDER_HEADERS = {
    "gs1-cbv-version": "2.0.0",
    "gs1-epcis-version": "2.0.1",
}
PROGRAMS = (
    "commissioning",
    "aggregation",
    "shipping",
    "receiving",
    "transformation",
    "correction",
    "decommission",
)
sys.path.insert(0, str(ROOT / "src"))

from datalox_gated_runtime.behavior_harvest.engines import v3  # noqa: E402
from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (  # noqa: E402
    canonical_json_bytes,
    sha256_digest,
)


def _builder() -> Any:
    spec = importlib.util.spec_from_file_location("datalox_gs1_behavior_builder", BUILDER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load GS1 behavior builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _authorization() -> str:
    value = os.environ.get("DATALOX_GS1_REFERENCE_AUTHORIZATION")
    if value is None or not value.startswith("Basic "):
        raise RuntimeError(
            "DATALOX_GS1_REFERENCE_AUTHORIZATION must contain the reviewed synthetic "
            "Basic Authorization value"
        )
    return value


def _docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", "--context", DOCKER_CONTEXT, *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"docker {' '.join(arguments)} failed: {result.stdout}{result.stderr}".strip()
        )
    return result


def _remove_container() -> None:
    result = _docker("container", "inspect", CONTAINER, check=False)
    if result.returncode == 0:
        _docker("container", "rm", "--force", CONTAINER)


def _create_container(*, start: bool, snapshot: Path | None = None) -> str:
    _remove_container()
    command = "run" if start and snapshot is None else "create"
    arguments = [
        command,
        "--name",
        CONTAINER,
        "--platform",
        "linux/amd64",
        "--publish",
        "127.0.0.1:17882:8080",
        IMAGE,
    ]
    if command == "run":
        arguments.insert(1, "--detach")
    container_id = _docker(*arguments).stdout.strip()
    if not container_id:
        raise RuntimeError("docker did not return a container id")
    if snapshot is not None:
        _docker("container", "cp", str(snapshot), f"{CONTAINER}:/epcis/epcis.db")
    if command == "create":
        _docker("container", "start", CONTAINER)
    _wait_ready()
    return container_id


def _wait_ready() -> None:
    deadline = time.monotonic() + 45.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status, _, body = _request("GET", "/eventTypes")
            if status == 200 and isinstance(body, dict):
                return
        except (ConnectionError, OSError, http.client.HTTPException) as error:
            last_error = error
        time.sleep(0.25)
    logs = _docker("container", "logs", CONTAINER, check=False)
    raise RuntimeError(
        f"FasTnT did not become ready: {last_error}; logs={logs.stdout}{logs.stderr}"
    )


def _request(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], Any]:
    target = path
    if query:
        target += "?" + urlencode(query)
    request_headers = (
        {**PROVIDER_HEADERS, "authorization": _authorization()}
        if headers is None
        else dict(headers)
    )
    encoded: bytes | None = None
    if body is not None:
        encoded = canonical_json_bytes(body)
        request_headers["content-type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", 17882, timeout=10)
    try:
        connection.request(method, target, body=encoded, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
    finally:
        connection.close()
    parsed: Any = None
    if raw:
        decoded = raw.decode("utf-8")
        content_type = response_headers.get("content-type", "")
        parsed = json.loads(decoded) if "json" in content_type.lower() else decoded
    return response.status, response_headers, parsed


def _assert_empty_identity() -> dict[str, Any]:
    status, headers, body = _request("GET", "/eventTypes")
    if status != 200 or not isinstance(body, dict) or body.get("member") != []:
        raise RuntimeError(f"FasTnT repository is not empty: status={status} body={body!r}")
    return {"status_code": status, "headers": headers, "body": body}


def _query_event(event_id: str) -> dict[str, Any]:
    status, headers, body = _request(
        "GET",
        "/events",
        query={"EQ_eventID": event_id},
    )
    if status != 200 or not isinstance(body, dict):
        raise RuntimeError(f"event query failed: status={status} body={body!r}")
    return {"status_code": status, "headers": headers, "body": body}


def _event_list(exchange: dict[str, Any]) -> list[Any]:
    try:
        value = exchange["body"]["epcisBody"]["queryResults"]["resultsBody"]["eventList"]
    except (KeyError, TypeError) as error:
        raise RuntimeError("query response has no EPCIS eventList") from error
    if not isinstance(value, list):
        raise RuntimeError("query response eventList is not an array")
    return value


def _image_receipt() -> dict[str, Any]:
    result = _docker("image", "inspect", IMAGE)
    values = json.loads(result.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise RuntimeError("exactly one pinned FasTnT image must be installed")
    image = values[0]
    if image.get("Id") != IMAGE_ID:
        raise RuntimeError(f"loaded FasTnT image id differs: {image.get('Id')!r}")
    repo_digests = image.get("RepoDigests")
    if not isinstance(repo_digests, list) or not any(
        item.endswith(f"@{IMAGE_MANIFEST}") for item in repo_digests
    ):
        raise RuntimeError("loaded FasTnT image is not pinned by the reviewed manifest")
    config_sha256 = sha256_digest(canonical_json_bytes(image.get("Config")))
    rootfs = image.get("RootFS")
    if not isinstance(rootfs, dict):
        raise RuntimeError("loaded FasTnT image has no RootFS receipt")
    rootfs_layers_sha256 = sha256_digest(canonical_json_bytes(rootfs.get("Layers")))
    if config_sha256 != CONFIG_SHA256 or rootfs_layers_sha256 != ROOTFS_LAYERS_SHA256:
        raise RuntimeError("loaded FasTnT image content differs from the reviewed image")
    return {
        "context": DOCKER_CONTEXT,
        "image": IMAGE,
        "image_id": image["Id"],
        "repo_digests": sorted(repo_digests),
        "docker_identity_semantics": (
            "Docker 29's containerd image store reports the pulled manifest descriptor "
            "digest as image Id for this digest-qualified reference."
        ),
        "content_identity": {
            "config_sha256": config_sha256,
            "rootfs_layers_sha256": rootfs_layers_sha256,
        },
    }


def _validate_empty_snapshot(path: Path) -> None:
    digest = sha256_digest(path.read_bytes())
    if digest != EMPTY_SNAPSHOT_SHA256:
        raise RuntimeError(f"migrated-empty snapshot digest differs: {digest}")
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        migration = connection.execute("SELECT MigrationId FROM __EFMigrationsHistory").fetchall()
        counts = {
            table: connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in ("Event", "Request", "Subscription")
        }
    finally:
        connection.close()
    if migration != [(MIGRATION_ID,)]:
        raise RuntimeError(f"migrated-empty snapshot migration differs: {migration!r}")
    if counts != {"Event": 0, "Request": 0, "Subscription": 0}:
        raise RuntimeError(f"migrated-empty snapshot contains provider state: {counts!r}")


def _capture_reset(builder: Any, temporary: Path, seed_snapshot: Path) -> dict[str, Any]:
    values = builder.events()
    mutation = values["commissioning"]
    probe = values["decommission"]
    snapshot = temporary / "migrated-empty-epcis.db"
    shutil.copyfile(seed_snapshot, snapshot)
    initial_container_id = _create_container(start=False, snapshot=snapshot)
    initial_identity = _assert_empty_identity()
    snapshot_bytes = snapshot.read_bytes()
    if not snapshot_bytes:
        raise RuntimeError("empty SQLite snapshot has no bytes")

    mutation_status, mutation_headers, mutation_body = _request("POST", "/events", body=mutation)
    if mutation_status != 201:
        raise RuntimeError(f"reset mutation failed: {mutation_status} {mutation_body!r}")
    mutated_state = _query_event(mutation["eventID"])
    if len(_event_list(mutated_state)) != 1:
        raise RuntimeError("reset mutation did not create exactly one event")

    _docker("container", "stop", "--time", "10", CONTAINER)
    stopped = json.loads(_docker("container", "inspect", CONTAINER).stdout)[0]
    if stopped["State"]["Running"] is not False:
        raise RuntimeError("FasTnT container did not stop")
    _docker("container", "rm", CONTAINER)

    restored_container_id = _create_container(start=False, snapshot=snapshot)
    restored_identity = _assert_empty_identity()
    cleared_state = _query_event(mutation["eventID"])
    if _event_list(cleared_state) != []:
        raise RuntimeError("restored snapshot retained the pre-reset mutation")
    probe_status, probe_headers, probe_body = _request("POST", "/events", body=probe)
    if probe_status != 201:
        raise RuntimeError(f"post-reset behavior probe failed: {probe_status} {probe_body!r}")
    probe_state = _query_event(probe["eventID"])
    if len(_event_list(probe_state)) != 1:
        raise RuntimeError("post-reset write/read probe did not create exactly one event")

    return {
        "schema_id": "datalox_epcis_reset_equivalence_v1",
        "passed": True,
        "provider_id": "gs1_epcis",
        "provider_version": "2.0.1-fastnt-v2.8.2",
        "image": _image_receipt(),
        "empty_snapshot": {
            "bytes": len(snapshot_bytes),
            "sha256": sha256_digest(snapshot_bytes),
            "migration": MIGRATION_ID,
            "database": "digest-pinned migrated-empty SQLite authoring snapshot",
        },
        "initial_container_id": initial_container_id,
        "restored_container_id": restored_container_id,
        "initial_identity": initial_identity,
        "mutation": {
            "operation_id": "epcis.capture_event",
            "request_body_sha256": sha256_digest(canonical_json_bytes(mutation)),
            "status_code": mutation_status,
            "headers": mutation_headers,
            "body": mutation_body,
        },
        "mutated_state": mutated_state,
        "stop_receipt": {
            "container_id": stopped["Id"],
            "image": stopped["Image"],
            "running": stopped["State"]["Running"],
            "exit_code": stopped["State"]["ExitCode"],
        },
        "restored_identity": restored_identity,
        "cleared_state": cleared_state,
        "behavioral_probe": {
            "operation_id": "epcis.capture_event",
            "request_body_sha256": sha256_digest(canonical_json_bytes(probe)),
            "status_code": probe_status,
            "headers": probe_headers,
            "body": probe_body,
            "resulting_state": probe_state,
        },
        "claim_boundary": (
            "Functional equivalence is claimed only for this pinned disposable FasTnT "
            "SQLite snapshot restore: identity, cleared state, and a fresh write/read probe."
        ),
    }


def _write_reset(value: dict[str, Any]) -> None:
    RESET_EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    temporary = RESET_EVIDENCE.with_suffix(".json.new")
    temporary.write_bytes(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    os.replace(temporary, RESET_EVIDENCE)


def _capture_programs(builder: Any, snapshot: Path, temporary: Path) -> None:
    authorization = _authorization()
    connector = EVIDENCE / "sandbox_connector.v3.json"
    reference = EVIDENCE / "reference_system.json"
    connector_digest = sha256_digest(connector.read_bytes())
    reference_digest = sha256_digest(reference.read_bytes())
    outputs: dict[str, Path] = {}
    for name in PROGRAMS:
        _create_container(start=False, snapshot=snapshot)
        recipe = EVIDENCE / f"{name}.behavior_recipe_v1.json"
        output = temporary / f"{name}.capture.v1.json"
        result = v3.BehaviorHarvester().run(
            connector_path=connector,
            recipe_path=recipe,
            expected_connector_sha256=connector_digest,
            expected_recipe_sha256=sha256_digest(recipe.read_bytes()),
            expected_engine=v3.current_engine_identity(),
            run_id=f"gs1-epcis-fastnt-v2-8-2-{name}-20260805-remediation",
            output_path=output,
            sensitive_values={"authorization": authorization.encode("ascii")},
            static_input_paths={"reference_system": reference},
            expected_static_input_sha256={"reference_system": reference_digest},
            execute_sandbox_writes=True,
        )
        by_step = {exchange.step_id: exchange for exchange in result.capture.exchanges}
        if by_step["duplicate"].status_code != 201:
            raise RuntimeError(f"{name} repeat did not return the observed 201")
        resulting = by_step["resulting_state"].body
        expected_count = 3 if name == "correction" else 2
        event_list = resulting["epcisBody"]["queryResults"]["resultsBody"]["eventList"]
        if len(event_list) != expected_count:
            raise RuntimeError(f"{name} repeat did not persist {expected_count} records")
        outputs[name] = output
        _remove_container()

    CAPTURES.mkdir(parents=True, exist_ok=True)
    for name, output in outputs.items():
        os.replace(output, CAPTURES / f"{name}.capture.v1.json")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute-reviewed-reference-writes", action="store_true")
    parser.add_argument("--migrated-empty-snapshot", type=Path, default=EMPTY_SNAPSHOT)
    args = parser.parse_args()
    if not args.execute_reviewed_reference_writes:
        parser.error("capture requires --execute-reviewed-reference-writes")
    if os.environ.get("DATALOX_GS1_REFERENCE_AUTHORING_APPROVED") != "1":
        parser.error("set DATALOX_GS1_REFERENCE_AUTHORING_APPROVED=1 after review")

    builder = _builder()
    _authorization()
    _image_receipt()
    seed_snapshot = args.migrated_empty_snapshot.resolve()
    _validate_empty_snapshot(seed_snapshot)
    try:
        with tempfile.TemporaryDirectory(prefix="datalox-gs1-epcis-authoring-") as directory:
            temporary = Path(directory)
            reset = _capture_reset(builder, temporary, seed_snapshot)
            snapshot_source = temporary / "migrated-empty-epcis.db"
            _write_reset(reset)
            builder.build()
            _capture_programs(builder, snapshot_source, temporary)
            builder.build()
    finally:
        _remove_container()
    print("Re-harvested seven pinned FasTnT programs and functional reset evidence.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
