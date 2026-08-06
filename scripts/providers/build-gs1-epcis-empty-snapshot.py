#!/usr/bin/env python3
"""Prove reconstruction of the retained empty FasTnT SQLite fixture."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "envs/gs1_epcis_2_0_1_v0/evidence/behavior_harvest"
OUTPUT = EVIDENCE / "restricted/fastnt-v2.8.2-migrated-empty.sqlite3"
REPORT = EVIDENCE / "empty_snapshot_construction.v1.json"
BEHAVIOR_BUILDER = ROOT / "scripts/providers/build-gs1-epcis-behavior-evidence.py"
SOURCE_ARCHIVE_SHA256 = "b9e49b2770d526584a9c650b65cd3bc1645c0301edc92d20f1738665980d75d6"
SOURCE_COMMIT = "b164868e3ffd5c7cfb7e23de7b423617da3af97b"
SOURCE_ARCHIVE_URL = f"https://github.com/louisaxel-ambroise/epcis/archive/{SOURCE_COMMIT}.tar.gz"
SDK_IMAGE = (
    "mcr.microsoft.com/dotnet/sdk:9.0.306-bookworm-slim"
    "@sha256:81f6d622fe21ed9d31375167f62a3538ff4d6835f9d5e6da9c2defa8a84b7687"
)
PROVIDER_MANIFEST = "sha256:118a410f91b6f25cf858ca314b92c420a51a9e063b030d115e409ffa271a483b"
PROVIDER_IMAGE = f"ghcr.io/louisaxel-ambroise/epcis@{PROVIDER_MANIFEST}"
SNAPSHOT_SHA256 = "17cfa60b5dfa36c8fcf06d25e7f16704f55ca28db61c83d82460f44e0c1f4f7d"
LOGICAL_RECEIPT_SHA256 = "0d787ef06422a8641e2f7335a162a3458302b8668b7627a94752fb776fb7e676"
MIGRATION_ID = "20250421102751_InitialV2_8_0"
PORT = 17883
PROVIDER_HEADERS = {
    "gs1-cbv-version": "2.0.0",
    "gs1-epcis-version": "2.0.1",
}

PROGRAM = """using FasTnT.Application.Database;
using FasTnT.Sqlite;
using Microsoft.EntityFrameworkCore;

if (args.Length != 1)
{
    throw new ArgumentException("Expected exactly one SQLite database path.");
}

var options = new DbContextOptionsBuilder<EpcisContext>()
    .UseSqlite(
        $"Data Source={Path.GetFullPath(args[0])}",
        sqlite => sqlite.MigrationsAssembly(typeof(SqliteProvider).Assembly.FullName)
    )
    .Options;
await using var context = new EpcisContext(options);
await context.Database.MigrateAsync();
"""

PROJECT = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net9.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="9.0.10" />
    <ProjectReference Include="/src/source/src/FasTnT.Application/FasTnT.Application.csproj" />
    <ProjectReference Include="/src/source/src/Providers/FasTnT.Sqlite/FasTnT.Sqlite.csproj" />
  </ItemGroup>
</Project>
"""

DOCKERFILE = f"""FROM {SDK_IMAGE}
WORKDIR /src
COPY source/ /src/source/
COPY builder/ /src/builder/
RUN mkdir -p /snapshot \\
    && dotnet run --project /src/builder/Migrate.csproj --configuration Release -- /snapshot/epcis.db
"""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _run(*arguments: str, context: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", "--context", context, *arguments],
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


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _logical_receipt(path: Path) -> dict[str, Any]:
    connection = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    try:
        schema = [
            {"type": row[0], "name": row[1], "table": row[2], "sql": row[3]}
            for row in connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name, tbl_name"
            )
        ]
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        row_counts = {
            table: connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
            for table in tables
        }
        migrations = [
            {"migration_id": row[0], "product_version": row[1]}
            for row in connection.execute(
                "SELECT MigrationId, ProductVersion FROM __EFMigrationsHistory ORDER BY MigrationId"
            )
        ]
        pragmas = {
            name: connection.execute(f"PRAGMA {name}").fetchone()[0]
            for name in (
                "application_id",
                "auto_vacuum",
                "encoding",
                "journal_mode",
                "page_size",
                "schema_version",
                "user_version",
            )
        }
    finally:
        connection.close()
    receipt = {
        "migrations": migrations,
        "pragmas": pragmas,
        "row_counts": row_counts,
        "schema": schema,
    }
    if migrations != [{"migration_id": MIGRATION_ID, "product_version": "9.0.10"}]:
        raise RuntimeError(f"generated snapshot migration differs: {migrations!r}")
    mutable_counts = {
        name: count
        for name, count in row_counts.items()
        if name not in {"__EFMigrationsHistory", "__EFMigrationsLock"}
    }
    if any(mutable_counts.values()):
        raise RuntimeError(f"generated snapshot contains provider state: {mutable_counts!r}")
    digest = hashlib.sha256(_canonical_json_bytes(receipt)).hexdigest()
    if digest != LOGICAL_RECEIPT_SHA256:
        raise RuntimeError(f"generated logical receipt differs: sha256:{digest}")
    return receipt


def _extract_source(archive: Path, destination: Path) -> Path:
    if _sha256(archive) != SOURCE_ARCHIVE_SHA256:
        raise RuntimeError("FasTnT source archive digest differs")
    with tarfile.open(archive, "r:gz") as source:
        roots = {Path(member.name).parts[0] for member in source.getmembers() if member.name}
        expected_root = f"epcis-{SOURCE_COMMIT}"
        if roots != {expected_root}:
            raise RuntimeError(f"FasTnT source archive root differs: {sorted(roots)!r}")
        source.extractall(destination, filter="data")
    return destination / expected_root


def _build_candidate(*, archive: Path, destination: Path, context: str) -> dict[str, Any]:
    tag = f"datalox/gs1-empty-snapshot-builder:{uuid.uuid4().hex}"
    container = f"datalox-gs1-empty-snapshot-{uuid.uuid4().hex}"
    with tempfile.TemporaryDirectory(prefix="datalox-gs1-empty-build-context-") as directory:
        temporary = Path(directory)
        build_context = temporary / "context"
        source = _extract_source(archive, temporary / "extracted")
        shutil.copytree(source, build_context / "source")
        builder = build_context / "builder"
        builder.mkdir(parents=True)
        (builder / "Program.cs").write_text(PROGRAM, encoding="utf-8")
        (builder / "Migrate.csproj").write_text(PROJECT, encoding="utf-8")
        (build_context / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
        try:
            _run(
                "image",
                "build",
                "--no-cache",
                "--tag",
                tag,
                str(build_context),
                context=context,
            )
            _run("container", "create", "--name", container, tag, context=context)
            _run(
                "container",
                "cp",
                f"{container}:/snapshot/epcis.db",
                str(destination),
                context=context,
            )
        finally:
            _run("container", "remove", "--force", container, context=context, check=False)
            _run("image", "remove", "--force", tag, context=context, check=False)
    receipt = _logical_receipt(destination)
    return {
        "bytes": destination.stat().st_size,
        "no_cache": True,
        "raw_sha256": f"sha256:{_sha256(destination)}",
        "logical_receipt_sha256": f"sha256:{LOGICAL_RECEIPT_SHA256}",
        "logical_receipt": receipt,
    }


def _authorization() -> str:
    value = os.environ.get("DATALOX_GS1_REFERENCE_AUTHORIZATION")
    if value is None or not value.startswith("Basic "):
        raise RuntimeError(
            "DATALOX_GS1_REFERENCE_AUTHORIZATION must contain the reviewed synthetic "
            "Basic Authorization value"
        )
    return value


def _request(
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    body: Any = None,
) -> tuple[int, Any]:
    target = path if not query else f"{path}?{urlencode(query)}"
    headers = {**PROVIDER_HEADERS, "authorization": _authorization()}
    encoded = None
    if body is not None:
        encoded = _canonical_json_bytes(body)
        headers["content-type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
    try:
        connection.request(method, target, body=encoded, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.getheader("content-type", "")
    finally:
        connection.close()
    parsed = json.loads(raw.decode("utf-8")) if raw and "json" in content_type.lower() else None
    return response.status, parsed


def _probe_event() -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location("gs1_behavior_builder", BEHAVIOR_BUILDER)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load GS1 behavior builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.events()["commissioning"]


def _wait_ready(container: str, context: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            status, body = _request("GET", "/eventTypes")
            if status == 200 and isinstance(body, dict):
                return
        except (ConnectionError, OSError, http.client.HTTPException):
            pass
        time.sleep(0.25)
    logs = _run("container", "logs", container, context=context, check=False)
    raise RuntimeError(f"FasTnT did not become ready: {logs.stdout}{logs.stderr}")


def _provider_probe(snapshot: Path, *, context: str) -> dict[str, Any]:
    container = f"datalox-gs1-empty-probe-{uuid.uuid4().hex}"
    try:
        _run(
            "container",
            "create",
            "--name",
            container,
            "--platform",
            "linux/amd64",
            "--publish",
            f"127.0.0.1:{PORT}:8080",
            PROVIDER_IMAGE,
            context=context,
        )
        _run("container", "cp", str(snapshot), f"{container}:/epcis/epcis.db", context=context)
        _run("container", "start", container, context=context)
        _wait_ready(container, context)
        initial_status, initial_body = _request("GET", "/eventTypes")
        if (
            initial_status != 200
            or not isinstance(initial_body, dict)
            or initial_body.get("member") != []
        ):
            raise RuntimeError("reconstructed snapshot did not boot as an empty repository")
        event = _probe_event()
        write_status, _ = _request("POST", "/events", body=event)
        if write_status != 201:
            raise RuntimeError(f"reconstructed snapshot write probe failed: {write_status}")
        read_status, read_body = _request(
            "GET", "/events", query={"EQ_eventID": str(event["eventID"])}
        )
        try:
            event_list = read_body["epcisBody"]["queryResults"]["resultsBody"]["eventList"]
        except (KeyError, TypeError) as error:
            raise RuntimeError("reconstructed snapshot read probe has no eventList") from error
        if (
            read_status != 200
            or len(event_list) != 1
            or event_list[0]["eventID"] != event["eventID"]
        ):
            raise RuntimeError("reconstructed snapshot did not pass exact write/read identity")
        inspected = json.loads(_run("container", "inspect", container, context=context).stdout)[0]
        return {
            "container_image_id": inspected["Image"],
            "initial_identity_status": initial_status,
            "initial_member_count": 0,
            "query_status": read_status,
            "readback_event_id": event["eventID"],
            "request_body_sha256": f"sha256:{hashlib.sha256(_canonical_json_bytes(event)).hexdigest()}",
            "write_status": write_status,
        }
    finally:
        _run("container", "remove", "--force", container, context=context, check=False)


def _validate_image(context: str) -> dict[str, Any]:
    values = json.loads(_run("image", "inspect", PROVIDER_IMAGE, context=context).stdout)
    if len(values) != 1 or values[0].get("Id") != PROVIDER_MANIFEST:
        raise RuntimeError("loaded FasTnT image identity differs")
    return {
        "image": PROVIDER_IMAGE,
        "image_id": values[0]["Id"],
        "repo_digests": sorted(values[0].get("RepoDigests", [])),
    }


def build(*, archive: Path, output: Path, context: str, write_report: bool) -> None:
    if os.environ.get("DATALOX_GS1_REFERENCE_AUTHORING_APPROVED") != "1":
        raise RuntimeError("set DATALOX_GS1_REFERENCE_AUTHORING_APPROVED=1 after review")
    _authorization()
    if not output.exists() or _sha256(output) != SNAPSHOT_SHA256:
        raise RuntimeError("the retained exact authoring fixture is missing or differs")
    retained_receipt = _logical_receipt(output)
    image = _validate_image(context)
    with tempfile.TemporaryDirectory(prefix="datalox-gs1-empty-snapshot-") as directory:
        temporary = Path(directory)
        candidates = []
        for index in range(2):
            candidate = temporary / f"candidate-{index + 1}.sqlite3"
            receipt = _build_candidate(archive=archive, destination=candidate, context=context)
            receipt["provider_probe"] = _provider_probe(candidate, context=context)
            candidates.append(receipt)
        if candidates[0]["logical_receipt"] != candidates[1]["logical_receipt"]:
            raise RuntimeError("independent logical reconstruction receipts differ")
        if candidates[0]["logical_receipt"] != retained_receipt:
            raise RuntimeError("reconstructed logical receipt differs from retained fixture")
    report = {
        "schema_id": "datalox_epcis_empty_snapshot_construction_v1",
        "passed": True,
        "source": {
            "archive_sha256": f"sha256:{SOURCE_ARCHIVE_SHA256}",
            "archive_url": SOURCE_ARCHIVE_URL,
            "commit": SOURCE_COMMIT,
            "sdk_image": SDK_IMAGE,
        },
        "provider_image": image,
        "retained_fixture": {
            "bytes": output.stat().st_size,
            "raw_sha256": f"sha256:{SNAPSHOT_SHA256}",
            "logical_receipt_sha256": f"sha256:{LOGICAL_RECEIPT_SHA256}",
        },
        "independent_no_cache_builds": candidates,
        "raw_byte_boundary": (
            "EF migration lock acquisition leaves a deleted UTC timestamp in free SQLite "
            "page content. Independent unmodified builds are therefore compared by the full "
            "logical receipt and exact-provider behavior, not raw byte equality. The retained "
            "fixture remains byte-pinned for reset."
        ),
    }
    if write_report:
        temporary_report = REPORT.with_suffix(".json.new")
        temporary_report.write_bytes(json.dumps(report, indent=2, sort_keys=True).encode() + b"\n")
        os.replace(temporary_report, REPORT)
    elif not REPORT.exists():
        raise RuntimeError("construction report is missing; rerun with --write-report")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=OUTPUT)
    parser.add_argument(
        "--docker-context",
        default=os.environ.get("DATALOX_GS1_SNAPSHOT_DOCKER_CONTEXT", "colima"),
    )
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    build(
        archive=args.source_archive.resolve(),
        output=args.out.resolve(),
        context=args.docker_context,
        write_report=args.write_report,
    )
    print(f"GS1 migrated-empty logical reconstruction proof passed: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
