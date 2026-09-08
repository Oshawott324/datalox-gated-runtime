#!/usr/bin/env python3
"""Build the grounded UniProt ID Mapping temporal provider release."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from datalox_gated_runtime.provider_runtime import (
    admit_provider_runtime,
    build_provider_runtime_from_world,
)
from datalox_gated_runtime.provider_runtime.release import (
    ProviderReleaseProfileInput,
    build_provider_release,
)
from datalox_gated_runtime.world_v1.bundle import compute_bundle_hashes, validate_world_bundle

sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / "envs" / "uniprot_idmapping_v0"
PROVIDER_ID = "uniprot"
AUTHORITY = "rest.uniprot.org"
BUNDLE_VERSION = "2026_03-idmapping-v0"
EPISODE_ID = "uniprot_idmapping_reference"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _copy_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def _checker() -> Any:
    path = ROOT / "scripts" / "providers" / "check-uniprot-idmapping-lifecycle.py"
    spec = importlib.util.spec_from_file_location("check_uniprot_idmapping_lifecycle", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load lifecycle checker: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _world_manifest(source_world: Path) -> dict[str, Any]:
    return {
        "schema_version": "datalox_world_bundle_v1",
        "world_id": "uniprot_idmapping_v0",
        "bundle_version": BUNDLE_VERSION,
        "implementation": "world/v1/implementation.py:create_world",
        "episodes_path": "world/v1/episodes.jsonl",
        "roles_path": "world/v1/roles.json",
        "tools_path": "world/v1/tools.json",
        "verifier_path": "world/v1/verifier.json",
        "sources_path": "world/v1/sources.json",
        "default_actor_role": "idmapping_client",
        "required_runtime_capabilities": [
            "actors",
            "role_scoped_tools",
            "transactions",
            "clock",
            "scheduled_events",
        ],
        "trajectory_paths": [],
        "content_hashes": compute_bundle_hashes(source_world),
    }


def _admitted_at(source: Path) -> datetime:
    provenance = json.loads((source / "evidence" / "provenance.json").read_text(encoding="utf-8"))
    if provenance.get("provider") != "UniProt REST API":
        raise ValueError("UniProt provenance does not identify the provider")
    value = provenance.get("observed_at")
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("UniProt observed_at must be an explicit UTC timestamp")
    return datetime.fromisoformat(value).astimezone(UTC) + timedelta(seconds=1)


def build(source: Path, output: Path) -> dict[str, Any]:
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"output already exists: {output}")
    source = source.resolve(strict=True)
    output.mkdir(parents=True)

    for relative in (
        "evidence/authored-write-completeness.json",
        "evidence/observed-lifecycle.json",
        "evidence/observed-status-failure.json",
        "evidence/observed-uniref-result-failure.json",
        "evidence/provenance.json",
        "evidence/operation-claims.json",
    ):
        _copy_file(source / relative, output / relative)
    shutil.copytree(
        source / "source-world",
        output / "source-world",
        ignore=shutil.ignore_patterns("manifest.json", "__pycache__", "*.pyc"),
    )
    _write_json(
        output / "source-world" / "world" / "manifest.json",
        _world_manifest(output / "source-world"),
    )
    validate_world_bundle(output / "source-world")

    runtime = output / "provider-runtime"
    build_provider_runtime_from_world(
        source_world_dir=output / "source-world",
        output_dir=runtime,
        provider_id=PROVIDER_ID,
        authorities=(AUTHORITY,),
        episode_id=EPISODE_ID,
    )
    admission_path = output / "provider-admission.json"
    admission = admit_provider_runtime(
        bundle_dir=runtime,
        claims_path=output / "evidence" / "operation-claims.json",
        output_path=admission_path,
        admitted_at=_admitted_at(source),
    )
    release = build_provider_release(
        profiles=(
            ProviderReleaseProfileInput(
                profile_id="default",
                bundle_dir=runtime,
                admission_path=admission_path,
            ),
        ),
        release_version=BUNDLE_VERSION,
        output_dir=output / "provider-release",
    )
    checker = _checker()
    if (source / "evidence" / "restricted").is_dir():
        differential = checker.check(output, evidence_env=source)
        _write_json(output / "evidence" / "differential-report.json", differential)
    else:
        differential = checker.validate_public_report(source)
        _copy_file(
            source / "evidence" / "differential-report.json",
            output / "evidence" / "differential-report.json",
        )
    return {
        "admission_sha256": admission.sha256,
        "differential_sha256": _sha256(output / "evidence" / "differential-report.json"),
        "output": str(output),
        "release_manifest_digest": release.manifest_descriptor["digest"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.source, args.out), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
