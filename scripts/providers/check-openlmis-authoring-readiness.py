#!/usr/bin/env python3
"""Read-only, fail-closed OpenLMIS behavior-authoring readiness check.

The checker never starts containers and never sends an HTTP request.  It proves
that the reviewed connector, complete-program inventory, official compose
source, pinned images, operator-provided secrets, and fixed local origin are
present before a separately approved authoring run is attempted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


EVIDENCE_ROOT = ROOT / "envs/openlmis_supply_chain_v0/evidence/behavior_harvest"
CONNECTOR_PATH = EVIDENCE_ROOT / "sandbox_connector.json"
COVERAGE_PATH = EVIDENCE_ROOT / "core_program_coverage.json"
EXPECTED_RELEASE_COMMIT = "4c5eea24743367790b419e18a9565934ba73ab62"
EXPECTED_RELEASE_ARCHIVE_SHA256 = (
    "sha256:46ac79c2b0e765a8efb83f5c5fdba20f6e64965674bd90873edf9cbef34666fd"
)
REQUIRED_RELEASE_FILES = (
    ".env",
    "docker-compose.yml",
    "docker-compose.demo-data.yml",
)
REQUIRED_SERVICE_IMAGES = (
    "openlmis/auth:4.4.0",
    "openlmis/referencedata:15.4.0",
    "openlmis/requisition:8.5.0",
    "openlmis/stockmanagement:5.3.0",
    "openlmis/fulfillment:9.3.0",
    "openlmis/notification:4.4.0",
    "openlmis/report:1.5.0",
    "openlmis/nginx:v7.1",
    "openlmis/postgres:14-debezium",
)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} must contain a JSON object")
    return value


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def assess_contracts() -> dict[str, Any]:
    from datalox_gated_runtime.behavior_harvest import (
        BehaviorContractError,
        load_connector,
        load_recipe,
    )

    connector_digest = _sha256(CONNECTOR_PATH)
    load_connector(CONNECTOR_PATH, expected_sha256=connector_digest)
    connector = _load_json(CONNECTOR_PATH)
    coverage = _load_json(COVERAGE_PATH)
    operations = coverage.get("operations")
    if not isinstance(operations, list):
        raise TypeError("core_program_coverage.json operations must be an array")

    selected = []
    targeted = []
    invalid_recipes = []
    invalid_observed_programs = []
    observed_complete = []
    recipe_digests: dict[str, str] = {}
    for row in operations:
        if not isinstance(row, dict) or not isinstance(row.get("operation_id"), str):
            raise TypeError("every coverage operation must have an operation_id")
        operation_id = row["operation_id"]
        selected.append(operation_id)
        recipe_ref = row.get("recipe_path")
        if recipe_ref is None:
            continue
        recipe_path = ROOT / str(recipe_ref)
        if not recipe_path.is_file():
            invalid_recipes.append({"operation_id": operation_id, "reason": "recipe_missing"})
            continue
        recipe_digest = _sha256(recipe_path)
        try:
            load_recipe(recipe_path, expected_sha256=recipe_digest)
        except BehaviorContractError:
            invalid_recipes.append(
                {"operation_id": operation_id, "reason": "recipe_contract_invalid"}
            )
            continue
        recipe = _load_json(recipe_path)
        has_target_success = any(
            isinstance(step, dict)
            and step.get("operation_id") == operation_id
            and step.get("kind") == "mutation"
            and step.get("role") == "success"
            for step in recipe.get("steps", [])
        )
        if not has_target_success:
            invalid_recipes.append(
                {"operation_id": operation_id, "reason": "target_success_step_missing"}
            )
            continue
        targeted.append(operation_id)
        recipe_digests[str(recipe_ref)] = recipe_digest

        if row.get("classification") == "generic_reloadable_complete":
            observed_complete.append(operation_id)
            continue
        observed_ref = row.get("observed_program_path")
        if observed_ref is None:
            continue
        observed_path = ROOT / str(observed_ref)
        if not observed_path.is_file():
            invalid_observed_programs.append(
                {"operation_id": operation_id, "reason": "observed_program_missing"}
            )
            continue
        observed = _load_json(observed_path)
        roles = {
            step.get("role")
            for step in observed.get("steps", [])
            if isinstance(step, dict) and step.get("operation_id") == operation_id
        }
        required_roles = {"success", "duplicate", "native_failure"}
        contracts = observed.get("contracts")
        review = observed.get("review")
        if (
            observed.get("schema_id") != "datalox_observed_behavior_program_v1"
            or observed.get("program_id") != recipe.get("program_id")
            or not isinstance(contracts, dict)
            or contracts.get("connector_sha256") != connector_digest
            or contracts.get("recipe_sha256") != recipe_digest
            or not required_roles <= roles
            or not isinstance(review, dict)
            or review.get("provider_observed_program_complete") is not True
        ):
            invalid_observed_programs.append(
                {"operation_id": operation_id, "reason": "observed_program_invalid"}
            )
            continue
        observed_complete.append(operation_id)

    missing_targets = sorted(set(selected) - set(targeted))
    blockers = []
    if invalid_recipes:
        blockers.append("invalid_behavior_recipe")
    if invalid_observed_programs:
        blockers.append("invalid_observed_behavior_program")
    if missing_targets:
        blockers.append("operation_program_coverage_incomplete")
    return {
        "connector_id": connector.get("connector_id"),
        "connector_sha256": connector_digest,
        "coverage_sha256": _sha256(COVERAGE_PATH),
        "selected_write_count": len(selected),
        "targeted_write_count": len(targeted),
        "targeted_operations": sorted(targeted),
        "missing_target_operations": missing_targets,
        "invalid_recipes": invalid_recipes,
        "invalid_observed_programs": invalid_observed_programs,
        "provider_observed_complete_program_count": len(observed_complete),
        "provider_observed_complete_operations": sorted(observed_complete),
        "recipe_digests": recipe_digests,
        "blockers": blockers,
    }


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def assess_release_source(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"ready": False, "blocker": "official_release_source_not_supplied"}
    if not path.exists():
        return {"ready": False, "blocker": "official_release_source_missing"}
    if path.is_file():
        actual_digest = _sha256(path)
        try:
            with tarfile.open(path, mode="r:gz") as archive:
                names = tuple(archive.getnames())
        except (tarfile.TarError, OSError):
            return {"ready": False, "blocker": "official_release_archive_invalid"}
        present = {member.rsplit("/", 1)[-1] for member in names if member.count("/") == 1}
        missing = [name for name in REQUIRED_RELEASE_FILES if name not in present]
        ready = actual_digest == EXPECTED_RELEASE_ARCHIVE_SHA256 and not missing
        return {
            "ready": ready,
            "source_kind": "exact_codeload_archive",
            "expected_commit": EXPECTED_RELEASE_COMMIT,
            "expected_archive_sha256": EXPECTED_RELEASE_ARCHIVE_SHA256,
            "actual_archive_sha256": actual_digest,
            "missing_files": missing,
            "blocker": None if ready else "official_release_source_identity_mismatch",
        }
    if not path.is_dir():
        return {"ready": False, "blocker": "official_release_source_invalid_type"}
    revision = _run(["git", "-C", str(path), "rev-parse", "HEAD"])
    if revision.returncode != 0:
        return {"ready": False, "blocker": "official_release_source_not_git"}
    actual = revision.stdout.strip()
    missing = [name for name in REQUIRED_RELEASE_FILES if not (path / name).is_file()]
    ready = actual == EXPECTED_RELEASE_COMMIT and not missing
    return {
        "ready": ready,
        "source_kind": "git_worktree",
        "expected_commit": EXPECTED_RELEASE_COMMIT,
        "actual_commit": actual,
        "missing_files": missing,
        "blocker": None if ready else "official_release_source_identity_mismatch",
    }


def assess_images(context: str, connector: dict[str, Any]) -> dict[str, Any]:
    expected = connector["identity_preflight"]["expected_identity"]["docker"]["images"]
    command = ["docker", "--context", context, "image", "inspect", *expected]
    result = _run(command)
    if result.returncode != 0:
        return {
            "ready": False,
            "matched_count": 0,
            "expected_count": len(expected),
            "blocker": "pinned_images_unavailable",
        }
    inspected = json.loads(result.stdout)
    actual: dict[str, str] = {}
    for image in inspected:
        image_id = image.get("Id")
        for tag in image.get("RepoTags") or []:
            actual[tag] = image_id
    mismatches = {
        tag: {"expected": digest, "actual": actual.get(tag)}
        for tag, digest in expected.items()
        if actual.get(tag) != digest
    }
    return {
        "ready": not mismatches,
        "matched_count": len(expected) - len(mismatches),
        "expected_count": len(expected),
        "mismatches": mismatches,
        "blocker": None if not mismatches else "pinned_image_identity_mismatch",
    }


def assess_deployment(context: str) -> dict[str, Any]:
    listed = _run(["docker", "--context", context, "ps", "-q"])
    if listed.returncode != 0:
        return {"ready": False, "blocker": "docker_context_unavailable"}
    container_ids = listed.stdout.split()
    if not container_ids:
        return {
            "ready": False,
            "running_container_count": 0,
            "missing_service_images": list(REQUIRED_SERVICE_IMAGES),
            "compose_projects": [],
            "blocker": "disposable_deployment_absent",
        }
    inspected = _run(["docker", "--context", context, "container", "inspect", *container_ids])
    if inspected.returncode != 0:
        return {"ready": False, "blocker": "deployment_inspection_failed"}
    containers = json.loads(inspected.stdout)
    running_images = {
        item.get("Config", {}).get("Image")
        for item in containers
        if item.get("State", {}).get("Running") is True
    }
    projects = sorted(
        {
            project
            for item in containers
            if (
                project := item.get("Config", {})
                .get("Labels", {})
                .get("com.docker.compose.project")
            )
        }
    )
    missing = sorted(set(REQUIRED_SERVICE_IMAGES) - running_images)
    ready = not missing and len(projects) == 1
    return {
        "ready": ready,
        "running_container_count": len(containers),
        "missing_service_images": missing,
        "compose_projects": projects,
        "blocker": None if ready else "disposable_deployment_incomplete",
    }


def assess_secrets(connector: dict[str, Any]) -> dict[str, Any]:
    names = [item["name"] for item in connector["auth"]["secret_sources"]]
    missing = sorted(name for name in names if not os.environ.get(name))
    return {
        "ready": not missing,
        "required_count": len(names),
        "present_count": len(names) - len(missing),
        "missing_names": missing,
        "blocker": None if not missing else "operator_authoring_secrets_missing",
    }


def assess_origin(origin: str) -> dict[str, Any]:
    parsed = urlsplit(origin)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    ready = False
    try:
        with socket.create_connection((parsed.hostname or "", port), timeout=1.0):
            ready = True
    except OSError:
        pass
    return {
        "ready": ready,
        "origin": origin,
        "check": "tcp_connect_only_no_http_request",
        "blocker": None if ready else "authoring_origin_unreachable",
    }


def build_report(*, release_source: Path | None, docker_context: str) -> dict[str, Any]:
    connector = _load_json(CONNECTOR_PATH)
    contracts = assess_contracts()
    sections = {
        "contracts": contracts,
        "release_source": assess_release_source(release_source),
        "images": assess_images(docker_context, connector),
        "deployment": assess_deployment(docker_context),
        "secrets": assess_secrets(connector),
        "origin": assess_origin(connector["origin"]),
    }
    blockers = list(contracts["blockers"])
    blockers.extend(
        section["blocker"]
        for name, section in sections.items()
        if name != "contracts" and section.get("blocker") is not None
    )
    return {
        "schema_id": "datalox_openlmis_authoring_readiness_v1",
        "environment_id": "openlmis_supply_chain_v0",
        "read_only": True,
        "ready": not blockers,
        "blockers": blockers,
        "sections": sections,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-source", type=Path)
    parser.add_argument("--docker-context", default="colima-openlmis")
    parser.add_argument("--require-ready", action="store_true")
    args = parser.parse_args()
    report = build_report(
        release_source=args.release_source,
        docker_context=args.docker_context,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if args.require_ready and not report["ready"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
