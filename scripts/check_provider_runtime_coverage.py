"""Compile every registered provider asset into the task-free runtime contract."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    build_provider_runtime_from_gate_config,
    build_provider_runtime_from_world,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.world_v1.bundle import validate_world_bundle

ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = ROOT / "docs/reports/provider-runtime-coverage.json"


def validate_report(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict) or set(report) != {
        "schema_version",
        "scope",
        "authority_note",
        "summary",
        "providers",
        "excluded",
    }:
        raise ValueError("provider runtime coverage report has invalid top-level fields")
    if report["schema_version"] != "datalox_provider_runtime_coverage_v1":
        raise ValueError("provider runtime coverage report has an unsupported schema")
    if not isinstance(report["scope"], str) or not report["scope"]:
        raise ValueError("provider runtime coverage scope is invalid")
    if not isinstance(report["authority_note"], str) or not report["authority_note"]:
        raise ValueError("provider runtime coverage authority note is invalid")
    providers = report["providers"]
    excluded = report["excluded"]
    summary = report["summary"]
    if (
        not isinstance(providers, list)
        or not isinstance(excluded, list)
        or not isinstance(summary, dict)
    ):
        raise ValueError("provider runtime coverage report collections are invalid")
    required_provider_fields = {
        "env_id",
        "provider_id",
        "source_kind",
        "behavior_protocol",
        "operation_count",
        "reset_passed",
        "task_assets_present",
        "status",
    }
    if any(
        not isinstance(item, dict) or set(item) != required_provider_fields for item in providers
    ):
        raise ValueError("provider runtime coverage entry fields are invalid")
    if any(
        not isinstance(item["env_id"], str)
        or not item["env_id"]
        or not isinstance(item["provider_id"], str)
        or not item["provider_id"]
        for item in providers
    ):
        raise ValueError("provider runtime coverage identifiers are invalid")
    if any(
        not isinstance(item, dict)
        or set(item) != {"env_id", "reason"}
        or not isinstance(item["env_id"], str)
        or not item["env_id"]
        or not isinstance(item["reason"], str)
        or not item["reason"]
        for item in excluded
    ):
        raise ValueError("provider runtime coverage exclusions are invalid")
    if len({item["env_id"] for item in providers}) != len(providers):
        raise ValueError("provider runtime coverage contains duplicate environment ids")
    if any(
        item["source_kind"] not in {"world_v1", "gate_config"}
        or item["behavior_protocol"]
        != ("world_v1_adapter" if item["source_kind"] == "world_v1" else "gate_config_v1")
        or type(item["operation_count"]) is not int
        or item["operation_count"] <= 0
        or item["reset_passed"] is not True
        or item["task_assets_present"] is not False
        or item["status"] != "passed"
        for item in providers
    ):
        raise ValueError("provider runtime coverage contains a failed or inconsistent entry")
    expected_summary = {
        "registered_environment_count": len(providers) + len(excluded),
        "provider_count": len(providers),
        "world_v1_count": sum(item["source_kind"] == "world_v1" for item in providers),
        "gate_config_count": sum(item["source_kind"] == "gate_config" for item in providers),
        "excluded_composite_count": len(excluded),
        "passed_count": len(providers),
    }
    if summary != expected_summary:
        raise ValueError("provider runtime coverage summary does not match its entries")
    return report


def load_and_validate_report(path: Path = REPORT_PATH) -> dict[str, Any]:
    return validate_report(json.loads(path.read_text(encoding="utf-8")))


def build_report(root: Path = ROOT) -> dict[str, Any]:
    registry = json.loads((root / "envs/registry.json").read_text(encoding="utf-8"))
    providers: list[dict[str, Any]] = []
    excluded: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="datalox-provider-coverage-", dir="/tmp") as temp:
        output_root = Path(temp)
        for entry in registry["environments"]:
            provider = entry["provider"]
            if provider.get("kind", "actual_provider") == "modeled_composite":
                excluded.append(
                    {
                        "env_id": entry["env_id"],
                        "reason": "consumer-owned cross-provider world, not a provider behavior pack",
                    }
                )
                continue
            env_root = root / entry["artifact_path"]
            provider_id = provider["id"]
            authority = f"{provider_id.replace('_', '-')}.datalox.invalid"
            bundle_root = output_root / entry["env_id"]
            if entry["statefulness_level"] == "full_world":
                source = validate_world_bundle(env_root)
                episode_id = source.episodes[0]["id"]
                build_provider_runtime_from_world(
                    source_world_dir=env_root,
                    output_dir=bundle_root,
                    provider_id=provider_id,
                    authorities=(authority,),
                    episode_id=episode_id,
                )
                source_kind = "world_v1"
                expected_count = len(source.tools)
            else:
                build_provider_runtime_from_gate_config(
                    source_gate_config=env_root / "gate_config.json",
                    output_dir=bundle_root,
                    provider_id=provider_id,
                    authorities=(authority,),
                )
                source_kind = "gate_config"
                expected_count = entry["counts"]["response_cases"]
            bundle = load_provider_runtime_bundle(bundle_root)
            actual_count = (
                len(bundle.tools)
                if source_kind == "world_v1"
                else len(bundle.gate_config.response_cases)  # type: ignore[union-attr]
            )
            if actual_count != expected_count:
                raise ValueError(
                    f"{entry['env_id']} operation count changed during provider compilation"
                )
            runtime = ProviderRuntime(
                bundle_dir=bundle_root,
                run_dir=output_root / f"{entry['env_id']}-run",
            )
            try:
                reset = runtime.reset()
            finally:
                runtime.close()
            providers.append(
                {
                    "env_id": entry["env_id"],
                    "provider_id": provider_id,
                    "source_kind": source_kind,
                    "behavior_protocol": bundle.manifest.behavior.protocol,
                    "operation_count": actual_count,
                    "reset_passed": reset["call_evidence"]["events"] == [],
                    "task_assets_present": any(
                        path.name in {"task.json", "episodes.jsonl", "verifier.json", "reward.json"}
                        for path in bundle_root.rglob("*")
                    ),
                    "status": "passed",
                }
            )
    providers.sort(key=lambda item: item["env_id"])
    excluded.sort(key=lambda item: item["env_id"])
    return validate_report(
        {
            "schema_version": "datalox_provider_runtime_coverage_v1",
            "scope": "registered actual-provider environments",
            "authority_note": (
                "Compilation uses reserved .invalid authorities only for structural proof. "
                "A deployment must compile the exact operator-declared provider authority."
            ),
            "summary": {
                "registered_environment_count": len(registry["environments"]),
                "provider_count": len(providers),
                "world_v1_count": sum(item["source_kind"] == "world_v1" for item in providers),
                "gate_config_count": sum(
                    item["source_kind"] == "gate_config" for item in providers
                ),
                "excluded_composite_count": len(excluded),
                "passed_count": sum(item["status"] == "passed" for item in providers),
            },
            "providers": providers,
            "excluded": excluded,
        }
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--validate-report", action="store_true")
    args = parser.parse_args()
    if args.validate_report:
        try:
            report = load_and_validate_report()
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            print(f"Provider runtime coverage report is invalid: {exc}")
            return 1
        print(
            f"Provider runtime coverage report is valid: "
            f"{report['summary']['passed_count']} provider assets"
        )
        return 0
    report = build_report()
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.write:
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(rendered, encoding="utf-8")
        print(f"Wrote {REPORT_PATH.relative_to(ROOT)}")
        return 0
    if not REPORT_PATH.is_file() or REPORT_PATH.read_text(encoding="utf-8") != rendered:
        print(f"Provider runtime coverage report is stale: {REPORT_PATH.relative_to(ROOT)}")
        return 1
    print(f"Provider runtime coverage passed: {report['summary']['passed_count']} provider assets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
