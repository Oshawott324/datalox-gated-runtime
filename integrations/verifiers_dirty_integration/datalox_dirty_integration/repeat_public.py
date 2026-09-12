"""Offline checks for a reviewed, controller-only public evidence projection.

This is deliberately separate from the native audit. It rechecks published
provider effects, interventions and verifier components, not withheld model
responses, reasoning continuity, inference receipts or hosted-model identity.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from types import SimpleNamespace
from typing import Any

from datalox_dirty_integration.audit import audit_episode_export, canonical_sha256
from datalox_dirty_integration.episode import sha256_file
from datalox_dirty_integration.repeat_analysis import first_divergence
from datalox_dirty_integration.repeat_contract import ExperimentConfig
from datalox_dirty_integration.repeat_evidence import (
    RepeatEvidenceError,
    _audit_provider_calls,
    join_tool_observations,
    read_json,
)
from datalox_dirty_integration.scoring import (
    EvaluationOracle,
    request_discipline_report_for_episode,
    verify_task_for_episode,
)

SCOPE = "reviewed_provider_and_tool_projection_v1"
EPISODE_SCHEMA = "datalox_verifiers_rollout_evidence_v1"
FILES = {"experiment.json", "rollouts.jsonl", "summary.json"}
REVIEW_FIELDS = {
    "path",
    "sha256",
    "distribution",
    "origin",
    "captured_at",
    "source_license",
    "redistribution_basis",
    "sensitivity",
    "contains_provider_payload",
    "sanitization",
    "grounding_level",
}


def _equal(left: Any, right: Any, label: str) -> None:
    if isinstance(left, set) and isinstance(right, set):
        left, right = sorted(left), sorted(right)
    if canonical_sha256(left) != canonical_sha256(right):
        raise RepeatEvidenceError(f"public evidence {label} mismatch")


def _tool_projection(completion: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Retain original serialized calls/results; omit all assistant prose/extras."""
    projected = []
    for message in completion:
        if message["role"] == "assistant" and message.get("tool_calls"):
            projected.append({"role": "assistant", "tool_calls": message["tool_calls"]})
        elif message["role"] == "tool":
            projected.append({key: message[key] for key in ("role", "tool_call_id", "content")})
    return projected


def project_slot(source: Path, config: ExperimentConfig, slot: Any) -> dict[str, Any]:
    """Create a review candidate after the full private audit; grants no rights."""
    from datalox_dirty_integration.repeat_evidence import collect_slot

    audited = collect_slot(source, config, slot, verify_index=True)
    evidence_dir = next((source / "evidence").iterdir())
    native = read_json(source / "native" / "results.jsonl")
    row = {
        "slot": slot.model_dump(mode="json"),
        "episode_export": {
            "provider": read_json(evidence_dir / "provider-export.json"),
            "intervention": read_json(evidence_dir / "intervention-trace.json"),
            "delivered_calls": audited["provider_calls"],
        },
        "episode_manifest": read_json(evidence_dir / "manifest.json"),
        "verification": {key: audited[key] for key in ("task_correctness", "request_discipline")},
        "tool_transcript": _tool_projection(native["completion"]),
        "source_sha256": {
            "native_results": sha256_file(source / "native" / "results.jsonl"),
            "slot_index": sha256_file(source / "index.json"),
            "episode_manifest": sha256_file(evidence_dir / "manifest.json"),
        },
        "native_outcome": {
            key: native[key] for key in ("is_completed", "is_truncated", "error", "stop_condition")
        },
    }
    check_row(row, config, slot)
    return row


def check_row(row: dict[str, Any], config: ExperimentConfig, slot: Any) -> dict[str, Any]:
    _equal(
        set(row),
        {
            "slot",
            "episode_export",
            "verification",
            "tool_transcript",
            "source_sha256",
            "native_outcome",
            "episode_manifest",
        },
        "row fields",
    )
    _equal(row["slot"], slot.model_dump(mode="json"), "slot")
    _equal(
        set(row["source_sha256"]),
        {"native_results", "slot_index", "episode_manifest"},
        "source commitments",
    )
    for digest in row["source_sha256"].values():
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise RepeatEvidenceError("invalid source commitment")
    manifest = row["episode_manifest"]
    _equal(manifest["schema_version"], EPISODE_SCHEMA, "episode version")
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    _equal(
        "sha256:" + hashlib.sha256(manifest_bytes).hexdigest(),
        row["source_sha256"]["episode_manifest"],
        "source episode manifest",
    )
    _equal(manifest["profile"], slot.profile, "episode profile")
    for name, digest in manifest["provider"].items():
        if name in {"bundle_version", "profile_id", "release_version"}:
            continue
        _equal(config.bindings[f"provider.{name}"], digest, "frozen provider binding")
    exported = row["episode_export"]
    provider, intervention, calls = (
        exported["provider"],
        exported["intervention"],
        exported["delivered_calls"],
    )
    _equal(intervention["seed"], slot.seed, "seed")
    _equal(intervention["enabled"], True, "enabled policy")
    _equal(intervention["policy_sha256"], config.bindings[f"policy.{slot.profile}"], "policy")
    for name, value in manifest["intervention"].items():
        _equal(intervention[name], value, "episode intervention")
    # The original controller writer uses this exact JSON encoding. Reconstruct
    # its bytes to bind the public values to the original artifact commitments.
    artifacts = {
        "provider-export.json": provider,
        "intervention-trace.json": intervention,
        "delivered-observations.json": {
            "schema_version": EPISODE_SCHEMA,
            "calls": calls,
        },
        "verification.json": {
            "schema_version": EPISODE_SCHEMA,
            **row["verification"],
        },
    }
    _equal(set(manifest["artifacts"]), set(artifacts), "original artifact inventory")
    for name, value in artifacts.items():
        payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        _equal(
            "sha256:" + hashlib.sha256(payload).hexdigest(),
            manifest["artifacts"][name],
            "original controller bytes",
        )
    audit = audit_episode_export(exported)
    _audit_provider_calls(provider, intervention, calls)
    view = SimpleNamespace(
        provider=SimpleNamespace(export=lambda: provider),
        delivered_calls=calls,
        failed_calls=sum(not 200 <= call["observation"]["status_code"] < 300 for call in calls),
    )
    oracle = EvaluationOracle()
    expected = {
        "task_correctness": verify_task_for_episode(view, oracle).to_dict(),
        "request_discipline": request_discipline_report_for_episode(view, oracle).to_dict(),
    }
    _equal(expected, row["verification"], "recomputed verification")
    _equal(_tool_projection(row["tool_transcript"]), row["tool_transcript"], "tool-only surface")
    joined = join_tool_observations(row["tool_transcript"], calls)
    if joined["unexecuted_tool_attempts"]:
        raise RepeatEvidenceError("this completed public cohort requires executed tool calls")
    _equal(
        row["native_outcome"],
        {
            "is_completed": True,
            "is_truncated": False,
            "error": None,
            "stop_condition": "no_tools_called",
        },
        "declared native completion",
    )
    if not audit["passed"]:
        raise RepeatEvidenceError("public intervention audit failed")
    return {**expected, "audit": audit, **joined}


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Provider-only statistics; no raw-native-message or inference audit claim."""
    groups = []
    for profile, seed in sorted({(row["slot"]["profile"], row["slot"]["seed"]) for row in rows}):
        selected = [
            row for row in rows if (row["slot"]["profile"], row["slot"]["seed"]) == (profile, seed)
        ]
        paths: dict[str, dict[str, Any]] = {}
        for row in selected:
            calls = row["episode_export"]["delivered_calls"]
            digest = canonical_sha256(calls)
            path = paths.setdefault(
                digest,
                {
                    "provider_trace_sha256": digest,
                    "slots": [],
                    "product_offsets": [
                        int(call["request"]["query"]["offset"])
                        for call in calls
                        if call["request"]["path"] == "/store/products"
                    ],
                },
            )
            path["slots"].append(row["slot"]["slot_id"])
        exposure = Counter()
        for row in selected:
            events = row["episode_export"]["intervention"]["events"]
            exposure[
                (
                    sum(event["applied"] for event in events),
                    sum(event["observation_changed"] is True for event in events),
                )
            ] += 1
        groups.append(
            {
                "profile": profile,
                "seed": seed,
                "runs": len(selected),
                "task_passes": sum(
                    row["verification"]["task_correctness"]["passed"] for row in selected
                ),
                "provider_call_counts": sorted(
                    {len(row["episode_export"]["delivered_calls"]) for row in selected}
                ),
                "discipline_scores": sorted(
                    {row["verification"]["request_discipline"]["score"] for row in selected}
                ),
                "distinct_provider_traces": len(paths),
                "paths": sorted(paths.values(), key=lambda path: path["slots"][0]),
                "exposure": [
                    {"applied": applied, "changed": changed, "runs": count}
                    for (applied, changed), count in sorted(exposure.items())
                ],
            }
        )
    divergences = []
    for index, left in enumerate(rows):
        for right in rows[index + 1 :]:
            if (left["slot"]["profile"], left["slot"]["seed"]) != (
                right["slot"]["profile"],
                right["slot"]["seed"],
            ):
                continue
            a, b = (row["episode_export"]["delivered_calls"] for row in (left, right))
            request = first_divergence(
                [{key: call[key] for key in ("operation_id", "request")} for call in a],
                [{key: call[key] for key in ("operation_id", "request")} for call in b],
            )
            observation = first_divergence(
                [call["observation"] for call in a], [call["observation"] for call in b]
            )
            divergences.append(
                {
                    "left": left["slot"]["slot_id"],
                    "right": right["slot"]["slot_id"],
                    "first_request_position": request["position"] if request else None,
                    "first_observation_position": observation["position"] if observation else None,
                }
            )
    return {
        "scope": SCOPE,
        "runs": len(rows),
        "groups": groups,
        "pairwise_divergences": divergences,
    }


def verify_public_bundle(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest = read_json(root / "PUBLIC_EVIDENCE_MANIFEST.json")
    _equal(
        set(manifest),
        {"schema_version", "scope", "source_commitments", "artifacts"},
        "manifest fields",
    )
    _equal(manifest["schema_version"], "datalox_reviewed_repeat_evidence_v1", "version")
    _equal(manifest["scope"], SCOPE, "scope")
    commitments = manifest["source_commitments"]
    _equal(
        set(commitments),
        {"experiment_file", "collection_file", "native_analysis_summary", "public_source_manifest"},
        "collection source commitments",
    )
    if any(
        not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value)
        for value in commitments.values()
    ):
        raise RepeatEvidenceError("invalid collection source commitment")
    _equal(
        commitments["experiment_file"],
        sha256_file(root / "experiment.json"),
        "original frozen experiment",
    )
    entries = manifest["artifacts"]
    if not isinstance(entries, list) or len(entries) != len(FILES):
        raise RepeatEvidenceError("public artifact inventory is incomplete")
    _equal({entry["path"] for entry in entries}, FILES, "file inventory")
    for entry in entries:
        _equal(set(entry), REVIEW_FIELDS, "review fields")
        if (
            entry["distribution"] != "public"
            or any(
                not isinstance(entry[field], str) or not entry[field].strip()
                for field in REVIEW_FIELDS - {"contains_provider_payload"}
            )
            or type(entry["contains_provider_payload"]) is not bool
        ):
            raise RepeatEvidenceError("public artifact requires a completed rights/content review")
        path = PurePosixPath(entry["path"])
        if path.as_posix() not in FILES:
            raise RepeatEvidenceError("unexpected public artifact path")
        _equal(sha256_file(root / path), entry["sha256"], "artifact digest")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RepeatEvidenceError("public evidence contains a symlink")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    _equal(actual, FILES | {"PUBLIC_EVIDENCE_MANIFEST.json"}, "exact file set")
    config = ExperimentConfig.model_validate_json((root / "experiment.json").read_text())
    from datalox_dirty_integration.repeat_evidence import parse_json

    rows = [parse_json(line) for line in (root / "rollouts.jsonl").read_text().splitlines()]
    if len(rows) != len(config.schedule):
        raise RepeatEvidenceError("public evidence must cover every declared rollout")
    for row, slot in zip(rows, config.schedule, strict=True):
        check_row(row, config, slot)
    summary = summarize(rows)
    _equal(summary, read_json(root / "summary.json"), "summary")
    return {
        "passed": True,
        "scope": SCOPE,
        "runs": len(rows),
        "summary_sha256": canonical_sha256(summary),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(verify_public_bundle(args.source), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
