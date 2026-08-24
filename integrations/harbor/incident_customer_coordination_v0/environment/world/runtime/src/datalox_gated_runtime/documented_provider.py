from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.models import ResponseCase

SCHEMA_VERSION = "documented_provider_v0"
GROUNDING_LEVELS = {
    "G1_DOCUMENTED_EXAMPLE",
    "G1_SCHEMA_INSTANTIATED",
}
SOURCE_KINDS = {
    "official_docs_example",
    "official_openapi",
    "official_discovery",
    "official_schema_repo",
}
TARGET_ARTIFACT_NAMES = ("gate_config.json", "task.json", "replay_script.json")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def compile_documented_provider_env(*, source: Path, out_dir: Path) -> dict[str, Any]:
    source = source.resolve()
    source_bytes = source.read_bytes()
    manifest = _load_manifest(source_bytes)
    validated = _validate_manifest(manifest)

    response_cases = [
        ResponseCase(
            case_id=case["case_id"],
            method=case["method"],
            path=case["path"],
            query=dict(case["query"]),
            status_code=case["status_code"],
            body=case["body"],
            evidence_ref=_evidence_ref(manifest, case, validated["sources_by_id"]),
        )
        for case in manifest["cases"]
    ]
    replay_script = [
        {
            "surface": "http",
            "method": case.method,
            "path": case.path,
            "query": dict(case.query),
            "body": None,
        }
        for case in response_cases
    ]

    _refuse_existing_target_artifacts(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    provider_id = manifest["provider_id"]
    config_id = f"documented_{provider_id}_{_slug(manifest['api_version'])}"
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    counts = validated["grounding_counts"]
    gate_config_payload = {
        "config_id": config_id,
        "metadata": {
            "provenance": "official_documentation",
            "provider": provider_id,
            "display_name": manifest["display_name"],
            "api_version": manifest["api_version"],
            "source_manifest": {
                "path": _portable_source_path(source),
                "sha256": source_sha256,
                "schema_version": SCHEMA_VERSION,
                "retrieved_at": manifest["retrieved_at"],
            },
            "grounding": {
                "level": "G1_DOCUMENTED",
                "case_levels": counts,
                "live_probe_level": None,
                "not_g2_reason": manifest["not_live_reason"],
            },
            "coverage": manifest["coverage"],
            "sources": manifest["sources"],
        },
        "response_cases": [asdict(case) for case in response_cases],
        "audit_rules": [],
        "policy": _replay_only_policy(),
    }
    task_payload = {
        "task_id": config_id,
        "title": f"[DRAFT] {manifest['display_name']} documented-response replay",
        "instructions": (
            "Use this credential-free replay environment as official-documentation-grounded "
            "API context. Response bodies preserve the provider's documented top-level shape. "
            "Evidence records distinguish documented examples from deterministic schema "
            "instantiations. No provider traffic was captured."
        ),
        "success_criteria": [
            "Session check passes.",
            "Every replay call is served without provider credentials or network access.",
            "Do not treat G1 documented cases as live-observed provider state or behavior.",
        ],
    }

    _write_json(out_dir / "gate_config.json", gate_config_payload)
    _write_json(out_dir / "task.json", task_payload)
    _write_json(out_dir / "replay_script.json", replay_script)
    load_gate_config(out_dir / "gate_config.json")

    return {
        "out_dir": str(out_dir.resolve()),
        "source": str(source),
        "source_sha256": source_sha256,
        "config_id": config_id,
        "provider_id": provider_id,
        "response_case_count": len(response_cases),
        "replay_step_count": len(replay_script),
        "family_count": len(manifest["coverage"]["families"]),
        "grounding_counts": counts,
    }


def _load_manifest(source_bytes: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(source_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("documented provider manifest must be utf-8 json") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid documented provider json: line {exc.lineno}") from exc
    if not isinstance(payload, dict):
        raise ValueError("documented provider manifest must contain an object")
    return payload


def _validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    for key in (
        "provider_id",
        "display_name",
        "api_version",
        "retrieved_at",
        "not_live_reason",
    ):
        _require_non_empty_string(manifest, key)
    if manifest["not_live_reason"].lower().find("no provider traffic") < 0:
        raise ValueError(
            "not_live_reason must explicitly state that no provider traffic was captured"
        )

    sources = manifest.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("sources must be a non-empty list")
    sources_by_id: dict[str, dict[str, Any]] = {}
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise ValueError(f"sources[{index}] must be an object")
        for key in ("source_id", "url", "kind", "retrieved_at", "locator"):
            _require_non_empty_string(source, key, prefix=f"sources[{index}]")
        if source["source_id"] in sources_by_id:
            raise ValueError(f"duplicate source_id: {source['source_id']}")
        if source["kind"] not in SOURCE_KINDS:
            raise ValueError(f"sources[{index}].kind is unsupported: {source['kind']}")
        parsed = urlparse(source["url"])
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError(f"sources[{index}].url must be an official https URL")
        sources_by_id[source["source_id"]] = source

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a non-empty list")
    case_ids: set[str] = set()
    replay_keys: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()
    grounding_counts = {level: 0 for level in sorted(GROUNDING_LEVELS)}
    families: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"cases[{index}] must be an object")
        for key in (
            "case_id",
            "operation_id",
            "family",
            "method",
            "path",
            "grounding",
            "source_locator",
            "derivation",
        ):
            _require_non_empty_string(case, key, prefix=f"cases[{index}]")
        if case["case_id"] in case_ids:
            raise ValueError(f"duplicate case_id: {case['case_id']}")
        case_ids.add(case["case_id"])
        if case["method"] != "GET":
            raise ValueError(f"cases[{index}].method must be GET")
        if not case["path"].startswith("/") or "{" in case["path"] or "}" in case["path"]:
            raise ValueError(f"cases[{index}].path must be a concrete absolute path")
        query = case.get("query")
        if not isinstance(query, dict) or any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in query.items()
        ):
            raise ValueError(f"cases[{index}].query must map strings to strings")
        status_code = case.get("status_code")
        if type(status_code) is not int or status_code < 100 or status_code > 599:
            raise ValueError(f"cases[{index}].status_code must be an HTTP status int")
        if "body" not in case:
            raise ValueError(f"cases[{index}].body is required")
        if case["grounding"] not in GROUNDING_LEVELS:
            raise ValueError(f"cases[{index}].grounding is unsupported: {case['grounding']}")
        grounding_counts[case["grounding"]] += 1
        refs = case.get("source_refs")
        if (
            not isinstance(refs, list)
            or not refs
            or any(not isinstance(ref, str) or ref not in sources_by_id for ref in refs)
        ):
            raise ValueError(f"cases[{index}].source_refs must resolve to declared sources")
        synthetic_values = case.get("synthetic_values")
        if not isinstance(synthetic_values, dict):
            raise ValueError(f"cases[{index}].synthetic_values must be an object")
        if case["grounding"] == "G1_SCHEMA_INSTANTIATED" and not synthetic_values:
            raise ValueError(
                f"cases[{index}].synthetic_values must disclose schema-instantiated values"
            )
        replay_key = ("GET", case["path"], tuple(sorted(query.items())))
        if replay_key in replay_keys:
            raise ValueError(f"duplicate replay key for cases[{index}]")
        replay_keys.add(replay_key)
        families.add(case["family"])

    coverage = manifest.get("coverage")
    if not isinstance(coverage, dict):
        raise ValueError("coverage must be an object")
    declared_families = coverage.get("families")
    if not isinstance(declared_families, list) or set(declared_families) != families:
        raise ValueError("coverage.families must exactly match case families")
    expected_counts = {
        "case_count": len(cases),
        "documented_example_count": grounding_counts["G1_DOCUMENTED_EXAMPLE"],
        "schema_instantiated_count": grounding_counts["G1_SCHEMA_INSTANTIATED"],
    }
    for key, expected in expected_counts.items():
        if coverage.get(key) != expected:
            raise ValueError(f"coverage.{key} must equal {expected}")
    if not isinstance(coverage.get("known_gaps"), list):
        raise ValueError("coverage.known_gaps must be a list")
    return {"sources_by_id": sources_by_id, "grounding_counts": grounding_counts}


def _evidence_ref(
    manifest: dict[str, Any],
    case: dict[str, Any],
    sources_by_id: dict[str, dict[str, Any]],
) -> str:
    evidence = {
        "provider": manifest["provider_id"],
        "api_version": manifest["api_version"],
        "grounding_level": case["grounding"],
        "live_probe_level": None,
        "operation_id": case["operation_id"],
        "family": case["family"],
        "source_locator": case["source_locator"],
        "derivation": case["derivation"],
        "synthetic_values": case["synthetic_values"],
        "sources": [sources_by_id[ref] for ref in case["source_refs"]],
    }
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"))


def _require_non_empty_string(
    value: dict[str, Any], key: str, *, prefix: str | None = None
) -> None:
    if not isinstance(value.get(key), str) or not value[key].strip():
        name = f"{prefix}.{key}" if prefix else key
        raise ValueError(f"{name} must be a non-empty string")


def _replay_only_policy() -> dict[str, Any]:
    return {
        "deny": [
            {
                "method": method,
                "path_prefix": "/",
                "reason_code": "documented_provider_replay_only",
                "message": "Documented-provider environments do not permit writes.",
            }
            for method in WRITE_METHODS
        ],
        "shadow_write": [],
        "live_capture": [],
    }


def _refuse_existing_target_artifacts(out_dir: Path) -> None:
    existing = [name for name in TARGET_ARTIFACT_NAMES if (out_dir / name).exists()]
    if existing:
        raise ValueError(
            f"refusing to overwrite existing environment artifacts: {', '.join(existing)}"
        )


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_") or "unknown"


def _portable_source_path(source: Path) -> str:
    try:
        return source.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return source.as_uri()
