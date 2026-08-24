from __future__ import annotations

import ast
import hashlib
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from datalox_gated_runtime.world_v1.bundle import (
    compute_bundle_hashes,
    load_world_bundle,
    validate_world_bundle,
)
from datalox_gated_runtime.world_v1.errors import WorldBundleError

ADMISSION_SCHEMA_VERSION = "datalox_world_admission_v1"
WORLD_SCHEMA_VERSION = "datalox_world_bundle_v1"
GROUNDING_LEVEL_PATTERN = re.compile(r"^G[0-4](?:_[A-Z0-9_]+)?$")


@dataclass(frozen=True)
class AdmissionFinding:
    code: str
    check: str
    message: str
    path: str | None = None
    context: dict[str, Any] = field(default_factory=dict)
    severity: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TrajectoryOutcome:
    passed: bool
    failure_codes: tuple[str, ...] = ()
    export_path: str | None = None


@dataclass(frozen=True)
class ParityOutcome:
    matched: bool
    http_fingerprint: str | None = None
    mcp_fingerprint: str | None = None


ResetFingerprintCallback = Callable[[Path, str], str]
TrajectoryCallback = Callable[[Path, Mapping[str, Any]], TrajectoryOutcome]
ParityCallback = Callable[[Path, Mapping[str, Any]], ParityOutcome]
ExportCallback = Callable[[Path], Mapping[str, Any]]


@dataclass(frozen=True)
class AdmissionCallbacks:
    """Runtime-dependent checks supplied by the CLI/runtime integration.

    Callbacks receive the bundle root and declared episode/trajectory data.
    They must create fresh sessions internally. Admission never supplies or
    reads provider credentials.
    """

    reset_fingerprint: ResetFingerprintCallback | None = None
    run_trajectory: TrajectoryCallback | None = None
    run_parity: ParityCallback | None = None
    export_session: ExportCallback | None = None


@dataclass(frozen=True)
class AdmissionReport:
    schema_version: str
    world_id: str | None
    bundle_version: str | None
    admitted: bool
    admission_timestamp: str
    bundle_path: str
    artifact_hashes: dict[str, str]
    checks: dict[str, dict[str, Any]]
    coverage: dict[str, Any]
    provenance: dict[str, Any]
    tests: dict[str, Any]
    findings: tuple[AdmissionFinding, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["findings"] = [finding.to_dict() for finding in self.findings]
        return payload


class _Collector:
    def __init__(self, bundle_root: Path) -> None:
        self.bundle_root = bundle_root
        self.findings: list[AdmissionFinding] = []
        self.executed: set[str] = set()

    def mark_executed(self, check: str) -> None:
        self.executed.add(check)

    def add(
        self,
        code: str,
        check: str,
        message: str,
        *,
        path: Path | str | None = None,
        context: Mapping[str, Any] | None = None,
        severity: str = "error",
    ) -> None:
        if isinstance(path, Path):
            try:
                rendered_path = path.relative_to(self.bundle_root).as_posix()
            except ValueError:
                rendered_path = str(path)
        else:
            rendered_path = path
        self.findings.append(
            AdmissionFinding(
                code=code,
                check=check,
                message=message,
                path=rendered_path,
                context=dict(context or {}),
                severity=severity,
            )
        )

    def checks(self) -> dict[str, dict[str, Any]]:
        names = (
            "structure",
            "hashes",
            "provenance",
            "cross_references",
            "reset_determinism",
            "surface_parity",
            "trajectories",
            "hidden_leakage",
            "credential_freedom",
            "no_live_writes",
            "session_export",
        )
        return {
            name: {
                "executed": name in self.executed,
                "passed": name in self.executed
                and not any(
                    finding.check == name and finding.severity == "error"
                    for finding in self.findings
                ),
                "finding_codes": [
                    finding.code for finding in self.findings if finding.check == name
                ],
            }
            for name in names
        }


def admit_world(
    bundle_path: Path | str,
    *,
    callbacks: AdmissionCallbacks | None = None,
    admitted_at: str | None = None,
) -> AdmissionReport:
    """Run all independent admission checks and return one machine-readable report."""

    root = Path(bundle_path).resolve()
    callbacks = callbacks or AdmissionCallbacks()
    collector = _Collector(root)

    manifest_path = root / "world" / "manifest.json"
    manifest = _load_manifest(manifest_path, collector)
    artifacts: dict[str, str] = {}
    documents: dict[str, Any] = {}
    episodes: list[dict[str, Any]] = []
    trajectories: list[dict[str, Any]] = []

    if manifest is not None:
        artifacts = _validate_structure_and_hashes(root, manifest, collector)
        documents = _load_declared_documents(root, manifest, collector)
        episodes = _episode_records(documents.get("episodes"), collector, manifest)
        trajectories = _trajectory_records(root, manifest, collector)
        _validate_provenance(documents.get("sources"), collector, manifest)
        _validate_cross_references(documents, manifest, collector)
        _validate_hidden_leakage(root, documents, episodes, collector)
        _validate_credentials(root, manifest, documents, collector)
        _validate_no_live_writes(root, manifest, documents, collector)
        structural_errors = any(
            finding.severity == "error" and finding.check in {"structure", "hashes"}
            for finding in collector.findings
        )
        if structural_errors:
            _block_runtime_checks(collector)
        else:
            _run_reset_checks(root, episodes, callbacks, collector)
            _run_trajectory_checks(root, trajectories, episodes, callbacks, collector)
            _run_parity_checks(root, trajectories, callbacks, collector)
            _run_export_check(root, callbacks, collector)
    else:
        for check in (
            "hashes",
            "provenance",
            "cross_references",
            "reset_determinism",
            "surface_parity",
            "trajectories",
            "hidden_leakage",
            "credential_freedom",
            "no_live_writes",
            "session_export",
        ):
            collector.add(
                "world_admission_manifest_required",
                check,
                "check could not run without a valid world/manifest.json",
                path=manifest_path,
            )

    checks = collector.checks()
    admitted = all(check["passed"] for check in checks.values())
    sources = _named_records(documents.get("sources"), "sources")
    source_levels = Counter(
        str(source.get("grounding_level")) for source in sources if source.get("grounding_level")
    )
    roles = _named_records(documents.get("roles"), "roles")
    tools = _named_records(documents.get("tools"), "tools")
    trajectory_kinds = Counter(str(item.get("kind")) for item in trajectories)
    provenance = {
        "source_count": len(sources),
        "grounding_levels": {key: source_levels[key] for key in sorted(source_levels)},
        "grounding_gaps": _grounding_gaps(documents.get("sources")),
    }
    coverage = {
        "role_count": len(roles),
        "tool_count": len(tools),
        "episode_count": len(episodes),
        "trajectory_count": len(trajectories),
        "reference_trajectory_count": trajectory_kinds["reference"],
        "negative_trajectory_count": trajectory_kinds["negative"],
        "parity_case_count": trajectory_kinds["parity"],
        "operation_families": sorted(
            {
                str(tool["operation_family"])
                for tool in tools
                if isinstance(tool.get("operation_family"), str)
            }
        ),
    }
    tests = {
        "reset_episode_count": len(episodes) if callbacks.reset_fingerprint else 0,
        "trajectory_results": _trajectory_test_summaries(trajectories, collector.findings),
        "session_export_executed": callbacks.export_session is not None,
    }
    return AdmissionReport(
        schema_version=ADMISSION_SCHEMA_VERSION,
        world_id=_string_or_none(manifest, "world_id"),
        bundle_version=_string_or_none(manifest, "bundle_version"),
        admitted=admitted,
        admission_timestamp=admitted_at or datetime.now(UTC).isoformat(),
        bundle_path=str(root),
        artifact_hashes=artifacts,
        checks=checks,
        coverage=coverage,
        provenance=provenance,
        tests=tests,
        findings=tuple(collector.findings),
    )


def write_admission_artifact(
    report: AdmissionReport,
    *,
    path: Path | str | None = None,
) -> Path:
    """Write a successful report; failed admission artifacts are never blessed."""

    if not report.admitted:
        raise ValueError("cannot write world_admission.json for a failed admission")
    destination = (
        Path(path) if path is not None else Path(report.bundle_path) / "world_admission.json"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(f"{destination.suffix}.tmp")
    temporary.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(destination)
    return destination


def _load_manifest(path: Path, collector: _Collector) -> dict[str, Any] | None:
    collector.mark_executed("structure")
    return _read_json_object(path, collector, "structure", "world_admission_manifest_invalid")


def _validate_structure_and_hashes(
    root: Path, manifest: Mapping[str, Any], collector: _Collector
) -> dict[str, str]:
    collector.mark_executed("hashes")
    try:
        validate_world_bundle(root)
        computed = compute_bundle_hashes(root)
        artifacts = dict(computed)
        load_world_bundle(root)
    except WorldBundleError as exc:
        collector.add(exc.code, "structure", str(exc), path=root / "world" / "manifest.json")
        artifacts = _compute_local_hashes(root)

    declared = manifest.get("content_hashes")
    if not isinstance(declared, dict):
        collector.add(
            "world_admission_hashes_invalid",
            "hashes",
            "manifest.content_hashes must be an object",
            path=root / "world" / "manifest.json",
        )
        return artifacts
    for relative, digest in declared.items():
        if not isinstance(relative, str) or not isinstance(digest, str):
            collector.add(
                "world_admission_hash_invalid",
                "hashes",
                "content hash entries must map relative paths to digest strings",
                path=root / "world" / "manifest.json",
            )
            continue
        actual = artifacts.get(relative)
        if actual is None:
            collector.add(
                "world_admission_hashed_artifact_missing",
                "hashes",
                f"declared hashed artifact is missing: {relative}",
                path=relative,
            )
        elif actual != digest:
            collector.add(
                "world_admission_hash_mismatch",
                "hashes",
                f"content hash mismatch for {relative}",
                path=relative,
                context={"declared": digest, "actual": actual},
            )
    return artifacts


def _load_declared_documents(
    root: Path, manifest: Mapping[str, Any], collector: _Collector
) -> dict[str, Any]:
    documents: dict[str, Any] = {}
    fields = {
        "roles": "roles_path",
        "tools": "tools_path",
        "verifier": "verifier_path",
        "sources": "sources_path",
    }
    for name, field_name in fields.items():
        relative = manifest.get(field_name)
        if not isinstance(relative, str):
            continue
        documents[name] = _read_json_object(
            root / relative,
            collector,
            "structure",
            f"world_admission_{name}_invalid",
        )
    episodes_path = manifest.get("episodes_path")
    if isinstance(episodes_path, str):
        documents["episodes"] = _read_jsonl(root / episodes_path, collector, "structure")
    task_path = root / "task.json"
    if task_path.is_file():
        documents["task"] = _read_json_object(
            task_path, collector, "hidden_leakage", "world_admission_task_invalid"
        )
    gate_path = root / "gate_config.json"
    if gate_path.is_file():
        documents["gate_config"] = _read_json_object(
            gate_path, collector, "credential_freedom", "world_admission_gate_config_invalid"
        )
    return documents


def _episode_records(
    value: Any, collector: _Collector, manifest: Mapping[str, Any]
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        collector.add(
            "world_admission_episodes_invalid",
            "structure",
            "episodes_path must contain JSON objects, one per line",
            path=str(manifest.get("episodes_path")),
        )
        return []
    records: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            collector.add(
                "world_admission_episode_invalid",
                "structure",
                f"episode line {index + 1} must be an object",
                path=str(manifest.get("episodes_path")),
            )
            continue
        records.append(item)
    return records


def _trajectory_records(
    root: Path, manifest: Mapping[str, Any], collector: _Collector
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    paths = manifest.get("trajectory_paths", [])
    if not isinstance(paths, list):
        collector.add(
            "world_admission_trajectory_paths_invalid",
            "structure",
            "manifest.trajectory_paths must be a list",
            path=root / "world" / "manifest.json",
        )
        return records
    for relative in paths:
        if not isinstance(relative, str):
            collector.add(
                "world_admission_trajectory_path_invalid",
                "structure",
                "trajectory path must be a string",
                path=root / "world" / "manifest.json",
            )
            continue
        payload = _read_json_value(
            root / relative,
            collector,
            "structure",
            "world_admission_trajectory_invalid",
        )
        if isinstance(payload, dict):
            candidates = payload.get("trajectories", [payload])
        else:
            candidates = payload
        if not isinstance(candidates, list):
            collector.add(
                "world_admission_trajectory_invalid",
                "structure",
                "trajectory file must contain an object, list, or {trajectories: [...]}",
                path=relative,
            )
            continue
        for item in candidates:
            if not isinstance(item, dict):
                collector.add(
                    "world_admission_trajectory_invalid",
                    "structure",
                    "every trajectory must be an object",
                    path=relative,
                )
                continue
            enriched = dict(item)
            enriched["_path"] = relative
            records.append(enriched)
    return records


def _validate_provenance(value: Any, collector: _Collector, manifest: Mapping[str, Any]) -> None:
    collector.mark_executed("provenance")
    sources = _named_records(value, "sources")
    if not sources:
        collector.add(
            "world_admission_sources_empty",
            "provenance",
            "world must declare at least one grounded source",
            path=str(manifest.get("sources_path")),
        )
        return
    seen: set[str] = set()
    for index, source in enumerate(sources):
        source_id = source.get("id")
        if not isinstance(source_id, str) or not source_id:
            collector.add(
                "world_admission_source_id_invalid",
                "provenance",
                f"sources[{index}].id must be a non-empty string",
                path=str(manifest.get("sources_path")),
            )
        elif source_id in seen:
            collector.add(
                "world_admission_source_id_duplicate",
                "provenance",
                f"duplicate source id: {source_id}",
                path=str(manifest.get("sources_path")),
            )
        else:
            seen.add(source_id)
        for field_name in ("kind", "locator", "derivation"):
            if not isinstance(source.get(field_name), str) or not source[field_name].strip():
                collector.add(
                    "world_admission_source_provenance_incomplete",
                    "provenance",
                    f"source {source_id or index!r} requires non-empty {field_name}",
                    path=str(manifest.get("sources_path")),
                    context={"source_id": source_id, "field": field_name},
                )
        level = source.get("grounding_level")
        if not isinstance(level, str) or not GROUNDING_LEVEL_PATTERN.fullmatch(level):
            collector.add(
                "world_admission_grounding_level_invalid",
                "provenance",
                f"source {source_id or index!r} has invalid grounding_level",
                path=str(manifest.get("sources_path")),
                context={"grounding_level": level},
            )
        supports = source.get("supports")
        if (
            not isinstance(supports, list)
            or not supports
            or not all(isinstance(item, str) and item for item in supports)
        ):
            collector.add(
                "world_admission_source_claims_missing",
                "provenance",
                f"source {source_id or index!r} must declare supported claims",
                path=str(manifest.get("sources_path")),
            )


def _validate_cross_references(
    documents: Mapping[str, Any], manifest: Mapping[str, Any], collector: _Collector
) -> None:
    collector.mark_executed("cross_references")
    roles = _named_records(documents.get("roles"), "roles")
    tools = _named_records(documents.get("tools"), "tools")
    sources = _named_records(documents.get("sources"), "sources")
    role_ids = {item.get("id") for item in roles if isinstance(item.get("id"), str)}
    tool_ids = {item.get("id") for item in tools if isinstance(item.get("id"), str)}
    source_ids = {item.get("id") for item in sources if isinstance(item.get("id"), str)}

    default_role = manifest.get("default_actor_role")
    if default_role not in role_ids:
        collector.add(
            "world_admission_default_role_unknown",
            "cross_references",
            f"default_actor_role {default_role!r} is not declared in roles",
            path=str(manifest.get("roles_path")),
        )
    for tool in tools:
        tool_id = tool.get("id")
        for field_name in ("list_roles", "invoke_roles"):
            refs = tool.get(field_name)
            if not isinstance(refs, list):
                collector.add(
                    "world_admission_tool_roles_invalid",
                    "cross_references",
                    f"tool {tool_id!r} requires a {field_name} list",
                    path=str(manifest.get("tools_path")),
                )
                continue
            for role in refs:
                if role not in role_ids:
                    collector.add(
                        "world_admission_tool_role_unknown",
                        "cross_references",
                        f"tool {tool_id!r} references unknown role {role!r}",
                        path=str(manifest.get("tools_path")),
                        context={"tool_id": tool_id, "field": field_name, "role": role},
                    )
        source_refs = tool.get("source_refs", [])
        if not isinstance(source_refs, list):
            collector.add(
                "world_admission_tool_sources_invalid",
                "cross_references",
                f"tool {tool_id!r} source_refs must be a list",
                path=str(manifest.get("tools_path")),
            )
        else:
            for source_ref in source_refs:
                if source_ref not in source_ids:
                    collector.add(
                        "world_admission_tool_source_unknown",
                        "cross_references",
                        f"tool {tool_id!r} references unknown source {source_ref!r}",
                        path=str(manifest.get("tools_path")),
                    )

    verifier = documents.get("verifier")
    if isinstance(verifier, dict):
        for assertion in verifier.get("assertions", []):
            if not isinstance(assertion, dict):
                continue
            role_ref = assertion.get("role_id")
            tool_ref = assertion.get("tool_id")
            if role_ref is not None and role_ref not in role_ids:
                collector.add(
                    "world_admission_verifier_role_unknown",
                    "cross_references",
                    f"verifier references unknown role {role_ref!r}",
                    path=str(manifest.get("verifier_path")),
                )
            if tool_ref is not None and tool_ref not in tool_ids:
                collector.add(
                    "world_admission_verifier_tool_unknown",
                    "cross_references",
                    f"verifier references unknown tool {tool_ref!r}",
                    path=str(manifest.get("verifier_path")),
                )


def _validate_hidden_leakage(
    root: Path,
    documents: Mapping[str, Any],
    episodes: Sequence[Mapping[str, Any]],
    collector: _Collector,
) -> None:
    collector.mark_executed("hidden_leakage")
    shared_visible: list[Any] = [documents.get("task")]
    verifier = documents.get("verifier")
    shared_hidden = verifier.get("hidden_expected_values", []) if isinstance(verifier, dict) else []
    for episode in episodes:
        episode_id = episode.get("id")
        hidden: list[Any] = list(shared_hidden) if isinstance(shared_hidden, list) else []
        hidden.extend(_declared_hidden_values(episode))
        visible = shared_visible + _declared_visible_values(episode)
        visible_scalars = list(_scalars(visible))
        visible_text = json.dumps(visible, sort_keys=True, ensure_ascii=False).casefold()
        for value in _scalars(hidden):
            if value is None or isinstance(value, bool):
                continue
            exact = any(value == candidate for candidate in visible_scalars)
            substring = isinstance(value, str) and value.casefold() in visible_text
            if exact or substring:
                collector.add(
                    "world_admission_hidden_value_leaked",
                    "hidden_leakage",
                    f"hidden expected value is present in agent-visible data for episode {episode_id!r}",
                    path=root / "task.json",
                    context={"episode_id": episode_id, "value": value},
                )


def _validate_credentials(
    root: Path,
    manifest: Mapping[str, Any],
    documents: Mapping[str, Any],
    collector: _Collector,
) -> None:
    collector.mark_executed("credential_freedom")
    forbidden_keys = {
        "api_key",
        "api_key_env",
        "auth_env",
        "authorization",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "password",
        "required_env",
        "secret",
        "secrets",
    }
    for document_name, payload in documents.items():
        for location, key, value in _mapping_entries(payload):
            normalized = key.casefold().replace("-", "_")
            is_forbidden = normalized in forbidden_keys or normalized.endswith(
                ("_api_key", "_password", "_secret", "_token")
            )
            if is_forbidden and value not in (None, "", [], {}):
                collector.add(
                    "world_admission_credential_requirement",
                    "credential_freedom",
                    f"credential-bearing field {key!r} is not allowed in a world bundle",
                    path=_document_path(root, manifest, document_name),
                    context={"json_path": location},
                )
            if isinstance(value, str) and (
                "-----BEGIN PRIVATE KEY-----" in value
                or re.search(r"https?://[^/:\s]+:[^/@\s]+@", value)
            ):
                collector.add(
                    "world_admission_credential_value",
                    "credential_freedom",
                    "credential-like value is persisted in the bundle",
                    path=_document_path(root, manifest, document_name),
                    context={"json_path": location},
                )

    for source_path in _python_source_paths(root, manifest):
        tree = _parse_implementation(source_path)
        if tree is not None:
            reported_lines: set[int | None] = set()
            for node in ast.walk(tree):
                environment_access = (
                    isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id == "os"
                    and node.attr in {"environ", "getenv"}
                ) or (
                    isinstance(node, ast.ImportFrom)
                    and node.module == "os"
                    and any(alias.name in {"environ", "getenv"} for alias in node.names)
                )
                line = getattr(node, "lineno", None)
                if environment_access and line not in reported_lines:
                    reported_lines.add(line)
                    collector.add(
                        "world_admission_credential_requirement",
                        "credential_freedom",
                        "world implementation may not depend on process environment credentials",
                        path=source_path,
                        context={"line": line},
                    )


def _validate_no_live_writes(
    root: Path,
    manifest: Mapping[str, Any],
    documents: Mapping[str, Any],
    collector: _Collector,
) -> None:
    collector.mark_executed("no_live_writes")
    for document_name, payload in documents.items():
        for location, key, value in _mapping_entries(payload):
            normalized_key = key.casefold().replace("-", "_")
            normalized_value = value.casefold().replace("-", "_") if isinstance(value, str) else ""
            if normalized_key == "live_write" or normalized_value == "live_write":
                collector.add(
                    "world_admission_live_write_expressible",
                    "no_live_writes",
                    "live writes must remain inexpressible",
                    path=_document_path(root, manifest, document_name),
                    context={"json_path": location},
                )

    gate = documents.get("gate_config")
    if isinstance(gate, dict):
        policy = gate.get("policy")
        live_rules = policy.get("live_capture", []) if isinstance(policy, dict) else []
        if isinstance(live_rules, list):
            for index, rule in enumerate(live_rules):
                method = rule.get("method") if isinstance(rule, dict) else None
                if method != "GET":
                    collector.add(
                        "world_admission_live_capture_not_get",
                        "no_live_writes",
                        "every live_capture rule must be explicitly GET-only",
                        path=root / "gate_config.json",
                        context={"rule_index": index, "method": method},
                    )

    for source_path in _python_source_paths(root, manifest):
        tree = _parse_implementation(source_path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            value: str | None = None
            if isinstance(node, ast.Name):
                value = node.id
            elif isinstance(node, ast.Attribute):
                value = node.attr
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
            if value and "live_write" in value.casefold().replace("-", "_"):
                collector.add(
                    "world_admission_live_write_expressible",
                    "no_live_writes",
                    "implementation contains a live_write execution symbol or value",
                    path=source_path,
                    context={"line": getattr(node, "lineno", None)},
                )


def _run_reset_checks(
    root: Path,
    episodes: Sequence[Mapping[str, Any]],
    callbacks: AdmissionCallbacks,
    collector: _Collector,
) -> None:
    collector.mark_executed("reset_determinism")
    if callbacks.reset_fingerprint is None:
        collector.add(
            "world_admission_reset_runner_missing",
            "reset_determinism",
            "runtime reset callback is required for admission",
        )
        return
    for episode in episodes:
        episode_id = episode.get("id")
        if not isinstance(episode_id, str):
            continue
        try:
            first = callbacks.reset_fingerprint(root, episode_id)
            second = callbacks.reset_fingerprint(root, episode_id)
        except Exception as exc:
            collector.add(
                "world_admission_reset_failed",
                "reset_determinism",
                f"fresh reset failed for episode {episode_id!r}: {exc}",
                context={"episode_id": episode_id},
            )
            continue
        if not isinstance(first, str) or not isinstance(second, str) or first != second:
            collector.add(
                "world_admission_reset_nondeterministic",
                "reset_determinism",
                f"fresh resets differ for episode {episode_id!r}",
                context={"episode_id": episode_id, "first": first, "second": second},
            )


def _block_runtime_checks(collector: _Collector) -> None:
    for check in (
        "reset_determinism",
        "surface_parity",
        "trajectories",
        "session_export",
    ):
        collector.mark_executed(check)
        collector.add(
            "world_admission_execution_blocked",
            check,
            "runtime check was not executed because structural or hash validation failed",
        )


def _run_trajectory_checks(
    root: Path,
    trajectories: Sequence[Mapping[str, Any]],
    episodes: Sequence[Mapping[str, Any]],
    callbacks: AdmissionCallbacks,
    collector: _Collector,
) -> None:
    collector.mark_executed("trajectories")
    executable = [item for item in trajectories if item.get("kind") in {"reference", "negative"}]
    if not any(item.get("kind") == "reference" for item in executable):
        collector.add(
            "world_admission_reference_trajectory_missing",
            "trajectories",
            "at least one reference trajectory is required",
        )
    if not any(item.get("kind") == "negative" for item in executable):
        collector.add(
            "world_admission_negative_trajectory_missing",
            "trajectories",
            "at least one negative trajectory is required",
        )
    episode_ids = {item.get("id") for item in episodes if isinstance(item.get("id"), str)}
    reference_episode_ids = {
        item.get("episode_id") for item in executable if item.get("kind") == "reference"
    }
    for trajectory in executable:
        episode_id = trajectory.get("episode_id")
        if episode_id not in episode_ids:
            collector.add(
                "world_admission_trajectory_episode_unknown",
                "trajectories",
                f"trajectory {trajectory.get('id')!r} references unknown episode {episode_id!r}",
                path=str(trajectory.get("_path")),
                context={"trajectory_id": trajectory.get("id"), "episode_id": episode_id},
            )
    for episode_id in sorted(episode_ids - reference_episode_ids):
        collector.add(
            "world_admission_episode_reference_missing",
            "trajectories",
            f"episode {episode_id!r} has no reference trajectory",
            context={"episode_id": episode_id},
        )
    if callbacks.run_trajectory is None:
        collector.add(
            "world_admission_trajectory_runner_missing",
            "trajectories",
            "runtime trajectory callback is required for admission",
        )
        return
    for trajectory in executable:
        trajectory_id = trajectory.get("id")
        kind = trajectory.get("kind")
        expected = trajectory.get("expected")
        if not isinstance(trajectory_id, str) or not trajectory_id:
            collector.add(
                "world_admission_trajectory_id_invalid",
                "trajectories",
                "trajectory id must be a non-empty string",
                path=str(trajectory.get("_path")),
            )
            continue
        if not isinstance(expected, dict) or not isinstance(expected.get("passed"), bool):
            collector.add(
                "world_admission_trajectory_outcome_invalid",
                "trajectories",
                f"trajectory {trajectory_id!r} must declare expected.passed",
                path=str(trajectory.get("_path")),
            )
            continue
        expected_codes = expected.get("failure_codes", [])
        if not isinstance(expected_codes, list) or not all(
            isinstance(code, str) and code for code in expected_codes
        ):
            collector.add(
                "world_admission_trajectory_outcome_invalid",
                "trajectories",
                f"trajectory {trajectory_id!r} expected.failure_codes must be strings",
                path=str(trajectory.get("_path")),
            )
            continue
        if kind == "reference" and (expected["passed"] is not True or expected_codes):
            collector.add(
                "world_admission_reference_outcome_invalid",
                "trajectories",
                f"reference trajectory {trajectory_id!r} must declare a clean pass",
                path=str(trajectory.get("_path")),
            )
            continue
        if kind == "negative" and (expected["passed"] is not False or not expected_codes):
            collector.add(
                "world_admission_negative_outcome_invalid",
                "trajectories",
                f"negative trajectory {trajectory_id!r} must declare exact failure codes",
                path=str(trajectory.get("_path")),
            )
            continue
        try:
            outcome = callbacks.run_trajectory(root, trajectory)
        except Exception as exc:
            collector.add(
                "world_admission_trajectory_execution_failed",
                "trajectories",
                f"trajectory {trajectory_id!r} could not execute: {exc}",
                context={"trajectory_id": trajectory_id},
            )
            continue
        actual_codes = set(outcome.failure_codes)
        if outcome.passed != expected["passed"] or actual_codes != set(expected_codes):
            collector.add(
                "world_admission_trajectory_outcome_mismatch",
                "trajectories",
                f"trajectory {trajectory_id!r} did not produce its declared outcome",
                path=str(trajectory.get("_path")),
                context={
                    "trajectory_id": trajectory_id,
                    "expected_passed": expected["passed"],
                    "actual_passed": outcome.passed,
                    "expected_failure_codes": sorted(expected_codes),
                    "actual_failure_codes": sorted(actual_codes),
                    "export_path": outcome.export_path,
                },
            )


def _run_parity_checks(
    root: Path,
    trajectories: Sequence[Mapping[str, Any]],
    callbacks: AdmissionCallbacks,
    collector: _Collector,
) -> None:
    collector.mark_executed("surface_parity")
    parity_cases = [item for item in trajectories if item.get("kind") == "parity"]
    if not parity_cases:
        collector.add(
            "world_admission_parity_case_missing",
            "surface_parity",
            "at least one declared HTTP/MCP parity case is required",
        )
        return
    if callbacks.run_parity is None:
        collector.add(
            "world_admission_parity_runner_missing",
            "surface_parity",
            "runtime parity callback is required for declared parity cases",
        )
        return
    for parity_case in parity_cases:
        case_id = parity_case.get("id")
        try:
            outcome = callbacks.run_parity(root, parity_case)
        except Exception as exc:
            collector.add(
                "world_admission_parity_execution_failed",
                "surface_parity",
                f"parity case {case_id!r} could not execute: {exc}",
                context={"case_id": case_id},
            )
            continue
        if not outcome.matched:
            collector.add(
                "world_admission_surface_parity_mismatch",
                "surface_parity",
                f"HTTP and MCP produced different outcomes for parity case {case_id!r}",
                path=str(parity_case.get("_path")),
                context={
                    "case_id": case_id,
                    "http_fingerprint": outcome.http_fingerprint,
                    "mcp_fingerprint": outcome.mcp_fingerprint,
                },
            )


def _run_export_check(root: Path, callbacks: AdmissionCallbacks, collector: _Collector) -> None:
    collector.mark_executed("session_export")
    if callbacks.export_session is None:
        collector.add(
            "world_admission_export_runner_missing",
            "session_export",
            "runtime session export callback is required for admission",
        )
        return
    try:
        payload = callbacks.export_session(root)
    except Exception as exc:
        collector.add(
            "world_admission_export_failed",
            "session_export",
            f"session export failed: {exc}",
        )
        return
    if not isinstance(payload, Mapping) or payload.get("ok") is not True:
        collector.add(
            "world_admission_export_invalid",
            "session_export",
            "session export callback must return an object with ok=true",
        )


def _trajectory_test_summaries(
    trajectories: Sequence[Mapping[str, Any]], findings: Sequence[AdmissionFinding]
) -> list[dict[str, Any]]:
    failed_ids = {
        finding.context.get("trajectory_id")
        for finding in findings
        if finding.check == "trajectories"
    }
    return [
        {
            "id": item.get("id"),
            "kind": item.get("kind"),
            "declared_outcome": item.get("expected"),
            "passed": item.get("id") not in failed_ids,
            "path": item.get("_path"),
        }
        for item in trajectories
        if item.get("kind") in {"reference", "negative"}
    ]


def _compute_local_hashes(root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    if not root.is_dir():
        return hashes
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in {"world/manifest.json", "world_admission.json"}:
            continue
        hashes[relative] = f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"
    return hashes


def _parse_implementation(path: Path) -> ast.AST | None:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError):
        return None


def _python_source_paths(
    root: Path,
    manifest: Mapping[str, Any],
) -> tuple[Path, ...]:
    """Return every hashed Python source that resolves inside the bundle."""

    content_hashes = manifest.get("content_hashes")
    if not isinstance(content_hashes, dict):
        return ()
    paths: list[Path] = []
    for relative in content_hashes:
        if not isinstance(relative, str) or Path(relative).suffix != ".py":
            continue
        try:
            source_path = (root / relative).resolve(strict=True)
            source_path.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            continue
        if source_path.is_file():
            paths.append(source_path)
    return tuple(sorted(set(paths)))


def _read_json_object(
    path: Path, collector: _Collector, check: str, code: str
) -> dict[str, Any] | None:
    value = _read_json_value(path, collector, check, code)
    if value is not None and not isinstance(value, dict):
        collector.add(code, check, "JSON root must be an object", path=path)
        return None
    return value


def _read_json_value(path: Path, collector: _Collector, check: str, code: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        collector.add(code, check, str(exc), path=path)
        return None


def _read_jsonl(path: Path, collector: _Collector, check: str) -> list[Any] | None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        collector.add("world_admission_episodes_invalid", check, str(exc), path=path)
        return None
    values: list[Any] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            values.append(json.loads(line))
        except json.JSONDecodeError as exc:
            collector.add(
                "world_admission_episodes_invalid",
                check,
                f"invalid JSON on line {number}: {exc}",
                path=path,
            )
    return values


def _named_records(value: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    records = value.get(key)
    if not isinstance(records, list):
        return []
    return [item for item in records if isinstance(item, dict)]


def _declared_hidden_values(episode: Mapping[str, Any]) -> list[Any]:
    hidden = episode.get("hidden")
    if not isinstance(hidden, Mapping):
        return [hidden]
    explicitly_non_disclosed = [
        hidden[key] for key in ("expected_values", "non_disclosure_values") if key in hidden
    ]
    return explicitly_non_disclosed or [hidden]


def _declared_visible_values(episode: Mapping[str, Any]) -> list[Any]:
    return [
        episode.get("task"),
        episode.get("agent_visible"),
        episode.get("agent_visible_state"),
    ]


def _scalars(value: Any) -> Iterable[str | int | float | bool | None]:
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _scalars(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _scalars(item)
    elif isinstance(value, (str, int, float, bool)) or value is None:
        yield value


def _mapping_entries(value: Any, path: str = "$") -> Iterable[tuple[str, str, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, str(key), child
            yield from _mapping_entries(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _mapping_entries(child, f"{path}[{index}]")


def _document_path(root: Path, manifest: Mapping[str, Any], name: str) -> Path:
    mapping = {
        "roles": manifest.get("roles_path"),
        "tools": manifest.get("tools_path"),
        "verifier": manifest.get("verifier_path"),
        "sources": manifest.get("sources_path"),
        "episodes": manifest.get("episodes_path"),
        "task": "task.json",
        "gate_config": "gate_config.json",
    }
    relative = mapping.get(name)
    return root / relative if isinstance(relative, str) else root


def _grounding_gaps(value: Any) -> list[Any]:
    if not isinstance(value, dict):
        return []
    gaps = value.get("grounding_gaps", [])
    return list(gaps) if isinstance(gaps, list) else []


def _string_or_none(payload: Mapping[str, Any] | None, key: str) -> str | None:
    if payload is None:
        return None
    value = payload.get(key)
    return value if isinstance(value, str) else None
