from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Mapping


SCHEMA_VERSION = "datalox_provider_core_coverage_v1"
DECLARATION_NAME = "provider_core_coverage.json"
ALLOWED_CAPABILITIES = frozenset({"read", "write", "non_mutating_process"})
ALLOWED_EFFECTS = ALLOWED_CAPABILITIES
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"})
PROVIDER_EXECUTION_SOURCE_KINDS = frozenset(
    {
        "gated_probe",
        "gated_traffic",
        "local_provider_execution",
        "official_provider_registry_capture",
        "partner_certified",
        "public_production_capture",
        "public_production_nonmutating_process_capture",
        "public_production_probe_log",
    }
)
TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "env_id",
        "provider_id",
        "scope",
        "provider_mutability",
        "core_families",
        "write_families",
        "operations",
        "write_assurances",
        "process_assurances",
        "exclusions",
        "gaps",
    }
)


@dataclass(frozen=True)
class CoreCoverageFinding:
    code: str
    message: str
    path: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return value


def _string(value: Any) -> str | None:
    if isinstance(value, str) and value and value.strip() == value:
        return value
    return None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if _string(item) is not None]


def _objects(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _grounding_rank(source: Mapping[str, Any]) -> int | None:
    matched = re.match(r"^G([0-4])(?:_|$)", str(source.get("grounding_level", "")))
    return int(matched.group(1)) if matched is not None else None


def _is_official_source(source: Mapping[str, Any]) -> bool:
    kind = source.get("kind")
    return (
        isinstance(kind, str)
        and (kind == "official_source" or kind.startswith("official_"))
        and _grounding_rank(source) == 1
    )


def _is_provider_execution_source(source: Mapping[str, Any]) -> bool:
    rank = _grounding_rank(source)
    return source.get("kind") in PROVIDER_EXECUTION_SOURCE_KINDS and (
        rank is not None and rank >= 2
    )


def _source_map(env_dir: Path) -> tuple[dict[str, dict[str, Any]], Path]:
    manifest = _load_object(env_dir / "world" / "manifest.json")
    relative = manifest.get("sources_path")
    if not isinstance(relative, str):
        raise ValueError("world manifest does not declare sources_path")
    path = env_dir / relative
    document = _load_object(path)
    sources = document.get("sources")
    if not isinstance(sources, list):
        raise ValueError(f"sources must be an array: {path}")
    return {
        str(source["id"]): source
        for source in sources
        if isinstance(source, dict) and isinstance(source.get("id"), str)
    }, path


def _tool_map(env_dir: Path) -> tuple[dict[str, dict[str, Any]], Path]:
    manifest = _load_object(env_dir / "world" / "manifest.json")
    relative = manifest.get("tools_path")
    if not isinstance(relative, str):
        raise ValueError("world manifest does not declare tools_path")
    path = env_dir / relative
    document = _load_object(path)
    tools = document.get("tools")
    if not isinstance(tools, list):
        raise ValueError(f"tools must be an array: {path}")
    return {
        str(tool["id"]): tool
        for tool in tools
        if isinstance(tool, dict) and isinstance(tool.get("id"), str)
    }, path


def _finding(
    findings: list[CoreCoverageFinding],
    code: str,
    message: str,
    path: str,
) -> None:
    findings.append(CoreCoverageFinding(code, message, path))


def _validate_source_refs(
    *,
    findings: list[CoreCoverageFinding],
    refs: Any,
    sources: Mapping[str, Mapping[str, Any]],
    path: str,
    official: bool = False,
    provider_execution: bool = False,
) -> list[str]:
    values = _string_list(refs)
    if not isinstance(refs, list) or not values or len(values) != len(refs):
        _finding(
            findings,
            "core_coverage_source_refs_invalid",
            "Source refs must be a non-empty array of unique, non-empty strings.",
            path,
        )
        return values
    if len(set(values)) != len(values):
        _finding(
            findings,
            "core_coverage_source_refs_invalid",
            "Source refs must not contain duplicates.",
            path,
        )
    resolved_sources: list[tuple[str, Mapping[str, Any]]] = []
    for ref in values:
        source = sources.get(ref)
        if source is None:
            _finding(
                findings,
                "core_coverage_source_unknown",
                f"Source ref {ref!r} is not declared by the world.",
                path,
            )
            continue
        resolved_sources.append((ref, source))
        if provider_execution:
            if not _is_provider_execution_source(source):
                _finding(
                    findings,
                    "core_coverage_provider_execution_source_invalid",
                    f"Source ref {ref!r} is not G2+ provider execution evidence.",
                    path,
                )
    if official and not any(_is_official_source(source) for _, source in resolved_sources):
        _finding(
            findings,
            "core_coverage_official_source_required",
            "At least one source ref must resolve to an official source.",
            path,
        )
    return values


def _validate_local_ref(
    *,
    findings: list[CoreCoverageFinding],
    env_dir: Path,
    ref: Any,
    path: str,
    allowed_root: Path | None = None,
) -> None:
    value = _string(ref)
    if value is None or "::" not in value:
        _finding(
            findings,
            "core_coverage_local_evidence_ref_invalid",
            "Local evidence refs must use repo-relative path::anchor form.",
            path,
        )
        return
    relative, anchor = value.split("::", 1)
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not anchor:
        _finding(
            findings,
            "core_coverage_local_evidence_ref_invalid",
            "Local evidence refs must stay inside the repository and name an anchor.",
            path,
        )
        return
    repo_root = env_dir.parents[1]
    file_path = repo_root / pure
    if allowed_root is not None and not file_path.resolve().is_relative_to(allowed_root.resolve()):
        _finding(
            findings,
            "core_coverage_implementation_outside_environment",
            "Implementation refs must resolve inside the provider environment.",
            path,
        )
        return
    if not file_path.is_file():
        _finding(
            findings,
            "core_coverage_local_evidence_missing",
            f"Local evidence file {relative!r} does not exist.",
            path,
        )
        return
    text = file_path.read_text(encoding="utf-8")
    patterns = (
        rf"\bdef\s+{re.escape(anchor)}\s*\(",
        rf"\bclass\s+{re.escape(anchor)}\b",
    )
    if not any(re.search(pattern, text) for pattern in patterns):
        _finding(
            findings,
            "core_coverage_local_evidence_anchor_missing",
            f"Anchor {anchor!r} was not found in {relative!r}.",
            path,
        )


def _validate_local_refs(
    *,
    findings: list[CoreCoverageFinding],
    env_dir: Path,
    refs: Any,
    path: str,
) -> list[str]:
    values = _string_list(refs)
    if not isinstance(refs, list) or not values or len(values) != len(refs):
        _finding(
            findings,
            "core_coverage_local_evidence_refs_invalid",
            "Local evidence refs must be a non-empty array of unique strings.",
            path,
        )
        return values
    if len(set(values)) != len(values):
        _finding(
            findings,
            "core_coverage_local_evidence_refs_invalid",
            "Local evidence refs must not contain duplicates.",
            path,
        )
    for index, ref in enumerate(values):
        _validate_local_ref(
            findings=findings,
            env_dir=env_dir,
            ref=ref,
            path=f"{path}[{index}]",
        )
    return values


def evaluate_provider_core_coverage(
    env_dir: Path,
    *,
    expected_env_id: str | None = None,
    expected_provider_id: str | None = None,
    declaration: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate a provider declaration without trusting any declared status or counts."""

    env_dir = env_dir.resolve()
    declaration_path = env_dir / DECLARATION_NAME
    if declaration is None:
        declaration = _load_object(declaration_path)
    data = dict(declaration)
    tools, _ = _tool_map(env_dir)
    sources, _ = _source_map(env_dir)
    findings: list[CoreCoverageFinding] = []

    unknown_fields = sorted(set(data) - TOP_LEVEL_FIELDS)
    if unknown_fields:
        _finding(
            findings,
            "core_coverage_unknown_field",
            f"Provider core declaration has unknown fields: {unknown_fields}.",
            "$",
        )

    if data.get("schema_version") != SCHEMA_VERSION:
        _finding(
            findings,
            "core_coverage_schema_unsupported",
            f"schema_version must be {SCHEMA_VERSION!r}.",
            "schema_version",
        )
    env_id = _string(data.get("env_id"))
    provider_id = _string(data.get("provider_id"))
    if env_id is None or (expected_env_id is not None and env_id != expected_env_id):
        _finding(
            findings,
            "core_coverage_env_id_mismatch",
            f"env_id must match {expected_env_id or env_dir.name!r}.",
            "env_id",
        )
    if provider_id is None or (
        expected_provider_id is not None and provider_id != expected_provider_id
    ):
        _finding(
            findings,
            "core_coverage_provider_id_mismatch",
            f"provider_id must match {expected_provider_id!r}.",
            "provider_id",
        )

    scope = data.get("scope")
    if not isinstance(scope, dict):
        scope = {}
        _finding(
            findings,
            "core_coverage_scope_invalid",
            "scope must be an object.",
            "scope",
        )
    for field in ("name", "version", "primary_workflow"):
        if _string(scope.get(field)) is None:
            _finding(
                findings,
                "core_coverage_scope_invalid",
                f"scope.{field} must be a non-empty string.",
                f"scope.{field}",
            )
    _validate_source_refs(
        findings=findings,
        refs=scope.get("source_refs"),
        sources=sources,
        path="scope.source_refs",
        official=True,
    )

    mutability = data.get("provider_mutability")
    if not isinstance(mutability, dict):
        mutability = {}
        _finding(
            findings,
            "core_coverage_mutability_invalid",
            "provider_mutability must be an object.",
            "provider_mutability",
        )
    mutability_mode = mutability.get("mode")
    if mutability_mode not in {"mutable", "read_only"}:
        _finding(
            findings,
            "core_coverage_mutability_invalid",
            "provider_mutability.mode must be mutable or read_only.",
            "provider_mutability.mode",
        )
    if _string(mutability.get("reason")) is None:
        _finding(
            findings,
            "core_coverage_mutability_invalid",
            "provider_mutability.reason must explain the official capability boundary.",
            "provider_mutability.reason",
        )
    _validate_source_refs(
        findings=findings,
        refs=mutability.get("source_refs"),
        sources=sources,
        path="provider_mutability.source_refs",
        official=True,
    )

    operations = _objects(data.get("operations"))
    if not isinstance(data.get("operations"), list) or len(operations) != len(
        data.get("operations", [])
    ):
        _finding(
            findings,
            "core_coverage_operations_invalid",
            "operations must be an array of objects.",
            "operations",
        )
    operations_by_id: dict[str, dict[str, Any]] = {}
    for index, operation in enumerate(operations):
        path = f"operations[{index}]"
        operation_id = _string(operation.get("id"))
        family = _string(operation.get("family"))
        method = operation.get("method")
        effect = operation.get("effect")
        if operation_id is None:
            _finding(findings, "core_coverage_operation_invalid", "Operation id is required.", path)
            continue
        if operation_id in operations_by_id:
            _finding(
                findings,
                "core_coverage_operation_duplicate",
                f"Operation {operation_id!r} is declared more than once.",
                path,
            )
            continue
        operations_by_id[operation_id] = operation
        tool = tools.get(operation_id)
        if tool is None:
            _finding(
                findings,
                "core_coverage_operation_unknown",
                f"Operation {operation_id!r} is not a world tool.",
                path,
            )
        elif family != tool.get("operation_family"):
            _finding(
                findings,
                "core_coverage_operation_family_mismatch",
                f"Operation {operation_id!r} does not match its world tool family.",
                f"{path}.family",
            )
        if method not in ALLOWED_METHODS:
            _finding(
                findings,
                "core_coverage_operation_method_invalid",
                f"Operation {operation_id!r} has an unsupported method.",
                f"{path}.method",
            )
        if effect not in ALLOWED_EFFECTS:
            _finding(
                findings,
                "core_coverage_operation_effect_invalid",
                f"Operation {operation_id!r} has an unsupported effect.",
                f"{path}.effect",
            )
        elif effect == "read" and method not in {"GET", "HEAD", "OPTIONS"}:
            _finding(
                findings,
                "core_coverage_non_get_read_misclassified",
                "Non-GET/HEAD/OPTIONS read-like operations must be non_mutating_process.",
                f"{path}.effect",
            )
        elif effect == "write" and method in {"GET", "HEAD", "OPTIONS"}:
            _finding(
                findings,
                "core_coverage_get_write_invalid",
                "GET/HEAD/OPTIONS operations cannot be declared as writes.",
                f"{path}.effect",
            )
        source_refs = _validate_source_refs(
            findings=findings,
            refs=operation.get("source_refs"),
            sources=sources,
            path=f"{path}.source_refs",
            official=True,
        )
        if tool is not None and set(source_refs) != set(tool.get("source_refs", [])):
            _finding(
                findings,
                "core_coverage_operation_source_mismatch",
                f"Operation {operation_id!r} source refs must match its world tool.",
                f"{path}.source_refs",
            )
        execution = operation.get("provider_execution")
        if not isinstance(execution, dict):
            execution = {}
            _finding(
                findings,
                "core_coverage_provider_execution_invalid",
                "provider_execution must be an object.",
                f"{path}.provider_execution",
            )
        status = execution.get("status")
        evidence_refs = execution.get("evidence_refs")
        if status == "observed":
            provider_refs = _validate_source_refs(
                findings=findings,
                refs=evidence_refs,
                sources=sources,
                path=f"{path}.provider_execution.evidence_refs",
                provider_execution=True,
            )
            if not set(provider_refs).issubset(source_refs):
                _finding(
                    findings,
                    "core_coverage_provider_execution_source_mismatch",
                    "Provider execution evidence must also be attached to the operation.",
                    f"{path}.provider_execution.evidence_refs",
                )
        elif status == "not_observed":
            if evidence_refs != [] or _string(execution.get("note")) is None:
                _finding(
                    findings,
                    "core_coverage_unobserved_evidence_invalid",
                    "Unobserved operations require an empty evidence list and an explicit note.",
                    f"{path}.provider_execution",
                )
            if any(_is_provider_execution_source(sources.get(ref, {})) for ref in source_refs):
                _finding(
                    findings,
                    "core_coverage_unobserved_source_mismatch",
                    "An operation with provider execution evidence cannot be not_observed.",
                    f"{path}.provider_execution.status",
                )
        else:
            _finding(
                findings,
                "core_coverage_provider_execution_invalid",
                "Provider execution status must be observed or not_observed.",
                f"{path}.provider_execution.status",
            )

    missing_operations = sorted(set(tools) - set(operations_by_id))
    extra_operations = sorted(set(operations_by_id) - set(tools))
    if missing_operations or extra_operations:
        _finding(
            findings,
            "core_coverage_operation_inventory_mismatch",
            "Declared operations must exactly cover the world tool inventory; "
            f"missing={missing_operations}, extra={extra_operations}.",
            "operations",
        )

    families = _objects(data.get("core_families"))
    if not isinstance(data.get("core_families"), list) or len(families) != len(
        data.get("core_families", [])
    ):
        _finding(
            findings,
            "core_coverage_families_invalid",
            "core_families must be an array of objects.",
            "core_families",
        )
    families_by_id: dict[str, dict[str, Any]] = {}
    covered_operations: list[str] = []
    capability_write_families: set[str] = set()
    for index, family in enumerate(families):
        path = f"core_families[{index}]"
        family_id = _string(family.get("id"))
        if family_id is None:
            _finding(findings, "core_coverage_family_invalid", "Family id is required.", path)
            continue
        if family_id in families_by_id:
            _finding(
                findings,
                "core_coverage_family_duplicate",
                f"Family {family_id!r} is declared more than once.",
                path,
            )
            continue
        families_by_id[family_id] = family
        if family.get("role") not in {"primary", "supporting"}:
            _finding(
                findings,
                "core_coverage_family_role_invalid",
                "Family role must be primary or supporting.",
                f"{path}.role",
            )
        if _string(family.get("description")) is None:
            _finding(
                findings,
                "core_coverage_family_invalid",
                "Family description is required.",
                f"{path}.description",
            )
        capabilities = _string_list(family.get("capabilities"))
        if (
            not capabilities
            or len(capabilities) != len(family.get("capabilities", []))
            or len(set(capabilities)) != len(capabilities)
            or set(capabilities) - ALLOWED_CAPABILITIES
        ):
            _finding(
                findings,
                "core_coverage_family_capabilities_invalid",
                "Family capabilities must be unique read/write/non_mutating_process values.",
                f"{path}.capabilities",
            )
        capability_source_refs = family.get("capability_source_refs")
        if not isinstance(capability_source_refs, dict) or set(capability_source_refs) != set(
            capabilities
        ):
            _finding(
                findings,
                "core_coverage_family_capability_sources_invalid",
                "capability_source_refs must exactly map every declared capability.",
                f"{path}.capability_source_refs",
            )
            capability_source_refs = (
                capability_source_refs if isinstance(capability_source_refs, dict) else {}
            )
        for capability in capabilities:
            capability_refs = _validate_source_refs(
                findings=findings,
                refs=capability_source_refs.get(capability),
                sources=sources,
                path=f"{path}.capability_source_refs.{capability}",
                official=True,
            )
            operation_refs = {
                source_ref
                for operation_id, operation in operations_by_id.items()
                if operation.get("family") == family_id and operation.get("effect") == capability
                for source_ref in operation.get("source_refs", [])
                if _is_official_source(sources.get(source_ref, {}))
            }
            if not set(capability_refs).issubset(operation_refs):
                _finding(
                    findings,
                    "core_coverage_family_capability_source_mismatch",
                    f"Capability {capability!r} sources must ground operations in this family.",
                    f"{path}.capability_source_refs.{capability}",
                )
        implemented = _string_list(family.get("implemented_operations"))
        writes = _string_list(family.get("write_operations"))
        if not implemented or len(set(implemented)) != len(implemented):
            _finding(
                findings,
                "core_coverage_family_operations_invalid",
                "Each family needs unique implemented operations.",
                f"{path}.implemented_operations",
            )
        if len(set(writes)) != len(writes):
            _finding(
                findings,
                "core_coverage_family_operations_invalid",
                "Family write operations must be unique.",
                f"{path}.write_operations",
            )
        covered_operations.extend(implemented)
        actual = {
            operation_id
            for operation_id, operation in operations_by_id.items()
            if operation.get("family") == family_id
        }
        if set(implemented) != actual:
            _finding(
                findings,
                "core_coverage_family_inventory_mismatch",
                f"Family {family_id!r} implemented operations do not match the operation inventory.",
                f"{path}.implemented_operations",
            )
        actual_writes = {
            operation_id
            for operation_id in actual
            if operations_by_id[operation_id].get("effect") == "write"
        }
        if set(writes) != actual_writes:
            _finding(
                findings,
                "core_coverage_family_write_inventory_mismatch",
                f"Family {family_id!r} write operations do not match operation effects.",
                f"{path}.write_operations",
            )
        actual_capabilities = {
            str(operations_by_id[operation_id].get("effect")) for operation_id in actual
        }
        if set(capabilities) != actual_capabilities:
            _finding(
                findings,
                "core_coverage_family_capability_inventory_mismatch",
                f"Family {family_id!r} capabilities do not match implemented effects.",
                f"{path}.capabilities",
            )
        if "write" in capabilities:
            capability_write_families.add(family_id)
            if not actual_writes:
                _finding(
                    findings,
                    "core_coverage_write_capability_unimplemented",
                    f"Family {family_id!r} declares official write capability without a write.",
                    f"{path}.write_operations",
                )

    tool_families = {
        str(tool.get("operation_family"))
        for tool in tools.values()
        if isinstance(tool.get("operation_family"), str)
    }
    if set(families_by_id) != tool_families or len(covered_operations) != len(
        set(covered_operations)
    ):
        _finding(
            findings,
            "core_coverage_family_inventory_mismatch",
            "Core families must exactly and uniquely account for every world tool family.",
            "core_families",
        )

    write_families = _string_list(data.get("write_families"))
    if (
        not isinstance(data.get("write_families"), list)
        or len(write_families) != len(data.get("write_families", []))
        or set(write_families) != capability_write_families
        or len(write_families) != len(set(write_families))
    ):
        _finding(
            findings,
            "core_coverage_write_families_mismatch",
            "write_families must exactly match families with official write capability.",
            "write_families",
        )

    write_operations = {
        operation_id
        for operation_id, operation in operations_by_id.items()
        if operation.get("effect") == "write"
    }
    if mutability_mode == "mutable" and not write_operations:
        _finding(
            findings,
            "mutable_provider_has_no_write_operations",
            "A mutable provider cannot be core-complete without provider-shaped writes.",
            "operations",
        )
    if mutability_mode == "read_only" and write_operations:
        _finding(
            findings,
            "read_only_provider_declares_writes",
            "A read-only provider declaration cannot contain write effects.",
            "operations",
        )

    assurances = _objects(data.get("write_assurances"))
    if not isinstance(data.get("write_assurances"), list) or len(assurances) != len(
        data.get("write_assurances", [])
    ):
        _finding(
            findings,
            "core_coverage_write_assurances_invalid",
            "write_assurances must be an array of objects.",
            "write_assurances",
        )
    assurances_by_operation: dict[str, dict[str, Any]] = {}
    for index, assurance in enumerate(assurances):
        path = f"write_assurances[{index}]"
        operation_id = _string(assurance.get("operation_id"))
        if operation_id is None or operation_id in assurances_by_operation:
            _finding(
                findings,
                "core_coverage_write_assurance_invalid",
                "Each write assurance must name one unique operation.",
                path,
            )
            continue
        assurances_by_operation[operation_id] = assurance
        if operation_id not in write_operations:
            _finding(
                findings,
                "core_coverage_write_assurance_non_write",
                f"Assurance operation {operation_id!r} is not a declared write.",
                f"{path}.operation_id",
            )
        if assurance.get("execution_mode") != "local_shadow":
            _finding(
                findings,
                "core_coverage_live_write_inexpressible",
                "Write execution_mode must be local_shadow.",
                f"{path}.execution_mode",
            )
        _validate_local_ref(
            findings=findings,
            env_dir=env_dir,
            ref=assurance.get("implementation_ref"),
            path=f"{path}.implementation_ref",
            allowed_root=env_dir,
        )
        observation_mode = assurance.get("observation_mode", "read_after_write")
        readbacks = _string_list(assurance.get("read_after_write_operations"))
        if observation_mode == "read_after_write":
            if (
                not isinstance(assurance.get("read_after_write_operations"), list)
                or not readbacks
                or len(readbacks) != len(assurance.get("read_after_write_operations", []))
                or len(readbacks) != len(set(readbacks))
            ):
                _finding(
                    findings,
                    "core_coverage_read_after_write_invalid",
                    f"Write {operation_id!r} requires a non-empty unique string readback array.",
                    f"{path}.read_after_write_operations",
                )
            for readback in readbacks:
                operation = operations_by_id.get(readback)
                if operation is None or operation.get("effect") != "read":
                    _finding(
                        findings,
                        "core_coverage_read_after_write_invalid",
                        f"Readback {readback!r} is not a declared read operation.",
                        f"{path}.read_after_write_operations",
                    )
        elif observation_mode == "direct_write_response":
            if assurance.get("read_after_write_operations") != []:
                _finding(
                    findings,
                    "core_coverage_direct_write_response_invalid",
                    "Direct-write-response observation requires an explicit empty readback array.",
                    f"{path}.read_after_write_operations",
                )
            if _string(assurance.get("observation_note")) is None:
                _finding(
                    findings,
                    "core_coverage_direct_write_response_invalid",
                    "Direct-write-response observation must explain why no provider read API exists.",
                    f"{path}.observation_note",
                )
            _validate_local_refs(
                findings=findings,
                env_dir=env_dir,
                refs=assurance.get("direct_write_response_evidence_refs"),
                path=f"{path}.direct_write_response_evidence_refs",
            )
        else:
            _finding(
                findings,
                "core_coverage_write_observation_mode_invalid",
                "Write observation_mode must be read_after_write or direct_write_response.",
                f"{path}.observation_mode",
            )
        for field in (
            "local_evidence_refs",
            "reset_evidence_refs",
            "invalid_duplicate_atomicity_evidence_refs",
        ):
            _validate_local_refs(
                findings=findings,
                env_dir=env_dir,
                refs=assurance.get(field),
                path=f"{path}.{field}",
            )
    if set(assurances_by_operation) != write_operations:
        _finding(
            findings,
            "core_coverage_write_assurance_inventory_mismatch",
            "Write assurances must exactly cover every declared write operation.",
            "write_assurances",
        )

    process_operations = {
        operation_id
        for operation_id, operation in operations_by_id.items()
        if operation.get("effect") == "non_mutating_process"
    }
    process_assurances = _objects(data.get("process_assurances"))
    if not isinstance(data.get("process_assurances"), list) or len(process_assurances) != len(
        data.get("process_assurances", [])
    ):
        _finding(
            findings,
            "core_coverage_process_assurances_invalid",
            "process_assurances must be an array of objects.",
            "process_assurances",
        )
    process_assurance_ids: set[str] = set()
    for index, assurance in enumerate(process_assurances):
        path = f"process_assurances[{index}]"
        operation_id = _string(assurance.get("operation_id"))
        if operation_id is None or operation_id in process_assurance_ids:
            _finding(
                findings,
                "core_coverage_process_assurance_invalid",
                "Each process assurance must name one unique operation.",
                path,
            )
            continue
        process_assurance_ids.add(operation_id)
        if operation_id not in process_operations:
            _finding(
                findings,
                "core_coverage_process_assurance_unknown",
                f"Process assurance {operation_id!r} is not a non-mutating process.",
                path,
            )
        if assurance.get("execution_mode") != "local_replay":
            _finding(
                findings,
                "core_coverage_process_not_replayable",
                "Non-mutating processes must execute as local_replay.",
                f"{path}.execution_mode",
            )
        _validate_local_ref(
            findings=findings,
            env_dir=env_dir,
            ref=assurance.get("implementation_ref"),
            path=f"{path}.implementation_ref",
            allowed_root=env_dir,
        )
        _validate_local_refs(
            findings=findings,
            env_dir=env_dir,
            refs=assurance.get("local_evidence_refs"),
            path=f"{path}.local_evidence_refs",
        )
    if process_assurance_ids != process_operations:
        _finding(
            findings,
            "core_coverage_process_assurance_inventory_mismatch",
            "Process assurances must exactly cover non-mutating process operations.",
            "process_assurances",
        )

    exclusions = _objects(data.get("exclusions"))
    if not isinstance(data.get("exclusions"), list) or len(exclusions) != len(
        data.get("exclusions", [])
    ):
        _finding(
            findings,
            "core_coverage_exclusions_invalid",
            "exclusions must be an array of objects.",
            "exclusions",
        )
    exclusion_ids: set[str] = set()
    primary_families = {
        family_id for family_id, family in families_by_id.items() if family.get("role") == "primary"
    }
    for index, exclusion in enumerate(exclusions):
        path = f"exclusions[{index}]"
        exclusion_id = _string(exclusion.get("id"))
        if exclusion_id is None or exclusion_id in exclusion_ids:
            _finding(
                findings,
                "core_coverage_exclusion_invalid",
                "Each exclusion must have a unique id.",
                path,
            )
        else:
            exclusion_ids.add(exclusion_id)
            if exclusion_id in primary_families:
                _finding(
                    findings,
                    "core_coverage_primary_family_excluded",
                    f"Primary family {exclusion_id!r} cannot be excluded.",
                    f"{path}.id",
                )
        if exclusion.get("primary") is not False:
            _finding(
                findings,
                "core_coverage_primary_exclusion_invalid",
                "Every exclusion must explicitly be adjacent with primary=false.",
                f"{path}.primary",
            )
        if _string(exclusion.get("reason")) is None:
            _finding(
                findings,
                "core_coverage_exclusion_invalid",
                "Exclusions require a source-grounded reason.",
                f"{path}.reason",
            )
        _validate_source_refs(
            findings=findings,
            refs=exclusion.get("source_refs"),
            sources=sources,
            path=f"{path}.source_refs",
            official=True,
        )

    gaps = _objects(data.get("gaps"))
    if not isinstance(data.get("gaps"), list) or len(gaps) != len(data.get("gaps", [])):
        _finding(
            findings,
            "core_coverage_gaps_invalid",
            "gaps must be an array of objects.",
            "gaps",
        )
    gap_ids: set[str] = set()
    for index, gap in enumerate(gaps):
        path = f"gaps[{index}]"
        gap_id = _string(gap.get("id"))
        if gap_id is None or gap_id in gap_ids:
            _finding(
                findings,
                "core_coverage_gap_invalid",
                "Each gap must have a unique id.",
                path,
            )
        else:
            gap_ids.add(gap_id)
        if _string(gap.get("family")) is None or _string(gap.get("reason")) is None:
            _finding(
                findings,
                "core_coverage_gap_invalid",
                "Each gap requires family and reason strings.",
                path,
            )
        if not isinstance(gap.get("blocking"), bool):
            _finding(
                findings,
                "core_coverage_gap_invalid",
                "Each gap requires an explicit boolean blocking field.",
                f"{path}.blocking",
            )
        elif gap["blocking"]:
            _finding(
                findings,
                "core_coverage_blocking_gap",
                f"Blocking core gap {gap_id!r} remains unresolved.",
                path,
            )
        _validate_source_refs(
            findings=findings,
            refs=gap.get("source_refs"),
            sources=sources,
            path=f"{path}.source_refs",
        )

    observed_operations = {
        operation_id
        for operation_id, operation in operations_by_id.items()
        if isinstance(operation.get("provider_execution"), dict)
        and operation["provider_execution"].get("status") == "observed"
    }
    report = {
        "env_id": env_id or expected_env_id or env_dir.name,
        "provider_id": provider_id or expected_provider_id,
        "status": "core_complete" if not findings else "incomplete",
        "assessment_boundary": (
            "Machine validation covers the declared, official-source-grounded provider scope. "
            "Acceptance review must still reject a declaration that omits a primary provider "
            "family from that scope."
        ),
        "declaration_path": str(declaration_path.relative_to(env_dir.parents[1])),
        "provider_mutability": mutability_mode,
        "core_family_count": len(families_by_id),
        "primary_family_count": len(primary_families),
        "write_family_count": len(capability_write_families),
        "implemented_operation_count": len(operations_by_id),
        "write_operation_count": len(write_operations),
        "non_mutating_process_count": len(process_operations),
        "provider_observed_operation_count": len(observed_operations),
        "provider_unobserved_operation_count": len(set(operations_by_id) - observed_operations),
        "provider_observed_write_operation_count": len(write_operations & observed_operations),
        "provider_unobserved_write_operation_count": len(write_operations - observed_operations),
        "exclusion_count": len(exclusions),
        "gap_count": len(gaps),
        "blocking_gap_count": sum(gap.get("blocking") is True for gap in gaps),
        "core_families": sorted(families_by_id),
        "write_families": sorted(capability_write_families),
        "provider_observed_write_operations": sorted(write_operations & observed_operations),
        "provider_unobserved_write_operations": sorted(write_operations - observed_operations),
        "exclusions": exclusions,
        "gaps": gaps,
        "findings": [finding.to_dict() for finding in findings],
    }
    return report
