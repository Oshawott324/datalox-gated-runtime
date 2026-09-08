"""Provider-neutral state profiles and executable state admission.

The provider owns the shape of its state.  This module validates metadata,
grounding, and behavioral probes around that opaque state without translating
it into a Datalox-wide entity model.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from typing import Any

from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.provider_runtime.bundle import (
    WorldV1BehaviorSpec,
    compute_provider_runtime_hashes,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.runtime import ProviderRuntime
from datalox_gated_runtime.world_v1.contracts import ActorContext
from datalox_gated_runtime.world_v1.errors import WorldAuthorizationError

STATE_PROFILE_SCHEMA_VERSION = "datalox_provider_state_profile_v1"
STATE_ADMISSION_SCHEMA_VERSION = "datalox_provider_state_admission_v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_GROUNDING = re.compile(r"^G[0-4](?:_[A-Z0-9]+)*$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "profile_id",
        "provider_id",
        "bundle_version",
        "source_episode_id",
        "seed_sha256",
        "distribution_label",
        "rights_basis",
        "construction",
        "state_families",
        "relationship_checks",
        "observation_probes",
        "pagination_probes",
        "mutation_probes",
        "temporal",
        "information_boundary",
        "known_gaps",
    }
)
_CONSTRUCTION_FIELDS = frozenset(
    {
        "method",
        "base_seed_path",
        "base_seed_sha256",
        "trace_path",
        "trace_sha256",
        "operation_count",
        "source_release",
        "principal",
    }
)
_FAMILY_FIELDS = frozenset(
    {
        "family_id",
        "state_pointer",
        "instance_count",
        "value_origin",
        "grounding_level",
        "source_refs",
        "lifecycle",
    }
)
_RELATION_FIELDS = frozenset(
    {
        "check_id",
        "from_collection_pointer",
        "reference_pointer",
        "to_collection_pointer",
        "to_id_pointer",
        "nullable",
        "minimum_checked",
    }
)
_PROBE_FIELDS = frozenset(
    {
        "probe_id",
        "operation_id",
        "actor_id",
        "actor_role",
        "arguments",
        "expected_status_code",
        "assertions",
    }
)
_PAGINATION_FIELDS = frozenset(
    {
        "probe_id",
        "operation_id",
        "actor_id",
        "actor_role",
        "item_collection_pointer",
        "item_id_pointer",
        "expected_unique_items",
        "pages",
    }
)
_PAGE_FIELDS = frozenset({"arguments", "expected_status_code", "assertions"})
_ASSERTION_COMMON_FIELDS = frozenset({"operator", "pointer"})
_ASSERTION_EXPECTED_FIELDS = frozenset({"operator", "pointer", "expected"})
_MUTATION_FIELDS = _PROBE_FIELDS | frozenset({"expected_state_change"})
_TEMPORAL_FIELDS = frozenset({"logical_time", "scheduled_work_supported", "pending_state_pointers"})
_BOUNDARY_FIELDS = frozenset(
    {
        "contains_task_objectives",
        "contains_evaluation_ground_truth",
        "agent_selectable",
    }
)
_TRACE_FIELDS = frozenset(
    {
        "schema_version",
        "profile_id",
        "base_state_sha256",
        "final_state_sha256",
        "steps",
    }
)
_TRACE_STEP_FIELDS = frozenset(
    {
        "sequence",
        "operation_id",
        "actor_id",
        "actor_role",
        "arguments",
        "status_code",
        "response_body_sha256",
        "state_changed",
    }
)
_VALUE_ORIGINS = frozenset(
    {
        "self_authored",
        "provider_observed",
        "reference_service_instantiated",
        "authorized_snapshot_derived",
    }
)
_ADMISSION_FIELDS = frozenset(
    {
        "schema_version",
        "profile_id",
        "provider_id",
        "bundle_version",
        "provider_runtime_sha256",
        "profile_sha256",
        "seed_sha256",
        "construction_trace_sha256",
        "construction_replay_sha256",
        "admitted",
        "task_independent",
        "state_families",
        "relationship_checks",
        "observation_probe_sha256",
        "pagination_probe_sha256",
        "mutation_reset_sha256",
        "first_execution_sha256",
        "second_execution_sha256",
        "construction_step_count",
    }
)
_ADMITTED_FAMILY_FIELDS = frozenset(
    {"family_id", "instance_count", "observed_lifecycle_values", "passed"}
)
_ADMITTED_RELATION_FIELDS = frozenset({"check_id", "checked", "passed"})


@dataclass(frozen=True)
class ProviderStateAdmissionResult:
    path: Path
    sha256: str
    payload: dict[str, Any]


def load_provider_state_profile(path: Path) -> dict[str, Any]:
    """Load one strict state-profile claim document."""

    profile_path = _regular_file(path, code="provider_state_profile_missing")
    raw = _json_object(profile_path, code="provider_state_profile_invalid")
    _fields(raw, _TOP_LEVEL_FIELDS, name="state profile")
    if raw["schema_version"] != STATE_PROFILE_SCHEMA_VERSION:
        _fail("provider_state_profile_schema_unsupported", "Unsupported state profile schema.")

    profile = deepcopy(raw)
    profile["profile_id"] = _identifier(profile["profile_id"], field="profile_id")
    profile["provider_id"] = _identifier(profile["provider_id"], field="provider_id")
    profile["bundle_version"] = _identifier(profile["bundle_version"], field="bundle_version")
    profile["source_episode_id"] = _identifier(
        profile["source_episode_id"], field="source_episode_id"
    )
    profile["seed_sha256"] = _sha256(profile["seed_sha256"], field="seed_sha256")
    if profile["distribution_label"] not in {"public", "restricted", "private"}:
        _fail("provider_state_profile_distribution_invalid", "Invalid distribution label.")
    _nonempty(profile["rights_basis"], field="rights_basis")

    profile["construction"] = _construction(profile["construction"])
    profile["state_families"] = _state_families(profile["state_families"])
    profile["relationship_checks"] = _relationships(profile["relationship_checks"])
    profile["observation_probes"] = _probes(profile["observation_probes"], mutation=False)
    profile["pagination_probes"] = _pagination_probes(profile["pagination_probes"])
    profile["mutation_probes"] = _probes(profile["mutation_probes"], mutation=True)
    profile["temporal"] = _temporal(profile["temporal"])
    profile["information_boundary"] = _information_boundary(profile["information_boundary"])
    if not isinstance(profile["known_gaps"], list) or not all(
        isinstance(item, str) and item.strip() == item and item for item in profile["known_gaps"]
    ):
        _fail("provider_state_profile_known_gaps_invalid", "known_gaps must be strings.")
    return profile


def load_provider_state_admission(path: Path) -> dict[str, Any]:
    """Load one derived admission and enforce its deterministic pass contract."""

    admission_path = _regular_file(path, code="provider_state_admission_missing")
    admission = _json_object(admission_path, code="provider_state_admission_invalid")
    _fields(admission, _ADMISSION_FIELDS, name="state admission")
    if admission["schema_version"] != STATE_ADMISSION_SCHEMA_VERSION:
        _fail(
            "provider_state_admission_schema_unsupported",
            "Unsupported state admission schema.",
        )
    for field in ("profile_id", "provider_id", "bundle_version"):
        admission[field] = _identifier(admission[field], field=field)
    for field in (
        "provider_runtime_sha256",
        "profile_sha256",
        "seed_sha256",
        "construction_trace_sha256",
        "construction_replay_sha256",
        "observation_probe_sha256",
        "pagination_probe_sha256",
        "mutation_reset_sha256",
        "first_execution_sha256",
        "second_execution_sha256",
    ):
        admission[field] = _sha256(admission[field], field=field)
    if admission["admitted"] is not True or admission["task_independent"] is not True:
        _fail(
            "provider_state_admission_verdict_invalid",
            "State admission must record admitted and task_independent as true.",
        )
    if admission["first_execution_sha256"] != admission["second_execution_sha256"]:
        _fail(
            "provider_state_admission_reset_mismatch",
            "State admission executions do not prove deterministic reset behavior.",
        )
    admission["construction_step_count"] = _nonnegative_integer(
        admission["construction_step_count"], field="construction_step_count"
    )

    families = admission["state_families"]
    if not isinstance(families, list) or not families:
        _fail("provider_state_admission_families_invalid", "State families must be non-empty.")
    family_ids: set[str] = set()
    for family in families:
        _fields(family, _ADMITTED_FAMILY_FIELDS, name="admitted state family")
        family_id = _identifier(family["family_id"], field="family_id")
        if family_id in family_ids or family["passed"] is not True:
            _fail(
                "provider_state_admission_families_invalid",
                "Admitted state families must be unique passing checks.",
            )
        family_ids.add(family_id)
        _nonnegative_integer(family["instance_count"], field="instance_count")
        if not isinstance(family["observed_lifecycle_values"], list):
            _fail(
                "provider_state_admission_families_invalid",
                "Observed lifecycle values must be an array.",
            )

    relationships = admission["relationship_checks"]
    if not isinstance(relationships, list) or not relationships:
        _fail(
            "provider_state_admission_relationships_invalid",
            "Relationship checks must be non-empty.",
        )
    relation_ids: set[str] = set()
    for relationship in relationships:
        _fields(relationship, _ADMITTED_RELATION_FIELDS, name="admitted relationship")
        check_id = _identifier(relationship["check_id"], field="check_id")
        if check_id in relation_ids or relationship["passed"] is not True:
            _fail(
                "provider_state_admission_relationships_invalid",
                "Admitted relationships must be unique passing checks.",
            )
        relation_ids.add(check_id)
        _nonnegative_integer(relationship["checked"], field="checked")
    return deepcopy(admission)


def admit_provider_state_profile(
    *,
    bundle_dir: Path,
    profile_path: Path,
    output_path: Path,
) -> ProviderStateAdmissionResult:
    """Execute state, reachability, pagination, and reset claims for one profile."""

    if output_path.exists() or output_path.is_symlink():
        _fail("provider_state_admission_output_exists", "State admission output already exists.")
    bundle = load_provider_runtime_bundle(bundle_dir)
    if not isinstance(bundle.manifest.behavior, WorldV1BehaviorSpec) or bundle.seed is None:
        _fail(
            "provider_state_profile_runtime_unsupported",
            "State Profile v1 requires resettable world_v1_adapter provider behavior.",
        )
    profile_file = _regular_file(profile_path, code="provider_state_profile_missing")
    profile = load_provider_state_profile(profile_file)
    _bind_profile(profile, bundle)
    trace, base_seed = _load_construction_assets(
        profile,
        profile_file.parent,
        bundle.seed,
    )
    source_ids = _source_ids(bundle.source)
    unknown_sources = sorted(
        {
            source
            for family in profile["state_families"]
            for source in family["source_refs"]
            if source not in source_ids
        }
    )
    if unknown_sources:
        _fail(
            "provider_state_profile_source_unknown",
            "State-family grounding refers to unknown provider sources.",
            source_refs=unknown_sources,
        )

    state = bundle.seed.get("state", bundle.seed.get("initial_state"))
    if not isinstance(state, dict):
        _fail("provider_state_profile_seed_invalid", "Provider seed has no object state.")
    family_results = _evaluate_state_families(profile["state_families"], state)
    relationship_results = _evaluate_relationships(profile["relationship_checks"], state)
    _validate_temporal_binding(profile["temporal"], bundle.seed, state)

    operation_ids = {tool.id for tool in bundle.tools}
    role_ids = {role.id for role in bundle.roles}
    for probe in (
        *profile["observation_probes"],
        *profile["mutation_probes"],
        *profile["pagination_probes"],
    ):
        if probe["operation_id"] not in operation_ids:
            _fail(
                "provider_state_profile_operation_unknown",
                "State profile probe names an unknown operation.",
                operation_id=probe["operation_id"],
            )
        if probe["actor_role"] not in role_ids:
            _fail(
                "provider_state_profile_actor_role_unknown",
                "State profile probe names an unknown actor role.",
                actor_role=probe["actor_role"],
            )

    construction_replay = _replay_construction(
        bundle.root,
        bundle.manifest.behavior.seed_path,
        trace,
        base_seed,
    )
    first = _execute_profile_checks(bundle.root, profile)
    second = _execute_profile_checks(bundle.root, profile)
    first_digest = canonical_json_sha256(first)
    second_digest = canonical_json_sha256(second)
    if first_digest != second_digest:
        _fail(
            "provider_state_profile_reset_behavior_mismatch",
            "Fresh executions of the state profile produced different observations.",
            first=first_digest,
            second=second_digest,
        )

    payload = {
        "schema_version": STATE_ADMISSION_SCHEMA_VERSION,
        "profile_id": profile["profile_id"],
        "provider_id": profile["provider_id"],
        "bundle_version": profile["bundle_version"],
        "provider_runtime_sha256": _sha256_file(bundle.root / "provider-runtime.json"),
        "profile_sha256": _sha256_file(profile_file),
        "seed_sha256": profile["seed_sha256"],
        "construction_trace_sha256": profile["construction"]["trace_sha256"],
        "construction_replay_sha256": canonical_json_sha256(construction_replay),
        "admitted": True,
        "task_independent": True,
        "state_families": family_results,
        "relationship_checks": relationship_results,
        "observation_probe_sha256": canonical_json_sha256(first["observations"]),
        "pagination_probe_sha256": canonical_json_sha256(first["pagination"]),
        "mutation_reset_sha256": canonical_json_sha256(first["mutation_reset"]),
        "first_execution_sha256": first_digest,
        "second_execution_sha256": second_digest,
        "construction_step_count": len(trace["steps"]),
    }
    _write_json_atomic(output_path, payload)
    return ProviderStateAdmissionResult(
        path=output_path.resolve(strict=True),
        sha256=_sha256_file(output_path),
        payload=payload,
    )


def _execute_profile_checks(bundle_dir: Path, profile: Mapping[str, Any]) -> dict[str, Any]:
    with TemporaryDirectory(prefix="datalox-state-profile-") as temporary:
        runtime = ProviderRuntime(bundle_dir=bundle_dir, run_dir=Path(temporary) / "run")
        try:
            baseline = runtime.behavior_state_sha256()
            observations = [
                _run_probe(runtime, probe, require_read_only=True)
                for probe in profile["observation_probes"]
            ]
            pagination = [_run_pagination(runtime, probe) for probe in profile["pagination_probes"]]
            if runtime.behavior_state_sha256() != baseline:
                _fail(
                    "provider_state_profile_observation_mutated",
                    "Observation or pagination probes changed provider state.",
                )
            mutation_results = [
                _run_probe(runtime, probe, require_read_only=False)
                for probe in profile["mutation_probes"]
            ]
            mutated = runtime.behavior_state_sha256()
            if mutated == baseline:
                _fail(
                    "provider_state_profile_mutation_missing",
                    "State profile mutation probes did not change provider state.",
                )
            reset = runtime.reset()
            reset_digest = runtime.behavior_state_sha256()
            if reset_digest != baseline:
                _fail(
                    "provider_state_profile_reset_state_mismatch",
                    "Reset did not restore the admitted state profile.",
                    initial=baseline,
                    reset=reset_digest,
                )
            repeated_observations = [
                _run_probe(runtime, probe, require_read_only=True)
                for probe in profile["observation_probes"]
            ]
            repeated_pagination = [
                _run_pagination(runtime, probe) for probe in profile["pagination_probes"]
            ]
            if observations != repeated_observations or pagination != repeated_pagination:
                _fail(
                    "provider_state_profile_reset_observation_mismatch",
                    "Provider observations after reset differ from the initial profile.",
                )
            return {
                "observations": observations,
                "pagination": pagination,
                "mutation_reset": {
                    "initial_state_sha256": baseline,
                    "mutated_state_sha256": mutated,
                    "reset_state_sha256": reset_digest,
                    "mutation_results": mutation_results,
                    "reset_event_count": len(reset["call_evidence"]["events"]),
                },
            }
        finally:
            runtime.close()


def _run_probe(
    runtime: ProviderRuntime,
    probe: Mapping[str, Any],
    *,
    require_read_only: bool,
) -> dict[str, Any]:
    before = runtime.behavior_state_sha256()
    actor = ActorContext(actor_id=probe["actor_id"], role=probe["actor_role"])
    arguments = deepcopy(probe["arguments"])
    try:
        response = runtime.invoke_tool(
            probe["operation_id"],
            arguments,
            actor=actor,
        )
    except WorldAuthorizationError:
        implementation = runtime.bundle.implementation
        if implementation is None:
            raise
        request = implementation.request_for_tool(
            probe["operation_id"],
            arguments,
            actor=actor,
        )
        response = runtime.gate.handle_as(request, actor=actor)
    if response.status_code != probe["expected_status_code"]:
        _fail(
            "provider_state_profile_probe_status_mismatch",
            "State profile probe returned an unexpected status.",
            probe_id=probe["probe_id"],
            expected=probe["expected_status_code"],
            actual=response.status_code,
        )
    for assertion in probe["assertions"]:
        _evaluate_assertion(assertion, response.body, probe_id=probe["probe_id"])
    after = runtime.behavior_state_sha256()
    changed = before != after
    if require_read_only and changed:
        _fail(
            "provider_state_profile_observation_mutated",
            "An observation probe changed provider state.",
            probe_id=probe["probe_id"],
        )
    if not require_read_only and changed is not probe["expected_state_change"]:
        _fail(
            "provider_state_profile_mutation_relation_mismatch",
            "Mutation probe violated its declared state relation.",
            probe_id=probe["probe_id"],
        )
    return {
        "probe_id": probe["probe_id"],
        "status_code": response.status_code,
        "body_sha256": canonical_json_sha256(response.body),
        "state_changed": changed,
    }


def _run_pagination(runtime: ProviderRuntime, probe: Mapping[str, Any]) -> dict[str, Any]:
    if len(probe["pages"]) < 3:
        _fail(
            "provider_state_profile_pagination_thin",
            "A pagination admission probe must cross at least three pages.",
            probe_id=probe["probe_id"],
        )
    identifiers: list[Any] = []
    page_results = []
    for index, page in enumerate(probe["pages"]):
        response = runtime.invoke_tool(
            probe["operation_id"],
            deepcopy(page["arguments"]),
            actor=ActorContext(actor_id=probe["actor_id"], role=probe["actor_role"]),
        )
        if response.status_code != page["expected_status_code"]:
            _fail(
                "provider_state_profile_pagination_status_mismatch",
                "Pagination page returned an unexpected status.",
                probe_id=probe["probe_id"],
                page=index,
            )
        for assertion in page["assertions"]:
            _evaluate_assertion(assertion, response.body, probe_id=probe["probe_id"])
        found, items = _pointer(response.body, probe["item_collection_pointer"])
        if not found or not isinstance(items, list):
            _fail(
                "provider_state_profile_pagination_collection_invalid",
                "Pagination probe item collection is missing or is not an array.",
                probe_id=probe["probe_id"],
            )
        page_ids = []
        for item in items:
            found_id, identifier = _pointer(item, probe["item_id_pointer"])
            if not found_id:
                _fail(
                    "provider_state_profile_pagination_item_id_missing",
                    "Pagination item has no declared identifier.",
                    probe_id=probe["probe_id"],
                )
            page_ids.append(identifier)
        identifiers.extend(page_ids)
        page_results.append(
            {
                "page": index,
                "item_ids": page_ids,
                "body_sha256": canonical_json_sha256(response.body),
            }
        )
    if len(set(map(canonical_json_sha256, identifiers))) != len(identifiers):
        _fail(
            "provider_state_profile_pagination_duplicate",
            "Pagination pages repeat an item identifier.",
            probe_id=probe["probe_id"],
        )
    if probe["expected_unique_items"] != len(identifiers):
        _fail(
            "provider_state_profile_pagination_incomplete",
            "Declared traversal did not return its claimed number of unique items.",
            probe_id=probe["probe_id"],
            expected=probe["expected_unique_items"],
            actual=len(identifiers),
        )
    return {
        "probe_id": probe["probe_id"],
        "unique_items": len(identifiers),
        "page_count": len(page_results),
        "pages": page_results,
    }


def _evaluate_state_families(
    families: list[dict[str, Any]], state: Mapping[str, Any]
) -> list[dict[str, Any]]:
    results = []
    for family in families:
        found, value = _pointer(state, family["state_pointer"])
        if not found or not isinstance(value, (dict, list)):
            _fail(
                "provider_state_profile_family_missing",
                "State family pointer is missing or does not select a collection.",
                family_id=family["family_id"],
            )
        if len(value) != family["instance_count"]:
            _fail(
                "provider_state_profile_family_count_mismatch",
                "State family count differs from its profile claim.",
                family_id=family["family_id"],
                expected=family["instance_count"],
                actual=len(value),
            )
        lifecycle = family["lifecycle"]
        observed_values: list[Any] = []
        if lifecycle is not None:
            rows = list(value.values()) if isinstance(value, dict) else value
            for row in rows:
                exists, item = _pointer(row, lifecycle["value_pointer"])
                if exists and item not in observed_values:
                    observed_values.append(item)
            missing = [item for item in lifecycle["required_values"] if item not in observed_values]
            if missing:
                _fail(
                    "provider_state_profile_lifecycle_missing",
                    "State profile does not contain every declared lifecycle value.",
                    family_id=family["family_id"],
                    missing=missing,
                )
        results.append(
            {
                "family_id": family["family_id"],
                "instance_count": len(value),
                "observed_lifecycle_values": observed_values,
                "passed": True,
            }
        )
    return results


def _evaluate_relationships(
    checks: list[dict[str, Any]], state: Mapping[str, Any]
) -> list[dict[str, Any]]:
    results = []
    for check in checks:
        found_from, source = _pointer(state, check["from_collection_pointer"])
        found_to, target = _pointer(state, check["to_collection_pointer"])
        if not found_from or not isinstance(source, (dict, list)):
            _fail(
                "provider_state_profile_relation_source_invalid", "Relationship source is invalid."
            )
        if not found_to or not isinstance(target, (dict, list)):
            _fail(
                "provider_state_profile_relation_target_invalid", "Relationship target is invalid."
            )
        target_rows = list(target.values()) if isinstance(target, dict) else target
        target_ids = set()
        for row in target_rows:
            found_id, target_id = _pointer(row, check["to_id_pointer"])
            if found_id and target_id is not None:
                target_ids.add(canonical_json_sha256(target_id))
        checked = 0
        for row in list(source.values()) if isinstance(source, dict) else source:
            found, reference = _pointer(row, check["reference_pointer"])
            if (not found or reference is None) and check["nullable"]:
                continue
            if not found or canonical_json_sha256(reference) not in target_ids:
                _fail(
                    "provider_state_profile_relation_broken",
                    "A state relationship does not resolve to its declared target collection.",
                    check_id=check["check_id"],
                    reference=reference if found else None,
                )
            checked += 1
        if checked < check["minimum_checked"]:
            _fail(
                "provider_state_profile_relation_coverage_thin",
                "A relationship check resolved fewer references than declared.",
                check_id=check["check_id"],
                expected=check["minimum_checked"],
                actual=checked,
            )
        results.append({"check_id": check["check_id"], "checked": checked, "passed": True})
    return results


def _load_construction_assets(
    profile: Mapping[str, Any], profile_root: Path, seed: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    construction = profile["construction"]
    base_seed_path = _descendant_file(profile_root, construction["base_seed_path"])
    if _sha256_file(base_seed_path) != construction["base_seed_sha256"]:
        _fail(
            "provider_state_profile_base_seed_digest_mismatch",
            "Construction base-seed digest differs.",
        )
    base_seed = _json_object(base_seed_path, code="provider_state_profile_base_seed_invalid")
    if (
        base_seed.get("id") != profile["source_episode_id"]
        or not isinstance(base_seed.get("state"), dict)
        or {"task", "hidden", "expected"} & set(base_seed)
    ):
        _fail(
            "provider_state_profile_base_seed_invalid",
            "Construction base seed must be task-free and bind the source episode.",
        )
    trace_path = _descendant_file(profile_root, construction["trace_path"])
    if _sha256_file(trace_path) != construction["trace_sha256"]:
        _fail("provider_state_profile_trace_digest_mismatch", "Construction trace digest differs.")
    trace = _json_object(trace_path, code="provider_state_profile_trace_invalid")
    _fields(trace, _TRACE_FIELDS, name="construction trace")
    if trace["schema_version"] != "datalox_provider_state_construction_trace_v1":
        _fail("provider_state_profile_trace_schema_unsupported", "Unsupported trace schema.")
    if trace["profile_id"] != profile["profile_id"]:
        _fail("provider_state_profile_trace_binding_mismatch", "Trace profile id differs.")
    if (
        not isinstance(trace["steps"], list)
        or len(trace["steps"]) != construction["operation_count"]
    ):
        _fail("provider_state_profile_trace_step_count_mismatch", "Trace step count differs.")
    for index, step in enumerate(trace["steps"], 1):
        _fields(step, _TRACE_STEP_FIELDS, name=f"construction trace step {index}")
        if step["sequence"] != index:
            _fail(
                "provider_state_profile_trace_sequence_invalid", "Trace sequence is not contiguous."
            )
        _identifier(step["operation_id"], field="trace.operation_id")
        _nonempty(step["actor_id"], field="trace.actor_id")
        _identifier(step["actor_role"], field="trace.actor_role")
        if not isinstance(step["arguments"], dict):
            _fail(
                "provider_state_profile_trace_arguments_invalid",
                "Trace arguments must be an object.",
            )
        _status(step["status_code"])
        _sha256(step["response_body_sha256"], field="trace.response_body_sha256")
        if not isinstance(step["state_changed"], bool):
            _fail(
                "provider_state_profile_trace_state_relation_invalid",
                "Trace state relation must be boolean.",
            )
    _sha256(trace["base_state_sha256"], field="trace.base_state_sha256")
    _sha256(trace["final_state_sha256"], field="trace.final_state_sha256")
    state = seed.get("state", seed.get("initial_state"))
    if trace["final_state_sha256"] != canonical_json_sha256(state):
        _fail(
            "provider_state_profile_trace_final_state_mismatch",
            "Trace does not bind the seed state.",
        )
    if trace["base_state_sha256"] != canonical_json_sha256(base_seed["state"]):
        _fail(
            "provider_state_profile_trace_base_state_mismatch",
            "Trace does not bind the construction base state.",
        )
    return trace, base_seed


def _replay_construction(
    bundle_dir: Path,
    seed_path: str,
    trace: Mapping[str, Any],
    base_seed: Mapping[str, Any],
) -> list[dict[str, Any]]:
    with TemporaryDirectory(prefix="datalox-state-construction-") as temporary:
        replay_bundle = Path(temporary) / "runtime"
        shutil.copytree(bundle_dir, replay_bundle)
        _write_json_atomic(replay_bundle / seed_path, base_seed)
        manifest_path = replay_bundle / "provider-runtime.json"
        manifest = _json_object(
            manifest_path,
            code="provider_state_profile_runtime_manifest_invalid",
        )
        manifest["content_hashes"] = compute_provider_runtime_hashes(replay_bundle)
        _write_json_atomic(manifest_path, manifest)

        runtime = ProviderRuntime(
            bundle_dir=replay_bundle,
            run_dir=Path(temporary) / "run",
        )
        results: list[dict[str, Any]] = []
        try:
            for step in trace["steps"]:
                before = runtime.behavior_state_sha256()
                response = runtime.invoke_tool(
                    step["operation_id"],
                    deepcopy(step["arguments"]),
                    actor=ActorContext(step["actor_id"], step["actor_role"]),
                )
                after = runtime.behavior_state_sha256()
                state_changed = before != after
                if (
                    response.status_code != step["status_code"]
                    or canonical_json_sha256(response.body) != step["response_body_sha256"]
                    or state_changed is not step["state_changed"]
                ):
                    _fail(
                        "provider_state_profile_construction_replay_mismatch",
                        "Construction replay differs from its recorded operation outcome.",
                        sequence=step["sequence"],
                        operation_id=step["operation_id"],
                        expected_status=step["status_code"],
                        actual_status=response.status_code,
                        expected_response_body_sha256=step["response_body_sha256"],
                        actual_response_body_sha256=canonical_json_sha256(response.body),
                        expected_state_change=step["state_changed"],
                        actual_state_change=state_changed,
                    )
                results.append(
                    {
                        "sequence": step["sequence"],
                        "operation_id": step["operation_id"],
                        "status_code": response.status_code,
                        "state_changed": state_changed,
                        "body_sha256": canonical_json_sha256(response.body),
                    }
                )
            exported = runtime.export()["provider_state"]
            final_state = exported.get("state") if isinstance(exported, dict) else None
            if canonical_json_sha256(final_state) != trace["final_state_sha256"]:
                _fail(
                    "provider_state_profile_construction_final_state_mismatch",
                    "Replayed construction does not produce the admitted provider seed.",
                )
        finally:
            runtime.close()
    return results


def _bind_profile(profile: Mapping[str, Any], bundle: Any) -> None:
    if {"task", "hidden", "expected"} & set(bundle.seed):
        _fail(
            "provider_state_profile_seed_information_boundary_invalid",
            "The admitted provider seed must not contain task or evaluation fields.",
        )
    mismatches = {}
    if profile["provider_id"] != bundle.manifest.provider_id:
        mismatches["provider_id"] = bundle.manifest.provider_id
    if profile["bundle_version"] != bundle.manifest.bundle_version:
        mismatches["bundle_version"] = bundle.manifest.bundle_version
    if profile["source_episode_id"] != bundle.seed.get("id"):
        mismatches["source_episode_id"] = bundle.seed.get("id")
    seed_digest = canonical_json_sha256(bundle.seed)
    if profile["seed_sha256"] != seed_digest:
        mismatches["seed_sha256"] = seed_digest
    if mismatches:
        _fail(
            "provider_state_profile_binding_mismatch",
            "State profile does not bind the exact provider seed.",
            mismatches=mismatches,
        )


def _source_ids(source: Mapping[str, Any]) -> set[str]:
    declaration = source.get("source_declaration")
    if not isinstance(declaration, Mapping) or not isinstance(declaration.get("sources"), list):
        return set()
    return {
        str(item["id"])
        for item in declaration["sources"]
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    }


def _validate_temporal_binding(
    temporal: Mapping[str, Any], seed: Mapping[str, Any], state: Mapping[str, Any]
) -> None:
    metadata = seed.get("metadata")
    if not isinstance(metadata, Mapping) or metadata.get("clock") != temporal["logical_time"]:
        _fail(
            "provider_state_profile_time_mismatch", "Profile logical time differs from seed time."
        )
    for pointer in temporal["pending_state_pointers"]:
        found, _ = _pointer(state, pointer)
        if not found:
            _fail(
                "provider_state_profile_pending_pointer_missing",
                "A declared pending-work state pointer is missing.",
                pointer=pointer,
            )


def _construction(raw: Any) -> dict[str, Any]:
    _fields(raw, _CONSTRUCTION_FIELDS, name="construction")
    if raw["method"] not in {
        "seed_plus_provider_operation_trace_v1",
        "provider_operation_trace_v1",
        "compiled_seed_v1",
    }:
        _fail("provider_state_profile_construction_invalid", "Unknown construction method.")
    base_seed_path = _relative_path(raw["base_seed_path"], field="construction.base_seed_path")
    base_seed_digest = _sha256(raw["base_seed_sha256"], field="construction.base_seed_sha256")
    path = _relative_path(raw["trace_path"], field="construction.trace_path")
    digest = _sha256(raw["trace_sha256"], field="construction.trace_sha256")
    count = _nonnegative_integer(raw["operation_count"], field="construction.operation_count")
    _nonempty(raw["source_release"], field="construction.source_release")
    if raw["principal"] != "trusted_controller":
        _fail(
            "provider_state_profile_construction_principal_invalid",
            "Construction must be controller-owned.",
        )
    return {
        **deepcopy(raw),
        "base_seed_path": base_seed_path,
        "base_seed_sha256": base_seed_digest,
        "trace_path": path,
        "trace_sha256": digest,
        "operation_count": count,
    }


def _state_families(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_state_profile_families_invalid", "state_families must be non-empty.")
    result = []
    ids = set()
    for item in raw:
        _fields(item, _FAMILY_FIELDS, name="state family")
        family_id = _identifier(item["family_id"], field="family_id")
        if family_id in ids:
            _fail("provider_state_profile_family_duplicate", "State family ids must be unique.")
        ids.add(family_id)
        pointer = _json_pointer(item["state_pointer"], field="state_pointer")
        count = _nonnegative_integer(item["instance_count"], field="instance_count")
        if item["value_origin"] not in _VALUE_ORIGINS:
            _fail("provider_state_profile_value_origin_invalid", "Invalid state value origin.")
        if not isinstance(item["grounding_level"], str) or not _GROUNDING.fullmatch(
            item["grounding_level"]
        ):
            _fail("provider_state_profile_grounding_invalid", "Invalid grounding level.")
        refs = _identifiers(item["source_refs"], field="source_refs", allow_empty=False)
        lifecycle = item["lifecycle"]
        if lifecycle is not None:
            _fields(lifecycle, frozenset({"value_pointer", "required_values"}), name="lifecycle")
            lifecycle = {
                "value_pointer": _json_pointer(
                    lifecycle["value_pointer"], field="lifecycle.value_pointer"
                ),
                "required_values": _json_values(
                    lifecycle["required_values"], field="lifecycle.required_values"
                ),
            }
        result.append(
            {
                **deepcopy(item),
                "family_id": family_id,
                "state_pointer": pointer,
                "instance_count": count,
                "source_refs": refs,
                "lifecycle": lifecycle,
            }
        )
    return result


def _relationships(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        _fail(
            "provider_state_profile_relationships_invalid", "relationship_checks must be non-empty."
        )
    result = []
    ids = set()
    for item in raw:
        _fields(item, _RELATION_FIELDS, name="relationship check")
        check_id = _identifier(item["check_id"], field="check_id")
        if check_id in ids:
            _fail(
                "provider_state_profile_relationship_duplicate", "Relationship ids must be unique."
            )
        ids.add(check_id)
        if not isinstance(item["nullable"], bool):
            _fail(
                "provider_state_profile_relationship_nullable_invalid", "nullable must be boolean."
            )
        result.append(
            {
                **deepcopy(item),
                "check_id": check_id,
                "from_collection_pointer": _json_pointer(
                    item["from_collection_pointer"], field="from_collection_pointer"
                ),
                "reference_pointer": _json_pointer(
                    item["reference_pointer"], field="reference_pointer"
                ),
                "to_collection_pointer": _json_pointer(
                    item["to_collection_pointer"], field="to_collection_pointer"
                ),
                "to_id_pointer": _json_pointer(item["to_id_pointer"], field="to_id_pointer"),
                "minimum_checked": _positive_integer(
                    item["minimum_checked"], field="minimum_checked"
                ),
            }
        )
    return result


def _probes(raw: Any, *, mutation: bool) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_state_profile_probes_invalid", "Probe lists must be non-empty.")
    expected_fields = _MUTATION_FIELDS if mutation else _PROBE_FIELDS
    result = []
    ids = set()
    for item in raw:
        _fields(item, expected_fields, name="state profile probe")
        probe_id = _identifier(item["probe_id"], field="probe_id")
        if probe_id in ids:
            _fail("provider_state_profile_probe_duplicate", "Probe ids must be unique.")
        ids.add(probe_id)
        probe = {
            **deepcopy(item),
            "probe_id": probe_id,
            "operation_id": _identifier(item["operation_id"], field="operation_id"),
            "actor_id": _nonempty(item["actor_id"], field="actor_id"),
            "actor_role": _identifier(item["actor_role"], field="actor_role"),
            "arguments": _object(item["arguments"], field="arguments"),
            "expected_status_code": _status(item["expected_status_code"]),
            "assertions": _assertions(item["assertions"]),
        }
        if mutation and not isinstance(item["expected_state_change"], bool):
            _fail(
                "provider_state_profile_mutation_relation_invalid",
                "expected_state_change must be boolean.",
            )
        result.append(probe)
    return result


def _pagination_probes(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_state_profile_pagination_invalid", "pagination_probes must be non-empty.")
    result = []
    ids = set()
    for item in raw:
        _fields(item, _PAGINATION_FIELDS, name="pagination probe")
        probe_id = _identifier(item["probe_id"], field="probe_id")
        if probe_id in ids:
            _fail(
                "provider_state_profile_pagination_probe_duplicate",
                "Pagination probe ids must be unique.",
            )
        ids.add(probe_id)
        pages = item["pages"]
        if not isinstance(pages, list) or len(pages) < 3:
            _fail(
                "provider_state_profile_pagination_thin",
                "Pagination requires at least three pages.",
            )
        normalized_pages = []
        for page in pages:
            _fields(page, _PAGE_FIELDS, name="pagination page")
            normalized_pages.append(
                {
                    "arguments": _object(page["arguments"], field="page.arguments"),
                    "expected_status_code": _status(page["expected_status_code"]),
                    "assertions": _assertions(page["assertions"]),
                }
            )
        result.append(
            {
                **deepcopy(item),
                "probe_id": probe_id,
                "operation_id": _identifier(item["operation_id"], field="operation_id"),
                "actor_id": _nonempty(item["actor_id"], field="actor_id"),
                "actor_role": _identifier(item["actor_role"], field="actor_role"),
                "item_collection_pointer": _json_pointer(
                    item["item_collection_pointer"], field="item_collection_pointer"
                ),
                "item_id_pointer": _json_pointer(item["item_id_pointer"], field="item_id_pointer"),
                "expected_unique_items": _positive_integer(
                    item["expected_unique_items"], field="expected_unique_items"
                ),
                "pages": normalized_pages,
            }
        )
    return result


def _temporal(raw: Any) -> dict[str, Any]:
    _fields(raw, _TEMPORAL_FIELDS, name="temporal")
    logical_time = _nonempty(raw["logical_time"], field="temporal.logical_time")
    if not isinstance(raw["scheduled_work_supported"], bool):
        _fail(
            "provider_state_profile_temporal_invalid", "scheduled_work_supported must be boolean."
        )
    pointers = raw["pending_state_pointers"]
    if not isinstance(pointers, list):
        _fail("provider_state_profile_temporal_invalid", "pending_state_pointers must be an array.")
    return {
        "logical_time": logical_time,
        "scheduled_work_supported": raw["scheduled_work_supported"],
        "pending_state_pointers": [
            _json_pointer(item, field="pending_state_pointer") for item in pointers
        ],
    }


def _information_boundary(raw: Any) -> dict[str, bool]:
    _fields(raw, _BOUNDARY_FIELDS, name="information_boundary")
    expected = {
        "contains_task_objectives": False,
        "contains_evaluation_ground_truth": False,
        "agent_selectable": False,
    }
    if raw != expected:
        _fail(
            "provider_state_profile_information_boundary_invalid",
            "State profiles must remain task-free, verifier-free, and controller-selected.",
        )
    return deepcopy(expected)


def _assertions(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_state_profile_assertions_invalid", "assertions must be non-empty.")
    result = []
    for item in raw:
        if not isinstance(item, dict):
            _fail("provider_state_profile_assertion_invalid", "Assertion must be an object.")
        operator = item.get("operator")
        expected_fields = (
            _ASSERTION_COMMON_FIELDS if operator == "exists" else _ASSERTION_EXPECTED_FIELDS
        )
        _fields(item, expected_fields, name="assertion")
        if operator not in {"exists", "equals", "type", "length"}:
            _fail(
                "provider_state_profile_assertion_operator_invalid", "Unknown assertion operator."
            )
        assertion = {
            **deepcopy(item),
            "pointer": _json_pointer(item["pointer"], field="assertion.pointer"),
        }
        if operator == "type" and item["expected"] not in {
            "object",
            "array",
            "string",
            "number",
            "integer",
            "boolean",
            "null",
        }:
            _fail("provider_state_profile_assertion_type_invalid", "Invalid expected JSON type.")
        if operator == "length":
            _nonnegative_integer(item["expected"], field="assertion.expected")
        result.append(assertion)
    return result


def _evaluate_assertion(assertion: Mapping[str, Any], value: Any, *, probe_id: str) -> None:
    found, actual = _pointer(value, assertion["pointer"])
    operator = assertion["operator"]
    passed = found
    if operator == "equals":
        passed = found and actual == assertion["expected"]
    elif operator == "type":
        passed = found and _json_type(actual) == assertion["expected"]
    elif operator == "length":
        passed = (
            found and isinstance(actual, (dict, list, str)) and len(actual) == assertion["expected"]
        )
    if not passed:
        _fail(
            "provider_state_profile_assertion_failed",
            "State profile response assertion failed.",
            probe_id=probe_id,
            pointer=assertion["pointer"],
            operator=operator,
        )


def _pointer(value: Any, pointer: str) -> tuple[bool, Any]:
    if pointer == "":
        return True, value
    current = value
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and token in current:
            current = current[token]
        elif isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
        else:
            return False, None
    return True, current


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


def _fields(raw: Any, expected: frozenset[str], *, name: str) -> None:
    if not isinstance(raw, dict) or set(raw) != expected:
        actual = set(raw) if isinstance(raw, dict) else set()
        _fail(
            "provider_state_profile_fields_invalid",
            f"{name} fields do not match the contract.",
            missing=sorted(expected - actual),
            unknown=sorted(actual - expected),
        )


def _identifier(value: Any, *, field: str) -> str:
    value = _nonempty(value, field=field)
    if not _IDENTIFIER.fullmatch(value):
        _fail("provider_state_profile_identifier_invalid", f"{field} is invalid.")
    return value


def _identifiers(raw: Any, *, field: str, allow_empty: bool) -> list[str]:
    if not isinstance(raw, list) or (not raw and not allow_empty):
        _fail("provider_state_profile_identifiers_invalid", f"{field} must be a non-empty array.")
    values = [_identifier(item, field=field) for item in raw]
    if len(set(values)) != len(values):
        _fail("provider_state_profile_identifiers_invalid", f"{field} contains duplicates.")
    return values


def _json_values(raw: Any, *, field: str) -> list[Any]:
    if not isinstance(raw, list) or not raw:
        _fail("provider_state_profile_values_invalid", f"{field} must be a non-empty array.")
    try:
        json.dumps(raw, allow_nan=False)
    except (TypeError, ValueError) as exc:
        _fail("provider_state_profile_values_invalid", f"{field} is not JSON: {exc}.")
    if len({canonical_json_sha256(item) for item in raw}) != len(raw):
        _fail("provider_state_profile_values_invalid", f"{field} contains duplicates.")
    return deepcopy(raw)


def _object(value: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail("provider_state_profile_object_invalid", f"{field} must be an object.")
    return deepcopy(value)


def _nonempty(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        _fail("provider_state_profile_string_invalid", f"{field} must be a canonical string.")
    return value


def _nonnegative_integer(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail("provider_state_profile_integer_invalid", f"{field} must be a non-negative integer.")
    return value


def _positive_integer(value: Any, *, field: str) -> int:
    value = _nonnegative_integer(value, field=field)
    if value == 0:
        _fail("provider_state_profile_integer_invalid", f"{field} must be a positive integer.")
    return value


def _status(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 100 <= value <= 599:
        _fail("provider_state_profile_status_invalid", "HTTP status must be between 100 and 599.")
    return value


def _sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        _fail("provider_state_profile_sha256_invalid", f"{field} must be a SHA-256 digest.")
    return value


def _json_pointer(value: Any, *, field: str) -> str:
    value = _nonempty(value, field=field) if value != "" else ""
    if value and (
        not value.startswith("/")
        or any("~" in token.replace("~0", "").replace("~1", "") for token in value[1:].split("/"))
    ):
        _fail("provider_state_profile_pointer_invalid", f"{field} is not a JSON pointer.")
    return value


def _relative_path(value: Any, *, field: str) -> str:
    value = _nonempty(value, field=field)
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        _fail("provider_state_profile_path_invalid", f"{field} must be a canonical relative path.")
    return value


def _regular_file(path: Path, *, code: str) -> Path:
    if path.is_symlink() or not path.is_file():
        _fail(code, "Required state-profile file is missing.", path=str(path))
    return path.resolve(strict=True)


def _descendant_file(root: Path, relative: str) -> Path:
    resolved_root = root.resolve(strict=True)
    candidate = resolved_root / relative
    try:
        path = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        _fail(
            "provider_state_profile_asset_missing",
            "A declared state-profile asset is missing or unreadable.",
            path=relative,
        )
    try:
        path.relative_to(resolved_root)
    except ValueError:
        _fail("provider_state_profile_path_escape", "State-profile path escapes its root.")
    return _regular_file(path, code="provider_state_profile_asset_missing")


def _json_object(path: Path, *, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(code, f"Could not load JSON: {exc}.")
    if not isinstance(value, dict):
        _fail(code, "JSON document must be an object.")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderRuntimeError(code, message, details)
