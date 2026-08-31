"""Strict authored contracts for provider-mediated hidden causal edges.

A Composition Pack is a distributable claim artifact. It describes provider-
mediated behavior such as webhooks, asynchronous integration deliveries, and
explicit compensation. It is not an admission result and it never represents
agent-mediated coordination.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, TypeAlias

from datalox_gated_runtime.json_digest import canonical_json_bytes
from datalox_gated_runtime.provider_runtime.release import (
    LoadedProviderRelease,
    load_provider_release,
    load_provider_release_from_descriptor,
)

COMPOSITION_PACK_SCHEMA_VERSION = "datalox_composition_pack_v1"
COMPOSITION_PACK_CLAIM_STATUS = "authored_not_admitted"
COMPOSITION_PACK_MAX_JSON_BYTES = 8 * 1024 * 1024
COMPOSITION_PACK_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
COMPOSITION_PACK_MAX_TOTAL_BYTES = 512 * 1024 * 1024
COMPOSITION_PACK_MAX_FILES = 10_000
COMPOSITION_PACK_MAX_PATH_BYTES = 1024
COMPOSITION_PACK_MAX_PATH_DEPTH = 32
COMPOSITION_PACK_MAX_TEMPLATE_DEPTH = 64
COMPOSITION_PACK_MAX_SOURCE_MATCH_PREDICATES = 64
COMPOSITION_PACK_MAX_RETRY_DELAYS = 32
COMPOSITION_PACK_MAX_DELAY_SECONDS = 30 * 24 * 60 * 60
COMPOSITION_TIME_SCOPE = "delivery_scheduler_only_v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PATH_PARAMETER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$")
_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_DISTRIBUTION_ORDER = {"public": 0, "restricted": 1, "private": 2}
_DECISION_KINDS = {"replay", "shadow_read", "shadow_write", "deny", "miss"}
_TEMPLATE_KINDS = {"literal", "select", "object", "array"}
_TEMPLATE_CONTEXTS = {
    "request",
    "response",
    "provider_state",
    "source_event",
    "delivery_outcome",
}
_TEMPLATE_CONTEXT_ROOT_FIELDS = {
    "request": frozenset({"scheme", "authority", "method", "path", "query", "headers", "body"}),
    "response": frozenset({"status_code", "decision_kind", "headers", "body"}),
    "provider_state": frozenset(),
    "source_event": frozenset(
        {
            "source_event_id",
            "source_provider_id",
            "provider_event_id",
            "event_type",
            "payload",
            "correlation_ids",
            "idempotency_key",
            "sequence",
            "recorded_at",
        }
    ),
    "delivery_outcome": frozenset(
        {
            "delivery_id",
            "edge_id",
            "source_event_id",
            "target_provider_id",
            "target_operation_id",
            "attempt_number",
            "kind",
            "status_code",
            "receipt",
            "error_code",
            "error_message",
        }
    ),
}
_SOURCE_CONTEXTS = frozenset({"request", "response", "provider_state"})
_DELIVERY_CONTEXTS = frozenset({"source_event"})
_COMPENSATION_CONTEXTS = frozenset({"source_event", "delivery_outcome"})
_COMPENSATION_TRIGGERS = {"retry_exhausted", "terminal_failure"}
_DEFAULT_OUTCOME = "terminal_failure"
_CREDENTIAL_HEADER_NAMES = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
    }
)

JsonScalar: TypeAlias = None | bool | int | float | str
FrozenJson: TypeAlias = JsonScalar | tuple["FrozenJson", ...] | Mapping[str, "FrozenJson"]
ExpectedJsonType = Literal["object", "array", "string", "number", "integer", "boolean", "null"]


@dataclass(frozen=True)
class CompositionPackError(ValueError):
    """Stable controller-readable Composition Pack failure."""

    code: str
    message: str
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class LiteralTemplate:
    value: FrozenJson
    kind: Literal["literal"] = "literal"


@dataclass(frozen=True)
class SelectTemplate:
    context: str
    pointer: str
    kind: Literal["select"] = "select"


@dataclass(frozen=True)
class ObjectTemplate:
    fields: tuple[tuple[str, "TemplateExpression"], ...]
    kind: Literal["object"] = "object"


@dataclass(frozen=True)
class ArrayTemplate:
    items: tuple["TemplateExpression", ...]
    kind: Literal["array"] = "array"


TemplateExpression: TypeAlias = LiteralTemplate | SelectTemplate | ObjectTemplate | ArrayTemplate


@dataclass(frozen=True)
class ProviderBinding:
    provider_id: str
    release_manifest_sha256: str
    operation_contract_sha256: str


@dataclass(frozen=True)
class EvidenceSource:
    evidence_id: str
    artifact_path: str
    artifact_sha256: str
    grounding_level: str
    observed_at: str
    valid_through: str
    distribution_label: str
    rights_basis: str


@dataclass(frozen=True)
class GroundingClaim:
    level: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class RightsClaim:
    distribution_label: str
    behavior_distribution_basis: str


@dataclass(frozen=True)
class AcceptedSourceOutcome:
    status_code: int
    decision_kind: str


@dataclass(frozen=True)
class SourceMatchPredicate:
    context: str
    pointer: str
    operator: Literal["exists", "equals", "type"]
    expected_exists: bool | None = None
    expected_value: FrozenJson | None = None
    expected_type: ExpectedJsonType | None = None


@dataclass(frozen=True)
class SourceEventContract:
    source_contract_id: str
    provider_id: str
    source_operation_id: str
    event_type: str
    accepted_outcomes: tuple[AcceptedSourceOutcome, ...]
    match: tuple[SourceMatchPredicate, ...]
    provider_event_id: TemplateExpression
    payload: TemplateExpression
    correlations: tuple[tuple[str, TemplateExpression], ...]
    grounding: GroundingClaim
    rights: RightsClaim


@dataclass(frozen=True)
class RequestTemplate:
    path_params: tuple[tuple[str, TemplateExpression], ...]
    query: tuple[tuple[str, TemplateExpression], ...]
    headers: tuple[tuple[str, TemplateExpression], ...]
    body: TemplateExpression


@dataclass(frozen=True)
class CompensationContract:
    compensation_id: str
    triggers: tuple[str, ...]
    target_provider_id: str
    target_operation_id: str
    principal_context_id: str
    request: RequestTemplate
    logical_delay_seconds: int
    idempotency_key: TemplateExpression
    ordering_key: TemplateExpression
    correlations: tuple[tuple[str, TemplateExpression], ...]
    delivered_statuses: tuple[int, ...]
    default_outcome: Literal["terminal_failure"]
    grounding: GroundingClaim
    rights: RightsClaim


@dataclass(frozen=True)
class DeliveryEdge:
    edge_id: str
    source_contract_id: str
    target_provider_id: str
    target_operation_id: str
    principal_context_id: str
    request: RequestTemplate
    logical_delay_seconds: int
    retry_delays_seconds: tuple[int, ...]
    idempotency_key: TemplateExpression
    ordering_key: TemplateExpression
    correlations: tuple[tuple[str, TemplateExpression], ...]
    delivered_statuses: tuple[int, ...]
    retryable_statuses: tuple[int, ...]
    default_outcome: Literal["terminal_failure"]
    compensation: CompensationContract | None
    grounding: GroundingClaim
    rights: RightsClaim


@dataclass(frozen=True)
class LoadedCompositionPack:
    root: Path
    pack_id: str
    pack_version: str
    canonical_sha256: str
    distribution_label: str
    time_scope: Literal["delivery_scheduler_only_v1"]
    providers: tuple[ProviderBinding, ...]
    evidence_sources: tuple[EvidenceSource, ...]
    source_event_contracts: tuple[SourceEventContract, ...]
    delivery_edges: tuple[DeliveryEdge, ...]
    payload: Mapping[str, FrozenJson]


@dataclass(frozen=True)
class _ProviderReleaseContract:
    """Strictly validated provider-release fields needed by composition loading."""

    provider_id: str
    release_manifest_sha256: str
    config: Mapping[str, Any]


def load_composition_pack(
    pack_dir: Path,
    *,
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
) -> LoadedCompositionPack:
    """Load and bind an authored Composition Pack to exact provider releases.

    Loading proves structural and cryptographic consistency only. It does not
    admit the authored behavioral claims or prove the hidden integration.
    """

    contracts = _load_provider_release_contracts(provider_releases)
    return _load_composition_pack_from_contracts(pack_dir, provider_contracts=contracts)


def _load_composition_pack_from_contracts(
    pack_dir: Path,
    *,
    provider_contracts: Mapping[str, _ProviderReleaseContract],
) -> LoadedCompositionPack:
    """Internal runtime loader over already strict provider release contracts."""

    root = _resolve_directory(pack_dir)
    files = _inspect_tree(root)
    manifest_path = root / "composition-pack.json"
    raw = _load_json_object(manifest_path)
    normalized = _validate_pack(
        raw,
        root=root,
        files=files,
        provider_contracts=provider_contracts,
    )
    payload = _freeze(normalized)
    if not isinstance(payload, Mapping):
        raise AssertionError("normalized composition pack must be an object")
    return LoadedCompositionPack(
        root=root,
        pack_id=normalized["pack_id"],
        pack_version=normalized["pack_version"],
        canonical_sha256=_sha256_bytes(canonical_json_bytes(normalized)),
        distribution_label=normalized["distribution_label"],
        time_scope=normalized["time_scope"],
        providers=tuple(_provider_binding(item) for item in normalized["providers"]),
        evidence_sources=tuple(_evidence_source(item) for item in normalized["evidence_sources"]),
        source_event_contracts=tuple(
            _source_contract(item) for item in normalized["source_event_contracts"]
        ),
        delivery_edges=tuple(_delivery_edge(item) for item in normalized["delivery_edges"]),
        payload=payload,
    )


def evaluate_template(
    expression: TemplateExpression,
    *,
    contexts: Mapping[str, Any],
    expected_type: ExpectedJsonType | None = None,
    field_name: str = "template",
) -> Any:
    """Evaluate the finite template language with strict pointer and type checks."""

    if not isinstance(contexts, Mapping):
        _fail(
            "composition_template_contexts_invalid",
            "Template contexts must be supplied as a named mapping.",
            field=field_name,
        )
    if isinstance(expression, LiteralTemplate):
        value = _thaw(expression.value)
    elif isinstance(expression, SelectTemplate):
        if expression.context not in contexts:
            _fail(
                "composition_template_context_missing",
                "A selected template context was not supplied.",
                field=field_name,
                context=expression.context,
            )
        value = _resolve_pointer(contexts[expression.context], expression.pointer, field_name)
        value = _json_round_trip(value, field=field_name)
    elif isinstance(expression, ObjectTemplate):
        value = {
            key: evaluate_template(item, contexts=contexts, field_name=f"{field_name}.{key}")
            for key, item in expression.fields
        }
    elif isinstance(expression, ArrayTemplate):
        value = [
            evaluate_template(item, contexts=contexts, field_name=f"{field_name}[{index}]")
            for index, item in enumerate(expression.items)
        ]
    else:
        _fail(
            "composition_template_type_invalid",
            "Template evaluation requires a loaded TemplateExpression.",
            field=field_name,
        )
    if expected_type is not None and not _matches_json_type(value, expected_type):
        _fail(
            "composition_template_result_type_invalid",
            "A template result does not have its required JSON type.",
            field=field_name,
            expected_type=expected_type,
            actual_type=_json_type(value),
        )
    return value


def evaluate_string_template(
    expression: TemplateExpression,
    *,
    contexts: Mapping[str, Any],
    field_name: str,
) -> str:
    value = evaluate_template(
        expression,
        contexts=contexts,
        expected_type="string",
        field_name=field_name,
    )
    if not value:
        _fail(
            "composition_template_result_empty",
            "A string template result must be non-empty.",
            field=field_name,
        )
    return value


def evaluate_string_template_map(
    expressions: Sequence[tuple[str, TemplateExpression]],
    *,
    contexts: Mapping[str, Any],
    field_name: str,
) -> dict[str, str]:
    """Evaluate an immutable template map whose values must be non-empty strings."""

    return {
        key: evaluate_string_template(
            expression,
            contexts=contexts,
            field_name=f"{field_name}.{key}",
        )
        for key, expression in expressions
    }


def evaluate_source_match(
    predicates: Sequence[SourceMatchPredicate],
    *,
    contexts: Mapping[str, Any],
) -> bool:
    """Evaluate one finite conjunction over safe post-operation source contexts."""

    if not isinstance(contexts, Mapping):
        _fail(
            "composition_source_match_contexts_invalid",
            "Source match contexts must be supplied as a named mapping.",
        )
    for predicate in predicates:
        if not isinstance(predicate, SourceMatchPredicate):
            _fail(
                "composition_source_match_predicate_invalid",
                "Source matching requires loaded predicates.",
            )
        if predicate.context not in contexts:
            _fail(
                "composition_source_match_context_missing",
                "A source match context was not supplied.",
                context=predicate.context,
            )
        exists, value = _lookup_pointer(contexts[predicate.context], predicate.pointer)
        if predicate.operator == "exists":
            if exists is not predicate.expected_exists:
                return False
        elif predicate.operator == "equals":
            if not exists or canonical_json_bytes(value) != canonical_json_bytes(
                _thaw(predicate.expected_value)
            ):
                return False
        elif predicate.operator == "type":
            if not exists or not _matches_json_type(value, predicate.expected_type):
                return False
        else:
            raise AssertionError("loaded source match predicate has an invalid operator")
    return True


def evaluate_request_template(
    request: RequestTemplate,
    *,
    contexts: Mapping[str, Any],
    field_name: str = "request",
) -> dict[str, Any]:
    """Evaluate one exact target request without coercing selected values."""

    if not isinstance(request, RequestTemplate):
        _fail(
            "composition_template_type_invalid",
            "Request evaluation requires a loaded RequestTemplate.",
            field=field_name,
        )
    path_params = evaluate_string_template_map(
        request.path_params,
        contexts=contexts,
        field_name=f"{field_name}.path_params",
    )
    headers = evaluate_string_template_map(
        request.headers,
        contexts=contexts,
        field_name=f"{field_name}.headers",
    )
    query: dict[str, str | list[str]] = {}
    for key, expression in request.query:
        value = evaluate_template(
            expression,
            contexts=contexts,
            field_name=f"{field_name}.query.{key}",
        )
        if isinstance(value, str):
            query[key] = value
        elif isinstance(value, list) and all(isinstance(item, str) for item in value):
            query[key] = value
        else:
            _fail(
                "composition_template_result_type_invalid",
                "Query template results must be strings or arrays of strings.",
                field=f"{field_name}.query.{key}",
                actual_type=_json_type(value),
            )
    return {
        "path_params": path_params,
        "query": query,
        "headers": headers,
        "body": evaluate_template(
            request.body,
            contexts=contexts,
            field_name=f"{field_name}.body",
        ),
    }


def _validate_pack(
    raw: Any,
    *,
    root: Path,
    files: frozenset[str],
    provider_contracts: Mapping[str, _ProviderReleaseContract],
) -> dict[str, Any]:
    if not isinstance(provider_contracts, Mapping):
        _fail(
            "composition_pack_provider_releases_invalid",
            "Provider release contracts must be supplied as a provider-id mapping.",
        )
    fields = {
        "schema_version",
        "claim_status",
        "pack_id",
        "pack_version",
        "distribution_label",
        "time_scope",
        "providers",
        "evidence_sources",
        "source_event_contracts",
        "delivery_edges",
    }
    _exact_object(raw, fields, field="composition pack")
    if raw["schema_version"] != COMPOSITION_PACK_SCHEMA_VERSION:
        _fail("composition_pack_schema_unsupported", "Unsupported Composition Pack schema.")
    if raw["claim_status"] != COMPOSITION_PACK_CLAIM_STATUS:
        _fail(
            "composition_pack_claim_status_invalid",
            "Composition Pack v1 must remain truthfully marked authored_not_admitted.",
        )
    _identifier(raw["pack_id"], field="pack_id")
    _identifier(raw["pack_version"], field="pack_version")
    _distribution_label(raw["distribution_label"])
    if raw["time_scope"] != COMPOSITION_TIME_SCOPE:
        _fail(
            "composition_pack_time_scope_invalid",
            "Composition Pack v1 supports only its delivery scheduler clock.",
            expected=COMPOSITION_TIME_SCOPE,
        )

    providers = _validate_providers(raw["providers"], provider_contracts)
    operations = {
        provider_id: {
            operation["operation_id"]: operation for operation in release.config["operations"]
        }
        for provider_id, release in providers.items()
    }
    evidence = _validate_evidence(raw["evidence_sources"], root=root, files=files)
    evidence_by_id = {item["evidence_id"]: item for item in evidence}
    sources = _validate_sources(raw["source_event_contracts"], operations, evidence_by_id)
    source_by_id = {item["source_contract_id"]: item for item in sources}
    edges = _validate_edges(raw["delivery_edges"], source_by_id, operations, evidence_by_id)
    _validate_source_outcome_disjointness(sources)
    _validate_declaration_use(providers, evidence, sources, edges)
    _validate_compensation_cycles(sources, edges)

    rights_labels = [item["distribution_label"] for item in evidence]
    for claim in [*sources, *edges]:
        rights_labels.append(claim["rights"]["distribution_label"])
        if claim.get("compensation") is not None:
            rights_labels.append(claim["compensation"]["rights"]["distribution_label"])
    derived_label = max(rights_labels, key=_DISTRIBUTION_ORDER.__getitem__)
    if raw["distribution_label"] != derived_label:
        _fail(
            "composition_pack_distribution_invalid",
            "Pack distribution does not reflect its most restrictive claim or evidence.",
        )
    return {
        "schema_version": COMPOSITION_PACK_SCHEMA_VERSION,
        "claim_status": COMPOSITION_PACK_CLAIM_STATUS,
        "pack_id": raw["pack_id"],
        "pack_version": raw["pack_version"],
        "distribution_label": raw["distribution_label"],
        "time_scope": COMPOSITION_TIME_SCOPE,
        "providers": raw["providers"],
        "evidence_sources": evidence,
        "source_event_contracts": sources,
        "delivery_edges": edges,
    }


def _validate_providers(
    value: Any, provider_contracts: Mapping[str, _ProviderReleaseContract]
) -> dict[str, _ProviderReleaseContract]:
    if not isinstance(value, list) or not value:
        _fail("composition_pack_providers_invalid", "providers must be a non-empty list.")
    result: dict[str, _ProviderReleaseContract] = {}
    ids: list[str] = []
    fields = {"provider_id", "release_manifest_sha256", "operation_contract_sha256"}
    for index, item in enumerate(value):
        _exact_object(item, fields, field=f"providers[{index}]")
        provider_id = _identifier(item["provider_id"], field="provider_id")
        if provider_id in result:
            _fail("composition_pack_provider_duplicate", "Provider ids must be unique.")
        _sha256(item["release_manifest_sha256"], field="release_manifest_sha256")
        _sha256(item["operation_contract_sha256"], field="operation_contract_sha256")
        if provider_id not in provider_contracts:
            _fail(
                "composition_pack_provider_release_missing",
                "A declared provider release was not supplied for binding.",
                provider_id=provider_id,
            )
        release = provider_contracts[provider_id]
        if release.provider_id != provider_id:
            _fail(
                "composition_pack_provider_binding_invalid",
                "The supplied release provider id does not match its declaration.",
                provider_id=provider_id,
            )
        if (
            release.release_manifest_sha256 != item["release_manifest_sha256"]
            or release.config["operation_contract_sha256"] != item["operation_contract_sha256"]
        ):
            _fail(
                "composition_pack_provider_binding_invalid",
                "Provider release or operation-contract digest does not match the pack.",
                provider_id=provider_id,
            )
        result[provider_id] = release
        ids.append(provider_id)
    _require_sorted(ids, field="providers")
    return result


def _load_provider_release_contracts(
    provider_releases: Mapping[str, Path | LoadedProviderRelease],
) -> dict[str, _ProviderReleaseContract]:
    if not isinstance(provider_releases, Mapping):
        _fail(
            "composition_pack_provider_releases_invalid",
            "provider_releases must map provider ids to strict Provider Releases.",
        )
    result: dict[str, _ProviderReleaseContract] = {}
    for provider_id, supplied in provider_releases.items():
        if not isinstance(provider_id, str):
            _fail(
                "composition_pack_provider_release_invalid",
                "Provider release mapping keys must be provider ids.",
            )
        if isinstance(supplied, Path):
            release = load_provider_release(supplied)
        elif isinstance(supplied, LoadedProviderRelease):
            release = load_provider_release_from_descriptor(
                root=supplied.root,
                manifest_descriptor=supplied.manifest_descriptor,
            )
        else:
            _fail(
                "composition_pack_provider_release_invalid",
                "A provider binding requires a release path or LoadedProviderRelease.",
                provider_id=provider_id,
            )
        if release.provider_id != provider_id:
            _fail(
                "composition_pack_provider_binding_invalid",
                "The supplied release provider id does not match its mapping key.",
                provider_id=provider_id,
            )
        result[provider_id] = _ProviderReleaseContract(
            provider_id=release.provider_id,
            release_manifest_sha256=release.manifest_descriptor["digest"],
            config=release.config,
        )
    return result


def _validate_evidence(value: Any, *, root: Path, files: frozenset[str]) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _fail("composition_pack_evidence_invalid", "evidence_sources must be non-empty.")
    fields = {
        "evidence_id",
        "artifact_path",
        "artifact_sha256",
        "grounding_level",
        "observed_at",
        "valid_through",
        "distribution_label",
        "rights_basis",
    }
    result: list[dict[str, Any]] = []
    ids: list[str] = []
    artifact_paths: set[str] = set()
    for index, item in enumerate(value):
        _exact_object(item, fields, field=f"evidence_sources[{index}]")
        evidence_id = _identifier(item["evidence_id"], field="evidence_id")
        if evidence_id in ids:
            _fail("composition_pack_evidence_duplicate", "Evidence ids must be unique.")
        path = _relative_path(item["artifact_path"], field="artifact_path")
        if path == "composition-pack.json":
            _fail("composition_pack_evidence_invalid", "The pack manifest is not evidence.")
        artifact_paths.add(path)
        digest = _sha256(item["artifact_sha256"], field="artifact_sha256")
        grounding_level = _grounding_level(item["grounding_level"])
        observed = _utc_timestamp(item["observed_at"], field="observed_at")
        valid_through = _utc_timestamp(item["valid_through"], field="valid_through")
        if valid_through < observed:
            _fail(
                "composition_pack_evidence_freshness_invalid",
                "Evidence valid_through precedes observed_at.",
                evidence_id=evidence_id,
            )
        label = _distribution_label(item["distribution_label"])
        rights_basis = _nonempty_string(item["rights_basis"], field="rights_basis")
        artifact = root.joinpath(*PurePosixPath(path).parts)
        actual = _sha256_file(artifact, max_bytes=COMPOSITION_PACK_MAX_ARTIFACT_BYTES)
        if actual != digest:
            _fail(
                "composition_pack_evidence_digest_mismatch",
                "Evidence artifact bytes do not match the declared digest.",
                evidence_id=evidence_id,
            )
        result.append(
            {
                "evidence_id": evidence_id,
                "artifact_path": path,
                "artifact_sha256": digest,
                "grounding_level": grounding_level,
                "observed_at": item["observed_at"],
                "valid_through": item["valid_through"],
                "distribution_label": label,
                "rights_basis": rights_basis,
            }
        )
        ids.append(evidence_id)
    _require_sorted(ids, field="evidence_sources")
    declared_files = {"composition-pack.json", *artifact_paths}
    if files != declared_files:
        _fail(
            "composition_pack_files_undeclared",
            "Every regular file in a Composition Pack must be the manifest or declared evidence.",
            undeclared=sorted(files - declared_files),
            missing=sorted(declared_files - files),
        )
    return result


def _validate_sources(
    value: Any,
    operations: Mapping[str, Mapping[str, Mapping[str, Any]]],
    evidence: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _fail("composition_pack_sources_invalid", "source_event_contracts must be non-empty.")
    fields = {
        "source_contract_id",
        "provider_id",
        "source_operation_id",
        "event_type",
        "accepted_outcomes",
        "match",
        "provider_event_id",
        "payload",
        "correlations",
        "grounding",
        "rights",
    }
    result: list[dict[str, Any]] = []
    ids: list[str] = []
    for index, item in enumerate(value):
        _exact_object(item, fields, field=f"source_event_contracts[{index}]")
        source_id = _identifier(item["source_contract_id"], field="source_contract_id")
        if source_id in ids:
            _fail("composition_pack_source_duplicate", "Source contract ids must be unique.")
        provider_id = _bound_operation(
            operations,
            provider_id=item["provider_id"],
            operation_id=item["source_operation_id"],
            field=f"source_event_contracts[{index}]",
            require_write=False,
        )[0]
        outcomes = _accepted_outcomes(item["accepted_outcomes"], field=f"sources[{index}]")
        match = _source_match_predicates(
            item["match"],
            field=f"source_event_contracts[{index}].match",
        )
        provider_event_id = _template(
            item["provider_event_id"], allowed_contexts=_SOURCE_CONTEXTS, field="provider_event_id"
        )
        payload = _template(item["payload"], allowed_contexts=_SOURCE_CONTEXTS, field="payload")
        correlations = _template_map(
            item["correlations"],
            allowed_contexts=_SOURCE_CONTEXTS,
            field="correlations",
            require_nonempty=True,
        )
        _require_template_possible_type(provider_event_id, {"string"}, field="provider_event_id")
        _require_template_possible_type(payload, {"object"}, field="payload")
        _require_template_map_possible_type(correlations, {"string"}, field="correlations")
        grounding = _grounding(item["grounding"], evidence=evidence, field=f"sources[{index}]")
        rights = _rights(
            item["rights"],
            evidence_refs=grounding["evidence_refs"],
            evidence=evidence,
            field=f"sources[{index}]",
        )
        result.append(
            {
                "source_contract_id": source_id,
                "provider_id": provider_id,
                "source_operation_id": item["source_operation_id"],
                "event_type": _identifier(item["event_type"], field="event_type"),
                "accepted_outcomes": outcomes,
                "match": match,
                "provider_event_id": _template_payload(provider_event_id),
                "payload": _template_payload(payload),
                "correlations": _template_map_payload(correlations),
                "grounding": grounding,
                "rights": rights,
            }
        )
        ids.append(source_id)
    _require_sorted(ids, field="source_event_contracts")
    return result


def _validate_edges(
    value: Any,
    sources: Mapping[str, Mapping[str, Any]],
    operations: Mapping[str, Mapping[str, Mapping[str, Any]]],
    evidence: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _fail("composition_pack_edges_invalid", "delivery_edges must be non-empty.")
    fields = {
        "edge_id",
        "source_contract_id",
        "target_provider_id",
        "target_operation_id",
        "principal_context_id",
        "request",
        "logical_delay_seconds",
        "retry_delays_seconds",
        "idempotency_key",
        "ordering_key",
        "correlations",
        "delivered_statuses",
        "retryable_statuses",
        "default_outcome",
        "compensation",
        "grounding",
        "rights",
    }
    result: list[dict[str, Any]] = []
    ids: list[str] = []
    all_ids = set(sources)
    for index, item in enumerate(value):
        _exact_object(item, fields, field=f"delivery_edges[{index}]")
        edge_id = _identifier(item["edge_id"], field="edge_id")
        if edge_id in all_ids:
            _fail("composition_pack_id_duplicate", "Composition declaration ids must be unique.")
        all_ids.add(edge_id)
        ids.append(edge_id)
        source_id = _identifier(item["source_contract_id"], field="source_contract_id")
        if source_id not in sources:
            _fail(
                "composition_pack_source_reference_invalid",
                "A delivery edge references an unknown source contract.",
                edge_id=edge_id,
            )
        provider_id, operation = _bound_operation(
            operations,
            provider_id=item["target_provider_id"],
            operation_id=item["target_operation_id"],
            field=f"delivery_edges[{index}]",
            require_write=True,
        )
        request = _request_template(
            item["request"],
            allowed_contexts=_DELIVERY_CONTEXTS,
            operation=operation,
            field=f"delivery_edges[{index}].request",
        )
        delay = _delay(item["logical_delay_seconds"], field="logical_delay_seconds", zero=True)
        retry_delays = _retry_schedule(item["retry_delays_seconds"])
        idempotency = _template(
            item["idempotency_key"],
            allowed_contexts=_DELIVERY_CONTEXTS,
            field="idempotency_key",
        )
        ordering = _template(
            item["ordering_key"], allowed_contexts=_DELIVERY_CONTEXTS, field="ordering_key"
        )
        correlations = _template_map(
            item["correlations"],
            allowed_contexts=_DELIVERY_CONTEXTS,
            field="correlations",
            require_nonempty=True,
        )
        _require_template_possible_type(idempotency, {"string"}, field="idempotency_key")
        _require_template_possible_type(ordering, {"string"}, field="ordering_key")
        _require_template_map_possible_type(correlations, {"string"}, field="correlations")
        delivered = _statuses(item["delivered_statuses"], field="delivered_statuses", nonempty=True)
        retryable = _statuses(
            item["retryable_statuses"], field="retryable_statuses", nonempty=False
        )
        if set(delivered) & set(retryable):
            _fail(
                "composition_pack_status_ambiguous",
                "Delivered and retryable status sets must be disjoint.",
                edge_id=edge_id,
            )
        if item["default_outcome"] != _DEFAULT_OUTCOME:
            _fail(
                "composition_pack_default_outcome_invalid",
                "Every unlisted status must resolve to terminal_failure.",
            )
        grounding = _grounding(item["grounding"], evidence=evidence, field=f"edges[{index}]")
        rights = _rights(
            item["rights"],
            evidence_refs=grounding["evidence_refs"],
            evidence=evidence,
            field=f"edges[{index}]",
        )
        compensation = None
        if item["compensation"] is not None:
            compensation = _compensation(
                item["compensation"],
                allowed_contexts=_COMPENSATION_CONTEXTS,
                operations=operations,
                evidence=evidence,
                all_ids=all_ids,
                field=f"delivery_edges[{index}].compensation",
            )
            triggers = set(compensation["triggers"])
            if "retry_exhausted" in triggers and not retryable:
                _fail(
                    "composition_pack_compensation_trigger_unreachable",
                    "retry_exhausted compensation requires at least one retryable status.",
                    edge_id=edge_id,
                )
            if "terminal_failure" in triggers and len(set(delivered) | set(retryable)) == 500:
                _fail(
                    "composition_pack_compensation_trigger_unreachable",
                    "terminal_failure compensation requires at least one unlisted HTTP status.",
                    edge_id=edge_id,
                )
        result.append(
            {
                "edge_id": edge_id,
                "source_contract_id": source_id,
                "target_provider_id": provider_id,
                "target_operation_id": item["target_operation_id"],
                "principal_context_id": _identifier(
                    item["principal_context_id"], field="principal_context_id"
                ),
                "request": _request_payload(request),
                "logical_delay_seconds": delay,
                "retry_delays_seconds": retry_delays,
                "idempotency_key": _template_payload(idempotency),
                "ordering_key": _template_payload(ordering),
                "correlations": _template_map_payload(correlations),
                "delivered_statuses": delivered,
                "retryable_statuses": retryable,
                "default_outcome": _DEFAULT_OUTCOME,
                "compensation": compensation,
                "grounding": grounding,
                "rights": rights,
            }
        )
    _require_sorted(ids, field="delivery_edges")
    return result


def _compensation(
    value: Any,
    *,
    allowed_contexts: frozenset[str],
    operations: Mapping[str, Mapping[str, Mapping[str, Any]]],
    evidence: Mapping[str, Mapping[str, Any]],
    all_ids: set[str],
    field: str,
) -> dict[str, Any]:
    fields = {
        "compensation_id",
        "triggers",
        "target_provider_id",
        "target_operation_id",
        "principal_context_id",
        "request",
        "logical_delay_seconds",
        "idempotency_key",
        "ordering_key",
        "correlations",
        "delivered_statuses",
        "default_outcome",
        "grounding",
        "rights",
    }
    _exact_object(value, fields, field=field)
    compensation_id = _identifier(value["compensation_id"], field="compensation_id")
    if compensation_id in all_ids:
        _fail("composition_pack_id_duplicate", "Composition declaration ids must be unique.")
    all_ids.add(compensation_id)
    triggers = value["triggers"]
    if (
        not isinstance(triggers, list)
        or not triggers
        or len(set(triggers)) != len(triggers)
        or set(triggers) - _COMPENSATION_TRIGGERS
    ):
        _fail(
            "composition_pack_compensation_trigger_invalid",
            "Compensation may run only for terminal_failure or retry_exhausted.",
        )
    _require_sorted(triggers, field="compensation.triggers")
    provider_id, operation = _bound_operation(
        operations,
        provider_id=value["target_provider_id"],
        operation_id=value["target_operation_id"],
        field=field,
        require_write=True,
    )
    request = _request_template(
        value["request"],
        allowed_contexts=allowed_contexts,
        operation=operation,
        field=f"{field}.request",
    )
    grounding = _grounding(value["grounding"], evidence=evidence, field=field)
    rights = _rights(
        value["rights"],
        evidence_refs=grounding["evidence_refs"],
        evidence=evidence,
        field=field,
    )
    delivered = _statuses(value["delivered_statuses"], field=field, nonempty=True)
    if value["default_outcome"] != _DEFAULT_OUTCOME:
        _fail(
            "composition_pack_default_outcome_invalid",
            "Unlisted compensation statuses must resolve to terminal_failure.",
        )
    idempotency = _template(
        value["idempotency_key"],
        allowed_contexts=allowed_contexts,
        field="idempotency_key",
    )
    ordering = _template(
        value["ordering_key"], allowed_contexts=allowed_contexts, field="ordering_key"
    )
    correlations = _template_map(
        value["correlations"],
        allowed_contexts=allowed_contexts,
        field="correlations",
        require_nonempty=True,
    )
    _require_template_possible_type(idempotency, {"string"}, field="idempotency_key")
    _require_template_possible_type(ordering, {"string"}, field="ordering_key")
    _require_template_map_possible_type(correlations, {"string"}, field="correlations")
    return {
        "compensation_id": compensation_id,
        "triggers": triggers,
        "target_provider_id": provider_id,
        "target_operation_id": value["target_operation_id"],
        "principal_context_id": _identifier(
            value["principal_context_id"], field="principal_context_id"
        ),
        "request": _request_payload(request),
        "logical_delay_seconds": _delay(
            value["logical_delay_seconds"], field="logical_delay_seconds", zero=True
        ),
        "idempotency_key": _template_payload(idempotency),
        "ordering_key": _template_payload(ordering),
        "correlations": _template_map_payload(correlations),
        "delivered_statuses": delivered,
        "default_outcome": _DEFAULT_OUTCOME,
        "grounding": grounding,
        "rights": rights,
    }


def _request_template(
    value: Any,
    *,
    allowed_contexts: frozenset[str],
    operation: Mapping[str, Any],
    field: str,
) -> RequestTemplate:
    _exact_object(value, {"path_params", "query", "headers", "body"}, field=field)
    path_params = _template_map(
        value["path_params"],
        allowed_contexts=allowed_contexts,
        field=f"{field}.path_params",
        require_nonempty=False,
    )
    expected_params = set(_PATH_PARAMETER.findall(operation["native_surface"]["path_template"]))
    if {key for key, _ in path_params} != expected_params:
        _fail(
            "composition_pack_path_params_invalid",
            "Target path parameters must exactly match the admitted operation path template.",
            operation_id=operation["operation_id"],
        )
    _require_template_map_possible_type(path_params, {"string"}, field=f"{field}.path_params")
    query = _template_map(
        value["query"],
        allowed_contexts=allowed_contexts,
        field=f"{field}.query",
        require_nonempty=False,
        identifier_keys=False,
    )
    for name, _ in query:
        _query_name(name, field=f"{field}.query")
    headers = _header_template_map(
        value["headers"], allowed_contexts=allowed_contexts, field=f"{field}.headers"
    )
    _require_query_template_types(query, field=f"{field}.query")
    _require_template_map_possible_type(headers, {"string"}, field=f"{field}.headers")
    body = _template(value["body"], allowed_contexts=allowed_contexts, field=f"{field}.body")
    return RequestTemplate(path_params=path_params, query=query, headers=headers, body=body)


def _header_template_map(
    value: Any, *, allowed_contexts: frozenset[str], field: str
) -> tuple[tuple[str, TemplateExpression], ...]:
    result = _template_map(
        value,
        allowed_contexts=allowed_contexts,
        field=field,
        require_nonempty=False,
        identifier_keys=False,
    )
    lowered: set[str] = set()
    for name, _ in result:
        if _HEADER_NAME.fullmatch(name) is None:
            _fail("composition_pack_header_name_invalid", "Header template name is invalid.")
        folded = name.lower()
        if folded in lowered:
            _fail(
                "composition_pack_header_name_duplicate",
                "Header template names must be unique case-insensitively.",
            )
        if folded in _CREDENTIAL_HEADER_NAMES or folded.startswith("x-datalox-"):
            _fail(
                "composition_pack_credential_header_forbidden",
                "Composition Packs cannot own credential-bearing or Datalox control headers.",
                header_name=name,
            )
        lowered.add(folded)
    return result


def _template_map(
    value: Any,
    *,
    allowed_contexts: frozenset[str],
    field: str,
    require_nonempty: bool,
    identifier_keys: bool = True,
    template_depth: int = 0,
) -> tuple[tuple[str, TemplateExpression], ...]:
    if not isinstance(value, dict) or require_nonempty and not value:
        _fail("composition_pack_template_map_invalid", f"{field} must be a template object.")
    result: list[tuple[str, TemplateExpression]] = []
    for key in sorted(value):
        if not isinstance(key, str) or not key:
            _fail("composition_pack_template_map_invalid", f"{field} has an invalid key.")
        if identifier_keys:
            _identifier(key, field=f"{field} key")
        result.append(
            (
                key,
                _template(
                    value[key],
                    allowed_contexts=allowed_contexts,
                    field=f"{field}.{key}",
                    depth=template_depth,
                ),
            )
        )
    if list(value) != sorted(value):
        _fail("composition_pack_order_invalid", f"{field} keys must be sorted.")
    return tuple(result)


def _template(
    value: Any, *, allowed_contexts: frozenset[str], field: str, depth: int = 0
) -> TemplateExpression:
    if depth > COMPOSITION_PACK_MAX_TEMPLATE_DEPTH:
        _fail(
            "composition_pack_template_depth_exceeded",
            "Template nesting exceeds the Composition Pack v1 limit.",
            max_depth=COMPOSITION_PACK_MAX_TEMPLATE_DEPTH,
        )
    if not isinstance(value, dict) or value.get("kind") not in _TEMPLATE_KINDS:
        _fail("composition_pack_template_invalid", f"{field} is not a supported template.")
    kind = value["kind"]
    if kind == "literal":
        _exact_object(value, {"kind", "value"}, field=field)
        return LiteralTemplate(_freeze(_json_round_trip(value["value"], field=field)))
    if kind == "select":
        _exact_object(value, {"kind", "context", "pointer"}, field=field)
        context = value["context"]
        if context not in _TEMPLATE_CONTEXTS or context not in allowed_contexts:
            _fail(
                "composition_pack_template_context_invalid",
                "A template uses a context unavailable at its execution phase.",
                field=field,
                context=context,
            )
        pointer = _json_pointer(value["pointer"], field=field)
        _validate_safe_context_pointer(context, pointer, field=field)
        return SelectTemplate(context=context, pointer=pointer)
    if kind == "object":
        _exact_object(value, {"kind", "fields"}, field=field)
        fields = _template_map(
            value["fields"],
            allowed_contexts=allowed_contexts,
            field=f"{field}.fields",
            require_nonempty=False,
            identifier_keys=False,
            template_depth=depth + 1,
        )
        return ObjectTemplate(fields=fields)
    _exact_object(value, {"kind", "items"}, field=field)
    if not isinstance(value["items"], list):
        _fail("composition_pack_template_invalid", f"{field}.items must be an array.")
    return ArrayTemplate(
        items=tuple(
            _template(
                item,
                allowed_contexts=allowed_contexts,
                field=f"{field}[{index}]",
                depth=depth + 1,
            )
            for index, item in enumerate(value["items"])
        )
    )


def _template_payload(value: TemplateExpression) -> dict[str, Any]:
    if isinstance(value, LiteralTemplate):
        return {"kind": "literal", "value": _thaw(value.value)}
    if isinstance(value, SelectTemplate):
        return {"kind": "select", "context": value.context, "pointer": value.pointer}
    if isinstance(value, ObjectTemplate):
        return {
            "kind": "object",
            "fields": {key: _template_payload(item) for key, item in value.fields},
        }
    return {"kind": "array", "items": [_template_payload(item) for item in value.items]}


def _template_map_payload(
    value: tuple[tuple[str, TemplateExpression], ...],
) -> dict[str, dict[str, Any]]:
    return {key: _template_payload(item) for key, item in value}


def _require_template_possible_type(
    value: TemplateExpression, allowed: set[str], *, field: str
) -> None:
    known = _known_template_type(value)
    if known is not None and known not in allowed:
        _fail(
            "composition_pack_template_static_type_invalid",
            "A statically known template result has an invalid type for its use.",
            field=field,
            allowed_types=sorted(allowed),
            actual_type=known,
        )


def _require_template_map_possible_type(
    value: tuple[tuple[str, TemplateExpression], ...], allowed: set[str], *, field: str
) -> None:
    for key, expression in value:
        _require_template_possible_type(expression, allowed, field=f"{field}.{key}")


def _require_query_template_types(
    value: tuple[tuple[str, TemplateExpression], ...], *, field: str
) -> None:
    for key, expression in value:
        item_field = f"{field}.{key}"
        _require_template_possible_type(expression, {"array", "string"}, field=item_field)
        if isinstance(expression, ArrayTemplate):
            for index, item in enumerate(expression.items):
                _require_template_possible_type(item, {"string"}, field=f"{item_field}[{index}]")
        elif isinstance(expression, LiteralTemplate):
            literal = _thaw(expression.value)
            if isinstance(literal, list) and any(not isinstance(item, str) for item in literal):
                _fail(
                    "composition_pack_template_static_type_invalid",
                    "A literal query array may contain only strings.",
                    field=item_field,
                )


def _known_template_type(value: TemplateExpression) -> str | None:
    if isinstance(value, LiteralTemplate):
        return _json_type(_thaw(value.value))
    if isinstance(value, ObjectTemplate):
        return "object"
    if isinstance(value, ArrayTemplate):
        return "array"
    return None


def _request_payload(value: RequestTemplate) -> dict[str, Any]:
    return {
        "path_params": _template_map_payload(value.path_params),
        "query": _template_map_payload(value.query),
        "headers": _template_map_payload(value.headers),
        "body": _template_payload(value.body),
    }


def _accepted_outcomes(value: Any, *, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        _fail("composition_pack_source_outcomes_invalid", "accepted_outcomes must be non-empty.")
    result: list[dict[str, Any]] = []
    keys: list[tuple[int, str]] = []
    for index, item in enumerate(value):
        _exact_object(item, {"status_code", "decision_kind"}, field=f"{field}[{index}]")
        status = _status(item["status_code"], field="status_code")
        decision = _identifier(item["decision_kind"], field="decision_kind")
        if decision not in _DECISION_KINDS:
            _fail(
                "composition_pack_source_outcomes_invalid",
                "Source decision_kind is not a provider-runtime decision.",
                decision_kind=decision,
            )
        key = (status, decision)
        if key in keys:
            _fail("composition_pack_source_outcomes_invalid", "Accepted outcomes must be unique.")
        keys.append(key)
        result.append({"status_code": status, "decision_kind": decision})
    if keys != sorted(keys):
        _fail("composition_pack_order_invalid", "accepted_outcomes must be sorted.")
    return result


def _source_match_predicates(value: Any, *, field: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > COMPOSITION_PACK_MAX_SOURCE_MATCH_PREDICATES:
        _fail(
            "composition_pack_source_match_invalid",
            "Source match predicates must be a finite bounded array.",
            max_predicates=COMPOSITION_PACK_MAX_SOURCE_MATCH_PREDICATES,
        )
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        item_field = f"{field}[{index}]"
        if not isinstance(item, Mapping):
            _fail(
                "composition_pack_source_match_invalid",
                "Every source match predicate must be an object.",
                field=item_field,
            )
        operator = item.get("operator")
        expected_field = {
            "exists": "expected_exists",
            "equals": "expected_value",
            "type": "expected_type",
        }.get(operator)
        if expected_field is None:
            _fail(
                "composition_pack_source_match_invalid",
                "A source match predicate uses an unsupported operator.",
                field=item_field,
            )
        _exact_object(
            item,
            {"context", "pointer", "operator", expected_field},
            field=item_field,
        )
        context = item["context"]
        if context not in _SOURCE_CONTEXTS:
            _fail(
                "composition_pack_source_match_context_invalid",
                "Source match predicates may use only post-operation safe contexts.",
                field=item_field,
                context=context,
            )
        pointer = _json_pointer(item["pointer"], field=item_field)
        _validate_safe_context_pointer(context, pointer, field=item_field)
        normalized: dict[str, Any] = {
            "context": context,
            "pointer": pointer,
            "operator": operator,
        }
        if operator == "exists":
            if not isinstance(item[expected_field], bool):
                _fail(
                    "composition_pack_source_match_invalid",
                    "An exists predicate requires a boolean expected_exists value.",
                    field=item_field,
                )
            normalized[expected_field] = item[expected_field]
        elif operator == "equals":
            normalized[expected_field] = _json_round_trip(
                item[expected_field],
                field=f"{item_field}.expected_value",
            )
        else:
            if item[expected_field] not in {
                "object",
                "array",
                "string",
                "number",
                "integer",
                "boolean",
                "null",
            }:
                _fail(
                    "composition_pack_source_match_invalid",
                    "A type predicate requires a supported JSON type.",
                    field=item_field,
                )
            normalized[expected_field] = item[expected_field]
        result.append(normalized)
    keys = [_source_match_sort_key(item) for item in result]
    if len(set(keys)) != len(keys):
        _fail(
            "composition_pack_source_match_duplicate",
            "Source match predicates must be unique.",
            field=field,
        )
    if keys != sorted(keys):
        _fail(
            "composition_pack_order_invalid",
            "Source match predicates must use canonical order.",
            field=field,
        )
    for index, left in enumerate(result):
        for right in result[index + 1 :]:
            if _source_predicates_disjoint(left, right):
                _fail(
                    "composition_pack_source_match_unsatisfiable",
                    "One source contract contains mutually exclusive match predicates.",
                    field=field,
                )
    return result


def _source_match_sort_key(value: Mapping[str, Any]) -> tuple[str, str, str, bytes]:
    expected = next(
        value[field]
        for field in ("expected_exists", "expected_value", "expected_type")
        if field in value
    )
    return (
        value["context"],
        value["pointer"],
        value["operator"],
        canonical_json_bytes(expected),
    )


def _source_predicates_disjoint(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Return true only when two predicates provably cannot both hold."""

    if (left["context"], left["pointer"]) != (
        right["context"],
        right["pointer"],
    ):
        return False
    left_operator = left["operator"]
    right_operator = right["operator"]
    if left_operator == "exists" and right_operator == "exists":
        return left["expected_exists"] is not right["expected_exists"]
    if left_operator == "exists":
        return left["expected_exists"] is False
    if right_operator == "exists":
        return right["expected_exists"] is False
    if left_operator == "equals" and right_operator == "equals":
        return canonical_json_bytes(left["expected_value"]) != canonical_json_bytes(
            right["expected_value"]
        )
    if left_operator == "equals" and right_operator == "type":
        return not _matches_json_type(left["expected_value"], right["expected_type"])
    if left_operator == "type" and right_operator == "equals":
        return not _matches_json_type(right["expected_value"], left["expected_type"])
    return not _json_types_overlap(left["expected_type"], right["expected_type"])


def _json_types_overlap(left: ExpectedJsonType, right: ExpectedJsonType) -> bool:
    if left == right:
        return True
    return {left, right} == {"integer", "number"}


def _statuses(value: Any, *, field: str, nonempty: bool) -> list[int]:
    if not isinstance(value, list) or nonempty and not value:
        _fail("composition_pack_statuses_invalid", f"{field} is invalid.")
    result = [_status(item, field=field) for item in value]
    if len(set(result)) != len(result) or result != sorted(result):
        _fail("composition_pack_statuses_invalid", f"{field} must be sorted and unique.")
    return result


def _retry_schedule(value: Any) -> list[int]:
    if not isinstance(value, list) or len(value) > COMPOSITION_PACK_MAX_RETRY_DELAYS:
        _fail(
            "composition_pack_retry_schedule_invalid",
            "retry_delays_seconds must be a finite bounded array.",
            max_delays=COMPOSITION_PACK_MAX_RETRY_DELAYS,
        )
    return [_delay(item, field="retry_delays_seconds", zero=False) for item in value]


def _grounding(
    value: Any, *, evidence: Mapping[str, Mapping[str, Any]], field: str
) -> dict[str, Any]:
    _exact_object(value, {"level", "evidence_refs"}, field=f"{field}.grounding")
    level = _grounding_level(value["level"])
    refs = value["evidence_refs"]
    if (
        not isinstance(refs, list)
        or not refs
        or len(set(refs)) != len(refs)
        or refs != sorted(refs)
        or any(ref not in evidence for ref in refs)
    ):
        _fail(
            "composition_pack_grounding_invalid",
            "Grounding evidence references must be non-empty, sorted, unique, and declared.",
        )
    supported = max(_grounding_rank(evidence[ref]["grounding_level"]) for ref in refs)
    if supported < _grounding_rank(level):
        _fail(
            "composition_pack_grounding_overstated",
            "A behavior claim exceeds its referenced evidence grounding level.",
            field=field,
        )
    return {"level": level, "evidence_refs": refs}


def _rights(
    value: Any,
    *,
    evidence_refs: Sequence[str],
    evidence: Mapping[str, Mapping[str, Any]],
    field: str,
) -> dict[str, str]:
    _exact_object(
        value,
        {"distribution_label", "behavior_distribution_basis"},
        field=f"{field}.rights",
    )
    label = _distribution_label(value["distribution_label"])
    basis = _nonempty_string(
        value["behavior_distribution_basis"], field="behavior_distribution_basis"
    )
    required = max(
        (evidence[ref]["distribution_label"] for ref in evidence_refs),
        key=_DISTRIBUTION_ORDER.__getitem__,
    )
    if _DISTRIBUTION_ORDER[label] < _DISTRIBUTION_ORDER[required]:
        _fail(
            "composition_pack_rights_overstated",
            "Behavior distribution is broader than its referenced evidence permits.",
            field=field,
        )
    return {"distribution_label": label, "behavior_distribution_basis": basis}


def _bound_operation(
    operations: Mapping[str, Mapping[str, Mapping[str, Any]]],
    *,
    provider_id: Any,
    operation_id: Any,
    field: str,
    require_write: bool,
) -> tuple[str, Mapping[str, Any]]:
    provider = _identifier(provider_id, field="provider_id")
    operation = _identifier(operation_id, field="operation_id")
    if provider not in operations or operation not in operations[provider]:
        _fail(
            "composition_pack_operation_binding_invalid",
            "A composition operation is absent from its bound provider release.",
            field=field,
            provider_id=provider,
            operation_id=operation,
        )
    admitted = operations[provider][operation]
    if require_write and admitted["mutability"] != "write":
        _fail(
            "composition_pack_target_not_writable",
            "Delivery and compensation targets must be admitted write operations.",
            provider_id=provider,
            operation_id=operation,
        )
    return provider, admitted


def _validate_source_outcome_disjointness(sources: Sequence[Mapping[str, Any]]) -> None:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for source in sources:
        grouped.setdefault((source["provider_id"], source["source_operation_id"]), []).append(
            source
        )
    for (provider_id, operation_id), contracts in grouped.items():
        for index, left in enumerate(contracts):
            left_outcomes = {
                (item["status_code"], item["decision_kind"]) for item in left["accepted_outcomes"]
            }
            for right in contracts[index + 1 :]:
                right_outcomes = {
                    (item["status_code"], item["decision_kind"])
                    for item in right["accepted_outcomes"]
                }
                if not left_outcomes & right_outcomes:
                    continue
                if any(
                    _source_predicates_disjoint(left_predicate, right_predicate)
                    for left_predicate in left["match"]
                    for right_predicate in right["match"]
                ):
                    continue
                _fail(
                    "composition_pack_source_match_ambiguous",
                    "Overlapping source outcomes require provably disjoint match predicates.",
                    provider_id=provider_id,
                    operation_id=operation_id,
                    source_contract_ids=sorted(
                        (left["source_contract_id"], right["source_contract_id"])
                    ),
                )


def _validate_declaration_use(
    providers: Mapping[str, _ProviderReleaseContract],
    evidence: Sequence[Mapping[str, Any]],
    sources: Sequence[Mapping[str, Any]],
    edges: Sequence[Mapping[str, Any]],
) -> None:
    used_sources = {edge["source_contract_id"] for edge in edges}
    declared_sources = {source["source_contract_id"] for source in sources}
    if used_sources != declared_sources:
        _fail(
            "composition_pack_source_unused",
            "Every source event contract must feed at least one delivery edge.",
            unused=sorted(declared_sources - used_sources),
        )
    used_providers = {source["provider_id"] for source in sources}
    used_evidence: set[str] = set()
    for source in sources:
        used_evidence.update(source["grounding"]["evidence_refs"])
    for edge in edges:
        used_providers.add(edge["target_provider_id"])
        used_evidence.update(edge["grounding"]["evidence_refs"])
        compensation = edge.get("compensation")
        if compensation is not None:
            used_providers.add(compensation["target_provider_id"])
            used_evidence.update(compensation["grounding"]["evidence_refs"])
    if used_providers != set(providers):
        _fail(
            "composition_pack_provider_unused",
            "Every declared provider must participate in a source, delivery, or compensation.",
            unused=sorted(set(providers) - used_providers),
        )
    evidence_ids = {item["evidence_id"] for item in evidence}
    if used_evidence != evidence_ids:
        _fail(
            "composition_pack_evidence_unused",
            "Every evidence declaration must support at least one behavior claim.",
            unused=sorted(evidence_ids - used_evidence),
        )


def _validate_compensation_cycles(
    sources: Sequence[Mapping[str, Any]], edges: Sequence[Mapping[str, Any]]
) -> None:
    source_nodes = {
        source["source_contract_id"]: (source["provider_id"], source["source_operation_id"])
        for source in sources
    }
    graph: dict[tuple[str, str], set[tuple[str, str]]] = {}
    compensation_arcs: list[tuple[tuple[str, str], tuple[str, str]]] = []
    for edge in edges:
        source = source_nodes[edge["source_contract_id"]]
        target = (edge["target_provider_id"], edge["target_operation_id"])
        graph.setdefault(source, set()).add(target)
        if edge.get("compensation") is not None:
            compensation = edge["compensation"]
            compensation_target = (
                compensation["target_provider_id"],
                compensation["target_operation_id"],
            )
            graph.setdefault(target, set()).add(compensation_target)
            compensation_arcs.append((target, compensation_target))
    for origin, target in compensation_arcs:
        if _reachable(graph, start=target, target=origin):
            _fail(
                "composition_pack_compensation_cycle",
                "A compensation declaration creates a causal cycle.",
                origin=list(origin),
                target=list(target),
            )


def _reachable(
    graph: Mapping[tuple[str, str], set[tuple[str, str]]],
    *,
    start: tuple[str, str],
    target: tuple[str, str],
) -> bool:
    pending = [start]
    seen: set[tuple[str, str]] = set()
    while pending:
        current = pending.pop()
        if current == target:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(graph.get(current, set()) - seen)
    return False


def _provider_binding(value: Mapping[str, Any]) -> ProviderBinding:
    return ProviderBinding(**value)


def _evidence_source(value: Mapping[str, Any]) -> EvidenceSource:
    return EvidenceSource(**value)


def _source_contract(value: Mapping[str, Any]) -> SourceEventContract:
    return SourceEventContract(
        source_contract_id=value["source_contract_id"],
        provider_id=value["provider_id"],
        source_operation_id=value["source_operation_id"],
        event_type=value["event_type"],
        accepted_outcomes=tuple(
            AcceptedSourceOutcome(**item) for item in value["accepted_outcomes"]
        ),
        match=tuple(_source_match_predicate(item) for item in value["match"]),
        provider_event_id=_template_from_payload(value["provider_event_id"]),
        payload=_template_from_payload(value["payload"]),
        correlations=tuple(
            (key, _template_from_payload(item)) for key, item in value["correlations"].items()
        ),
        grounding=GroundingClaim(**value["grounding"]),
        rights=RightsClaim(**value["rights"]),
    )


def _source_match_predicate(value: Mapping[str, Any]) -> SourceMatchPredicate:
    expected_value = value.get("expected_value")
    return SourceMatchPredicate(
        context=value["context"],
        pointer=value["pointer"],
        operator=value["operator"],
        expected_exists=value.get("expected_exists"),
        expected_value=_freeze(expected_value) if "expected_value" in value else None,
        expected_type=value.get("expected_type"),
    )


def _delivery_edge(value: Mapping[str, Any]) -> DeliveryEdge:
    compensation = value["compensation"]
    return DeliveryEdge(
        edge_id=value["edge_id"],
        source_contract_id=value["source_contract_id"],
        target_provider_id=value["target_provider_id"],
        target_operation_id=value["target_operation_id"],
        principal_context_id=value["principal_context_id"],
        request=_request_from_payload(value["request"]),
        logical_delay_seconds=value["logical_delay_seconds"],
        retry_delays_seconds=tuple(value["retry_delays_seconds"]),
        idempotency_key=_template_from_payload(value["idempotency_key"]),
        ordering_key=_template_from_payload(value["ordering_key"]),
        correlations=tuple(
            (key, _template_from_payload(item)) for key, item in value["correlations"].items()
        ),
        delivered_statuses=tuple(value["delivered_statuses"]),
        retryable_statuses=tuple(value["retryable_statuses"]),
        default_outcome=_DEFAULT_OUTCOME,
        compensation=_compensation_from_payload(compensation) if compensation else None,
        grounding=GroundingClaim(**value["grounding"]),
        rights=RightsClaim(**value["rights"]),
    )


def _compensation_from_payload(value: Mapping[str, Any]) -> CompensationContract:
    return CompensationContract(
        compensation_id=value["compensation_id"],
        triggers=tuple(value["triggers"]),
        target_provider_id=value["target_provider_id"],
        target_operation_id=value["target_operation_id"],
        principal_context_id=value["principal_context_id"],
        request=_request_from_payload(value["request"]),
        logical_delay_seconds=value["logical_delay_seconds"],
        idempotency_key=_template_from_payload(value["idempotency_key"]),
        ordering_key=_template_from_payload(value["ordering_key"]),
        correlations=tuple(
            (key, _template_from_payload(item)) for key, item in value["correlations"].items()
        ),
        delivered_statuses=tuple(value["delivered_statuses"]),
        default_outcome=_DEFAULT_OUTCOME,
        grounding=GroundingClaim(**value["grounding"]),
        rights=RightsClaim(**value["rights"]),
    )


def _request_from_payload(value: Mapping[str, Any]) -> RequestTemplate:
    return RequestTemplate(
        path_params=tuple(
            (key, _template_from_payload(item)) for key, item in value["path_params"].items()
        ),
        query=tuple((key, _template_from_payload(item)) for key, item in value["query"].items()),
        headers=tuple(
            (key, _template_from_payload(item)) for key, item in value["headers"].items()
        ),
        body=_template_from_payload(value["body"]),
    )


def _template_from_payload(value: Mapping[str, Any]) -> TemplateExpression:
    kind = value["kind"]
    if kind == "literal":
        return LiteralTemplate(_freeze(value["value"]))
    if kind == "select":
        return SelectTemplate(context=value["context"], pointer=value["pointer"])
    if kind == "object":
        return ObjectTemplate(
            tuple((key, _template_from_payload(item)) for key, item in value["fields"].items())
        )
    return ArrayTemplate(tuple(_template_from_payload(item) for item in value["items"]))


def _resolve_pointer(value: Any, pointer: str, field_name: str) -> Any:
    current = value
    if pointer == "":
        return current
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                _fail(
                    "composition_template_pointer_missing",
                    "A selected JSON object member does not exist.",
                    field=field_name,
                    pointer=pointer,
                )
            current = current[token]
            continue
        if isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            if token == "0":
                index = 0
            elif token.isdigit() and not token.startswith("0"):
                index = int(token)
            else:
                _fail(
                    "composition_template_pointer_type_invalid",
                    "A JSON array pointer token must be a canonical in-range index.",
                    field=field_name,
                    pointer=pointer,
                )
            if index >= len(current):
                _fail(
                    "composition_template_pointer_missing",
                    "A selected JSON array element does not exist.",
                    field=field_name,
                    pointer=pointer,
                )
            current = current[index]
            continue
        _fail(
            "composition_template_pointer_type_invalid",
            "A JSON pointer traversed a scalar value.",
            field=field_name,
            pointer=pointer,
        )
    return current


def _lookup_pointer(value: Any, pointer: str) -> tuple[bool, Any]:
    current = value
    if pointer == "":
        return True, current
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                return False, None
            current = current[token]
            continue
        if isinstance(current, Sequence) and not isinstance(current, (str, bytes, bytearray)):
            if token == "0":
                index = 0
            elif token.isdigit() and not token.startswith("0"):
                index = int(token)
            else:
                return False, None
            if index >= len(current):
                return False, None
            current = current[index]
            continue
        return False, None
    return True, current


def _inspect_tree(root: Path) -> frozenset[str]:
    files: set[str] = set()
    total = 0
    entries = 0
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *names]:
            path = current_path / name
            entries += 1
            if entries > COMPOSITION_PACK_MAX_FILES:
                _fail(
                    "composition_pack_file_limit_exceeded",
                    "Composition Pack contains too many filesystem entries.",
                )
            if path.is_symlink():
                _fail(
                    "composition_pack_symlink_forbidden",
                    "Composition Packs may not contain symbolic links.",
                    path=str(path),
                )
            if not (path.is_dir() or path.is_file()):
                _fail(
                    "composition_pack_special_file_forbidden",
                    "Composition Packs may contain only directories and regular files.",
                    path=str(path),
                )
            relative = path.relative_to(root).as_posix()
            _relative_path(relative, field="pack path")
            if path.is_file():
                size = path.stat().st_size
                if size > COMPOSITION_PACK_MAX_ARTIFACT_BYTES:
                    _fail(
                        "composition_pack_artifact_limit_exceeded",
                        "Composition Pack file exceeds the per-file limit.",
                        path=relative,
                    )
                total += size
                if total > COMPOSITION_PACK_MAX_TOTAL_BYTES:
                    _fail(
                        "composition_pack_total_limit_exceeded",
                        "Composition Pack exceeds the total byte limit.",
                    )
                files.add(relative)
    return frozenset(files)


def _load_json_object(path: Path) -> dict[str, Any]:
    if path.is_symlink():
        _fail("composition_pack_symlink_forbidden", "Composition Pack manifest is a symlink.")
    try:
        size = path.stat().st_size
        if size > COMPOSITION_PACK_MAX_JSON_BYTES:
            _fail(
                "composition_pack_json_limit_exceeded",
                "Composition Pack manifest exceeds the JSON byte limit.",
            )
        with path.open("rb") as handle:
            payload = handle.read(COMPOSITION_PACK_MAX_JSON_BYTES + 1)
        if len(payload) > COMPOSITION_PACK_MAX_JSON_BYTES:
            _fail(
                "composition_pack_json_limit_exceeded",
                "Composition Pack manifest exceeds the JSON byte limit.",
            )
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_json_object_pairs)
    except CompositionPackError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        _fail(
            "composition_pack_json_invalid",
            f"Could not load Composition Pack manifest: {exc}.",
        )
    if not isinstance(value, dict):
        _fail("composition_pack_json_invalid", "Composition Pack manifest must be an object.")
    return value


def _resolve_directory(path: Path) -> Path:
    if path.is_symlink():
        _fail("composition_pack_symlink_forbidden", "Composition Pack root is a symlink.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail("composition_pack_unreadable", f"Could not resolve Composition Pack: {exc}.")
    if not resolved.is_dir():
        _fail("composition_pack_unreadable", "Composition Pack root must be a directory.")
    return resolved


def _relative_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail("composition_pack_path_invalid", f"{field} is invalid.")
    parsed = PurePosixPath(value)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != value
        or "." in parsed.parts
        or ".." in parsed.parts
        or len(parsed.parts) > COMPOSITION_PACK_MAX_PATH_DEPTH
        or len(value.encode("utf-8")) > COMPOSITION_PACK_MAX_PATH_BYTES
    ):
        _fail("composition_pack_path_invalid", f"{field} is invalid.")
    return value


def _exact_object(value: Any, fields: set[str], *, field: str) -> None:
    if not isinstance(value, dict) or set(value) != fields:
        _fail(
            "composition_pack_fields_invalid",
            f"{field} has unexpected or missing fields.",
            expected=sorted(fields),
        )


def _identifier(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _fail("composition_pack_identifier_invalid", f"{field} is not a canonical identifier.")
    return value


def _sha256(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        _fail("composition_pack_digest_invalid", f"{field} is not a SHA-256 digest.")
    return value


def _sha256_file(path: Path, *, max_bytes: int) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    _fail(
                        "composition_pack_artifact_limit_exceeded",
                        "Evidence artifact exceeds the per-file limit.",
                        path=str(path),
                    )
                digest.update(chunk)
    except CompositionPackError:
        raise
    except OSError as exc:
        _fail(
            "composition_pack_evidence_unreadable",
            f"Could not read an evidence artifact: {exc}.",
            path=str(path),
        )
    return f"sha256:{digest.hexdigest()}"


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _grounding_level(value: Any) -> str:
    if not isinstance(value, str) or re.fullmatch(r"G[0-4](?:_[A-Z0-9]+)*", value) is None:
        _fail("composition_pack_grounding_invalid", "Grounding level is invalid.")
    return value


def _grounding_rank(value: str) -> int:
    return int(value[1])


def _distribution_label(value: Any) -> str:
    if value not in _DISTRIBUTION_ORDER:
        _fail("composition_pack_rights_invalid", "Distribution label is invalid.")
    return value


def _utc_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        _fail("composition_pack_time_invalid", f"{field} must be an RFC 3339 UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CompositionPackError(
            "composition_pack_time_invalid",
            f"{field} must be an RFC 3339 UTC timestamp.",
        ) from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        _fail("composition_pack_time_invalid", f"{field} must use UTC.")
    return parsed.astimezone(UTC)


def _json_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(
                "composition_pack_json_duplicate_key",
                "Composition Pack JSON objects may not contain duplicate keys.",
                key=key,
            )
        result[key] = value
    return result


def _status(value: Any, *, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 100 <= value <= 599:
        _fail("composition_pack_status_invalid", f"{field} must be an HTTP status from 100 to 599.")
    return value


def _delay(value: Any, *, field: str, zero: bool) -> int:
    minimum = 0 if zero else 1
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= COMPOSITION_PACK_MAX_DELAY_SECONDS
    ):
        _fail(
            "composition_pack_delay_invalid",
            f"{field} must be an integer from {minimum} through {COMPOSITION_PACK_MAX_DELAY_SECONDS}.",
        )
    return value


def _json_pointer(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        _fail("composition_pack_pointer_invalid", f"{field} JSON pointer is invalid.")
    if value == "":
        return value
    if not value.startswith("/"):
        _fail("composition_pack_pointer_invalid", f"{field} JSON pointer is invalid.")
    for token in value[1:].split("/"):
        index = 0
        while index < len(token):
            if token[index] != "~":
                index += 1
                continue
            if index + 1 >= len(token) or token[index + 1] not in "01":
                _fail("composition_pack_pointer_invalid", f"{field} JSON pointer is invalid.")
            index += 2
    return value


def _validate_safe_context_pointer(context: str, pointer: str, *, field: str) -> None:
    if not pointer:
        return
    tokens = tuple(token.replace("~1", "/").replace("~0", "~") for token in pointer[1:].split("/"))
    first_token = tokens[0]
    if context != "provider_state" and first_token not in _TEMPLATE_CONTEXT_ROOT_FIELDS[context]:
        _fail(
            "composition_pack_template_pointer_root_invalid",
            "A source expression selects an undeclared root field from its context.",
            field=field,
            context=context,
            root_field=first_token,
        )
    if context in {"request", "response"} and first_token == "headers":
        if len(tokens) == 1:
            _fail(
                "composition_pack_credential_header_selection_forbidden",
                "Source expressions must select one named non-credential header, not the complete header map.",
                field=field,
                context=context,
            )
        header_name = tokens[1].lower()
        if header_name in _CREDENTIAL_HEADER_NAMES or header_name.startswith("x-datalox-"):
            _fail(
                "composition_pack_credential_header_selection_forbidden",
                "Source expressions cannot select credential-bearing or Datalox control headers.",
                field=field,
                context=context,
            )


def _nonempty_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail("composition_pack_string_invalid", f"{field} must be a non-empty string.")
    return value


def _query_name(value: str, *, field: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 256
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        _fail("composition_pack_query_name_invalid", f"{field} has an invalid query name.")
    return value


def _require_sorted(value: Sequence[Any], *, field: str) -> None:
    if list(value) != sorted(value):
        _fail("composition_pack_order_invalid", f"{field} must be sorted.")


def _json_round_trip(value: Any, *, field: str) -> Any:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        _fail("composition_pack_json_value_invalid", f"{field} must contain finite JSON: {exc}.")


def _freeze(value: Any) -> FrozenJson:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError("non-JSON value cannot be frozen")


def _thaw(value: FrozenJson) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


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
    return "non_json"


def _matches_json_type(value: Any, expected: ExpectedJsonType) -> bool:
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    expected_type: type[Any] | tuple[type[Any], ...] = {
        "object": dict,
        "array": list,
        "string": str,
        "boolean": bool,
        "null": type(None),
    }[expected]
    return isinstance(value, expected_type)


def _fail(code: str, message: str, **details: Any) -> None:
    raise CompositionPackError(code, message, MappingProxyType(dict(details)))
