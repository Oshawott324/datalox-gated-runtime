from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from test_provider_release_registry import _profile

from datalox_gated_runtime.composition.pack import (
    COMPOSITION_PACK_MAX_RETRY_DELAYS,
    COMPOSITION_PACK_MAX_TEMPLATE_DEPTH,
    CompositionPackError,
    evaluate_request_template,
    evaluate_source_match,
    evaluate_string_template,
    evaluate_template,
    load_composition_pack,
)
from datalox_gated_runtime.provider_runtime.release import build_provider_release

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _release(tmp_path: Path):
    profile = _profile(tmp_path / "profile", profile_id="default")
    return build_provider_release(
        profiles=(profile,),
        release_version="2026.08.25",
        output_dir=tmp_path / "release",
    )


def _select(context: str, pointer: str) -> dict[str, str]:
    return {"kind": "select", "context": context, "pointer": pointer}


def _literal(value: object) -> dict[str, object]:
    return {"kind": "literal", "value": value}


def _request_template(context: str) -> dict[str, object]:
    return {
        "path_params": {},
        "query": {
            "$select": _literal("id,name"),
            "page[size]": _literal(["10"]),
        },
        "headers": {
            "Idempotency-Key": _select(context, "/provider_event_id"),
        },
        "body": {
            "kind": "object",
            "fields": {
                "amount": _select(context, "/payload/amount"),
            },
        },
    }


def _grounding(evidence_id: str = "observed_delivery") -> dict[str, object]:
    return {"level": "G2_OBSERVED", "evidence_refs": [evidence_id]}


def _rights() -> dict[str, str]:
    return {
        "distribution_label": "public",
        "behavior_distribution_basis": "Self-authored test integration capture.",
    }


def _pack_payload(release, evidence_digest: str) -> dict[str, object]:
    return {
        "schema_version": "datalox_composition_pack_v1",
        "claim_status": "authored_not_admitted",
        "time_scope": "delivery_scheduler_only_v1",
        "pack_id": "counter_delivery",
        "pack_version": "2026.08.25",
        "distribution_label": "public",
        "providers": [
            {
                "provider_id": release.provider_id,
                "release_manifest_sha256": release.manifest_descriptor["digest"],
                "operation_contract_sha256": release.config["operation_contract_sha256"],
            }
        ],
        "evidence_sources": [
            {
                "evidence_id": "observed_delivery",
                "artifact_path": "evidence/delivery.json",
                "artifact_sha256": evidence_digest,
                "grounding_level": "G2_OBSERVED",
                "observed_at": "2026-08-01T00:00:00Z",
                "valid_through": "2027-08-01T00:00:00Z",
                "distribution_label": "public",
                "rights_basis": "Self-authored test integration capture.",
            }
        ],
        "source_event_contracts": [
            {
                "source_contract_id": "counter_incremented",
                "provider_id": release.provider_id,
                "source_operation_id": "counter.increment",
                "event_type": "counter.incremented",
                "accepted_outcomes": [{"status_code": 200, "decision_kind": "shadow_write"}],
                "match": [],
                "provider_event_id": _select("response", "/body/event_id"),
                "payload": {
                    "kind": "object",
                    "fields": {
                        "amount": _select("request", "/body/amount"),
                        "event_id": _select("response", "/body/event_id"),
                    },
                },
                "correlations": {"order_id": _select("request", "/body/order_id")},
                "grounding": _grounding(),
                "rights": _rights(),
            }
        ],
        "delivery_edges": [
            {
                "edge_id": "increment_replica",
                "source_contract_id": "counter_incremented",
                "target_provider_id": release.provider_id,
                "target_operation_id": "counter.increment",
                "principal_context_id": "integration_service",
                "request": _request_template("source_event"),
                "logical_delay_seconds": 2,
                "retry_delays_seconds": [1, 5, 30],
                "idempotency_key": _select("source_event", "/provider_event_id"),
                "ordering_key": _select("source_event", "/correlation_ids/order_id"),
                "correlations": {"order_id": _select("source_event", "/correlation_ids/order_id")},
                "delivered_statuses": [200],
                "retryable_statuses": [409, 429, 503],
                "default_outcome": "terminal_failure",
                "compensation": None,
                "grounding": _grounding(),
                "rights": _rights(),
            }
        ],
    }


def _pack(tmp_path: Path, release) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "pack"
    evidence = root / "evidence" / "delivery.json"
    _write_json(evidence, {"observation": "source write caused target delivery"})
    digest = "sha256:" + hashlib.sha256(evidence.read_bytes()).hexdigest()
    payload = _pack_payload(release, digest)
    _write_json(root / "composition-pack.json", payload)
    return root, payload


def _error_code(root: Path, release) -> str:
    with pytest.raises(CompositionPackError) as caught:
        load_composition_pack(root, provider_releases={release.provider_id: release})
    return caught.value.code


def test_loads_bound_authored_pack_schema_and_immutable_model(tmp_path: Path) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)

    loaded = load_composition_pack(
        root,
        provider_releases={release.provider_id: release},
    )
    again = load_composition_pack(
        root,
        provider_releases={release.provider_id: release},
    )

    assert loaded.canonical_sha256 == again.canonical_sha256
    assert loaded.pack_id == "counter_delivery"
    assert loaded.providers[0].release_manifest_sha256 == release.manifest_descriptor["digest"]
    assert loaded.source_event_contracts[0].source_operation_id == "counter.increment"
    assert loaded.delivery_edges[0].retry_delays_seconds == (1, 5, 30)
    assert loaded.delivery_edges[0].compensation is None
    with pytest.raises(TypeError):
        loaded.payload["pack_id"] = "changed"  # type: ignore[index]

    schema = json.loads(
        (ROOT / "schemas" / "composition-pack-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_template_evaluation_is_exact_and_type_checked(tmp_path: Path) -> None:
    release = _release(tmp_path)
    root, _ = _pack(tmp_path, release)
    loaded = load_composition_pack(root, provider_releases={release.provider_id: release})
    source = loaded.source_event_contracts[0]

    event_id = evaluate_string_template(
        source.provider_event_id,
        contexts={"response": {"body": {"event_id": "evt_native_1"}}},
        field_name="provider_event_id",
    )
    assert event_id == "evt_native_1"
    assert evaluate_template(
        source.payload,
        contexts={
            "request": {"body": {"amount": 4}},
            "response": {"body": {"event_id": "evt_native_1"}},
        },
        expected_type="object",
    ) == {"amount": 4, "event_id": "evt_native_1"}

    evaluated_request = evaluate_request_template(
        loaded.delivery_edges[0].request,
        contexts={
            "source_event": {
                "provider_event_id": "evt_native_1",
                "payload": {"amount": 4},
            }
        },
    )
    assert evaluated_request == {
        "path_params": {},
        "query": {"$select": "id,name", "page[size]": ["10"]},
        "headers": {"Idempotency-Key": "evt_native_1"},
        "body": {"amount": 4},
    }

    with pytest.raises(CompositionPackError) as caught:
        evaluate_string_template(
            source.provider_event_id,
            contexts={"response": {"body": {}}},
            field_name="provider_event_id",
        )
    assert caught.value.code == "composition_template_pointer_missing"

    with pytest.raises(CompositionPackError) as caught:
        evaluate_string_template(
            source.provider_event_id,
            contexts={"response": {"body": {"event_id": 4}}},
            field_name="provider_event_id",
        )
    assert caught.value.code == "composition_template_result_type_invalid"


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda value: value["providers"][0].__setitem__(
                "release_manifest_sha256", "sha256:" + "0" * 64
            ),
            "composition_pack_provider_binding_invalid",
        ),
        (
            lambda value: value["delivery_edges"][0].__setitem__(
                "target_operation_id", "counter.missing"
            ),
            "composition_pack_operation_binding_invalid",
        ),
        (
            lambda value: value["delivery_edges"][0].__setitem__(
                "idempotency_key", _select("request", "/body/id")
            ),
            "composition_pack_template_context_invalid",
        ),
        (
            lambda value: value["delivery_edges"][0].__setitem__(
                "idempotency_key", _select("source_event", "/request/body/id")
            ),
            "composition_pack_template_pointer_root_invalid",
        ),
        (
            lambda value: value["delivery_edges"][0].__setitem__(
                "retry_delays_seconds", [1] * (COMPOSITION_PACK_MAX_RETRY_DELAYS + 1)
            ),
            "composition_pack_retry_schedule_invalid",
        ),
        (
            lambda value: value["delivery_edges"][0].__setitem__("delivered_statuses", [200, 429]),
            "composition_pack_status_ambiguous",
        ),
        (
            lambda value: value["delivery_edges"][0]["request"].__setitem__(
                "credentials", _literal("secret")
            ),
            "composition_pack_fields_invalid",
        ),
        (
            lambda value: value["delivery_edges"][0].__setitem__(
                "idempotency_key", {"kind": "concat", "items": []}
            ),
            "composition_pack_template_invalid",
        ),
        (
            lambda value: value["source_event_contracts"][0].__setitem__(
                "provider_event_id", _literal(4)
            ),
            "composition_pack_template_static_type_invalid",
        ),
        (
            lambda value: value["source_event_contracts"][0]["accepted_outcomes"][0].__setitem__(
                "decision_kind", "invented"
            ),
            "composition_pack_source_outcomes_invalid",
        ),
        (
            lambda value: value["delivery_edges"][0]["request"].__setitem__(
                "query", {"page[size]": _literal([1])}
            ),
            "composition_pack_template_static_type_invalid",
        ),
    ],
)
def test_rejects_provider_operation_context_retry_status_and_language_errors(
    tmp_path: Path, mutate, expected: str
) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    mutate(payload)
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == expected


def test_rejects_ambiguous_sources_unused_evidence_and_stale_interval(tmp_path: Path) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    duplicate = deepcopy(payload["source_event_contracts"][0])
    duplicate["source_contract_id"] = "counter_incremented_duplicate"
    payload["source_event_contracts"].append(duplicate)
    payload["source_event_contracts"].sort(key=lambda item: item["source_contract_id"])
    assert isinstance(payload["delivery_edges"], list)
    duplicate_edge = deepcopy(payload["delivery_edges"][0])
    duplicate_edge["edge_id"] = "increment_replica_duplicate"
    duplicate_edge["source_contract_id"] = "counter_incremented_duplicate"
    payload["delivery_edges"].append(duplicate_edge)
    payload["delivery_edges"].sort(key=lambda item: item["edge_id"])
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_source_match_ambiguous"

    root, payload = _pack(tmp_path / "unused", release)
    extra = root / "evidence" / "unused.json"
    _write_json(extra, {"unused": True})
    payload["evidence_sources"].append(
        {
            "evidence_id": "unused_evidence",
            "artifact_path": "evidence/unused.json",
            "artifact_sha256": "sha256:" + hashlib.sha256(extra.read_bytes()).hexdigest(),
            "grounding_level": "G1_OFFICIAL",
            "observed_at": "2026-08-01T00:00:00Z",
            "valid_through": "2027-08-01T00:00:00Z",
            "distribution_label": "public",
            "rights_basis": "Self-authored unused fixture.",
        }
    )
    payload["evidence_sources"].sort(key=lambda item: item["evidence_id"])
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_evidence_unused"

    root, payload = _pack(tmp_path / "freshness", release)
    payload["evidence_sources"][0]["valid_through"] = "2026-07-01T00:00:00Z"
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_evidence_freshness_invalid"


def test_rejects_evidence_tamper_symlink_and_undeclared_files(tmp_path: Path) -> None:
    release = _release(tmp_path)
    root, _ = _pack(tmp_path, release)
    (root / "evidence" / "delivery.json").write_text("changed\n", encoding="utf-8")
    assert _error_code(root, release) == "composition_pack_evidence_digest_mismatch"

    root, _ = _pack(tmp_path / "symlink", release)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    artifact = root / "evidence" / "delivery.json"
    artifact.unlink()
    artifact.symlink_to(outside)
    assert _error_code(root, release) == "composition_pack_symlink_forbidden"

    root, _ = _pack(tmp_path / "extra", release)
    (root / "undeclared.txt").write_text("extra\n", encoding="utf-8")
    assert _error_code(root, release) == "composition_pack_files_undeclared"


def test_rejects_compensation_cycle(tmp_path: Path) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    payload["delivery_edges"][0]["compensation"] = {
        "compensation_id": "increment_compensation",
        "triggers": ["retry_exhausted", "terminal_failure"],
        "target_provider_id": release.provider_id,
        "target_operation_id": "counter.increment",
        "principal_context_id": "integration_service",
        "request": _request_template("source_event"),
        "logical_delay_seconds": 0,
        "idempotency_key": _select("source_event", "/provider_event_id"),
        "ordering_key": _select("source_event", "/correlation_ids/order_id"),
        "correlations": {"order_id": _select("source_event", "/correlation_ids/order_id")},
        "delivered_statuses": [200],
        "default_outcome": "terminal_failure",
        "grounding": _grounding(),
        "rights": _rights(),
    }
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_compensation_cycle"


def test_rejects_duplicate_json_keys_and_excessive_template_depth(tmp_path: Path) -> None:
    release = _release(tmp_path)
    root, _ = _pack(tmp_path, release)
    manifest = root / "composition-pack.json"
    text = manifest.read_text(encoding="utf-8")
    text = text.replace(
        '"pack_id": "counter_delivery",',
        '"pack_id": "counter_delivery",\n  "pack_id": "duplicate",',
        1,
    )
    manifest.write_text(text, encoding="utf-8")
    assert _error_code(root, release) == "composition_pack_json_duplicate_key"

    root, payload = _pack(tmp_path / "depth", release)
    expression: dict[str, object] = _literal(None)
    for _ in range(COMPOSITION_PACK_MAX_TEMPLATE_DEPTH + 2):
        expression = {"kind": "array", "items": [expression]}
    payload["delivery_edges"][0]["request"]["body"] = expression
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_template_depth_exceeded"


@pytest.mark.parametrize(
    "header_name",
    [
        "Authorization",
        "PROXY-AUTHORIZATION",
        "Cookie",
        "Set-Cookie",
        "X-API-Key",
        "api-key",
        "X-Datalox-Actor-Role",
        "x-datalox-control-token",
    ],
)
def test_rejects_credential_and_control_header_templates_case_insensitively(
    tmp_path: Path, header_name: str
) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    payload["delivery_edges"][0]["request"]["headers"] = {
        header_name: _literal("pack-owned-secret")
    }
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_credential_header_forbidden"


@pytest.mark.parametrize(
    ("context", "pointer"),
    [
        ("request", "/headers"),
        ("request", "/headers/Authorization"),
        ("request", "/headers/X-API-Key"),
        ("request", "/headers/X-Datalox-Control-Token"),
        ("response", "/headers/Set-Cookie"),
    ],
)
def test_rejects_credential_header_selection_from_source_contexts(
    tmp_path: Path, context: str, pointer: str
) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    payload["source_event_contracts"][0]["payload"] = {
        "kind": "object",
        "fields": {"unsafe": _select(context, pointer)},
    }
    _write_json(root / "composition-pack.json", payload)

    assert _error_code(root, release) == "composition_pack_credential_header_selection_forbidden"


def test_allows_named_noncredential_header_selection(tmp_path: Path) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    payload["source_event_contracts"][0]["payload"] = {
        "kind": "object",
        "fields": {"request_id": _select("response", "/headers/X-Request-Id")},
    }
    _write_json(root / "composition-pack.json", payload)

    loaded = load_composition_pack(root, provider_releases={release.provider_id: release})

    assert loaded.pack_id == "counter_delivery"


def test_source_match_is_finite_exact_and_supports_post_operation_provider_state(
    tmp_path: Path,
) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    payload["source_event_contracts"][0]["match"] = [
        {
            "context": "provider_state",
            "pointer": "/state/counter",
            "operator": "equals",
            "expected_value": 2,
        },
        {
            "context": "response",
            "pointer": "/body/event_id",
            "operator": "type",
            "expected_type": "string",
        },
    ]
    _write_json(root / "composition-pack.json", payload)
    loaded = load_composition_pack(root, provider_releases={release.provider_id: release})
    predicates = loaded.source_event_contracts[0].match

    assert evaluate_source_match(
        predicates,
        contexts={
            "provider_state": {"state": {"counter": 2}},
            "response": {"body": {"event_id": "event-2"}},
        },
    )
    assert not evaluate_source_match(
        predicates,
        contexts={
            "provider_state": {"state": {"counter": 1}},
            "response": {"body": {"event_id": "event-2"}},
        },
    )


def test_source_match_rejects_unsafe_unsatisfiable_and_ambiguous_contracts(
    tmp_path: Path,
) -> None:
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    payload["source_event_contracts"][0]["match"] = [
        {
            "context": "request",
            "pointer": "/headers/Authorization",
            "operator": "exists",
            "expected_exists": True,
        }
    ]
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_credential_header_selection_forbidden"

    root, payload = _pack(tmp_path / "unsatisfiable", release)
    payload["source_event_contracts"][0]["match"] = [
        {
            "context": "provider_state",
            "pointer": "/state/counter",
            "operator": "exists",
            "expected_exists": False,
        },
        {
            "context": "provider_state",
            "pointer": "/state/counter",
            "operator": "type",
            "expected_type": "integer",
        },
    ]
    _write_json(root / "composition-pack.json", payload)
    assert _error_code(root, release) == "composition_pack_source_match_unsatisfiable"

    root, payload = _pack(tmp_path / "disjoint", release)
    first = payload["source_event_contracts"][0]
    first["match"] = [
        {
            "context": "provider_state",
            "pointer": "/state/counter",
            "operator": "equals",
            "expected_value": 1,
        }
    ]
    second = deepcopy(first)
    second["source_contract_id"] = "counter_incremented_second"
    second["match"][0]["expected_value"] = 2
    payload["source_event_contracts"].append(second)
    payload["source_event_contracts"].sort(key=lambda item: item["source_contract_id"])
    duplicate_edge = deepcopy(payload["delivery_edges"][0])
    duplicate_edge["edge_id"] = "increment_replica_second"
    duplicate_edge["source_contract_id"] = "counter_incremented_second"
    payload["delivery_edges"].append(duplicate_edge)
    payload["delivery_edges"].sort(key=lambda item: item["edge_id"])
    _write_json(root / "composition-pack.json", payload)
    assert (
        load_composition_pack(root, provider_releases={release.provider_id: release})
        .source_event_contracts[1]
        .match[0]
        .expected_value
        == 2
    )
