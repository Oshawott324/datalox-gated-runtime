from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    PROVIDER_ID,
    build_stateful_provider_bundle,
)

from datalox_gated_runtime.cli import main
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntimeError,
    admit_provider_runtime,
    load_provider_admission,
)

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _request(
    method: str,
    *,
    body: object = None,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "scheme": "https",
        "authority": PROVIDER_AUTHORITY,
        "method": method,
        "path": "/counter",
        "query": {},
        "headers": headers or {},
        "body": body,
    }


def _claims(tmp_path: Path) -> Path:
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"source":"self-authored-test-contract"}\n', encoding="utf-8")
    invalid_header = {"x-datalox-actor-role": "viewer"}
    read = _request("GET")
    write = _request("POST", body={"amount": 2})
    payload = {
        "schema_version": "datalox_provider_operation_claims_v1",
        "provider_id": PROVIDER_ID,
        "bundle_version": "1.0.0",
        "evidence_sources": [
            {
                "evidence_id": "official_contract",
                "artifact_ref": "evidence.json",
                "artifact_sha256": _sha256(evidence),
                "grounding_level": "G1_OFFICIAL_SOURCE",
                "observed_at": "2026-08-01T00:00:00Z",
                "valid_through": "2027-08-01T00:00:00Z",
                "distribution_label": "public",
                "rights_basis": "Self-authored test contract.",
            }
        ],
        "operations": [
            {
                "operation_id": "counter.read",
                "native_surface": {
                    "type": "http",
                    "scheme": "https",
                    "authority": PROVIDER_AUTHORITY,
                    "method": "GET",
                    "path_template": "/counter",
                },
                "mutability": "read",
                "behavior_program": "counter_read_program",
                "state_effects": [],
                "grounding": {
                    "level": "G1_OFFICIAL_SOURCE",
                    "evidence_refs": ["official_contract"],
                },
                "rights": {
                    "distribution_label": "public",
                    "behavior_distribution_basis": "Self-authored provider behavior.",
                },
                "covered_behaviors": ["success", "failure"],
            },
            {
                "operation_id": "counter.increment",
                "native_surface": {
                    "type": "http",
                    "scheme": "https",
                    "authority": PROVIDER_AUTHORITY,
                    "method": "POST",
                    "path_template": "/counter",
                },
                "mutability": "write",
                "behavior_program": "counter_increment_program",
                "state_effects": ["counter"],
                "grounding": {
                    "level": "G1_OFFICIAL_SOURCE",
                    "evidence_refs": ["official_contract"],
                },
                "rights": {
                    "distribution_label": "public",
                    "behavior_distribution_basis": "Self-authored provider behavior.",
                },
                "covered_behaviors": ["success", "failure", "duplicate", "readback"],
            },
        ],
        "provider_invariants": [
            {
                "predicate_id": "counter_remains_integer",
                "source": "provider_state",
                "operator": "type",
                "pointer": "/state/counter",
                "expected_type": "integer",
            }
        ],
        "receipt_predicates": [
            {
                "predicate_id": "response_is_object",
                "source": "response_body",
                "operator": "type",
                "pointer": "",
                "expected_type": "object",
            },
            {
                "predicate_id": "call_was_recorded",
                "source": "call_evidence",
                "operator": "type",
                "pointer": "/events",
                "expected_type": "array",
            },
        ],
        "reset_profiles": [{"profile_id": "default", "kind": "compiled_seed"}],
        "behavior_probes": [
            {
                "probe_id": "counter_behavior",
                "reset_profile": "default",
                "steps": [
                    {
                        "step_id": "read_success",
                        "operation_id": "counter.read",
                        "request": read,
                        "expected_status_code": 200,
                        "expected_decision_kind": "replay",
                        "covers": [{"operation_id": "counter.read", "behavior": "success"}],
                        "receipt_predicate_refs": [
                            "response_is_object",
                            "call_was_recorded",
                        ],
                    },
                    {
                        "step_id": "read_failure",
                        "operation_id": "counter.read",
                        "request": _request("GET", headers=invalid_header),
                        "expected_status_code": 400,
                        "expected_decision_kind": "deny",
                        "covers": [{"operation_id": "counter.read", "behavior": "failure"}],
                        "receipt_predicate_refs": ["response_is_object"],
                    },
                    {
                        "step_id": "write_success",
                        "operation_id": "counter.increment",
                        "request": write,
                        "expected_status_code": 200,
                        "expected_decision_kind": "shadow_write",
                        "covers": [{"operation_id": "counter.increment", "behavior": "success"}],
                        "receipt_predicate_refs": ["response_is_object"],
                    },
                    {
                        "step_id": "write_duplicate",
                        "operation_id": "counter.increment",
                        "request": deepcopy(write),
                        "expected_status_code": 200,
                        "expected_decision_kind": "shadow_write",
                        "covers": [{"operation_id": "counter.increment", "behavior": "duplicate"}],
                        "receipt_predicate_refs": ["response_is_object"],
                    },
                    {
                        "step_id": "write_readback",
                        "operation_id": "counter.read",
                        "request": deepcopy(read),
                        "expected_status_code": 200,
                        "expected_decision_kind": "replay",
                        "covers": [{"operation_id": "counter.increment", "behavior": "readback"}],
                        "receipt_predicate_refs": ["response_is_object"],
                    },
                    {
                        "step_id": "write_failure",
                        "operation_id": "counter.increment",
                        "request": _request("POST", body={"amount": 2}, headers=invalid_header),
                        "expected_status_code": 400,
                        "expected_decision_kind": "deny",
                        "covers": [{"operation_id": "counter.increment", "behavior": "failure"}],
                        "receipt_predicate_refs": ["response_is_object"],
                    },
                ],
            }
        ],
    }
    path = tmp_path / "operation-claims.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_provider_admission_executes_writes_receipts_and_functional_reset(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    output = tmp_path / "provider-admission.json"

    result = admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims,
        output_path=output,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )

    assert result.path == output.resolve()
    assert result.sha256 == _sha256(output)
    assert "admission_sha256" not in result.payload
    assert result.payload["admitted"] is True
    assert result.payload["task_free"] is True
    assert (
        result.payload["behavior_probes"][0]["first_run_sha256"]
        == (result.payload["behavior_probes"][0]["second_run_sha256"])
    )
    operations = {item["operation_id"]: item for item in result.payload["operations"]}
    assert operations["counter.increment"]["covered_behaviors"] == {
        "duplicate": True,
        "failure": True,
        "readback": True,
        "success": True,
    }
    assert operations["counter.increment"]["grounding"]["grounded"] is False
    assert load_provider_admission(output) == result.payload

    for schema_name, payload in (
        ("provider-operation-claims-v1.schema.json", json.loads(claims.read_text())),
        ("provider-admission-v1.schema.json", result.payload),
    ):
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(payload)


def test_admission_rejects_digest_mismatch_without_writing_output(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    payload = json.loads(claims.read_text(encoding="utf-8"))
    payload["evidence_sources"][0]["artifact_sha256"] = "sha256:" + "0" * 64
    claims.write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "admission.json"

    with pytest.raises(ProviderRuntimeError) as caught:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims,
            output_path=output,
            admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
        )

    assert caught.value.code == "provider_admission_evidence_digest_mismatch"
    assert not output.exists()


def test_admission_rejects_write_without_core_duplicate_coverage(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    payload = json.loads(claims.read_text(encoding="utf-8"))
    payload["operations"][1]["covered_behaviors"].remove("duplicate")
    payload["behavior_probes"][0]["steps"] = [
        step
        for step in payload["behavior_probes"][0]["steps"]
        if step["step_id"] != "write_duplicate"
    ]
    claims.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims,
            output_path=tmp_path / "admission.json",
            admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
        )

    assert caught.value.code == "provider_admission_core_behavior_missing"


def test_admission_rejects_embedded_path_parameters(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    payload = json.loads(claims.read_text(encoding="utf-8"))
    payload["operations"][0]["native_surface"]["path_template"] = "/counter-{id}"
    claims.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims,
            output_path=tmp_path / "admission.json",
            admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
        )

    assert caught.value.code == "provider_admission_surface_invalid"


def test_admission_equals_predicate_preserves_json_type(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    payload = json.loads(claims.read_text(encoding="utf-8"))
    payload["provider_invariants"] = [
        {
            "predicate_id": "boolean_must_not_equal_integer_zero",
            "source": "provider_state",
            "operator": "equals",
            "pointer": "/state/counter",
            "expected": False,
        }
    ]
    claims.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims,
            output_path=tmp_path / "admission.json",
            admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
        )

    assert caught.value.code == "provider_admission_predicate_failed"


def test_admission_rejects_duplicate_that_does_not_repeat_success(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    payload = json.loads(claims.read_text(encoding="utf-8"))
    duplicate = payload["behavior_probes"][0]["steps"][3]
    duplicate["request"]["body"] = {"amount": 3}
    claims.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims,
            output_path=tmp_path / "admission.json",
            admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
        )

    assert caught.value.code == "provider_admission_duplicate_probe_invalid"


def test_admission_rejects_duplicate_before_success_in_the_behavior_program(
    tmp_path: Path,
) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    payload = json.loads(claims.read_text(encoding="utf-8"))
    steps = payload["behavior_probes"][0]["steps"]
    steps[2], steps[3] = steps[3], steps[2]
    claims.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims,
            output_path=tmp_path / "admission.json",
            admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
        )

    assert caught.value.code == "provider_admission_duplicate_probe_invalid"


def test_admission_rejects_successful_write_without_observable_state_change(
    tmp_path: Path,
) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    payload = json.loads(claims.read_text(encoding="utf-8"))
    steps = payload["behavior_probes"][0]["steps"]
    steps[2]["request"]["body"] = {"amount": 0}
    steps[3]["request"]["body"] = {"amount": 0}
    claims.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims,
            output_path=tmp_path / "admission.json",
            admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
        )

    assert caught.value.code == "provider_admission_write_transition_missing"


def test_strict_admission_loader_rejects_forged_reset_result(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    output = tmp_path / "provider-admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims,
        output_path=output,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["behavior_probes"][0]["second_run_sha256"] = "sha256:" + "0" * 64
    output.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        load_provider_admission(output)

    assert caught.value.code == "provider_admission_invalid"


def test_provider_admit_cli_reports_external_artifact_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    claims = _claims(tmp_path)
    output = tmp_path / "provider-admission.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "datalox-gate",
            "provider",
            "admit",
            "--bundle",
            str(bundle),
            "--claims",
            str(claims),
            "--out",
            str(output),
            "--json",
        ],
    )

    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["admission"] == str(output.resolve())
    assert payload["admission_sha256"] == _sha256(output)
