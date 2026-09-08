from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    PROVIDER_ID,
    build_stateful_provider_bundle,
)
from test_provider_admission import _claims

from datalox_gated_runtime.provider_differential import (
    DIFFERENTIAL_COMPARISON_PROFILE,
    DifferentialProgramBinding,
    GroundingMeasurement,
    ProviderDifferentialAttestation,
    ProviderDifferentialError,
    ProviderReleaseTarget,
    run_provider_release_differential,
)
from datalox_gated_runtime.provider_runtime import FIXED_PRINCIPAL_CONTEXT_ID
from datalox_gated_runtime.provider_runtime.admission import admit_provider_runtime
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.provider_runtime.release import (
    ProviderReleaseProfileInput,
    build_provider_release,
)
from datalox_gated_runtime.reference import (
    ConformanceMismatch,
    ConformanceReport,
    ReferenceCall,
)

TRACE_DIGEST = "sha256:" + "a" * 64
COMPILED_PROGRAM_DIGEST = "sha256:" + "e" * 64
ROOT = Path(__file__).resolve().parents[1]


def _registry(tmp_path: Path) -> tuple[FilesystemProviderReleaseRegistry, str]:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-source")
    admission = tmp_path / "provider-admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=_claims(tmp_path),
        output_path=admission,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    release = build_provider_release(
        profiles=(
            ProviderReleaseProfileInput(
                profile_id="default",
                bundle_dir=bundle,
                admission_path=admission,
            ),
        ),
        release_version="1.0.0",
        output_dir=tmp_path / "release",
    )
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")
    published = registry.publish(release)
    return registry, published.reference


def _measurement(
    *,
    capture_sha256: str = TRACE_DIGEST,
    compiled_program_sha256: str = COMPILED_PROGRAM_DIGEST,
) -> GroundingMeasurement:
    return GroundingMeasurement(
        measurement_id="counter.capture.20260904",
        provider_id=PROVIDER_ID,
        provider_version="reference-1",
        program_id="counter.lifecycle",
        observed_at="2026-09-04T08:00:00Z",
        capture_sha256=capture_sha256,
        connector_sha256="sha256:" + "b" * 64,
        recipe_sha256="sha256:" + "c" * 64,
        harvest_engine_sha256="sha256:" + "d" * 64,
        compiled_program_sha256=compiled_program_sha256,
        completion="complete",
        rights_ref="self_authored_test",
        distribution="public",
    )


def _report(
    target: ProviderReleaseTarget,
    *,
    mismatches: tuple[ConformanceMismatch, ...] = (),
) -> ConformanceReport:
    return ConformanceReport(
        trace_schema_id="datalox_reference_trace_v2",
        trace_digest=TRACE_DIGEST,
        provider_id=PROVIDER_ID,
        provider_version="reference-1",
        target_id=target.target_id,
        target_version=target.target_version,
        profile_id=DIFFERENTIAL_COMPARISON_PROFILE,
        seed=41,
        mismatches=mismatches,
    )


def _passing_program() -> DifferentialProgramBinding:
    def run(target: ProviderReleaseTarget) -> ConformanceReport:
        target.reset(41)
        initial = target.execute(
            ReferenceCall("GET", "/counter", "counter.read"),
            principal_context_id="reader_capture_context",
        )
        assert initial.status_code == 200
        assert initial.body["counter"] == 1
        written = target.execute(
            ReferenceCall(
                "POST",
                "/counter",
                "counter.increment",
                body={"amount": 2},
            ),
            principal_context_id="writer_capture_context",
        )
        assert written.status_code == 200
        assert written.body["counter"] == 3
        readback = target.execute(
            ReferenceCall("GET", "/counter", "counter.read"),
            principal_context_id="reader_capture_context",
        )
        assert readback.body["counter"] == 3
        return _report(target)

    return DifferentialProgramBinding(
        program_id="counter.lifecycle",
        provider_id=PROVIDER_ID,
        provider_version="reference-1",
        trace_schema_id="datalox_reference_trace_v2",
        trace_digest=TRACE_DIGEST,
        connector_sha256="sha256:" + "b" * 64,
        recipe_sha256="sha256:" + "c" * 64,
        harvest_engine_sha256="sha256:" + "d" * 64,
        compiled_program_sha256=COMPILED_PROGRAM_DIGEST,
        seed=41,
        profile_id=DIFFERENTIAL_COMPARISON_PROFILE,
        runner=run,
    )


def _bindings() -> dict[str, str]:
    return {
        "reader_capture_context": FIXED_PRINCIPAL_CONTEXT_ID,
        "writer_capture_context": FIXED_PRINCIPAL_CONTEXT_ID,
    }


def test_release_target_preserves_exact_request_and_explicit_step_principals(
    tmp_path: Path,
) -> None:
    registry, reference = _registry(tmp_path)
    target = ProviderReleaseTarget(
        registry=registry,
        release_reference=reference,
        profile_id="default",
        authority=PROVIDER_AUTHORITY,
        principal_bindings=_bindings(),
    )
    try:
        target.reset(41)
        response = target.execute(
            ReferenceCall(
                "POST",
                "/counter",
                "counter.increment",
                query={"include": "receipt"},
                body={"amount": 2},
                headers={"x-request-id": "request-1"},
            ),
            principal_context_id="writer_capture_context",
        )
        assert response.status_code == 200
        request = target.transcript()[0]["request"]
        assert request == {
            "scheme": "https",
            "authority": PROVIDER_AUTHORITY,
            "method": "POST",
            "path": "/counter",
            "query": {"include": "receipt"},
            "body": {"amount": 2},
            "headers": {"x-request-id": "request-1"},
            "operation_id": "counter.increment",
            "auth_context_id": "writer_capture_context",
            "provider_principal_context_id": FIXED_PRINCIPAL_CONTEXT_ID,
        }

        target.execute(
            ReferenceCall("GET", "/counter", "counter.read"),
            principal_context_id="reader_capture_context",
        )
        assert [item["request"]["auth_context_id"] for item in target.transcript()] == [
            "writer_capture_context",
            "reader_capture_context",
        ]
        assert target.behavior_state_sha256().startswith("sha256:")
        assert target.behavioral_fingerprint().startswith("sha256:")

        with pytest.raises(ProviderDifferentialError) as caught:
            target.execute(
                ReferenceCall("GET", "/counter", "counter.read"),
                principal_context_id="undeclared_capture_context",
            )
        assert caught.value.code == "provider_differential_principal_unbound"
    finally:
        target.close()


def test_differential_binds_inputs_and_proves_reset_and_fresh_instance(
    tmp_path: Path,
) -> None:
    registry, reference = _registry(tmp_path)
    measurement = _measurement()
    result = run_provider_release_differential(
        registry=registry,
        release_reference=reference,
        profile_id="default",
        authority=PROVIDER_AUTHORITY,
        principal_bindings=_bindings(),
        measurement=measurement,
        program=_passing_program(),
        observed_at="2026-09-07T09:30:00Z",
    )

    assert result.passed is True
    assert result.measurement_sha256 == measurement.sha256
    assert result.source["capture_sha256"] == TRACE_DIGEST
    assert result.replica["release_reference"] == reference
    assert result.replica["release_manifest_sha256"].startswith("sha256:")
    assert result.functional_reset == {
        "within_instance_equivalent": True,
        "fresh_instance_equivalent": True,
        "passed": True,
    }
    assert result.runs["within_instance_initial"].reset_generation == 1
    assert result.runs["within_instance_after_reset"].reset_generation == 2
    assert result.runs["fresh_instance"].reset_generation == 1
    assert len({run.initial_state_sha256 for run in result.runs.values()}) == 1
    assert len({run.final_state_sha256 for run in result.runs.values()}) == 1
    assert len({run.behavioral_fingerprint for run in result.runs.values()}) == 1
    assert ProviderDifferentialAttestation.from_dict(result.to_dict()) == result

    for schema_name, payload in (
        ("provider-grounding-measurement-v1.schema.json", measurement.to_dict()),
        ("provider-differential-attestation-v1.schema.json", result.to_dict()),
    ):
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(payload)


def test_differential_preserves_conformance_mismatches_in_every_run(tmp_path: Path) -> None:
    registry, reference = _registry(tmp_path)

    def run(target: ProviderReleaseTarget) -> ConformanceReport:
        target.reset(41)
        actual = target.execute(
            ReferenceCall("GET", "/counter", "counter.read"),
            principal_context_id="reader_capture_context",
        )
        return _report(
            target,
            mismatches=(
                ConformanceMismatch(
                    code="response_value_mismatch",
                    path="/body/counter",
                    expected=999,
                    actual=actual.body["counter"],
                    step_id="read_initial",
                ),
            ),
        )

    program = DifferentialProgramBinding(
        program_id="counter.lifecycle",
        provider_id=PROVIDER_ID,
        provider_version="reference-1",
        trace_schema_id="datalox_reference_trace_v2",
        trace_digest=TRACE_DIGEST,
        connector_sha256="sha256:" + "b" * 64,
        recipe_sha256="sha256:" + "c" * 64,
        harvest_engine_sha256="sha256:" + "d" * 64,
        compiled_program_sha256=COMPILED_PROGRAM_DIGEST,
        seed=41,
        profile_id=DIFFERENTIAL_COMPARISON_PROFILE,
        runner=run,
    )
    result = run_provider_release_differential(
        registry=registry,
        release_reference=reference,
        profile_id="default",
        authority=PROVIDER_AUTHORITY,
        principal_bindings=_bindings(),
        measurement=_measurement(),
        program=program,
        observed_at="2026-09-07T09:30:00Z",
    )

    assert result.passed is False
    assert result.functional_reset["passed"] is True
    for run in result.runs.values():
        assert run.status == "completed"
        assert run.passed is False
        assert run.to_dict()["report"]["mismatches"] == [
            {
                "code": "response_value_mismatch",
                "path": "/body/counter",
                "expected": 999,
                "actual": 1,
                "step_id": "read_initial",
                "observation_id": None,
            }
        ]


def test_differential_rejects_measurement_program_digest_mismatch(tmp_path: Path) -> None:
    registry, reference = _registry(tmp_path)
    with pytest.raises(ProviderDifferentialError) as caught:
        run_provider_release_differential(
            registry=registry,
            release_reference=reference,
            profile_id="default",
            authority=PROVIDER_AUTHORITY,
            principal_bindings=_bindings(),
            measurement=_measurement(capture_sha256="sha256:" + "f" * 64),
            program=_passing_program(),
            observed_at="2026-09-07T09:30:00Z",
        )
    assert caught.value.code == "provider_differential_input_binding_mismatch"

    with pytest.raises(ProviderDifferentialError) as caught:
        run_provider_release_differential(
            registry=registry,
            release_reference=reference,
            profile_id="default",
            authority=PROVIDER_AUTHORITY,
            principal_bindings=_bindings(),
            measurement=_measurement(compiled_program_sha256="sha256:" + "f" * 64),
            program=_passing_program(),
            observed_at="2026-09-07T09:30:00Z",
        )
    assert caught.value.code == "provider_differential_input_binding_mismatch"


def test_incomplete_measurement_records_absent_compiled_program_explicitly() -> None:
    measurement = GroundingMeasurement(
        measurement_id="counter.capture.failed",
        provider_id=PROVIDER_ID,
        provider_version="reference-1",
        program_id="counter.lifecycle",
        observed_at="2026-09-04T08:00:00Z",
        capture_sha256=TRACE_DIGEST,
        connector_sha256="sha256:" + "b" * 64,
        recipe_sha256="sha256:" + "c" * 64,
        harvest_engine_sha256="sha256:" + "d" * 64,
        compiled_program_sha256=None,
        completion="incomplete",
        rights_ref="self_authored_test",
        distribution="public",
    )
    assert measurement.to_dict()["compiled_program_sha256"] is None

    with pytest.raises(ProviderDifferentialError) as caught:
        GroundingMeasurement(
            **{
                **measurement.to_dict(),
                "completion": "complete",
            }
        )
    assert caught.value.code == "provider_grounding_measurement_compiled_program_binding_invalid"
