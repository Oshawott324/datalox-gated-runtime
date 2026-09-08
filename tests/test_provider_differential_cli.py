from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import jsonschema
from provider_runtime_helpers import PROVIDER_AUTHORITY
from test_provider_assessment_registry import RELEASE, _assessment
from test_provider_release_differential import _measurement, _registry

from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (
    AssertionSpec,
    BehaviorRecipe,
    BehaviorStep,
    ProgramRequirements,
    RequestTemplate,
    canonical_contract_digest,
)
from datalox_gated_runtime.cli import main
from datalox_gated_runtime.json_digest import canonical_json_bytes, canonical_json_sha256
from datalox_gated_runtime.provider_differential.compiled_program import (
    CompiledBehaviorAttempt,
    CompiledBehaviorProgram,
    CompiledBehaviorStep,
    write_compiled_behavior_program,
)
from datalox_gated_runtime.provider_differential.contracts import (
    GroundingMeasurement,
    load_differential_attestation,
)
from datalox_gated_runtime.provider_runtime import FIXED_PRINCIPAL_CONTEXT_ID


def _run_json(arguments: list[str], capsys: object) -> tuple[int, dict[str, object]]:
    with patch.object(sys, "argv", ["datalox-gate", *arguments, "--json"]):
        result = main()
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    return result, json.loads(captured.out)


def _assertion(
    assertion_id: str,
    kind: str,
    *,
    expected: object = None,
    pointer: str | None = None,
    prior_step_id: str | None = None,
    prior_pointer: str | None = None,
) -> AssertionSpec:
    return AssertionSpec(
        assertion_id=assertion_id,
        kind=kind,  # type: ignore[arg-type]
        expected=expected,
        pointer=pointer,
        prior_step_id=prior_step_id,
        prior_pointer=prior_pointer,
    )


def _counter_program() -> CompiledBehaviorProgram:
    actor = "capture_actor"
    subject = "counter_one"
    requests = (
        RequestTemplate(method="GET", path="/counter"),
        RequestTemplate(method="POST", path="/counter", body={"amount": 0}),
        RequestTemplate(method="POST", path="/counter", body={"amount": 0}),
        RequestTemplate(method="POST", path="/missing", body={}),
        RequestTemplate(method="GET", path="/counter"),
    )
    steps = (
        BehaviorStep(
            step_id="before",
            operation_id="counter.read",
            kind="read",
            role="before",
            expected_outcome="read_success",
            subject_id=subject,
            auth_context_id=actor,
            request=requests[0],
            assertions=(_assertion("before_status", "status_equals", expected=200),),
        ),
        BehaviorStep(
            step_id="success",
            operation_id="counter.increment",
            kind="mutation",
            role="success",
            expected_outcome="mutation_success",
            subject_id=subject,
            auth_context_id=actor,
            request=requests[1],
            assertions=(_assertion("success_status", "status_equals", expected=200),),
        ),
        BehaviorStep(
            step_id="duplicate",
            operation_id="counter.increment",
            kind="mutation",
            role="duplicate",
            expected_outcome="idempotent_success",
            subject_id=subject,
            auth_context_id=actor,
            request=requests[2],
            assertions=(
                _assertion(
                    "duplicate_request",
                    "request_equals_step",
                    prior_step_id="success",
                ),
                _assertion("duplicate_status", "status_equals", expected=200),
                _assertion(
                    "duplicate_counter",
                    "json_pointer_equals",
                    pointer="/counter",
                    expected=1,
                ),
            ),
        ),
        BehaviorStep(
            step_id="native_failure",
            operation_id="counter.invalid",
            kind="mutation",
            role="native_failure",
            expected_outcome="native_failure",
            subject_id=subject,
            auth_context_id=actor,
            request=requests[3],
            assertions=(
                _assertion("failure_status", "status_equals", expected=403),
                _assertion(
                    "failure_code",
                    "json_pointer_equals",
                    pointer="/error/code",
                    expected="provider_operation_not_admitted",
                ),
            ),
        ),
        BehaviorStep(
            step_id="resulting_state",
            operation_id="counter.read",
            kind="read",
            role="resulting_state",
            expected_outcome="read_success",
            subject_id=subject,
            auth_context_id=actor,
            request=requests[4],
            assertions=(
                _assertion("result_status", "status_equals", expected=200),
                _assertion(
                    "counter_unchanged",
                    "state_equals_step",
                    pointer="/counter",
                    prior_step_id="before",
                    prior_pointer="/counter",
                ),
            ),
        ),
    )
    recipe = BehaviorRecipe(
        program_id="counter.lifecycle",
        seed=41,
        requirements=ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=steps,
    )
    bodies = (
        {"counter": 1, "actor_role": "operator"},
        {"counter": 1, "actor_role": "operator"},
        {"counter": 1, "actor_role": "operator"},
        {
            "error": {
                "code": "provider_operation_not_admitted",
                "message": "This native provider operation is outside the admitted runtime surface.",
                "details": {},
            }
        },
        {"counter": 1, "actor_role": "operator"},
    )
    compiled_steps = tuple(
        CompiledBehaviorStep(
            step_id=step.step_id,
            operation_id=step.operation_id,
            kind=step.kind,
            role=step.role,
            expected_outcome=step.expected_outcome,
            subject_id=step.subject_id,
            auth_context_id=step.auth_context_id,
            request=step.request,
            poll=None,
            expected_attempts=(
                CompiledBehaviorAttempt(
                    attempt_number=1,
                    expected_status_code=403 if step.role == "native_failure" else 200,
                    expected_body_template=body,
                    expected_headers={},
                ),
            ),
            bindings=(),
        )
        for step, body in zip(steps, bodies, strict=True)
    )
    return CompiledBehaviorProgram(
        provider_id="example_provider",
        provider_version="reference-1",
        seed=41,
        capture_sha256="sha256:" + "a" * 64,
        connector_sha256="sha256:" + "b" * 64,
        connector_canonical_sha256="sha256:" + "b" * 64,
        recipe_sha256="sha256:" + "c" * 64,
        recipe_canonical_sha256=canonical_contract_digest(recipe),
        harvest_engine_id="behavior_harvest_test",
        harvest_engine_version="1",
        harvest_engine_sha256="sha256:" + "d" * 64,
        static_input_sha256={},
        static_artifact_sha256={},
        steps=compiled_steps,
        observed_relations={},
        recipe=recipe,
    )


def _write_program_measurement(
    root: Path,
    *,
    name: str,
    program: CompiledBehaviorProgram,
    observed_at: str,
    completion: str = "complete",
) -> tuple[Path, str, Path, GroundingMeasurement]:
    program_path = root / f"{name}-program.json"
    if completion == "complete":
        program_sha256 = write_compiled_behavior_program(program_path, program)
    else:
        program_sha256 = None
    measurement = GroundingMeasurement(
        measurement_id=name,
        provider_id=program.provider_id,
        provider_version=program.provider_version,
        program_id=program.recipe.program_id,
        observed_at=observed_at,
        capture_sha256=program.capture_sha256,
        connector_sha256=program.connector_sha256,
        recipe_sha256=program.recipe_sha256,
        harvest_engine_sha256=program.harvest_engine_sha256,
        compiled_program_sha256=program_sha256,
        completion=completion,
        rights_ref="self_authored_test",
        distribution="public",
    )
    measurement_path = root / f"{name}-measurement.json"
    measurement_path.write_bytes(canonical_json_bytes(measurement.to_dict()))
    return program_path, program_sha256 or "", measurement_path, measurement


def test_provider_differential_cli_writes_bound_attestation_and_refuses_overwrite(
    tmp_path: Path,
    capsys: object,
) -> None:
    registry, reference = _registry(tmp_path)
    program = _counter_program()
    program_path = tmp_path / "counter-program.json"
    program_file_sha256 = write_compiled_behavior_program(program_path, program)
    measurement = _measurement(
        capture_sha256=program.capture_sha256,
        compiled_program_sha256=program_file_sha256,
    )
    measurement_path = tmp_path / "measurement.json"
    measurement_path.write_bytes(canonical_json_bytes(measurement.to_dict()))
    principals = tmp_path / "principal-bindings.json"
    principal_payload = {
        "schema_version": "datalox_provider_differential_principal_bindings_v1",
        "bindings": [
            {
                "auth_context_id": "capture_actor",
                "principal_context_id": FIXED_PRINCIPAL_CONTEXT_ID,
            }
        ],
    }
    principal_schema = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "schemas/provider-differential-principal-bindings-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(principal_schema)
    jsonschema.Draft202012Validator(principal_schema).validate(principal_payload)
    principals.write_bytes(canonical_json_bytes(principal_payload))
    output = tmp_path / "differential-attestation.json"
    arguments = [
        "provider",
        "differential",
        "--registry",
        str(registry.root),
        "--reference",
        reference,
        "--profile",
        "default",
        "--authority",
        PROVIDER_AUTHORITY,
        "--measurement",
        str(measurement_path),
        "--measurement-sha256",
        measurement.sha256,
        "--program",
        str(program_path),
        "--program-sha256",
        program_file_sha256,
        "--principal-bindings",
        str(principals),
        "--observed-at",
        "2026-09-07T09:30:00Z",
        "--out",
        str(output),
    ]
    status, payload = _run_json(arguments, capsys)
    assert status == 0
    assert payload["passed"] is True
    assert payload["measurement_sha256"] == measurement.sha256
    assert payload["attestation"] == str(output.resolve())
    assert load_differential_attestation(
        output,
        expected_sha256=str(payload["attestation_sha256"]),
    ).passed

    status, payload = _run_json(arguments, capsys)
    assert status == 1
    assert payload["error"]["code"] == "provider_differential_output_exists"  # type: ignore[index]


def test_provider_differential_cli_requires_exact_principal_coverage(
    tmp_path: Path,
    capsys: object,
) -> None:
    registry, reference = _registry(tmp_path)
    program = _counter_program()
    program_path = tmp_path / "counter-program.json"
    program_file_sha256 = write_compiled_behavior_program(program_path, program)
    measurement = _measurement(
        capture_sha256=program.capture_sha256,
        compiled_program_sha256=program_file_sha256,
    )
    measurement_path = tmp_path / "measurement.json"
    measurement_path.write_bytes(canonical_json_bytes(measurement.to_dict()))
    principals = tmp_path / "principal-bindings.json"
    principals.write_bytes(
        canonical_json_bytes(
            {
                "schema_version": "datalox_provider_differential_principal_bindings_v1",
                "bindings": [
                    {
                        "auth_context_id": "some_other_actor",
                        "principal_context_id": FIXED_PRINCIPAL_CONTEXT_ID,
                    }
                ],
            }
        )
    )
    status, payload = _run_json(
        [
            "provider",
            "differential",
            "--registry",
            str(registry.root),
            "--reference",
            reference,
            "--profile",
            "default",
            "--authority",
            PROVIDER_AUTHORITY,
            "--measurement",
            str(measurement_path),
            "--measurement-sha256",
            measurement.sha256,
            "--program",
            str(program_path),
            "--program-sha256",
            program_file_sha256,
            "--principal-bindings",
            str(principals),
            "--observed-at",
            "2026-09-07T09:30:00Z",
            "--out",
            str(tmp_path / "unused.json"),
        ],
        capsys,
    )
    assert status == 1
    assert payload["error"]["code"] == "provider_differential_principal_bindings_incomplete"  # type: ignore[index]


def test_provider_drift_cli_compares_and_derives_publishable_assessment(
    tmp_path: Path,
    capsys: object,
) -> None:
    baseline = _counter_program()
    candidate = replace(
        baseline,
        provider_version="reference-2",
        capture_sha256="sha256:" + "8" * 64,
    )
    baseline_path, baseline_sha, baseline_measurement_path, baseline_measurement = (
        _write_program_measurement(
            tmp_path,
            name="baseline",
            program=baseline,
            observed_at="2026-09-01T00:00:00Z",
        )
    )
    candidate_path, candidate_sha, candidate_measurement_path, candidate_measurement = (
        _write_program_measurement(
            tmp_path,
            name="candidate",
            program=candidate,
            observed_at="2026-09-07T00:00:00Z",
        )
    )
    scope = {"pagination_step_ids": []}
    scope_path = tmp_path / "classification-scope.json"
    scope_path.write_bytes(canonical_json_bytes(scope))
    report_path = tmp_path / "drift-report.json"
    status, report = _run_json(
        [
            "provider",
            "drift",
            "compare",
            "--report-id",
            "baseline-to-candidate",
            "--baseline-measurement",
            str(baseline_measurement_path),
            "--baseline-measurement-sha256",
            baseline_measurement.sha256,
            "--baseline-program",
            str(baseline_path),
            "--baseline-program-sha256",
            baseline_sha,
            "--candidate-measurement",
            str(candidate_measurement_path),
            "--candidate-measurement-sha256",
            candidate_measurement.sha256,
            "--candidate-program",
            str(candidate_path),
            "--candidate-program-sha256",
            candidate_sha,
            "--classification-scope",
            str(scope_path),
            "--classification-scope-sha256",
            canonical_json_sha256(scope),
            "--out",
            str(report_path),
        ],
        capsys,
    )
    assert status == 0
    assert report["comparison_status"] == "changed"
    assert report["summary"]["provider_version_changed"] == 1  # type: ignore[index]

    assessment_path = tmp_path / "assessment.json"
    status, assessment = _run_json(
        [
            "provider",
            "drift",
            "assess",
            "--assessment-id",
            "candidate-assessment",
            "--report",
            str(report_path),
            "--report-sha256",
            str(report["report_sha256"]),
            "--release-manifest-sha256",
            RELEASE,
            "--profile",
            "regional-network-v1",
            "--freshness-window-days",
            "30",
            "--out",
            str(assessment_path),
        ],
        capsys,
    )
    assert status == 0
    assert assessment["status"] == "provider_drift_detected"
    assert assessment_path.read_bytes() == canonical_json_bytes(
        {
            key: value
            for key, value in assessment.items()
            if key not in {"assessment", "assessment_sha256"}
        }
    )

    status, duplicate = _run_json(
        [
            "provider",
            "drift",
            "assess",
            "--assessment-id",
            "candidate-assessment",
            "--report",
            str(report_path),
            "--report-sha256",
            str(report["report_sha256"]),
            "--release-manifest-sha256",
            RELEASE,
            "--profile",
            "regional-network-v1",
            "--freshness-window-days",
            "30",
            "--out",
            str(assessment_path),
        ],
        capsys,
    )
    assert status == 1
    assert duplicate["error"]["code"] == "provider_drift_output_exists"  # type: ignore[index]


def test_provider_drift_cli_blocks_program_for_incomplete_candidate(
    tmp_path: Path,
    capsys: object,
) -> None:
    baseline = _counter_program()
    baseline_path, baseline_sha, baseline_measurement_path, baseline_measurement = (
        _write_program_measurement(
            tmp_path,
            name="baseline",
            program=baseline,
            observed_at="2026-09-01T00:00:00Z",
        )
    )
    _, _, candidate_measurement_path, candidate_measurement = _write_program_measurement(
        tmp_path,
        name="candidate-incomplete",
        program=baseline,
        observed_at="2026-09-07T00:00:00Z",
        completion="incomplete",
    )
    base_arguments = [
        "provider",
        "drift",
        "compare",
        "--report-id",
        "blocked-reacquisition",
        "--baseline-measurement",
        str(baseline_measurement_path),
        "--baseline-measurement-sha256",
        baseline_measurement.sha256,
        "--baseline-program",
        str(baseline_path),
        "--baseline-program-sha256",
        baseline_sha,
        "--candidate-measurement",
        str(candidate_measurement_path),
        "--candidate-measurement-sha256",
        candidate_measurement.sha256,
    ]
    blocked_path = tmp_path / "blocked-report.json"
    status, blocked = _run_json(
        [*base_arguments, "--out", str(blocked_path)],
        capsys,
    )
    assert status == 0
    assert blocked["comparison_status"] == "reacquisition_blocked"

    stray_program = tmp_path / "stray-program.json"
    stray_sha = write_compiled_behavior_program(stray_program, baseline)
    status, rejected = _run_json(
        [
            *base_arguments,
            "--candidate-program",
            str(stray_program),
            "--candidate-program-sha256",
            stray_sha,
            "--out",
            str(tmp_path / "must-not-exist.json"),
        ],
        capsys,
    )
    assert status == 1
    assert rejected["error"]["code"] == "provider_drift_incomplete_program_forbidden"  # type: ignore[index]


def test_provider_assessment_cli_create_publish_list_and_latest(
    tmp_path: Path,
    capsys: object,
) -> None:
    root = tmp_path / "assessments"
    status, created = _run_json(
        ["provider", "assessments", "create", "--root", str(root)],
        capsys,
    )
    assert status == 0
    assert created == {"assessment_registry": str(root.resolve())}

    assessment_path = tmp_path / "assessment.json"
    assessment_path.write_bytes(canonical_json_bytes(_assessment()))
    status, published = _run_json(
        [
            "provider",
            "assessments",
            "publish",
            "--root",
            str(root),
            "--assessment",
            str(assessment_path),
        ],
        capsys,
    )
    assert status == 0
    assert published["assessment_id"] == "openlmis-2026-09-04"

    binding = [
        "--root",
        str(root),
        "--release-manifest-sha256",
        RELEASE,
        "--profile",
        "regional-network-v1",
        "--program",
        "notification.update_contact_details",
    ]
    status, listed = _run_json(
        ["provider", "assessments", "list", *binding],
        capsys,
    )
    assert status == 0
    assert [item["assessment_id"] for item in listed["assessments"]] == [  # type: ignore[index]
        "openlmis-2026-09-04"
    ]

    status, latest = _run_json(
        ["provider", "assessments", "latest", *binding],
        capsys,
    )
    assert status == 0
    assert latest["assessment"]["content_sha256"] == published["content_sha256"]  # type: ignore[index]

    status, fresh = _run_json(
        [
            "provider",
            "assessments",
            "status",
            *binding,
            "--as-of",
            "2026-09-10T00:00:00Z",
        ],
        capsys,
    )
    assert status == 0
    assert fresh["status"] == "current"

    status, stale = _run_json(
        [
            "provider",
            "assessments",
            "status",
            *binding,
            "--as-of",
            "2026-10-04T08:00:00Z",
        ],
        capsys,
    )
    assert status == 0
    assert stale["status"] == "stale"
