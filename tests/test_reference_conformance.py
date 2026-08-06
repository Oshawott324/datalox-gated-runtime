from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from typing import Any

import pytest

from datalox_gated_runtime.reference import (
    ConformanceReport,
    ExpectedObservation,
    JsonValue,
    ObservationRequest,
    ObservedResponse,
    ReferenceCall,
    ReferenceContractError,
    ReferenceStep,
    ReferenceTrace,
    compute_reference_trace_digest,
    run_conformance,
)


def _observation(
    observation_id: str,
    expected: JsonValue,
    *,
    query: JsonValue | None = None,
) -> ExpectedObservation:
    return ExpectedObservation(
        request=ObservationRequest(
            observation_id=observation_id,
            query=query if query is not None else {"resource": observation_id},
        ),
        expected=expected,
    )


def _step(
    step_id: str,
    *,
    expected_body: JsonValue | None = None,
    observations: tuple[ExpectedObservation, ...] = (),
) -> ReferenceStep:
    return ReferenceStep(
        step_id=step_id,
        call=ReferenceCall(
            method="post",
            path=f"/records/{step_id}",
            query={},
            body={"step": step_id},
            headers={"content-type": "application/json"},
            operation_id=f"create:{step_id}",
        ),
        expected_response=ObservedResponse(
            status_code=201,
            body=expected_body if expected_body is not None else {"ok": True},
            headers={"content-type": "application/json"},
        ),
        post_observations=observations,
    )


def _trace(
    *,
    initial: tuple[ExpectedObservation, ...] = (),
    steps: tuple[ReferenceStep, ...] | None = None,
) -> ReferenceTrace:
    return ReferenceTrace(
        provider_id="example_service",
        provider_version="1.2.3",
        seed=17,
        initial_observations=initial,
        steps=steps if steps is not None else (_step("one"),),
        evidence_refs=("capture:sha256:abc",),
        metadata={"fixture": "local"},
    )


class FakeTarget:
    target_id = "fake_reference_service"
    target_version = "fixture-v1"

    def __init__(
        self,
        *,
        responses: dict[str, ObservedResponse] | None = None,
        observations: dict[str, JsonValue] | None = None,
    ) -> None:
        self.responses = responses or {
            "create:one": ObservedResponse(
                status_code=201,
                body={"ok": True},
                headers={"content-type": "application/json"},
            )
        }
        self.observations = observations or {}
        self.events: list[str] = []
        self.seed: int | None = None

    def reset(self, seed: int) -> None:
        self.seed = seed
        self.events.append(f"reset:{seed}")

    def execute(self, call: ReferenceCall) -> ObservedResponse:
        self.events.append(f"execute:{call.operation_id}")
        return self.responses[call.operation_id]

    def observe(self, request: ObservationRequest) -> JsonValue:
        self.events.append(f"observe:{request.observation_id}")
        return self.observations[request.observation_id]


def test_happy_path_and_serialization_round_trip() -> None:
    trace = _trace(
        initial=(_observation("before", {"count": 0}),),
        steps=(
            _step(
                "one",
                observations=(_observation("after", {"count": 1}),),
            ),
        ),
    )
    target = FakeTarget(
        observations={
            "before": {"count": 0},
            "after": {"count": 1},
        }
    )

    report = run_conformance(trace, target)

    assert report.passed is True
    assert report.mismatches == ()
    assert report.trace_digest == compute_reference_trace_digest(trace)
    assert report.target_id == "fake_reference_service"
    assert report.target_version == "fixture-v1"
    assert report.profile_id == "identity_exact_v1"
    assert ReferenceTrace.from_dict(trace.to_dict()) == trace
    assert ConformanceReport.from_dict(report.to_dict()) == report


def test_trace_digest_is_canonical_and_changes_with_exact_trace() -> None:
    trace = _trace()
    reordered_metadata = replace(
        trace,
        metadata={"second": 2, "first": 1},
    )
    same_metadata_different_order = replace(
        trace,
        metadata={"first": 1, "second": 2},
    )
    changed_seed = replace(reordered_metadata, seed=18)
    changed_provider_version = replace(reordered_metadata, provider_version="1.2.4")

    digest = compute_reference_trace_digest(reordered_metadata)

    assert digest.startswith("sha256:")
    assert len(digest) == 71
    assert digest == compute_reference_trace_digest(same_metadata_different_order)
    assert compute_reference_trace_digest(changed_seed) != digest
    assert compute_reference_trace_digest(changed_provider_version) != digest


def test_runner_resets_with_seed_and_preserves_sequence_order() -> None:
    trace = _trace(
        initial=(_observation("initial", {"phase": "before"}),),
        steps=(
            _step("one", observations=(_observation("after_one", {"value": 1}),)),
            _step("two", observations=(_observation("after_two", {"value": 2}),)),
        ),
    )
    target = FakeTarget(
        responses={
            "create:one": _step("one").expected_response,
            "create:two": _step("two").expected_response,
        },
        observations={
            "initial": {"phase": "before"},
            "after_one": {"value": 1},
            "after_two": {"value": 2},
        },
    )

    report = run_conformance(trace, target)

    assert report.passed is True
    assert target.events == [
        "reset:17",
        "observe:initial",
        "execute:create:one",
        "observe:after_one",
        "execute:create:two",
        "observe:after_two",
    ]


def test_response_mismatch_is_structured_and_does_not_stop_next_step() -> None:
    trace = _trace(steps=(_step("one"), _step("two")))
    target = FakeTarget(
        responses={
            "create:one": ObservedResponse(
                status_code=200,
                body={"ok": False},
                headers={"content-type": "application/json"},
            ),
            "create:two": _step("two").expected_response,
        }
    )

    report = run_conformance(trace, target)

    assert report.passed is False
    assert [(item.code, item.path, item.step_id) for item in report.mismatches] == [
        ("response_value_mismatch", "/body/ok", "one"),
        ("response_value_mismatch", "/status_code", "one"),
    ]
    assert target.events[-1] == "execute:create:two"


def test_nested_observation_mismatch_uses_escaped_json_pointer() -> None:
    trace = _trace(
        initial=(
            _observation(
                "nested",
                {"rows": [{"sample/id": {"state~code": "ready"}}]},
            ),
        ),
        steps=(),
    )
    target = FakeTarget(
        observations={"nested": {"rows": [{"sample/id": {"state~code": "failed"}}]}}
    )

    report = run_conformance(trace, target)

    assert len(report.mismatches) == 1
    assert report.mismatches[0].code == "observation_value_mismatch"
    assert report.mismatches[0].path == "/rows/0/sample~1id/state~0code"
    assert report.mismatches[0].observation_id == "nested"


def test_comparison_is_type_sensitive_for_bool_and_int() -> None:
    trace = _trace(initial=(_observation("typed", {"value": True}),), steps=())
    target = FakeTarget(observations={"typed": {"value": 1}})

    report = run_conformance(trace, target)

    assert [(item.code, item.path) for item in report.mismatches] == [
        ("observation_type_mismatch", "/value")
    ]


class ExplicitDynamicFieldProfile:
    profile_id = "drop_generated_response_id_v1"

    def normalize_response(
        self,
        *,
        step: ReferenceStep,
        response: ObservedResponse,
    ) -> ObservedResponse:
        body = response.to_dict()["body"]
        assert isinstance(body, dict)
        return ObservedResponse(
            status_code=response.status_code,
            body={"result": body["result"]},
            headers=response.headers,
        )

    def normalize_observation(
        self,
        *,
        request: ObservationRequest,
        value: JsonValue,
    ) -> JsonValue:
        return value


def test_dynamic_fields_require_an_explicit_profile() -> None:
    trace = _trace(
        steps=(
            _step(
                "one",
                expected_body={"generated_id": "reference-123", "result": "ok"},
            ),
        )
    )
    target = FakeTarget(
        responses={
            "create:one": ObservedResponse(
                status_code=201,
                body={"generated_id": "target-987", "result": "ok"},
                headers={"content-type": "application/json"},
            )
        }
    )

    exact_report = run_conformance(trace, target)
    normalized_report = run_conformance(
        trace,
        target,
        profile=ExplicitDynamicFieldProfile(),
    )

    assert exact_report.passed is False
    assert exact_report.mismatches[0].path == "/body/generated_id"
    assert normalized_report.passed is True
    assert normalized_report.profile_id == "drop_generated_response_id_v1"


def test_duplicate_step_and_observation_ids_are_rejected() -> None:
    with pytest.raises(ReferenceContractError, match="duplicate step ids"):
        _trace(steps=(_step("one"), _step("one")))

    with pytest.raises(ReferenceContractError, match="duplicate observation ids"):
        _trace(
            initial=(_observation("same", {"value": 0}),),
            steps=(
                _step(
                    "one",
                    observations=(_observation("same", {"value": 1}),),
                ),
            ),
        )


@pytest.mark.parametrize(
    "header",
    [
        "Authorization",
        "Cookie",
        "X-Api-Key",
        "Vendor-Api-Key",
        "X_Api_Key",
        "X-Auth-Token",
        "Vendor-Secret-Key",
    ],
)
def test_sensitive_request_headers_are_rejected(header: str) -> None:
    with pytest.raises(ReferenceContractError, match="sensitive header"):
        ReferenceCall(
            method="GET",
            path="/records",
            headers={header: "secret"},
            operation_id="list:records",
        )


def test_invalid_contract_values_and_unsupported_schema_are_rejected() -> None:
    with pytest.raises(ReferenceContractError, match="unsupported"):
        ReferenceCall(method="TRACE", path="/", operation_id="trace")
    with pytest.raises(ReferenceContractError, match="absolute path"):
        ReferenceCall(method="GET", path="records", operation_id="list")
    with pytest.raises(ReferenceContractError, match="line break"):
        ReferenceCall(
            method="GET",
            path="/records",
            operation_id="list",
            headers={"x-request-id": "safe\r\nunsafe"},
        )
    with pytest.raises(ReferenceContractError, match="between 100 and 599"):
        ObservedResponse(status_code=700)
    with pytest.raises(ReferenceContractError, match="non-JSON"):
        ObservationRequest(observation_id="bad", query={"value": object()})

    raw = _trace().to_dict()
    raw["schema_id"] = "future_trace_v2"
    with pytest.raises(ReferenceContractError, match="unsupported trace schema"):
        ReferenceTrace.from_dict(raw)


def test_target_execution_error_is_stable_and_stops_dependent_steps() -> None:
    class FailingTarget(FakeTarget):
        def execute(self, call: ReferenceCall) -> ObservedResponse:
            self.events.append(f"execute:{call.operation_id}")
            raise RuntimeError("provider-specific and potentially sensitive message")

    target = FailingTarget()

    report = run_conformance(_trace(steps=(_step("one"), _step("two"))), target)

    assert report.to_dict()["mismatches"] == [
        {
            "code": "target_execution_error",
            "path": "",
            "expected": None,
            "actual": {"error_type": "RuntimeError"},
            "step_id": "one",
            "observation_id": None,
        }
    ]
    assert target.events == ["reset:17", "execute:create:one"]


def test_contracts_are_deeply_immutable() -> None:
    call = ReferenceCall(
        method="POST",
        path="/records",
        body={"nested": [{"value": 1}]},
        operation_id="create:record",
    )

    with pytest.raises(FrozenInstanceError):
        call.path = "/other"  # type: ignore[misc]
    with pytest.raises(TypeError):
        call.body["nested"] = ()  # type: ignore[index]
    assert call.to_dict()["body"] == {"nested": [{"value": 1}]}


def test_report_rejects_inconsistent_passed_flag() -> None:
    report = run_conformance(_trace(), FakeTarget())
    raw: dict[str, Any] = report.to_dict()
    raw["passed"] = False

    with pytest.raises(ReferenceContractError, match="inconsistent"):
        ConformanceReport.from_dict(raw)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("trace_digest", "sha256:not-a-digest", "trace_digest"),
        ("target_id", "invalid target id", "stable identifier"),
        ("profile_id", "invalid profile id", "stable identifier"),
    ],
)
def test_report_rejects_invalid_evidence_identity(
    field: str,
    value: str,
    message: str,
) -> None:
    report = run_conformance(_trace(), FakeTarget())
    raw = report.to_dict()
    raw[field] = value

    with pytest.raises(ReferenceContractError, match=message):
        ConformanceReport.from_dict(raw)
