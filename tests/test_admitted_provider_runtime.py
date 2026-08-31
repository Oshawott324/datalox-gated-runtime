from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    PROVIDER_ID,
    build_stateful_provider_bundle,
    write_replay_provider_config,
)
from test_provider_admission import _claims
from world_v1_helpers import create_valid_bundle

from datalox_gated_runtime.interception.gateway import InterceptionGateway
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ANONYMOUS_PRINCIPAL_CONTEXT_ID,
    FIXED_PRINCIPAL_CONTEXT_ID,
    ProviderRuntime,
    ProviderRuntimeError,
    admit_provider_runtime,
    build_provider_runtime_from_gate_config,
    build_provider_runtime_from_world,
)


def _admitted(tmp_path: Path) -> tuple[Path, Path]:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    admission = tmp_path / "provider-admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=_claims(tmp_path),
        output_path=admission,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    return bundle, admission


def _rewrite_admission(path: Path, mutate: object) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert callable(mutate)
    mutate(payload)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _set_counter(runtime: ProviderRuntime, value: object) -> None:
    assert runtime.backend is not None
    with runtime.backend.session.transaction(operation_id="test.state_corruption"):
        runtime.backend.session.set_state("counter", value)


def _credential_bundle(tmp_path: Path) -> Path:
    operator_token = "Bearer provider-test-operator"
    viewer_token = "Bearer provider-test-viewer"
    identity = tmp_path / "identity.json"
    identity.write_text(
        json.dumps(
            {
                "schema_version": "datalox_provider_identity_v1",
                "mode": "credential_map",
                "principals": [
                    {
                        "principal_context_id": "provider_operator",
                        "actor_id": "operator-001",
                        "actor_role": "operator",
                        "credentials": [
                            {
                                "location": "header",
                                "name": "authorization",
                                "value_sha256": "sha256:"
                                + hashlib.sha256(operator_token.encode()).hexdigest(),
                            }
                        ],
                    },
                    {
                        "principal_context_id": "provider_viewer",
                        "actor_id": "viewer-001",
                        "actor_role": "viewer",
                        "credentials": [
                            {
                                "location": "header",
                                "name": "authorization",
                                "value_sha256": "sha256:"
                                + hashlib.sha256(viewer_token.encode()).hexdigest(),
                            }
                        ],
                    },
                ],
                "missing_identity": {
                    "status_code": 401,
                    "body": {"error": "missing"},
                    "headers": {"content-type": "application/json"},
                },
                "invalid_identity": {
                    "status_code": 403,
                    "body": {"error": "invalid"},
                    "headers": {"content-type": "application/json"},
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    bundle = tmp_path / "credential-provider"
    build_provider_runtime_from_world(
        source_world_dir=create_valid_bundle(tmp_path / "source-world"),
        output_dir=bundle,
        provider_id=PROVIDER_ID,
        authorities=(PROVIDER_AUTHORITY,),
        episode_id="episode-1",
        identity_policy_path=identity,
    )
    return bundle


@pytest.mark.parametrize("field", ["provider_id", "bundle_version", "provider_runtime_sha256"])
def test_admitted_runtime_rejects_bundle_binding_mismatch(tmp_path: Path, field: str) -> None:
    bundle, admission = _admitted(tmp_path)

    def mutate(payload: dict[str, object]) -> None:
        payload[field] = "different" if field != "provider_runtime_sha256" else "sha256:" + "0" * 64

    _rewrite_admission(admission, mutate)

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(
            bundle_dir=bundle,
            admission_path=admission,
            run_dir=tmp_path / "run",
        )

    assert caught.value.code == "provider_runtime_admission_mismatch"


def test_admitted_runtime_rejects_ambiguous_native_surfaces(tmp_path: Path) -> None:
    bundle, admission = _admitted(tmp_path)

    def mutate(payload: dict[str, object]) -> None:
        operations = payload["operations"]
        assert isinstance(operations, list)
        overlapping = deepcopy(operations[0])
        overlapping["operation_id"] = "counter.overlapping_read"
        overlapping["native_surface"]["path_template"] = "/{resource}"
        operations.append(overlapping)

    _rewrite_admission(admission, mutate)

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(
            bundle_dir=bundle,
            admission_path=admission,
            run_dir=tmp_path / "run",
        )

    assert caught.value.code == "provider_admission_surface_ambiguous"


def test_admitted_runtime_routes_exactly_one_operation_and_denies_unmatched(
    tmp_path: Path,
) -> None:
    bundle, admission = _admitted(tmp_path)
    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=tmp_path / "run",
    )
    try:
        unmatched = runtime.handle(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/outside")
        )
        assert unmatched.status_code == 403
        assert unmatched.decision.reason_code == "provider_operation_not_admitted"
        assert not any(
            event["event_type"] == "provider_operation_started"
            for event in runtime.export()["provider_state"]["verifier_events"]
        )

        matched = runtime.handle(
            CallRequest(
                method="GET",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
                operation_id="agent.supplied_value",
            )
        )
        assert matched.status_code == 200
        exported = runtime.export()
        started = [
            event
            for event in exported["provider_state"]["verifier_events"]
            if event["event_type"] == "provider_operation_started"
        ]
        assert started[-1]["operation_id"] == "counter.read"
        assurance = exported["provider_assurance"]
        assert set(assurance) == {
            "schema_version",
            "provider_admission_sha256",
            "operation_claims_sha256",
            "admitted_operation_ids",
            "status",
            "failure",
        }
        assert assurance["admitted_operation_ids"] == ["counter.read", "counter.increment"]
        assert assurance["failure"] is None
        assert assurance["status"] == "valid"
        assert not {"task", "verifier", "reward"} & set(assurance)
    finally:
        runtime.close()


def test_admitted_runtime_denies_surface_to_backend_mapping_mismatch(tmp_path: Path) -> None:
    bundle, admission = _admitted(tmp_path)

    def mutate(payload: dict[str, object]) -> None:
        operations = payload["operations"]
        assert isinstance(operations, list)
        operations[0]["operation_id"] = "counter.forged_read"

    _rewrite_admission(admission, mutate)
    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=tmp_path / "run",
    )
    try:
        denied = runtime.handle(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/counter")
        )
        assert denied.status_code == 500
        assert denied.decision.reason_code == "provider_operation_binding_mismatch"
        assert not any(
            event["event_type"] == "provider_operation_started"
            for event in runtime.export()["provider_state"]["verifier_events"]
        )
    finally:
        runtime.close()


def test_invariant_failure_hides_response_latches_and_trusted_reset_recovers(
    tmp_path: Path,
) -> None:
    bundle, admission = _admitted(tmp_path)

    def mutate(payload: dict[str, object]) -> None:
        invariants = payload["provider_invariants"]
        assert isinstance(invariants, list)
        invariants[0] = {
            "predicate_id": "counter_starts_at_one",
            "source": "provider_state",
            "operator": "equals",
            "pointer": "/state/counter",
            "expected": 1,
            "passed": True,
        }

    _rewrite_admission(admission, mutate)
    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=tmp_path / "run",
    )
    try:
        failed = runtime.handle(
            CallRequest(
                method="POST",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
                body={"amount": 2},
            )
        )
        assert failed.status_code == 500
        assert failed.decision.reason_code == "provider_invariant_failed"
        assert failed.body == {
            "error": {
                "code": "provider_invariant_failed",
                "message": (
                    "The admitted provider runtime is invalid until a trusted reset succeeds."
                ),
                "details": {
                    "code": "provider_invariant_failed",
                    "predicate_id": "counter_starts_at_one",
                },
            }
        }
        assert "counter" not in failed.body

        latched = runtime.handle(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/counter")
        )
        assert latched.status_code == 500
        assert runtime.export()["provider_assurance"]["status"] == "invalid"
        started = [
            event
            for event in runtime.export()["provider_state"]["verifier_events"]
            if event["event_type"] == "provider_operation_started"
        ]
        assert len(started) == 1

        reset = runtime.reset()
        assert reset["provider_assurance"]["status"] == "valid"
        recovered = runtime.handle(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/counter")
        )
        assert recovered.status_code == 200
        assert recovered.body["counter"] == 1
    finally:
        runtime.close()


def test_initial_reset_and_export_each_enforce_provider_invariants(tmp_path: Path) -> None:
    bundle, admission = _admitted(tmp_path)

    def initial_failure(payload: dict[str, object]) -> None:
        invariant = payload["provider_invariants"][0]
        invariant.update(
            {
                "operator": "equals",
                "expected": 2,
            }
        )
        invariant.pop("expected_type")

    invalid_admission = tmp_path / "invalid-initial-admission.json"
    invalid_admission.write_bytes(admission.read_bytes())
    _rewrite_admission(invalid_admission, initial_failure)
    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(
            bundle_dir=bundle,
            admission_path=invalid_admission,
            run_dir=tmp_path / "invalid-run",
        )
    assert caught.value.code == "provider_runtime_invariant_failed"

    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=tmp_path / "run",
    )
    assert runtime.backend is not None
    try:
        _set_counter(runtime, "invalid")
        assert runtime.export()["provider_assurance"]["status"] == "invalid"

        original_reset = runtime.backend.reset

        def invalid_reset() -> None:
            original_reset()
            _set_counter(runtime, "invalid")

        runtime.backend.reset = invalid_reset  # type: ignore[method-assign]
        with pytest.raises(ProviderRuntimeError) as reset_failure:
            runtime.reset()
        assert reset_failure.value.code == "provider_runtime_invariant_failed"

        runtime.backend.reset = original_reset  # type: ignore[method-assign]
        assert runtime.reset()["provider_assurance"]["status"] == "valid"
    finally:
        runtime.close()


def test_gateway_accepts_explicit_bundle_admission_binding(tmp_path: Path) -> None:
    bundle, admission = _admitted(tmp_path)
    gateway = InterceptionGateway.from_admitted_bundles(
        bundle_admissions=((bundle, admission),),
        run_root=tmp_path / "gateway-runs",
        control_token="controller-secret",
    )
    try:
        with TestClient(gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as agent:
            assert agent.get("/counter").status_code == 200
            denied = agent.get("/outside")
            assert denied.status_code == 403
            assert denied.json()["error"]["code"] == "provider_operation_not_admitted"
        with TestClient(gateway.control_app) as controller:
            exported = controller.get(
                f"/v1/providers/{PROVIDER_ID}/export",
                headers={"x-datalox-control-token": "controller-secret"},
            ).json()
            assert exported["provider_assurance"]["status"] == "valid"
            assert exported["provider_assurance"]["provider_admission_sha256"].startswith("sha256:")
    finally:
        gateway.close()


def test_controller_principal_context_selects_only_provider_declared_actor(
    tmp_path: Path,
) -> None:
    runtime = ProviderRuntime(
        bundle_dir=_credential_bundle(tmp_path),
        run_dir=tmp_path / "run",
    )
    try:
        allowed = runtime.handle_as_principal(
            CallRequest(
                method="POST",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
                body={"amount": 2},
                headers={
                    "authorization": "must-be-redacted-not-resolved",
                    "x-datalox-actor-role": "viewer",
                },
            ),
            principal_context_id="provider_operator",
        )
        assert allowed.status_code == 200
        assert allowed.body["actor_role"] == "operator"
        assert allowed.body["counter"] == 3

        denied_role = runtime.handle_as_principal(
            CallRequest(
                method="POST",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
                body={"amount": 7},
            ),
            principal_context_id="provider_viewer",
        )
        assert denied_role.status_code == 403
        assert denied_role.decision.reason_code == "world_tool_hidden"

        unknown = runtime.handle_as_principal(
            CallRequest(
                method="POST",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
                body={"amount": 11},
            ),
            principal_context_id="operator",
        )
        assert unknown.status_code == 403
        assert unknown.decision.reason_code == "provider_principal_context_unknown"
        assert runtime.export()["provider_state"]["state"]["counter"] == 3
        for event in runtime.export()["call_evidence"]["events"]:
            assert not {
                "authorization",
                "x-datalox-actor-role",
            } & {name.lower() for name in event["request"]["headers"]}

        with pytest.raises(TypeError):
            runtime.handle_as_principal(  # type: ignore[call-arg]
                CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/counter"),
                principal_context_id="provider_operator",
                actor_role="operator",
            )
    finally:
        runtime.close()


def test_fixed_and_anonymous_controller_contexts_are_explicit(tmp_path: Path) -> None:
    bundle, admission = _admitted(tmp_path)
    fixed = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=tmp_path / "fixed-run",
    )
    try:
        response = fixed.handle_as_principal(
            CallRequest(
                method="GET",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
                operation_id="caller.supplied",
            ),
            principal_context_id=FIXED_PRINCIPAL_CONTEXT_ID,
        )
        assert response.status_code == 200
        started = [
            event
            for event in fixed.export()["provider_state"]["verifier_events"]
            if event["event_type"] == "provider_operation_started"
        ]
        assert started[-1]["operation_id"] == "counter.read"
        unknown = fixed.handle_as_principal(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/counter"),
            principal_context_id=ANONYMOUS_PRINCIPAL_CONTEXT_ID,
        )
        assert unknown.status_code == 403
        assert unknown.decision.reason_code == "provider_principal_context_unknown"
    finally:
        fixed.close()

    gate_bundle = tmp_path / "gate-provider"
    build_provider_runtime_from_gate_config(
        source_gate_config=write_replay_provider_config(tmp_path),
        output_dir=gate_bundle,
        provider_id=PROVIDER_ID,
        authorities=(PROVIDER_AUTHORITY,),
    )
    anonymous = ProviderRuntime(bundle_dir=gate_bundle, run_dir=tmp_path / "anonymous-run")
    try:
        allowed = anonymous.handle_as_principal(
            CallRequest(
                method="GET",
                authority=PROVIDER_AUTHORITY,
                path="/v1/records",
            ),
            principal_context_id=ANONYMOUS_PRINCIPAL_CONTEXT_ID,
        )
        assert allowed.status_code == 200
        unknown = anonymous.handle_as_principal(
            CallRequest(
                method="GET",
                authority=PROVIDER_AUTHORITY,
                path="/v1/records",
            ),
            principal_context_id=FIXED_PRINCIPAL_CONTEXT_ID,
        )
        assert unknown.status_code == 403
        assert unknown.decision.reason_code == "provider_principal_context_unknown"
    finally:
        anonymous.close()


def test_controller_principal_path_enforces_admission_and_invariant_latch(
    tmp_path: Path,
) -> None:
    bundle, admission = _admitted(tmp_path)

    def mutate(payload: dict[str, object]) -> None:
        invariants = payload["provider_invariants"]
        assert isinstance(invariants, list)
        invariants[0] = {
            "predicate_id": "counter_starts_at_one",
            "source": "provider_state",
            "operator": "equals",
            "pointer": "/state/counter",
            "expected": 1,
            "passed": True,
        }

    _rewrite_admission(admission, mutate)
    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=tmp_path / "run",
    )
    try:
        unmatched = runtime.handle_as_principal(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/outside"),
            principal_context_id=FIXED_PRINCIPAL_CONTEXT_ID,
        )
        assert unmatched.decision.reason_code == "provider_operation_not_admitted"

        failed = runtime.handle_as_principal(
            CallRequest(
                method="POST",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
                body={"amount": 2},
            ),
            principal_context_id=FIXED_PRINCIPAL_CONTEXT_ID,
        )
        assert failed.status_code == 500
        assert failed.decision.reason_code == "provider_invariant_failed"
        assert "counter" not in failed.body

        latched = runtime.handle_as_principal(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/counter"),
            principal_context_id=FIXED_PRINCIPAL_CONTEXT_ID,
        )
        assert latched.status_code == 500
        runtime.reset()
        recovered = runtime.handle_as_principal(
            CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/counter"),
            principal_context_id=FIXED_PRINCIPAL_CONTEXT_ID,
        )
        assert recovered.status_code == 200
    finally:
        runtime.close()
