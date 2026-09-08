from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient
from world_v1_helpers import create_valid_bundle

from datalox_gated_runtime.interception.gateway import InterceptionGateway
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    admit_provider_runtime,
    build_provider_runtime_from_world,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.world_v1.bundle import compute_bundle_hashes

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_ID = "temporal_provider"
AUTHORITY = "api.temporal.example"

TEMPORAL_IMPLEMENTATION = """
from datetime import datetime, timedelta

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import WorldImplementationV1


class TemporalWorld(WorldImplementationV1):
    def initialize_episode(self, *, session, episode):
        session.reset(
            episode_id=episode["id"],
            initial_state=episode["initial_state"],
            initial_time=episode["initial_time"],
        )

    def tool_for_request(self, request):
        if request.path == "/jobs" and request.normalized_method() == "POST":
            return "job.submit"
        if request.path.startswith("/jobs/") and request.normalized_method() == "GET":
            return "job.status"
        return None

    def handle(self, request, *, actor, session):
        tool = self.tool_for_request(request)
        if tool == "job.submit":
            if request.body.get("invalid") is True:
                return WorldResponse(
                    status_code=400,
                    body={"error": "invalid mapping request"},
                    is_mutation=False,
                    world_id="temporal_world",
                    operation_id="job.submit",
                    decision_kind="replay",
                )
            jobs = session.get_state("jobs")
            created = "job-1" not in jobs
            if created:
                jobs["job-1"] = {"status": "RUNNING", "result": None}
                session.set_state("jobs", jobs)
                if session.get_state("unrelated_event_without_completion"):
                    session.schedule_event(
                        event_id="unrelated-1",
                        deliver_at=datetime.fromisoformat(session.current_time()) + timedelta(seconds=10),
                        kind="unrelated.tick",
                        payload={},
                    )
                elif not session.get_state("fake_terminal_without_event"):
                    session.schedule_event(
                        event_id="job-1:complete",
                        deliver_at=datetime.fromisoformat(session.current_time()) + timedelta(seconds=10),
                        kind="job.complete",
                        payload={"job_id": "job-1", "private_result": "must-not-reach-controller"},
                    )
            return WorldResponse(
                status_code=200,
                body={"jobId": "job-1"},
                is_mutation=created,
                world_id="temporal_world",
                operation_id="job.submit",
                decision_kind="shadow_write" if created else "replay",
            )
        if tool == "job.status":
            job_id = request.path.rsplit("/", 1)[-1]
            job = session.get_state("jobs").get(job_id)
            if job is None:
                return WorldResponse(
                    status_code=404,
                    body={"error": "job not found"},
                    is_mutation=False,
                    world_id="temporal_world",
                    operation_id="job.status",
                    decision_kind="replay",
                )
            status = job["status"]
            if (
                session.get_state("fake_terminal_without_event")
                and session.current_time() >= "2030-01-01T00:00:10+00:00"
            ):
                status = "FINISHED"
            return WorldResponse(
                status_code=200,
                body={"jobStatus": status},
                is_mutation=False,
                world_id="temporal_world",
                operation_id="job.status",
                decision_kind="replay",
            )
        return None

    def handle_scheduled_event(self, event, *, session):
        if event.kind == "unrelated.tick":
            return
        if event.kind != "job.complete":
            raise ValueError("unknown scheduled event")
        if session.get_state("raise_during_delivery"):
            raise ValueError("fixture delivery failure")
        if session.get_state("corrupt_during_delivery"):
            session.set_state("jobs", "corrupt")
            return
        jobs = session.get_state("jobs")
        jobs[event.payload["job_id"]] = {"status": "FINISHED", "result": ["P12345"]}
        session.set_state("jobs", jobs)

    def tool_schemas(self, *, actor):
        return {"job.submit": {}, "job.status": {}}

    def request_for_tool(self, tool_name, arguments, *, actor):
        if tool_name == "job.submit":
            return CallRequest(method="POST", path="/jobs", body={})
        return CallRequest(method="GET", path="/jobs/job-1")

    def operation_for_tool(self, tool_name):
        return tool_name

    def verify(self, *, session, episode):
        raise AssertionError("provider runtime must not call a world verifier")

    def task(self, *, episode):
        raise AssertionError("provider runtime must not request a task")


def create_world():
    return TemporalWorld()
"""


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _build_temporal_bundle(
    tmp_path: Path,
    *,
    include_handler: bool = True,
    temporal_capabilities: bool = True,
    fake_terminal_without_event: bool = False,
    unrelated_event_without_completion: bool = False,
    corrupt_during_delivery: bool = False,
    raise_during_delivery: bool = False,
) -> Path:
    source = create_valid_bundle(tmp_path / "source")
    (source / "world/implementation.py").write_text(
        (
            TEMPORAL_IMPLEMENTATION
            if include_handler
            else TEMPORAL_IMPLEMENTATION.replace(
                "def handle_scheduled_event(self, event, *, session):",
                "def fixture_only_event_handler(self, event, *, session):",
            )
        ),
        encoding="utf-8",
    )
    (source / "world/episodes.jsonl").write_text(
        json.dumps(
            {
                "id": "episode-1",
                "initial_state": {
                    "jobs": {},
                    "fake_terminal_without_event": (
                        fake_terminal_without_event or unrelated_event_without_completion
                    ),
                    "unrelated_event_without_completion": unrelated_event_without_completion,
                    "corrupt_during_delivery": corrupt_during_delivery,
                    "raise_during_delivery": raise_during_delivery,
                },
                "initial_time": "2030-01-01T00:00:00+00:00",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_json(
        source / "world/tools.json",
        {
            "tools": [
                {
                    "id": "job.submit",
                    "description": "Submit a job.",
                    "list_roles": ["operator"],
                    "invoke_roles": ["operator"],
                    "input_schema": {"type": "object", "properties": {}},
                    "source_refs": ["source-1"],
                    "operation_family": "jobs",
                },
                {
                    "id": "job.status",
                    "description": "Read job status.",
                    "list_roles": ["operator"],
                    "invoke_roles": ["operator"],
                    "input_schema": {"type": "object", "properties": {}},
                    "source_refs": ["source-1"],
                    "operation_family": "jobs",
                },
            ]
        },
    )
    manifest_path = source / "world/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["required_runtime_capabilities"] = [
        "actors",
        "role_scoped_tools",
        "transactions",
    ]
    if temporal_capabilities:
        manifest["required_runtime_capabilities"].extend(["clock", "scheduled_events"])
    manifest["content_hashes"] = compute_bundle_hashes(source)
    _write_json(manifest_path, manifest)
    bundle = tmp_path / "bundle"
    build_provider_runtime_from_world(
        source_world_dir=source,
        output_dir=bundle,
        provider_id=PROVIDER_ID,
        authorities=(AUTHORITY,),
        episode_id="episode-1",
    )
    return bundle


def _submit(runtime: ProviderRuntime) -> None:
    response = runtime.handle(
        CallRequest(method="POST", path="/jobs", authority=AUTHORITY, body={})
    )
    assert response.status_code == 200


def _claims(tmp_path: Path, bundle: Path) -> Path:
    evidence = tmp_path / "evidence.json"
    _write_json(evidence, {"source": "self-authored temporal conformance fixture"})
    digest = "sha256:" + hashlib.sha256(evidence.read_bytes()).hexdigest()
    request_base = {
        "scheme": "https",
        "authority": AUTHORITY,
        "query": {},
        "headers": {},
    }
    claims = {
        "schema_version": "datalox_provider_operation_claims_v1",
        "provider_id": PROVIDER_ID,
        "bundle_version": "1.0.0",
        "evidence_sources": [
            {
                "evidence_id": "temporal-fixture",
                "artifact_ref": "evidence.json",
                "artifact_sha256": digest,
                "grounding_level": "G2",
                "observed_at": "2026-09-02T00:00:00+00:00",
                "valid_through": "2031-01-01T00:00:00+00:00",
                "distribution_label": "public",
                "rights_basis": "Self-authored conformance fixture.",
            }
        ],
        "operations": [
            {
                "operation_id": "job.submit",
                "native_surface": {
                    "type": "http",
                    "scheme": "https",
                    "authority": AUTHORITY,
                    "method": "POST",
                    "path_template": "/jobs",
                },
                "mutability": "write",
                "behavior_program": "job-submit",
                "state_effects": ["job-created"],
                "grounding": {"level": "G2", "evidence_refs": ["temporal-fixture"]},
                "rights": {
                    "distribution_label": "public",
                    "behavior_distribution_basis": "Self-authored fixture.",
                },
                "covered_behaviors": ["success", "failure", "duplicate", "readback"],
            },
            {
                "operation_id": "job.status",
                "native_surface": {
                    "type": "http",
                    "scheme": "https",
                    "authority": AUTHORITY,
                    "method": "GET",
                    "path_template": "/jobs/{job_id}",
                },
                "mutability": "read",
                "behavior_program": "job-status",
                "state_effects": [],
                "grounding": {"level": "G2", "evidence_refs": ["temporal-fixture"]},
                "rights": {
                    "distribution_label": "public",
                    "behavior_distribution_basis": "Self-authored fixture.",
                },
                "covered_behaviors": ["success", "failure", "async"],
            },
        ],
        "provider_invariants": [
            {
                "predicate_id": "jobs-exist",
                "source": "provider_state",
                "operator": "type",
                "pointer": "/state/jobs",
                "expected_type": "object",
            },
            {
                "predicate_id": "fake-terminal-flag-is-boolean",
                "source": "provider_state",
                "operator": "type",
                "pointer": "/state/fake_terminal_without_event",
                "expected_type": "boolean",
            },
            {
                "predicate_id": "unrelated-event-flag-is-boolean",
                "source": "provider_state",
                "operator": "type",
                "pointer": "/state/unrelated_event_without_completion",
                "expected_type": "boolean",
            },
            {
                "predicate_id": "corrupt-delivery-flag-is-boolean",
                "source": "provider_state",
                "operator": "type",
                "pointer": "/state/corrupt_during_delivery",
                "expected_type": "boolean",
            },
            {
                "predicate_id": "raise-delivery-flag-is-boolean",
                "source": "provider_state",
                "operator": "type",
                "pointer": "/state/raise_during_delivery",
                "expected_type": "boolean",
            },
        ],
        "receipt_predicates": [
            {
                "predicate_id": "job-id",
                "source": "response_body",
                "operator": "equals",
                "pointer": "/jobId",
                "expected": "job-1",
            },
            {
                "predicate_id": "pending",
                "source": "response_body",
                "operator": "equals",
                "pointer": "/jobStatus",
                "expected": "RUNNING",
            },
            {
                "predicate_id": "invalid",
                "source": "response_body",
                "operator": "equals",
                "pointer": "/error",
                "expected": "invalid mapping request",
            },
            {
                "predicate_id": "missing",
                "source": "response_body",
                "operator": "equals",
                "pointer": "/error",
                "expected": "job not found",
            },
            {
                "predicate_id": "terminal",
                "source": "response_body",
                "operator": "equals",
                "pointer": "/jobStatus",
                "expected": "FINISHED",
            },
        ],
        "reset_profiles": [{"profile_id": "default", "kind": "compiled_seed"}],
        "behavior_probes": [
            {
                "probe_id": "job-lifecycle",
                "reset_profile": "default",
                "steps": [
                    {
                        "step_id": "submit",
                        "operation_id": "job.submit",
                        "request": {
                            **request_base,
                            "method": "POST",
                            "path": "/jobs",
                            "body": {},
                        },
                        "expected_status_code": 200,
                        "expected_decision_kind": "shadow_write",
                        "expected_state_change": True,
                        "covers": [{"operation_id": "job.submit", "behavior": "success"}],
                        "receipt_predicate_refs": ["job-id"],
                    },
                    {
                        "step_id": "duplicate",
                        "operation_id": "job.submit",
                        "request": {
                            **request_base,
                            "method": "POST",
                            "path": "/jobs",
                            "body": {},
                        },
                        "expected_status_code": 200,
                        "expected_decision_kind": "replay",
                        "expected_state_change": False,
                        "covers": [{"operation_id": "job.submit", "behavior": "duplicate"}],
                        "receipt_predicate_refs": ["job-id"],
                    },
                    {
                        "step_id": "invalid",
                        "operation_id": "job.submit",
                        "request": {
                            **request_base,
                            "method": "POST",
                            "path": "/jobs",
                            "body": {"invalid": True},
                        },
                        "expected_status_code": 400,
                        "expected_decision_kind": "replay",
                        "expected_state_change": False,
                        "covers": [{"operation_id": "job.submit", "behavior": "failure"}],
                        "receipt_predicate_refs": ["invalid"],
                    },
                    {
                        "step_id": "missing",
                        "operation_id": "job.status",
                        "request": {
                            **request_base,
                            "method": "GET",
                            "path": "/jobs/missing",
                            "body": None,
                        },
                        "expected_status_code": 404,
                        "expected_decision_kind": "replay",
                        "expected_state_change": False,
                        "covers": [{"operation_id": "job.status", "behavior": "failure"}],
                        "receipt_predicate_refs": ["missing"],
                    },
                    {
                        "step_id": "pending",
                        "operation_id": "job.status",
                        "request": {
                            **request_base,
                            "method": "GET",
                            "path": "/jobs/job-1",
                            "body": None,
                        },
                        "expected_status_code": 200,
                        "expected_decision_kind": "replay",
                        "expected_state_change": False,
                        "async_observation": "pending",
                        "async_transition_id": "job-1-completion",
                        "covers": [
                            {"operation_id": "job.status", "behavior": "success"},
                            {"operation_id": "job.status", "behavior": "async"},
                            {"operation_id": "job.submit", "behavior": "readback"},
                        ],
                        "receipt_predicate_refs": ["pending"],
                    },
                    {
                        "step_id": "terminal",
                        "operation_id": "job.status",
                        "controller_actions_before": [
                            {
                                "action": "advance_provider_time",
                                "target": "2030-01-01T00:00:10+00:00",
                                "async_transition_id": "job-1-completion",
                                "expected_event_id": "job-1:complete",
                                "expected_event_kind": "job.complete",
                            }
                        ],
                        "request": {
                            **request_base,
                            "method": "GET",
                            "path": "/jobs/job-1",
                            "body": None,
                        },
                        "expected_status_code": 200,
                        "expected_decision_kind": "replay",
                        "expected_state_change": False,
                        "async_observation": "terminal",
                        "async_transition_id": "job-1-completion",
                        "covers": [{"operation_id": "job.status", "behavior": "async"}],
                        "receipt_predicate_refs": ["terminal"],
                    },
                ],
            }
        ],
    }
    path = tmp_path / "claims.json"
    _write_json(path, claims)
    schema = json.loads(
        (ROOT / "schemas/provider-operation-claims-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(claims)
    return path


def test_provider_local_time_is_explicit_atomic_persistent_and_resettable(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir)
    assert runtime.provider_time()["current_time"] == "2030-01-01T00:00:00+00:00"
    _submit(runtime)

    before_poll = runtime.provider_time()
    pending = runtime.handle(CallRequest(method="GET", path="/jobs/job-1", authority=AUTHORITY))
    assert pending.body == {"jobStatus": "RUNNING"}
    assert runtime.provider_time() == before_poll

    before_same_target = runtime.export()["provider_state"]
    same = runtime.advance_provider_time("2030-01-01T00:00:00Z")
    assert same["delivered_events"] == []
    assert runtime.export()["provider_state"] == before_same_target

    with pytest.raises(ProviderRuntimeError, match="may not move backwards") as reverse:
        runtime.advance_provider_time("2029-12-31T23:59:59+00:00")
    assert reverse.value.code == "world_clock_reverse_forbidden"

    advanced = runtime.advance_provider_time("2030-01-01T00:00:10Z")
    assert advanced == {
        "schema_version": "datalox_provider_time_advance_v1",
        "provider_id": PROVIDER_ID,
        "previous_time": "2030-01-01T00:00:00+00:00",
        "current_time": "2030-01-01T00:00:10+00:00",
        "delivered_events": [
            {
                "event_id": "job-1:complete",
                "deliver_at": "2030-01-01T00:00:10+00:00",
                "kind": "job.complete",
            }
        ],
    }
    assert "private_result" not in json.dumps(advanced)
    assert runtime.handle(
        CallRequest(method="GET", path="/jobs/job-1", authority=AUTHORITY)
    ).body == {"jobStatus": "FINISHED"}
    delivered_state = runtime.export()["provider_state"]
    repeated = runtime.advance_provider_time("2030-01-01T00:00:10+00:00")
    assert repeated["delivered_events"] == []
    assert runtime.export()["provider_state"] == delivered_state
    runtime.close()

    resumed = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir, lifecycle="resume")
    assert resumed.provider_time()["current_time"] == "2030-01-01T00:00:10+00:00"
    assert resumed.handle(
        CallRequest(method="GET", path="/jobs/job-1", authority=AUTHORITY)
    ).body == {"jobStatus": "FINISHED"}
    reset = resumed.reset()
    assert reset["provider_state"]["simulation_time"] == "2030-01-01T00:00:00+00:00"
    assert reset["provider_state"]["state"]["jobs"] == {}
    assert reset["provider_state"]["scheduled_events"] == []
    resumed.close()


def test_provider_time_requires_both_capabilities_and_is_isolated(tmp_path: Path) -> None:
    from provider_runtime_helpers import build_stateful_provider_bundle

    unsupported_bundle = build_stateful_provider_bundle(tmp_path / "unsupported")
    unsupported = ProviderRuntime(
        bundle_dir=unsupported_bundle,
        run_dir=tmp_path / "unsupported-run",
    )
    with pytest.raises(ProviderRuntimeError) as error:
        unsupported.provider_time()
    assert error.value.code == "provider_runtime_time_unsupported"
    unsupported.close()

    bundle = _build_temporal_bundle(tmp_path / "temporal")
    first = ProviderRuntime(bundle_dir=bundle, run_dir=tmp_path / "first")
    second = ProviderRuntime(bundle_dir=bundle, run_dir=tmp_path / "second")
    _submit(first)
    first.advance_provider_time("2030-01-01T00:00:10+00:00")
    assert first.provider_time()["current_time"] == "2030-01-01T00:00:10+00:00"
    assert second.provider_time()["current_time"] == "2030-01-01T00:00:00+00:00"
    assert second.export()["provider_state"]["state"]["jobs"] == {}
    first.close()
    second.close()


def test_provider_time_assurance_precondition_prevents_any_temporal_mutation(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    admission_path = tmp_path / "admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=_claims(tmp_path, bundle),
        output_path=admission_path,
        admitted_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission_path,
        run_dir=tmp_path / "run",
    )
    try:
        _submit(runtime)
        assert runtime.backend is not None
        with runtime.backend.session.transaction(operation_id="test.corrupt_assurance"):
            runtime.backend.session.set_state("fake_terminal_without_event", "corrupt")
        before = deepcopy(runtime.export()["provider_state"])
        with pytest.raises(ProviderRuntimeError) as caught:
            runtime.advance_provider_time("2030-01-01T00:00:10+00:00")
        assert caught.value.code == "provider_runtime_invariant_failed"
        assert runtime.export()["provider_state"] == before
    finally:
        runtime.close()


def test_provider_time_controller_is_authenticated_and_absent_from_data_plane(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    gateway = InterceptionGateway.from_bundles(
        bundle_dirs=(bundle,),
        run_root=tmp_path / "runs",
        control_token="controller-secret",
    )
    headers = {"x-datalox-control-token": "controller-secret"}
    try:
        with TestClient(gateway.control_app) as controller:
            assert controller.get(f"/v1/providers/{PROVIDER_ID}/time").status_code == 401
            assert (
                controller.post(
                    f"/v1/providers/{PROVIDER_ID}/time/advance",
                    json={"target": "2030-01-01T00:00:10Z"},
                ).status_code
                == 401
            )
            inspected = controller.get(
                f"/v1/providers/{PROVIDER_ID}/time",
                headers=headers,
            )
            assert inspected.json()["current_time"] == "2030-01-01T00:00:00+00:00"
            invalid = controller.post(
                f"/v1/providers/{PROVIDER_ID}/time/advance",
                headers=headers,
                json={"target": "2030-01-01T00:00:10Z", "extra": True},
            )
            assert invalid.status_code == 400
            reverse = controller.post(
                f"/v1/providers/{PROVIDER_ID}/time/advance",
                headers=headers,
                json={"target": "2029-01-01T00:00:00Z"},
            )
            assert reverse.status_code == 409
            assert reverse.json()["detail"]["code"] == "world_clock_reverse_forbidden"

        with TestClient(gateway.data_app, base_url=f"https://{AUTHORITY}") as agent:
            probe = agent.get(f"/v1/providers/{PROVIDER_ID}/time")
            assert probe.status_code == 404

        with TestClient(gateway.control_app) as controller:
            after = controller.get(
                f"/v1/providers/{PROVIDER_ID}/time",
                headers=headers,
            )
            assert after.json()["current_time"] == "2030-01-01T00:00:00+00:00"
    finally:
        gateway.close()


def test_provider_time_controller_rejects_invalid_framing_and_unsupported_bundle(
    tmp_path: Path,
) -> None:
    from provider_runtime_helpers import build_stateful_provider_bundle

    bundle = build_stateful_provider_bundle(tmp_path)
    gateway = InterceptionGateway.from_bundles(
        bundle_dirs=(bundle,),
        run_root=tmp_path / "runs",
        control_token="controller-secret",
    )
    headers = {"x-datalox-control-token": "controller-secret"}
    try:
        with TestClient(gateway.control_app) as controller:
            unsupported_get = controller.get(
                "/v1/providers/example_provider/time",
                headers=headers,
            )
            assert unsupported_get.status_code == 422
            assert unsupported_get.json()["detail"]["code"] == ("provider_runtime_time_unsupported")
            missing_content_type = controller.post(
                "/v1/providers/example_provider/time/advance",
                headers=headers,
                content=b"{}",
            )
            assert missing_content_type.status_code == 415
            invalid_json = controller.post(
                "/v1/providers/example_provider/time/advance",
                headers={**headers, "content-type": "application/json"},
                content=b"{",
            )
            assert invalid_json.status_code == 400
            oversized = controller.post(
                "/v1/providers/example_provider/time/advance",
                headers={**headers, "content-type": "application/json"},
                content=b"{" + b'"target":"' + b"x" * 5000 + b'"}',
            )
            assert oversized.status_code == 413
            invalid_fields = controller.post(
                "/v1/providers/example_provider/time/advance",
                headers=headers,
                json={},
            )
            assert invalid_fields.status_code == 400
            unsupported_advance = controller.post(
                "/v1/providers/example_provider/time/advance",
                headers=headers,
                json={"target": "2030-01-01T00:00:10Z"},
            )
            assert unsupported_advance.status_code == 422
            assert unsupported_advance.json()["detail"]["code"] == (
                "provider_runtime_time_unsupported"
            )
    finally:
        gateway.close()


def test_temporal_admission_proves_ordered_lifecycle_twice_across_reset(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    claims = _claims(tmp_path, bundle)
    result = admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims,
        output_path=tmp_path / "provider-admission.json",
        admitted_at=None,
    )
    probe = result.payload["behavior_probes"][0]
    assert probe["step_count"] == 6
    assert probe["first_run_sha256"] == probe["second_run_sha256"]


def test_temporal_admission_rejects_cross_operation_phase_pairing(tmp_path: Path) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    claims_path = _claims(tmp_path, bundle)
    claims = json.loads(claims_path.read_text(encoding="utf-8"))
    claims["operations"].append(
        {
            **deepcopy(claims["operations"][1]),
            "operation_id": "job.results",
            "native_surface": {
                **deepcopy(claims["operations"][1]["native_surface"]),
                "path_template": "/jobs/{job_id}/results",
            },
            "behavior_program": "job-results",
            "covered_behaviors": ["success", "failure", "async"],
        }
    )
    terminal = claims["behavior_probes"][0]["steps"][5]
    terminal["operation_id"] = "job.results"
    terminal["request"]["path"] = "/jobs/job-1/results"
    terminal["covers"] = [
        {"operation_id": "job.results", "behavior": "success"},
        {"operation_id": "job.results", "behavior": "async"},
    ]
    _write_json(claims_path, claims)
    with pytest.raises(ProviderRuntimeError) as error:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims_path,
            output_path=tmp_path / "rejected.json",
        )
    assert error.value.code == "provider_admission_async_probe_invalid"


def test_temporal_admission_rejects_ambiguous_simultaneous_transitions(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    claims_path = _claims(tmp_path, bundle)
    claims = json.loads(claims_path.read_text(encoding="utf-8"))
    second_pending = deepcopy(claims["behavior_probes"][0]["steps"][4])
    second_pending["step_id"] = "second-pending"
    second_pending["async_transition_id"] = "job-2-completion"
    claims["behavior_probes"][0]["steps"].insert(5, second_pending)
    _write_json(claims_path, claims)
    with pytest.raises(ProviderRuntimeError) as error:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims_path,
            output_path=tmp_path / "rejected.json",
        )
    assert error.value.code == "provider_admission_async_probe_ambiguous"


def test_temporal_admission_rejects_time_action_without_async_coverage(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    claims_path = _claims(tmp_path, bundle)
    claims = json.loads(claims_path.read_text(encoding="utf-8"))
    claims["operations"][1]["covered_behaviors"] = ["success", "failure"]
    for step in claims["behavior_probes"][0]["steps"][4:]:
        step.pop("async_observation", None)
        step.pop("async_transition_id", None)
        step["covers"] = [{"operation_id": "job.status", "behavior": "success"}]
    _write_json(claims_path, claims)
    with pytest.raises(ProviderRuntimeError) as error:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims_path,
            output_path=tmp_path / "rejected.json",
        )
    assert error.value.code == "provider_admission_async_probe_invalid"


@pytest.mark.parametrize(
    ("include_handler", "temporal_capabilities", "expected_code"),
    [
        (True, False, "provider_runtime_time_unsupported"),
        (False, True, "provider_runtime_scheduled_event_handler_missing"),
    ],
)
def test_temporal_admission_requires_declared_capabilities_and_event_handler(
    tmp_path: Path,
    include_handler: bool,
    temporal_capabilities: bool,
    expected_code: str,
) -> None:
    bundle = _build_temporal_bundle(
        tmp_path,
        include_handler=include_handler,
        temporal_capabilities=temporal_capabilities,
    )
    claims_path = _claims(tmp_path, bundle)
    with pytest.raises(ProviderRuntimeError) as error:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims_path,
            output_path=tmp_path / "rejected.json",
        )
    assert error.value.code == expected_code


def test_temporal_admission_rejects_terminal_response_without_delivered_event(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path, fake_terminal_without_event=True)
    claims_path = _claims(tmp_path, bundle)
    with pytest.raises(ProviderRuntimeError) as error:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims_path,
            output_path=tmp_path / "rejected.json",
        )
    assert error.value.code == "provider_admission_async_event_delivery_missing"


def test_temporal_admission_rejects_unrelated_delivered_event(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(
        tmp_path,
        unrelated_event_without_completion=True,
    )
    claims_path = _claims(tmp_path, bundle)
    with pytest.raises(ProviderRuntimeError) as error:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims_path,
            output_path=tmp_path / "rejected.json",
        )
    assert error.value.code == "provider_admission_async_event_delivery_missing"


def test_temporal_admission_rejects_same_kind_with_wrong_expected_event_id(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path)
    claims_path = _claims(tmp_path, bundle)
    claims = json.loads(claims_path.read_text(encoding="utf-8"))
    action = claims["behavior_probes"][0]["steps"][5]["controller_actions_before"][0]
    assert action["expected_event_kind"] == "job.complete"
    action["expected_event_id"] = "another-job:complete"
    _write_json(claims_path, claims)

    with pytest.raises(ProviderRuntimeError) as error:
        admit_provider_runtime(
            bundle_dir=bundle,
            claims_path=claims_path,
            output_path=tmp_path / "rejected.json",
        )
    assert error.value.code == "provider_admission_async_event_delivery_missing"


def test_provider_time_rolls_back_handler_invariant_failure_without_latching(
    tmp_path: Path,
) -> None:
    bundle = _build_temporal_bundle(tmp_path, corrupt_during_delivery=True)
    admission_path = tmp_path / "admission.json"
    claims_path = _claims(tmp_path, bundle)
    claims = json.loads(claims_path.read_text(encoding="utf-8"))
    claims["behavior_probes"][0]["steps"] = claims["behavior_probes"][0]["steps"][:5]
    claims["operations"][1]["covered_behaviors"] = ["success", "failure"]
    claims["receipt_predicates"] = [
        predicate
        for predicate in claims["receipt_predicates"]
        if predicate["predicate_id"] != "terminal"
    ]
    claims["behavior_probes"][0]["steps"][4].pop("async_observation")
    claims["behavior_probes"][0]["steps"][4].pop("async_transition_id")
    claims["behavior_probes"][0]["steps"][4]["covers"] = [
        {"operation_id": "job.status", "behavior": "success"},
        {"operation_id": "job.submit", "behavior": "readback"},
    ]
    _write_json(claims_path, claims)
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims_path,
        output_path=admission_path,
        admitted_at=datetime(2026, 9, 2, tzinfo=UTC),
    )
    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission_path,
        run_dir=tmp_path / "run",
    )
    try:
        _submit(runtime)
        before = deepcopy(runtime.export()["provider_state"])
        with pytest.raises(ProviderRuntimeError) as error:
            runtime.advance_provider_time("2030-01-01T00:00:10+00:00")
        assert error.value.code == "provider_runtime_invariant_failed"
        after = runtime.export()
        assert after["provider_state"] == before
        assert after["provider_assurance"]["status"] == "valid"
        assert after["provider_assurance"]["failure"] is None
    finally:
        runtime.close()


def test_provider_time_normalizes_handler_failure_and_rolls_back(tmp_path: Path) -> None:
    bundle = _build_temporal_bundle(tmp_path, raise_during_delivery=True)
    gateway = InterceptionGateway.from_bundles(
        bundle_dirs=(bundle,),
        run_root=tmp_path / "runs",
        control_token="controller-secret",
    )
    provider = gateway.providers[PROVIDER_ID]
    try:
        with provider.binding.lock:
            _submit(provider.runtime)
            before = deepcopy(provider.runtime.export()["provider_state"])
        with TestClient(gateway.control_app) as controller:
            response = controller.post(
                f"/v1/providers/{PROVIDER_ID}/time/advance",
                headers={"x-datalox-control-token": "controller-secret"},
                json={"target": "2030-01-01T00:00:10+00:00"},
            )
        assert response.status_code == 422
        assert response.json()["detail"] == {
            "code": "provider_runtime_scheduled_event_delivery_failed",
            "message": (
                "A provider scheduled-event handler failed; the time advance was rolled back."
            ),
            "details": {},
        }
        with provider.binding.lock:
            assert provider.runtime.export()["provider_state"] == before
    finally:
        gateway.close()
