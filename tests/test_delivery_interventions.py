from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient
from provider_runtime_helpers import PROVIDER_AUTHORITY, PROVIDER_ID
from test_provider_release_registry import _profile

from datalox_gated_runtime.interception import interventions as intervention_module
from datalox_gated_runtime.interception.gateway import InterceptionGateway
from datalox_gated_runtime.interception.interventions import (
    DELIVERY_INTERVENTION_TRACE_SCHEMA_VERSION,
    DeliveryInterventionError,
    DeliveryInterventionSession,
    InterventionDecision,
    JsonTypeDriftAction,
    ProviderBaseBinding,
    QuotaResponseAction,
    RepeatPageAction,
    load_delivery_intervention,
    validate_policy_for_operations,
)
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse
from datalox_gated_runtime.provider_runtime.release import build_provider_release

ROOT = Path(__file__).resolve().parents[1]
DUMMY_SHA256 = "sha256:" + "1" * 64
PROVIDER = ProviderBaseBinding(
    provider_id="example_provider",
    release_version="test-release",
    profile_id="default",
    bundle_version="1.0.0",
    release_config_sha256=DUMMY_SHA256,
    provider_runtime_sha256=DUMMY_SHA256,
    provider_admission_sha256=DUMMY_SHA256,
    operation_contract_sha256=DUMMY_SHA256,
)
ALLOWED_READS = frozenset({"records.list"})


class _Policy:
    policy_id = "dirty_integration"
    policy_version = "1"
    policy_sha256 = "sha256:" + "1" * 64

    def decide(
        self,
        *,
        seed: str,
        logical_request_index: int,
        operation_id: str,
        request: CallRequest,
    ) -> InterventionDecision | None:
        del request
        schedules = {
            "seed-a": {
                2: InterventionDecision(
                    "repeat_second_page",
                    operation_id,
                    RepeatPageAction(source_request_index=1),
                ),
                3: InterventionDecision(
                    "quota_third_request",
                    operation_id,
                    QuotaResponseAction(
                        status_code=429,
                        headers={"content-type": "application/json"},
                        body={"error": {"code": "quota_exhausted"}},
                    ),
                ),
            },
            "seed-b": {
                1: InterventionDecision(
                    "drift_first_count",
                    operation_id,
                    JsonTypeDriftAction(
                        pointer="/count",
                        from_type="integer",
                        to_type="string",
                        value="2",
                    ),
                )
            },
        }
        return schedules[seed].get(logical_request_index)


def _response(index: int) -> GateResponse:
    return GateResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body={"records": [{"id": f"record-{index}"}], "count": 2, "offset": index - 1},
        decision=GateDecision(
            kind="replay",
            reason_code="provider_base",
            message="Provider base response.",
        ),
        event_id=f"evt_base_{index}",
    )


def _request() -> CallRequest:
    return CallRequest(
        "GET",
        "/v1/records",
        operation_id="records.list",
        authority="api.provider.example",
    )


def test_off_is_identity_and_records_same_counterfactual_decisions(tmp_path: Path) -> None:
    session = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=False,
        trace_path=tmp_path / "off.jsonl",
    )
    first = _response(1)
    second = _response(2)

    delivered_first = session.handle(_request(), lambda: first)
    delivered_second = session.handle(_request(), lambda: second)

    assert delivered_first is first
    assert delivered_second is second
    exported = session.export()
    assert exported["schema_version"] == DELIVERY_INTERVENTION_TRACE_SCHEMA_VERSION
    assert exported["events"][1]["decision"]["decision_id"] == "repeat_second_page"
    assert exported["events"][1]["decision"]["kind"] == "repeat_page"
    assert exported["events"][1]["decision"]["action"] == {
        "kind": "repeat_page",
        "source_request_index": 1,
    }
    assert exported["events"][1]["enabled"] is False
    assert exported["events"][1]["applied"] is False
    assert (
        exported["events"][1]["base"]["response_sha256"]
        == exported["events"][1]["delivered"]["response_sha256"]
    )

    schema = json.loads(
        (ROOT / "schemas/delivery-intervention-trace-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(exported)


def test_on_applies_repeat_and_quota_without_modifying_base_evidence(tmp_path: Path) -> None:
    session = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=True,
        trace_path=tmp_path / "on.jsonl",
    )
    base_calls: list[int] = []

    def invoke(index: int) -> GateResponse:
        base_calls.append(index)
        return _response(index)

    first = session.handle(_request(), lambda: invoke(1))
    second = session.handle(_request(), lambda: invoke(2))
    third = session.handle(_request(), lambda: invoke(3))

    assert first.body["records"] == [{"id": "record-1"}]
    assert second.body["records"] == [{"id": "record-1"}]
    assert second.event_id == "evt_base_2"
    assert third.status_code == 429
    assert base_calls == [1, 2]

    events = session.export()["events"]
    assert events[1]["base"] == {
        "invoked": True,
        "event_id": "evt_base_2",
        "response_sha256": canonical_json_sha256(
            {
                "status_code": 200,
                "headers": {"content-type": "application/json"},
                "body": _response(2).body,
            }
        ),
    }
    assert events[1]["base"]["response_sha256"] != events[1]["delivered"]["response_sha256"]
    assert events[2]["base"] == {
        "invoked": False,
        "event_id": None,
        "response_sha256": None,
    }
    assert events[2]["stage"] == "pre_dispatch"

    off = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=False,
    )
    off.handle(_request(), lambda: _response(1))
    off.handle(_request(), lambda: _response(2))
    assert off.export()["events"][1]["event_id"] == events[1]["event_id"]

    reset = session.reset()
    assert reset["next_request_index"] == 1
    assert reset["events"] == []
    assert (tmp_path / "on.jsonl").read_text(encoding="utf-8") == ""
    assert session.handle(_request(), lambda: _response(1)).body == _response(1).body


def test_same_seed_repeats_schedule_and_different_seed_selects_another_schedule() -> None:
    first_a = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=False,
    )
    second_a = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=False,
    )
    seed_b = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-b",
        enabled=True,
    )

    for session in (first_a, second_a):
        session.handle(_request(), lambda: _response(1))
        session.handle(_request(), lambda: _response(2))
    drifted = seed_b.handle(_request(), lambda: _response(1))

    assert first_a.export()["events"][1]["decision"] == second_a.export()["events"][1]["decision"]
    assert drifted.body["count"] == "2"
    assert seed_b.export()["events"][0]["decision"]["kind"] == "json_type_drift"


def test_pair_correlation_binds_exact_release_but_not_mode() -> None:
    changed_release = replace(
        PROVIDER,
        release_version="test-release-2",
        release_config_sha256="sha256:" + "2" * 64,
    )
    off = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=False,
    )
    on = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=True,
    )
    another_release = DeliveryInterventionSession(
        _Policy(),
        provider=changed_release,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=False,
    )
    for session in (off, on, another_release):
        session.handle(_request(), lambda: _response(1))
    assert off.export()["events"][0]["event_id"] == on.export()["events"][0]["event_id"]
    assert (
        off.export()["events"][0]["event_id"] != another_release.export()["events"][0]["event_id"]
    )


def test_application_failure_is_traced_and_terminal_until_reset(tmp_path: Path) -> None:
    session = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-b",
        enabled=True,
        trace_path=tmp_path / "failure.jsonl",
    )
    invalid_base = GateResponse(
        status_code=200,
        headers={},
        body={"records": []},
        decision=GateDecision("replay", "provider_base", "Provider base response."),
        event_id="evt_invalid_shape",
    )
    with pytest.raises(DeliveryInterventionError, match="could not be applied exactly"):
        session.handle(_request(), lambda: invalid_base)

    exported = session.export()
    assert exported["terminal_failure"]["code"] == "delivery_intervention_application_failed"
    assert exported["events"][0]["outcome"] == "terminal_failure"
    assert exported["events"][0]["base"]["event_id"] == "evt_invalid_shape"
    assert exported["events"][0]["delivered"] is None
    schema = json.loads(
        (ROOT / "schemas/delivery-intervention-trace-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(exported)
    with pytest.raises(DeliveryInterventionError, match="trusted reset is required"):
        session.handle(_request(), lambda: _response(2))
    assert session.export()["next_request_index"] == 2

    reset = session.reset()
    assert reset["terminal_failure"] is None
    assert reset["next_request_index"] == 1


def test_direct_session_rejects_unknown_and_write_operations_before_consuming_index() -> None:
    session = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=True,
    )
    base_calls = 0

    def invoke() -> GateResponse:
        nonlocal base_calls
        base_calls += 1
        return _response(1)

    for operation_id in ("records.write", "records.unknown"):
        request = CallRequest(
            "POST",
            "/v1/records",
            operation_id=operation_id,
            authority="api.provider.example",
        )
        with pytest.raises(DeliveryInterventionError, match="admitted read operation set"):
            session.handle(request, invoke)
    assert base_calls == 0
    assert session.export()["next_request_index"] == 1
    assert session.export()["events"] == []


def test_trace_append_writes_all_bytes_after_short_os_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trace = tmp_path / "short-writes.jsonl"
    session = DeliveryInterventionSession(
        _Policy(),
        provider=PROVIDER,
        allowed_read_operation_ids=ALLOWED_READS,
        seed="seed-a",
        enabled=False,
        trace_path=trace,
    )
    real_write = intervention_module.os.write
    calls = 0

    def short_write(descriptor: int, payload: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        chunk_size = max(1, len(payload) // 3)
        return real_write(descriptor, payload[:chunk_size])

    monkeypatch.setattr(intervention_module.os, "write", short_write)
    session.handle(_request(), lambda: _response(1))

    assert calls > 1
    persisted = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    assert persisted == session.export()["events"]


def _config(tmp_path: Path, *, action: dict[str, object]) -> Path:
    policy = {
        "schema_version": "datalox_delivery_intervention_policy_v1",
        "policy_id": "static_policy",
        "policy_version": "1",
        "schedules": [
            {
                "seed": "episode-1",
                "decisions": [
                    {
                        "decision_id": "decision_1",
                        "request_index": 1,
                        "operation_id": "records.list",
                        "action": action,
                    }
                ],
            }
        ],
    }
    payload = {
        "schema_version": "datalox_delivery_intervention_v1",
        "provider_id": "example_provider",
        "mode": "off",
        "seed": "episode-1",
        "policy": policy,
        "policy_sha256": canonical_json_sha256(policy),
    }
    path = tmp_path / "intervention.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_static_config_is_strict_and_timeout_is_unsupported(tmp_path: Path) -> None:
    valid = _config(
        tmp_path,
        action={
            "kind": "quota_response",
            "response": {
                "status_code": 429,
                "headers": {"content-type": "application/json"},
                "body": {"error": "quota"},
            },
        },
    )
    loaded = load_delivery_intervention(valid)
    validate_policy_for_operations(
        loaded.policy,
        operation_mutability={"records.list": "read"},
    )
    schema = json.loads(
        (ROOT / "schemas/delivery-intervention-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(schema).validate(json.loads(valid.read_text(encoding="utf-8")))

    invalid_timeout = json.loads(valid.read_text(encoding="utf-8"))
    invalid_timeout["policy"]["schedules"][0]["decisions"][0]["action"] = {
        "kind": "timeout",
        "duration_ms": 1000,
    }
    invalid_timeout["policy_sha256"] = canonical_json_sha256(invalid_timeout["policy"])
    valid.write_text(json.dumps(invalid_timeout), encoding="utf-8")
    with pytest.raises(DeliveryInterventionError, match="unsupported intervention action"):
        load_delivery_intervention(valid)


def test_policy_mismatch_and_unsafe_actions_fail_closed(tmp_path: Path) -> None:
    path = _config(
        tmp_path,
        action={
            "kind": "quota_response",
            "response": {
                "status_code": 429,
                "headers": {"x-datalox-mode": "on"},
                "body": {"error": "quota"},
            },
        },
    )
    with pytest.raises(DeliveryInterventionError, match="provider-shaped"):
        load_delivery_intervention(path)

    path = _config(
        tmp_path,
        action={
            "kind": "quota_response",
            "response": {"status_code": 429, "headers": {}, "body": None},
        },
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["policy_sha256"] = "sha256:" + "0" * 64
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DeliveryInterventionError, match="digest does not match"):
        load_delivery_intervention(path)

    loaded_path = _config(
        tmp_path,
        action={
            "kind": "quota_response",
            "response": {"status_code": 429, "headers": {}, "body": None},
        },
    )
    loaded = load_delivery_intervention(loaded_path)
    with pytest.raises(DeliveryInterventionError, match="read operations only"):
        validate_policy_for_operations(
            loaded.policy,
            operation_mutability={"records.list": "write"},
        )


def test_admitted_gateway_keeps_base_and_delivery_evidence_separate_and_resets(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release = build_provider_release(
        profiles=(profile,),
        release_version="2026.09.01",
        output_dir=tmp_path / "release",
    )
    release_config = tmp_path / "provider-release.json"
    release_config.write_text(
        json.dumps(release.config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    policy = {
        "schema_version": "datalox_delivery_intervention_policy_v1",
        "policy_id": "gateway_policy",
        "policy_version": "1",
        "schedules": [
            {
                "seed": "episode-1",
                "decisions": [
                    {
                        "decision_id": "drift_counter",
                        "request_index": 1,
                        "operation_id": "counter.read",
                        "action": {
                            "kind": "json_type_drift",
                            "pointer": "/counter",
                            "from_type": "integer",
                            "to_type": "string",
                            "value": "1",
                        },
                    }
                ],
            }
        ],
    }
    config = {
        "schema_version": "datalox_delivery_intervention_v1",
        "provider_id": PROVIDER_ID,
        "mode": "on",
        "seed": "episode-1",
        "policy": policy,
        "policy_sha256": canonical_json_sha256(policy),
    }
    intervention_config = tmp_path / "gateway-intervention.json"
    intervention_config.write_text(json.dumps(config), encoding="utf-8")

    off_config = tmp_path / "gateway-intervention-off.json"
    off_config.write_text(json.dumps({**config, "mode": "off"}), encoding="utf-8")
    baseline_gateway = InterceptionGateway.from_admitted_release_bindings(
        bundle_admission_configs=((profile.bundle_dir, profile.admission_path, release_config),),
        run_root=tmp_path / "baseline-run",
        control_token="baseline-secret",
    )
    off_gateway = InterceptionGateway.from_admitted_release_bindings(
        bundle_admission_configs=((profile.bundle_dir, profile.admission_path, release_config),),
        delivery_intervention_configs={PROVIDER_ID: off_config},
        run_root=tmp_path / "off-run",
        control_token="off-secret",
    )
    try:
        with (
            TestClient(
                baseline_gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}"
            ) as baseline_agent,
            TestClient(off_gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as off_agent,
        ):
            baseline_response = baseline_agent.get("/counter")
            off_response = off_agent.get("/counter")
            assert off_response.status_code == baseline_response.status_code
            assert off_response.content == baseline_response.content
            assert dict(off_response.headers) == dict(baseline_response.headers)
        with (
            TestClient(baseline_gateway.control_app) as baseline_controller,
            TestClient(off_gateway.control_app) as off_controller,
        ):
            baseline_export = baseline_controller.get(
                f"/v1/providers/{PROVIDER_ID}/export",
                headers={"x-datalox-control-token": "baseline-secret"},
            ).json()
            off_export = off_controller.get(
                f"/v1/providers/{PROVIDER_ID}/export",
                headers={"x-datalox-control-token": "off-secret"},
            ).json()
            assert off_export["provider_state"] == baseline_export["provider_state"]
            off_trace = off_controller.get(
                f"/v1/providers/{PROVIDER_ID}/delivery-interventions/export",
                headers={"x-datalox-control-token": "off-secret"},
            ).json()
            assert off_trace["events"][0]["decision"]["kind"] == "json_type_drift"
            assert off_trace["events"][0]["applied"] is False
            assert (
                off_trace["events"][0]["base"]["response_sha256"]
                == off_trace["events"][0]["delivered"]["response_sha256"]
            )
    finally:
        baseline_gateway.close()
        off_gateway.close()

    gateway = InterceptionGateway.from_admitted_release_bindings(
        bundle_admission_configs=((profile.bundle_dir, profile.admission_path, release_config),),
        delivery_intervention_configs={PROVIDER_ID: intervention_config},
        run_root=tmp_path / "gateway-run",
        control_token="controller-secret",
    )
    headers = {"x-datalox-control-token": "controller-secret"}
    try:
        with TestClient(gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as agent:
            unknown = agent.get("/outside-admitted-surface")
            assert unknown.status_code == 403
            reserved = agent.get("/counter", headers={"x-datalox-mode": "on"})
            assert reserved.status_code == 400
            delivered = agent.get("/counter")
            assert delivered.status_code == 200
            assert delivered.json()["counter"] == "1"
        with TestClient(gateway.control_app) as controller:
            base = controller.get(f"/v1/providers/{PROVIDER_ID}/export", headers=headers).json()
            delivery = controller.get(
                f"/v1/providers/{PROVIDER_ID}/delivery-interventions/export",
                headers=headers,
            ).json()
            assert base["call_evidence"]["events"][-1]["response_body"]["counter"] == 1
            assert delivery["events"][0]["delivered"]["response"]["body"]["counter"] == "1"
            assert len(delivery["events"]) == 1
            assert delivery["events"][0]["logical_request_index"] == 1
            assert (
                delivery["events"][0]["base"]["event_id"]
                == base["call_evidence"]["events"][-1]["event_id"]
            )
            controller.post(f"/v1/providers/{PROVIDER_ID}/reset", headers=headers)
            reset_delivery = controller.get(
                f"/v1/providers/{PROVIDER_ID}/delivery-interventions/export",
                headers=headers,
            ).json()
            assert reset_delivery["events"] == []
            assert reset_delivery["next_request_index"] == 1
        with TestClient(gateway.data_app, base_url=f"https://{PROVIDER_AUTHORITY}") as agent:
            write = agent.post("/counter", json={"amount": 2})
            assert write.status_code == 200
            assert write.json()["counter"] == 3
        with TestClient(gateway.control_app) as controller:
            after_write = controller.get(
                f"/v1/providers/{PROVIDER_ID}/delivery-interventions/export",
                headers=headers,
            ).json()
            assert after_write["events"] == []
            assert after_write["next_request_index"] == 1
    finally:
        gateway.close()
