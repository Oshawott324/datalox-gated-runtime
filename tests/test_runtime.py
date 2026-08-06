from datalox_gated_runtime import (
    CallRequest,
    GatePolicy,
    GatedRuntime,
    ResponseCase,
    run_basic_audit,
)


def test_replays_captured_get_response() -> None:
    runtime = GatedRuntime(
        policy=GatePolicy.default(),
        response_cases=[
            ResponseCase(
                case_id="case_001",
                method="GET",
                path="/experiments/exp-001",
                status_code=200,
                body={"id": "exp-001", "status": "active"},
            )
        ],
    )

    response = runtime.handle(CallRequest(method="GET", path="/experiments/exp-001"))
    run_export = runtime.export()

    assert response.status_code == 200
    assert response.decision.kind == "replay"
    assert response.response_case_id == "case_001"
    assert run_export.events[0].response_case_id == "case_001"


def test_shadow_writes_do_not_require_response_case() -> None:
    runtime = GatedRuntime()

    response = runtime.handle(
        CallRequest(method="POST", path="/assay-results", body={"result": "pass"})
    )
    run_export = runtime.export()

    assert response.status_code == 202
    assert response.decision.kind == "shadow_write"
    assert run_export.shadow_state["writes"] == [
        {"method": "POST", "path": "/assay-results", "query": {}, "body": {"result": "pass"}}
    ]


def test_blocks_known_live_hardware_action() -> None:
    runtime = GatedRuntime()

    response = runtime.handle(CallRequest(method="POST", path="/robot/move", body={"axis": "x"}))
    run_export = runtime.export()
    audit = run_basic_audit(run_export)

    assert response.status_code == 403
    assert response.decision.kind == "deny"
    assert response.decision.reason_code == "live_action_not_allowed"
    assert audit.checks["live_actions_denied"] is True


def test_audit_fails_on_unknown_miss() -> None:
    runtime = GatedRuntime()

    runtime.handle(CallRequest(method="GET", path="/unknown"))
    audit = run_basic_audit(runtime.export())

    assert audit.passed is False
    assert "no_missed_calls" in audit.failure_codes
