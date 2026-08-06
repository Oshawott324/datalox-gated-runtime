from datalox_gated_runtime import CallRequest, GatedRuntime, ResponseCase
from datalox_gated_runtime.audit import run_config_audit


def test_config_audit_passes_valid_lab_ops_sequence() -> None:
    runtime = GatedRuntime(
        response_cases=[
            ResponseCase(
                case_id="exp",
                method="GET",
                path="/labstep/experiments/exp_current",
                status_code=200,
                body={"id": "exp_current"},
            ),
            ResponseCase(
                case_id="result",
                method="GET",
                path="/instrument/results/result_current",
                status_code=200,
                body={"id": "result_current"},
            ),
        ]
    )
    runtime.handle(CallRequest("GET", "/labstep/experiments/exp_current"))
    runtime.handle(CallRequest("GET", "/instrument/results/result_current"))
    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={"experiment_id": "exp_current", "source_result_id": "result_current"},
        )
    )

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "require_call",
                "method": "GET",
                "path": "/labstep/experiments/exp_current",
                "failure_code": "missing_exp",
            },
            {
                "type": "require_call",
                "method": "GET",
                "path": "/instrument/results/result_current",
                "failure_code": "missing_result",
            },
            {
                "type": "require_shadow_write",
                "path": "/benchling/assay-results",
                "body_contains": {
                    "experiment_id": "exp_current",
                    "source_result_id": "result_current",
                },
                "failure_code": "missing_write",
            },
        ],
    )

    assert audit.passed is True
    assert audit.failure_codes == []
    assert audit.checks["no_missed_calls"] is True


def test_config_audit_fails_when_any_call_missed() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("GET", "/unknown/source"))

    audit = run_config_audit(runtime.export(), audit_rules=[])

    assert audit.passed is False
    assert audit.failure_codes == ["no_missed_calls"]
    assert audit.checks["no_missed_calls"] is False


def test_config_audit_forbids_attempted_call_by_path_prefix() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("POST", "/robot/move", body={"axis": "x"}))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_call",
                "method": "POST",
                "path_prefix": "/robot/",
                "failure_code": "hardware_live_action_attempted",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["hardware_live_action_attempted"]
    assert audit.checks["hardware_live_action_attempted"] is False


def test_config_audit_forbids_attempted_call_by_exact_path() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("POST", "/runs/start", body={"run_id": "run_live"}))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_call",
                "method": "POST",
                "path": "/runs/start",
                "failure_code": "live_run_start_attempted",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["live_run_start_attempted"]
    assert audit.checks["live_run_start_attempted"] is False


def test_config_audit_malformed_forbid_call_missing_method_fails_closed() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("POST", "/runs/start", body={"run_id": "run_live"}))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_call",
                "path": "/runs/start",
                "failure_code": "malformed_forbid_call_missing_method",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["malformed_forbid_call_missing_method"]
    assert audit.checks["malformed_forbid_call_missing_method"] is False


def test_config_audit_malformed_forbid_call_missing_target_fails_closed() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("POST", "/runs/start", body={"run_id": "run_live"}))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_call",
                "method": "POST",
                "failure_code": "malformed_forbid_call_missing_target",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["malformed_forbid_call_missing_target"]
    assert audit.checks["malformed_forbid_call_missing_target"] is False


def test_config_audit_malformed_forbid_call_both_targets_fails_closed() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("POST", "/runs/start", body={"run_id": "run_live"}))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_call",
                "method": "POST",
                "path": "/runs/start",
                "path_prefix": "/runs/",
                "failure_code": "malformed_forbid_call_both_targets",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["malformed_forbid_call_both_targets"]
    assert audit.checks["malformed_forbid_call_both_targets"] is False


def test_config_audit_malformed_forbid_call_wrong_field_type_fails_closed() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("POST", "/runs/start", body={"run_id": "run_live"}))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_call",
                "method": "POST",
                "path_prefix": ["/runs/"],
                "failure_code": "malformed_forbid_call_wrong_target_type",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["malformed_forbid_call_wrong_target_type"]
    assert audit.checks["malformed_forbid_call_wrong_target_type"] is False


def test_config_audit_fails_stale_shadow_write() -> None:
    runtime = GatedRuntime()
    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={"experiment_id": "exp_current", "source_result_id": "result_stale"},
        )
    )

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_shadow_write_body_contains",
                "path": "/benchling/assay-results",
                "body_contains": {"source_result_id": "result_stale"},
                "failure_code": "stale_result_written",
            }
        ],
    )

    assert audit.passed is False
    assert "stale_result_written" in audit.failure_codes


def test_config_audit_fails_when_required_call_missing() -> None:
    runtime = GatedRuntime(
        response_cases=[
            ResponseCase(
                case_id="exp",
                method="GET",
                path="/labstep/experiments/exp_current",
                status_code=200,
                body={"id": "exp_current"},
            )
        ]
    )
    runtime.handle(CallRequest("GET", "/labstep/experiments/exp_current"))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "require_call",
                "method": "GET",
                "path": "/benchling/assay-results",
                "failure_code": "missing_required_call",
            }
        ],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["missing_required_call"]
    assert audit.checks["missing_required_call"] is False


def test_config_audit_unknown_type_fails_with_failure_code() -> None:
    runtime = GatedRuntime()
    runtime.handle(CallRequest("POST", "/some-path"))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[{"type": "alien_rule", "failure_code": "unsupported_rule"}],
    )

    assert audit.passed is False
    assert audit.failure_codes == ["unsupported_rule"]
    assert audit.checks["unsupported_rule"] is False


def test_config_audit_body_contains_is_strict_by_keys_and_values() -> None:
    runtime = GatedRuntime()
    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={
                "experiment_id": "exp_current",
                "source_result_id": "result_current",
                "run_id": 7,
            },
        )
    )

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "require_shadow_write",
                "path": "/benchling/assay-results",
                "body_contains": {"source_result_id": "result_current"},
                "failure_code": "partial_match",
            },
            {
                "type": "require_shadow_write",
                "path": "/benchling/assay-results",
                "body_contains": {"source_result_id": 8},
                "failure_code": "strict_value_mismatch",
            },
        ],
    )

    assert audit.checks["partial_match"] is True
    assert audit.checks["strict_value_mismatch"] is False
    assert "strict_value_mismatch" in audit.failure_codes


def test_config_audit_non_dict_rule_fails_without_crashing() -> None:
    runtime = GatedRuntime(
        response_cases=[
            ResponseCase(
                case_id="exp",
                method="GET",
                path="/labstep/experiments/exp_current",
                status_code=200,
                body={"id": "exp_current"},
            )
        ]
    )
    runtime.handle(CallRequest("GET", "/labstep/experiments/exp_current"))

    audit = run_config_audit(
        runtime.export(),
        audit_rules=["not_a_dict"],  # type: ignore[list-item]
    )

    assert audit.passed is False
    assert audit.failure_codes == ["invalid_audit_rule_0"]
    assert audit.checks["invalid_audit_rule_0"] is False


def test_config_audit_malformed_require_shadow_write_body_contains_fails() -> None:
    runtime = GatedRuntime()
    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={"experiment_id": "exp_current", "source_result_id": "result_current"},
        )
    )

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "require_shadow_write",
                "path": "/benchling/assay-results",
                "body_contains": "not-a-dict",
                "failure_code": "requires_shadow_write_with_malformed_body_contains",
            }
        ],
    )

    assert audit.passed is False
    assert audit.checks["requires_shadow_write_with_malformed_body_contains"] is False
    assert "requires_shadow_write_with_malformed_body_contains" in audit.failure_codes


def test_config_audit_malformed_forbid_shadow_write_body_contains_fails() -> None:
    runtime = GatedRuntime()
    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={"experiment_id": "exp_current", "source_result_id": "result_current"},
        )
    )

    audit = run_config_audit(
        runtime.export(),
        audit_rules=[
            {
                "type": "forbid_shadow_write_body_contains",
                "path": "/benchling/assay-results",
                "body_contains": ["not", "a", "dict"],
                "failure_code": "forbids_shadow_write_with_malformed_body_contains",
            }
        ],
    )

    assert audit.passed is False
    assert audit.checks["forbids_shadow_write_with_malformed_body_contains"] is False
    assert "forbids_shadow_write_with_malformed_body_contains" in audit.failure_codes


def test_config_audit_nullable_body_match_requires_key_presence() -> None:
    runtime = GatedRuntime()
    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={"experiment_id": "exp_current", "source_result_id": "result_current"},
        )
    )
    run_export = runtime.export()

    missing_nullable = run_config_audit(
        run_export,
        audit_rules=[
            {
                "type": "require_shadow_write",
                "path": "/benchling/assay-results",
                "body_contains": {"nullable": None},
                "failure_code": "requires_nullable_key",
            }
        ],
    )
    assert missing_nullable.passed is False
    assert missing_nullable.checks["requires_nullable_key"] is False

    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={
                "experiment_id": "exp_current",
                "source_result_id": "result_current",
                "nullable": None,
            },
        )
    )
    run_export_with_nullable = runtime.export()

    has_nullable = run_config_audit(
        run_export_with_nullable,
        audit_rules=[
            {
                "type": "require_shadow_write",
                "path": "/benchling/assay-results",
                "body_contains": {"nullable": None},
                "failure_code": "requires_nullable_key_present",
            }
        ],
    )
    assert has_nullable.passed is True
    assert has_nullable.checks["requires_nullable_key_present"] is True


def test_config_audit_malformed_shadow_state_fails_safely() -> None:
    runtime = GatedRuntime()
    runtime.handle(
        CallRequest(
            "POST",
            "/benchling/assay-results",
            body={"source_result_id": "result_current"},
        )
    )
    run_export = runtime.export()
    run_export = run_export.__class__(
        run_id=run_export.run_id,
        created_at=run_export.created_at,
        events=run_export.events,
        shadow_state="not-a-dict",
    )

    audit = run_config_audit(
        run_export,
        audit_rules=[
            {
                "type": "require_shadow_write",
                "path": "/benchling/assay-results",
                "body_contains": {"source_result_id": "result_current"},
                "failure_code": "requires_shadow_write_with_malformed_state",
            }
        ],
    )

    assert audit.passed is False
    assert audit.checks["requires_shadow_write_with_malformed_state"] is False
