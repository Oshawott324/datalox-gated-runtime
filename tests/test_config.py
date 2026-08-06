from pathlib import Path

from datalox_gated_runtime.config import load_gate_config


def test_loads_example_gate_config() -> None:
    config = load_gate_config(Path("examples/lab_ops_stale_result/gate_config.json"))

    assert config.config_id == "lab_ops_stale_result_v0"
    assert len(config.response_cases) == 3
    assert config.response_cases[0].path == "/labstep/experiments/exp_current"
    assert config.audit_rules[0]["type"] == "require_call"


def test_config_rejects_missing_response_case_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[{"method":"GET"}],"audit_rules":[]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "response_cases[0].path" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_load_gate_config_rejects_non_object_root(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text("[]", encoding="utf-8")

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "gate config must be an object" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_non_int_status_code(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[{"case_id":"case_001","method":"GET","path":"/x","status_code":"200"}],"audit_rules":[]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "response_cases[0].status_code" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_primitive_audit_rule(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[{"case_id":"c","method":"GET","path":"/x","status_code":200}],"audit_rules":["bad"]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "audit_rules[0]" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_audit_rule_missing_failure_code(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[{"case_id":"c","method":"GET","path":"/x","status_code":200}],"audit_rules":[{"type":"require_call"}]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "audit_rules[0].failure_code" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_forbid_call_missing_method(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[],"audit_rules":[{"type":"forbid_call","path":"/runs/start","failure_code":"bad_forbid_call"}]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "audit_rules[0].method is required for forbid_call" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_forbid_call_missing_path_and_path_prefix(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[],"audit_rules":[{"type":"forbid_call","method":"POST","failure_code":"bad_forbid_call"}]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "audit_rules[0] forbid_call requires exactly one of path or path_prefix" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_forbid_call_with_path_and_path_prefix(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[],"audit_rules":[{"type":"forbid_call","method":"POST","path":"/runs/start","path_prefix":"/runs/","failure_code":"bad_forbid_call"}]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "audit_rules[0] forbid_call requires exactly one of path or path_prefix" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_mcp_audit_rule_without_tool_name(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[],"audit_rules":[{"type":"require_mcp_call","failure_code":"missing"}]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "audit_rules[0].tool_name" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_mcp_audit_rule_non_object_arguments_contains(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"bad","response_cases":[],"audit_rules":[{"type":"require_mcp_call","tool_name":"github.get_issue","arguments_contains":[],"failure_code":"missing"}]}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "audit_rules[0].arguments_contains" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_rejects_malformed_json(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text("{bad json", encoding="utf-8")

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "invalid gate config json" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_config_loads_strict_world_bundle_v1_reference(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"world","response_cases":[],"audit_rules":[], '
        '"world":{"kind":"world_bundle_v1","seed":3}}',
        encoding="utf-8",
    )

    config = load_gate_config(config_path)

    assert config.world is not None
    assert config.world.id == "world_bundle_v1"
    assert config.world.seed == 3


def test_config_rejects_world_bundle_v1_unknown_fields(tmp_path: Path) -> None:
    config_path = tmp_path / "gate_config.json"
    config_path.write_text(
        '{"config_id":"world","response_cases":[],"audit_rules":[], '
        '"world":{"kind":"world_bundle_v1","seed":0,"domain":"commerce"}}',
        encoding="utf-8",
    )

    try:
        load_gate_config(config_path)
    except ValueError as exc:
        assert "unknown fields for world_bundle_v1" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
