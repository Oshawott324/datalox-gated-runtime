from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.models import ResponseCaseStateWorldConfig
from datalox_gated_runtime.world_backend import initialize_world
from datalox_gated_runtime.worlds.response_case_state_v0.contracts import (
    WorldContractError,
    parse_verifier,
)
from response_case_state_helpers import EXAMPLE_ROOT, configure_assignee_lookup


def test_parse_strict_response_case_world_config() -> None:
    config = load_gate_config(EXAMPLE_ROOT / "gate_config.json")

    assert isinstance(config.world, ResponseCaseStateWorldConfig)
    assert config.world.id == "response_case_state_v0"
    assert config.world.episodes == "world/episodes.jsonl"
    assert config.world.artifact_paths()[-1] == "world/sources.json"


@pytest.mark.parametrize(
    "value",
    [
        "../episodes.jsonl",
        "world/../episodes.jsonl",
        "/world/episodes.jsonl",
        "world/nested/episodes.jsonl",
        "world\\episodes.jsonl",
    ],
)
def test_world_config_rejects_artifact_traversal(tmp_path: Path, value: str) -> None:
    payload = json.loads((EXAMPLE_ROOT / "gate_config.json").read_text(encoding="utf-8"))
    payload["world"]["episodes"] = value
    path = tmp_path / "gate_config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="strict world/<file>"):
        load_gate_config(path)


def test_world_config_rejects_unknown_fields(tmp_path: Path) -> None:
    payload = json.loads((EXAMPLE_ROOT / "gate_config.json").read_text(encoding="utf-8"))
    payload["world"]["fallback"] = True
    path = tmp_path / "gate_config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="unknown fields"):
        load_gate_config(path)


def test_world_config_rejects_negative_seed(tmp_path: Path) -> None:
    payload = json.loads((EXAMPLE_ROOT / "gate_config.json").read_text(encoding="utf-8"))
    payload["world"]["seed"] = -1
    path = tmp_path / "gate_config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="non-negative"):
        load_gate_config(path)


@pytest.mark.parametrize(
    ("operator", "target", "code"),
    [
        ("execute_code", "/data/status", "unknown_transition_operator"),
        ("set_literal", "/data/~2bad", "invalid_json_pointer"),
        ("set_literal", "/data/-", "invalid_array_index"),
    ],
)
def test_artifact_contract_rejects_unknown_operator_and_invalid_pointer(
    tmp_path: Path,
    operator: str,
    target: str,
    code: str,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    transitions_path = source / "world" / "transitions.json"
    transitions = json.loads(transitions_path.read_text(encoding="utf-8"))
    effect = transitions["operations"][0]["effects"][0]
    effect["operator"] = operator
    effect["target"] = target
    if operator == "set_literal":
        effect.pop("request_pointer", None)
        effect["value"] = "changed"
    transitions_path.write_text(json.dumps(transitions), encoding="utf-8")
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == code


@pytest.mark.parametrize("extra_operand", [None, "value"])
def test_state_lookup_requires_exact_operands(tmp_path: Path, extra_operand: str | None) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    configure_assignee_lookup(source)
    transitions_path = source / "world" / "transitions.json"
    transitions = json.loads(transitions_path.read_text(encoding="utf-8"))
    effect = transitions["operations"][0]["effects"][1]
    if extra_operand is None:
        del effect["value_pointer"]
    else:
        effect[extra_operand] = "unexpected"
    transitions_path.write_text(json.dumps(transitions), encoding="utf-8")
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == "invalid_transition_operands"


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("source_missing", "state_lookup_source_missing"),
        ("source_not_array", "state_lookup_source_not_array"),
        ("source_empty", "state_lookup_source_empty"),
        ("match_missing", "state_lookup_match_missing"),
        ("value_missing", "state_lookup_value_missing"),
        ("duplicate_match", "state_lookup_ambiguous"),
        ("wrong_match_type", "state_lookup_match_type_mismatch"),
        ("wrong_value_type", "state_lookup_value_type_mismatch"),
    ],
)
def test_state_lookup_initialization_validates_every_episode(
    tmp_path: Path,
    case: str,
    code: str,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    configure_assignee_lookup(source)
    episodes_path = source / "world" / "episodes.jsonl"
    episodes = [json.loads(line) for line in episodes_path.read_text(encoding="utf-8").splitlines()]
    lookup = episodes[1]["state"]["assignee_directory"]
    if case == "source_missing":
        del lookup["items"]
    elif case == "source_not_array":
        lookup["items"] = {"id": "second-owner@example.test", "display": "Second Owner"}
    elif case == "source_empty":
        lookup["items"] = []
    elif case == "match_missing":
        del lookup["items"][0]["id"]
    elif case == "value_missing":
        del lookup["items"][0]["display"]
    elif case == "duplicate_match":
        lookup["items"].append(dict(lookup["items"][0]))
    elif case == "wrong_match_type":
        lookup["items"][0]["id"] = 2
    elif case == "wrong_value_type":
        lookup["items"][0]["display"] = 2
    episodes_path.write_text(
        "\n".join(json.dumps(episode) for episode in episodes) + "\n",
        encoding="utf-8",
    )
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == code


def test_route_template_requires_exact_path_bindings(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    routes_path = source / "world" / "routes.json"
    routes = json.loads(routes_path.read_text(encoding="utf-8"))
    routes["routes"][0]["path_parameters"] = {}
    routes_path.write_text(json.dumps(routes), encoding="utf-8")
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == "invalid_path_parameter_bindings"


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("state_key", "state_key_missing"),
        ("route_binding_pointer", "state_value_missing"),
        ("transition_target_pointer", "state_value_missing"),
        ("transition_source_pointer", "state_value_missing"),
        ("transition_type", "state_type_mismatch"),
        ("verifier_state_pointer", "state_value_missing"),
        ("verifier_expected_pointer", "expected_value_missing"),
        ("strict_task", "unknown_world_contract_field"),
        ("provenance_source", "unknown_provenance_source"),
    ],
)
def test_initialization_validates_every_episode_and_cross_reference(
    tmp_path: Path,
    case: str,
    code: str,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    episodes_path = source / "world" / "episodes.jsonl"
    episodes = [json.loads(line) for line in episodes_path.read_text(encoding="utf-8").splitlines()]
    if case == "state_key":
        del episodes[1]["state"]["customer_ticket"]
    elif case == "route_binding_pointer":
        del episodes[1]["state"]["incident"]["data"]["id"]
    elif case == "transition_target_pointer":
        del episodes[1]["state"]["incident"]["data"]["status"]
    elif case == "transition_type":
        episodes[1]["state"]["incident"]["data"]["assignee"] = 1
    elif case == "verifier_expected_pointer":
        del episodes[1]["expected"]["assignee"]
    elif case == "strict_task":
        episodes[1]["task"]["hidden"] = True
    elif case == "provenance_source":
        episodes[1]["provenance"][0]["source_id"] = "missing-source"
    elif case == "transition_source_pointer":
        transitions_path = source / "world" / "transitions.json"
        transitions = json.loads(transitions_path.read_text(encoding="utf-8"))
        transitions["operations"][3]["effects"][0]["source_pointer"] = "/data/missing"
        transitions_path.write_text(json.dumps(transitions), encoding="utf-8")
    elif case == "verifier_state_pointer":
        verifier_path = source / "world" / "verifier.json"
        verifier = json.loads(verifier_path.read_text(encoding="utf-8"))
        verifier["assertions"][0]["pointer"] = "/data/missing"
        verifier_path.write_text(json.dumps(verifier), encoding="utf-8")
    episodes_path.write_text(
        "\n".join(json.dumps(episode) for episode in episodes) + "\n",
        encoding="utf-8",
    )
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == code


def test_verifier_expected_literal_and_pointer_are_mutually_exclusive(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    verifier_path = source / "world" / "verifier.json"
    verifier = json.loads(verifier_path.read_text(encoding="utf-8"))
    verifier["assertions"][0]["expected"] = "also-declared"
    verifier_path.write_text(json.dumps(verifier), encoding="utf-8")
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == "invalid_verifier_expected"


def test_state_values_equal_verifier_contract_is_strict() -> None:
    assertions = parse_verifier(
        {
            "assertions": [
                {
                    "another_pointer": "/ticket/owner",
                    "another_state_key": "customer_ticket",
                    "name": "provider_views_agree",
                    "pointer": "/data/assignee",
                    "state_key": "incident",
                    "type": "state_values_equal",
                }
            ],
            "version": "response_case_verifier_v0",
        }
    )

    assertion = assertions[0]
    assert assertion.assertion_type == "state_values_equal"
    assert assertion.another_state_key == "customer_ticket"
    assert assertion.another_pointer == "/ticket/owner"

    for field, code in (
        ("expected", "unknown_world_contract_field"),
        ("expected_pointer", "unknown_world_contract_field"),
        ("unknown", "unknown_world_contract_field"),
    ):
        raw = {
            "another_pointer": "/ticket/owner",
            "another_state_key": "customer_ticket",
            "name": "provider_views_agree",
            "pointer": "/data/assignee",
            "state_key": "incident",
            "type": "state_values_equal",
            field: True,
        }
        with pytest.raises(WorldContractError) as raised:
            parse_verifier(
                {
                    "assertions": [raw],
                    "version": "response_case_verifier_v0",
                }
            )
        assert raised.value.code == code

    with pytest.raises(WorldContractError) as raised:
        parse_verifier(
            {
                "assertions": [
                    {
                        "another_state_key": "customer_ticket",
                        "name": "provider_views_agree",
                        "pointer": "/data/assignee",
                        "state_key": "incident",
                        "type": "state_values_equal",
                    }
                ],
                "version": "response_case_verifier_v0",
            }
        )
    assert raised.value.code == "missing_world_contract_field"


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("first_state_key", "state_key_missing"),
        ("another_state_key", "state_key_missing"),
        ("first_pointer", "state_value_missing"),
        ("another_pointer", "state_value_missing"),
        ("type", "state_type_mismatch"),
    ],
)
def test_state_values_equal_initialization_validates_every_episode(
    tmp_path: Path,
    case: str,
    code: str,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    verifier_path = source / "world" / "verifier.json"
    verifier = json.loads(verifier_path.read_text(encoding="utf-8"))
    verifier["assertions"].append(
        {
            "another_pointer": "/ticket/owner",
            "another_state_key": "customer_ticket",
            "name": "provider_views_agree",
            "pointer": "/data/assignee",
            "state_key": "incident",
            "type": "state_values_equal",
        }
    )
    assertion = verifier["assertions"][-1]
    if case == "first_state_key":
        assertion["state_key"] = "missing_state"
    elif case == "another_state_key":
        assertion["another_state_key"] = "missing_state"
    elif case == "first_pointer":
        assertion["pointer"] = "/data/missing"
    elif case == "another_pointer":
        assertion["another_pointer"] = "/ticket/missing"
    verifier_path.write_text(json.dumps(verifier), encoding="utf-8")
    episodes_path = source / "world" / "episodes.jsonl"
    episodes = [json.loads(line) for line in episodes_path.read_text().splitlines()]
    if case == "type":
        episodes[1]["state"]["customer_ticket"]["ticket"]["owner"] = 1
    episodes_path.write_text(
        "\n".join(json.dumps(episode) for episode in episodes) + "\n",
        encoding="utf-8",
    )
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == code


def test_operation_not_attempted_verifier_contract_is_strict() -> None:
    assertions = parse_verifier(
        {
            "assertions": [
                {
                    "name": "external_send_not_attempted",
                    "operation_id": "send_customer_draft",
                    "type": "operation_not_attempted",
                }
            ],
            "version": "response_case_verifier_v0",
        }
    )

    assert assertions[0].assertion_type == "operation_not_attempted"
    assert assertions[0].operation_id == "send_customer_draft"

    with pytest.raises(WorldContractError) as raised:
        parse_verifier(
            {
                "assertions": [
                    {
                        "expected": True,
                        "name": "external_send_not_attempted",
                        "operation_id": "send_customer_draft",
                        "type": "operation_not_attempted",
                    }
                ],
                "version": "response_case_verifier_v0",
            }
        )

    assert raised.value.code == "unknown_world_contract_field"


def test_operation_not_attempted_requires_a_declared_route_operation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(EXAMPLE_ROOT, source)
    verifier_path = source / "world" / "verifier.json"
    verifier = json.loads(verifier_path.read_text(encoding="utf-8"))
    verifier["assertions"].append(
        {
            "name": "unknown_operation_not_attempted",
            "operation_id": "undeclared_operation",
            "type": "operation_not_attempted",
        }
    )
    verifier_path.write_text(json.dumps(verifier), encoding="utf-8")
    config = load_gate_config(source / "gate_config.json")
    assert isinstance(config.world, ResponseCaseStateWorldConfig)

    with pytest.raises(WorldContractError) as raised:
        initialize_world(run_dir=tmp_path / "run", config=config.world, source_dir=source)

    assert raised.value.code == "undeclared_verifier_operation"


def test_semantic_verifier_assertions_parse_strictly() -> None:
    assertions = parse_verifier(
        {
            "assertions": [
                {
                    "expected": ["OPS-100", "10:30 UTC"],
                    "name": "draft_facts",
                    "pointer": "/body/content",
                    "state_key": "draft",
                    "type": "state_text_contains_all",
                },
                {
                    "expected": ["oncall@example.test", "success@example.test"],
                    "item_pointer": "/emailAddress/address",
                    "name": "internal_recipients",
                    "pointer": "/toRecipients",
                    "state_key": "draft",
                    "type": "state_array_projection_equals_unordered",
                },
            ],
            "version": "response_case_verifier_v0",
        }
    )

    assert assertions[0].assertion_type == "state_text_contains_all"
    assert assertions[1].item_pointer == "/emailAddress/address"


@pytest.mark.parametrize(
    "assertion",
    [
        {
            "expected": "OPS-100",
            "name": "draft_facts",
            "pointer": "/body/content",
            "state_key": "draft",
            "type": "state_text_contains_all",
        },
        {
            "expected": [{"address": "oncall@example.test"}],
            "item_pointer": "/emailAddress/address",
            "name": "internal_recipients",
            "pointer": "/toRecipients",
            "state_key": "draft",
            "type": "state_array_projection_equals_unordered",
        },
        {
            "expected": ["oncall@example.test"],
            "item_pointer": "",
            "name": "internal_recipients",
            "pointer": "/toRecipients",
            "state_key": "draft",
            "type": "state_array_projection_equals_unordered",
        },
    ],
)
def test_semantic_verifier_assertions_reject_malformed_contracts(assertion: dict) -> None:
    with pytest.raises(WorldContractError) as raised:
        parse_verifier(
            {
                "assertions": [assertion],
                "version": "response_case_verifier_v0",
            }
        )

    assert raised.value.code in {"invalid_verifier_expected", "invalid_verifier_projection"}
