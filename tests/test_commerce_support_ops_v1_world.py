from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping

import pytest
from fastapi.testclient import TestClient

from datalox_gated_runtime.cli import _session_finalize
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.mcp_server import build_server
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.session import create_session
from datalox_gated_runtime.world_v1.bundle import load_world_bundle, validate_world_bundle
from datalox_gated_runtime.world_v1.backend import (
    WorldBundleBackend,
    initialize_world_bundle_session,
)
from datalox_gated_runtime.world_v1.contracts import ActorContext
from datalox_gated_runtime.world_v1.errors import WorldAuthorizationError
from datalox_gated_runtime.world_v1.session import WorldSession


ROOT = Path(__file__).resolve().parents[1]
ENV_DIR = ROOT / "envs" / "commerce_support_ops_v0"
BUILDER = ROOT / "scripts" / "worlds" / "build_commerce_support_ops.py"
TRAJECTORIES_PATH = ENV_DIR / "tests" / "trajectories" / "trajectories.json"


@pytest.fixture(scope="module")
def bundle():
    return load_world_bundle(ENV_DIR)


@pytest.fixture(scope="module")
def trajectories() -> list[dict[str, Any]]:
    return json.loads(TRAJECTORIES_PATH.read_text(encoding="utf-8"))["trajectories"]


def test_builder_is_deterministic_and_materializes_only_declared_files() -> None:
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "14 files" in result.stdout
    actual = {
        path.relative_to(ENV_DIR).as_posix()
        for path in ENV_DIR.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.name != "world_admission.json"
    }
    assert actual == {
        "gate_config.json",
        "replay_script.json",
        "skills/SKILL.md",
        "skills/references/commerce-policy.md",
        "task.json",
        "tests/trajectories/trajectories.json",
        "world/episodes.jsonl",
        "world/implementation.py",
        "world/manifest.json",
        "world/policies/commerce_policy.json",
        "world/roles.json",
        "world/sources.json",
        "world/tools.json",
        "world/verifier.json",
    }


def test_bundle_contract_has_exactly_twenty_deterministic_episodes_and_four_roles() -> None:
    validated = validate_world_bundle(ENV_DIR)

    assert validated.manifest.schema_version == "datalox_world_bundle_v1"
    assert validated.manifest.world_id == "commerce_support_ops_v0"
    assert len(validated.episodes) == 20
    assert [episode["seed"] for episode in validated.episodes] == list(range(20))
    assert len({episode["id"] for episode in validated.episodes}) == 20
    assert len({episode["task"]["task_id"] for episode in validated.episodes}) == 20
    assert {role.id for role in validated.roles} == {
        "billing_specialist",
        "support_owner",
        "engineering_owner",
        "communications_owner",
    }


def test_each_episode_has_cross_system_state_distractors_without_oracle_instructions(
    bundle,
) -> None:
    for episode in bundle.episodes:
        state = episode["initial_state"]
        assert set(state) >= {"billing", "orders", "crm", "engineering", "calendar", "oracle"}
        assert len(state["billing"]["customers"]) >= 2
        assert len(state["billing"]["payment_intents"]) >= 2
        assert len(state["orders"]["orders"]) >= 2
        assert len(state["crm"]["tickets"]) >= 2
        assert len(state["crm"]["companies"]) >= 2
        assert len(state["engineering"]["issues"]) >= 2
        task_text = json.dumps(episode["task"], sort_keys=True)
        oracle = state["oracle"]
        for hidden_value in (
            oracle["customer_id"],
            oracle["order_id"],
            oracle["payment_intent_id"],
            oracle["ticket_id"],
            oracle["issue_id"],
            str(oracle["refund_amount"]),
        ):
            assert hidden_value not in task_text


def test_role_scoped_tool_catalog_hides_and_denies_refund_for_support(bundle) -> None:
    catalog = bundle.tool_catalog
    support = ActorContext("support-agent", "support_owner")
    billing = ActorContext("billing-agent", "billing_specialist")

    assert "stripe.create_refund" not in {tool.id for tool in catalog.list_for(support)}
    assert "stripe.create_refund" in {tool.id for tool in catalog.list_for(billing)}
    with pytest.raises(WorldAuthorizationError) as raised:
        catalog.require_invocation(support, "stripe.create_refund")
    assert raised.value.code == "world_tool_hidden"


def test_every_reference_trajectory_passes_in_a_fresh_real_session(
    tmp_path: Path,
    bundle,
    trajectories: list[dict[str, Any]],
) -> None:
    references = [item for item in trajectories if item["kind"] == "reference"]
    assert len(references) == 20

    for trajectory in references:
        with WorldSession(tmp_path / f"{trajectory['id']}.sqlite") as session:
            result = _execute_trajectory(bundle, session, trajectory)
            assert result.passed is True, (trajectory["id"], result.to_dict())
            assert result.failure_codes == ()
            export = session.export()
            assert export["episode_id"] == trajectory["episode_id"]
            assert export["simulation_time"] == "2026-07-17T10:00:00+00:00"
            assert export["artifacts"][0]["kind"] == "internal_coordination_draft"
            assert export["artifacts"][0]["evidence_refs"]
            assert export["handoffs"][0]["status"] == "committed"


def test_declared_negative_trajectories_fail_for_only_the_declared_code(
    tmp_path: Path,
    bundle,
    trajectories: list[dict[str, Any]],
) -> None:
    negatives = [item for item in trajectories if item["kind"] == "negative"]
    assert {item["id"] for item in negatives} == {
        "wrong-entity",
        "wrong-amount",
        "stale-evidence",
        "unsafe-action",
        "unauthorized-role",
        "missing-no-call",
        "missing-required-read",
    }

    for trajectory in negatives:
        with WorldSession(tmp_path / f"{trajectory['id']}.sqlite") as session:
            result = _execute_trajectory(bundle, session, trajectory)
            assert result.passed is False
            assert set(result.failure_codes) == set(trajectory["expected"]["failure_codes"]), (
                trajectory["id"],
                result.to_dict(),
            )


def test_http_and_mcp_projection_mutate_identical_state_for_four_operation_families(
    tmp_path: Path,
    bundle,
    trajectories: list[dict[str, Any]],
) -> None:
    parity_cases = [item for item in trajectories if item["kind"] == "parity"]
    assert {item["id"] for item in parity_cases} == {
        "parity-refund",
        "parity-ticket",
        "parity-jira",
        "parity-draft",
    }

    for case in parity_cases:
        episode = bundle.episode(case["episode_id"])
        http_step = case["http_step"]
        mcp_step = case["mcp_step"]
        with WorldSession(tmp_path / f"{case['id']}-http.sqlite") as http_session:
            bundle.implementation.initialize_episode(session=http_session, episode=episode)
            _execute_http_step(bundle, http_session, http_step)
            http_fingerprint = _state_fingerprint(http_session)
        with WorldSession(tmp_path / f"{case['id']}-mcp.sqlite") as mcp_session:
            bundle.implementation.initialize_episode(session=mcp_session, episode=episode)
            actor = ActorContext("parity-agent", mcp_step["actor_role"])
            request = bundle.implementation.request_for_tool(
                mcp_step["tool_name"], mcp_step["arguments"], actor=actor
            )
            _execute_request(bundle, mcp_session, actor, request)
            mcp_fingerprint = _state_fingerprint(mcp_session)
        assert http_fingerprint == mcp_fingerprint, case["id"]


def test_installed_runtime_exposes_tools_without_copying_hidden_authoring_files(
    tmp_path: Path,
) -> None:
    http_run = tmp_path / "installed-http"
    mcp_run = tmp_path / "installed-mcp"
    episode_id = "refund-duplicate-payment-clean"
    initialize_world_bundle_session(
        source_bundle_dir=ENV_DIR, run_dir=http_run, episode_id=episode_id
    )
    initialize_world_bundle_session(
        source_bundle_dir=ENV_DIR, run_dir=mcp_run, episode_id=episode_id
    )

    copied_files = {
        path.relative_to(http_run).as_posix() for path in http_run.rglob("*") if path.is_file()
    }
    assert not any(
        forbidden in path
        for path in copied_files
        for forbidden in ("episodes", "sources", "verifier", "trajectories")
    )
    assert any(path.endswith("implementation.py") for path in copied_files)

    actor = ActorContext("billing-parity", "billing_specialist")
    body = {
        "customer_id": "cus-00-primary",
        "order_id": "ord-00-primary",
        "payment_intent_id": "pi-00-eligible",
        "amount": 1500,
        "currency": "usd",
    }
    http_backend = WorldBundleBackend(run_dir=http_run)
    mcp_backend = WorldBundleBackend(run_dir=mcp_run)
    try:
        assert "stripe.create_refund" in http_backend.tool_schemas(actor)
        http_response = http_backend.handle(
            CallRequest(
                method="POST",
                path="/v1/refunds",
                body=body,
                headers={
                    "x-datalox-actor-id": actor.actor_id,
                    "x-datalox-actor-role": actor.role,
                },
            )
        )
        mcp_request = mcp_backend.request_for_tool("stripe.create_refund", body, actor=actor)
        mcp_response = mcp_backend.handle(mcp_request)
        assert http_response is not None and mcp_response is not None
        assert http_response.to_dict() if hasattr(http_response, "to_dict") else http_response.body
        assert http_response.body == mcp_response.body
        assert _state_fingerprint(http_backend.session) == _state_fingerprint(mcp_backend.session)
    finally:
        http_backend.close()
        mcp_backend.close()


def test_gate_config_and_real_session_creation_select_episode_by_seed(
    tmp_path: Path, monkeypatch
) -> None:
    config = load_gate_config(ENV_DIR / "gate_config.json")
    assert config.world is not None
    assert config.world.kind == "world_bundle_v1"
    assert config.world.seed == 0

    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(ENV_DIR.parent))
    run_dir = tmp_path / "created-session"
    manifest = create_session(
        example="commerce_support_ops_v0",
        out_dir=run_dir,
        http_port=8765,
        seed=21,
    )
    assert manifest.expected_surfaces == ["http", "mcp"]
    backend = WorldBundleBackend(run_dir=run_dir)
    try:
        assert backend.session.episode_id == "refund-partial-shipping-failure"
        assert backend.task() is not None
        assert backend.task().task_id == "commerce-support-ops-01"
    finally:
        backend.close()


def test_real_http_adapter_serves_role_scoped_world_state(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(ENV_DIR.parent))
    run_dir = tmp_path / "http-session"
    create_session(
        example="commerce_support_ops_v0",
        out_dir=run_dir,
        http_port=8765,
        seed=0,
    )

    with TestClient(create_app(run_dir)) as client:
        response = client.get(
            "/v1/customers",
            headers={
                "x-datalox-actor-id": "billing-1",
                "x-datalox-actor-role": "billing_specialist",
            },
        )

    assert response.status_code == 200
    assert response.json()["object"] == "list"
    assert len(response.json()["data"]) >= 2


def test_real_http_reference_finalizes_with_world_export(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(ENV_DIR.parent))
    run_dir = tmp_path / "finalized-http-session"
    create_session(
        example="commerce_support_ops_v0",
        out_dir=run_dir,
        http_port=8765,
        seed=0,
    )
    trajectory = next(
        item
        for item in json.loads(TRAJECTORIES_PATH.read_text(encoding="utf-8"))["trajectories"]
        if item["kind"] == "reference" and item["episode_id"] == "refund-duplicate-payment-clean"
    )

    with TestClient(create_app(run_dir)) as client:
        for step in trajectory["steps"]:
            response = client.request(
                step["method"],
                step["path"],
                json=step.get("body"),
                headers={
                    "x-datalox-actor-id": f"test-{step['actor_role']}",
                    "x-datalox-actor-role": step["actor_role"],
                },
            )
            assert response.status_code < 400, response.text

    exit_code = _session_finalize(argparse.Namespace(run=str(run_dir), json=True))
    audit = json.loads(capsys.readouterr().out)
    run_export = json.loads((run_dir / "run_export.json").read_text(encoding="utf-8"))

    assert exit_code == 0
    assert audit["passed"] is True
    assert run_export["world"]["world_id"] == "commerce_support_ops_v0"
    assert run_export["world"]["verification"]["passed"] is True
    assert run_export["world"]["artifacts"][0]["source_artifact_ids"] == []
    assert run_export["world"]["handoffs"][0]["status"] == "committed"


def test_real_mcp_adapter_filters_tools_by_configured_actor_and_executes(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("DATALOX_GATE_EXAMPLES_DIR", str(ENV_DIR.parent))
    run_dir = tmp_path / "mcp-session"
    create_session(
        example="commerce_support_ops_v0",
        out_dir=run_dir,
        http_port=8765,
        seed=0,
    )
    server = build_server(
        run_dir,
        actor_context=ActorContext("support-1", "support_owner"),
    )
    names = {tool.name for tool in server._tool_manager.list_tools()}

    assert "hubspot.update_ticket" in names
    assert "stripe.create_refund" not in names
    result = asyncio.run(server.call_tool("commerce.list_orders", {}))
    content_blocks = result[0] if isinstance(result, tuple) else result
    payload = json.loads(content_blocks[0].text)
    assert payload["status_code"] == 200
    assert len(payload["body"]["orders"]) >= 2


def test_fresh_reset_is_seed_isolated_and_deterministic(tmp_path: Path, bundle) -> None:
    episode = bundle.episodes[3]
    exports = []
    for index in range(2):
        with WorldSession(tmp_path / f"reset-{index}.sqlite") as session:
            bundle.implementation.initialize_episode(session=session, episode=episode)
            exports.append(session.export())

    assert exports[0] == exports[1]
    other = bundle.episodes[4]
    with WorldSession(tmp_path / "other.sqlite") as session:
        bundle.implementation.initialize_episode(session=session, episode=other)
        assert session.episode_id != episode["id"]
        assert (
            session.get_state("oracle")["customer_id"]
            != episode["initial_state"]["oracle"]["customer_id"]
        )


def test_forbidden_send_cancel_capture_and_delete_are_denied_and_recorded(
    tmp_path: Path, bundle
) -> None:
    episode = bundle.episodes[0]
    cases = (
        ("communications_owner", "POST", "/me/sendMail", "graph.send_message"),
        (
            "support_owner",
            "POST",
            "/commerce/orders/ord-00-primary/cancel",
            "commerce.cancel_order",
        ),
        (
            "billing_specialist",
            "POST",
            "/v1/payment_intents/pi-00-eligible/capture",
            "stripe.capture_payment",
        ),
        ("support_owner", "DELETE", "/commerce/orders/ord-00-primary", "commerce.delete_order"),
    )
    with WorldSession(tmp_path / "denials.sqlite") as session:
        bundle.implementation.initialize_episode(session=session, episode=episode)
        for role, method, path, operation in cases:
            actor = ActorContext(f"agent-{role}", role)
            response = _execute_request(
                bundle, session, actor, CallRequest(method=method, path=path, body={})
            )
            assert response is not None
            assert response.status_code == 403
            assert response.operation_id == operation
            assert response.reason_code == "unsafe_action_attempted"
        denied = [
            event
            for event in session.list_events()
            if event["type"] == "commerce_operation" and event["payload"]["decision"] == "deny"
        ]
        assert len(denied) == 4


def _execute_trajectory(bundle, session: WorldSession, trajectory: Mapping[str, Any]):
    episode = bundle.episode(trajectory["episode_id"])
    bundle.implementation.initialize_episode(session=session, episode=episode)
    for step in trajectory["steps"]:
        _execute_http_step(bundle, session, step)
    return bundle.implementation.verify(session=session, episode=episode)


def _execute_http_step(bundle, session: WorldSession, step: Mapping[str, Any]):
    actor = ActorContext(f"agent-{step['actor_role']}", step["actor_role"])
    request = CallRequest(method=step["method"], path=step["path"], body=step.get("body"))
    return _execute_request(bundle, session, actor, request)


def _execute_request(bundle, session: WorldSession, actor: ActorContext, request: CallRequest):
    tool_id = bundle.implementation.tool_for_request(request)
    assert tool_id is not None
    try:
        bundle.tool_catalog.require_invocation(actor, tool_id)
    except WorldAuthorizationError as exc:
        session.record_denied_tool_attempt(
            actor=actor,
            tool_id=tool_id,
            arguments=request.body if isinstance(request.body, dict) else {},
            reason_code=exc.code,
        )
        return None
    with session.transaction(operation_id=tool_id, actor=actor):
        return bundle.implementation.handle(request, actor=actor, session=session)


def _state_fingerprint(session: WorldSession) -> str:
    return json.dumps(
        {
            "state": session.list_state(),
            "artifacts": session.list_artifacts(),
            "handoffs": session.list_handoffs(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
