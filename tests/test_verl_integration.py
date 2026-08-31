from __future__ import annotations

import asyncio
import copy
import importlib
import importlib.util
import io
import json
import subprocess
import sys
import types
import urllib.error
from email.message import Message
from pathlib import Path
from typing import Any, ClassVar

import pytest

from datalox_gated_runtime.rollout.pool import RolloutExecResult, RolloutPoolError
from datalox_gated_runtime.rollout.verl import (
    VerlRolloutContractError,
    current_verl_rollout_execution,
    extract_verl_rollout_identity,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "integrations" / "verl"


def test_core_package_and_rollout_import_without_verl() -> None:
    script = """
import sys
import datalox_gated_runtime
import datalox_gated_runtime.rollout
assert not any(name == 'verl' or name.startswith('verl.') for name in sys.modules)
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_direct_adapter_import_without_verl_fails_clearly() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import datalox_gated_runtime.integrations.verl"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "requires the veRL training environment" in result.stderr


@pytest.mark.parametrize(
    ("fields", "code"),
    [
        ({}, "verl_uid_invalid"),
        (
            {"uid": True, "session_id": 0, "extra_info": {"datalox": {"seed": 1}}},
            "verl_uid_invalid",
        ),
        (
            {"uid": " uid", "session_id": 0, "extra_info": {"datalox": {"seed": 1}}},
            "verl_uid_invalid",
        ),
        (
            {"uid": "x" * 257, "session_id": 0, "extra_info": {"datalox": {"seed": 1}}},
            "verl_uid_invalid",
        ),
        (
            {"uid": "uid", "session_id": True, "extra_info": {"datalox": {"seed": 1}}},
            "verl_session_id_invalid",
        ),
        (
            {"uid": "uid", "session_id": -1, "extra_info": {"datalox": {"seed": 1}}},
            "verl_session_id_invalid",
        ),
        ({"uid": "uid", "session_id": 0}, "verl_extra_info_invalid"),
        (
            {"uid": "uid", "session_id": 0, "extra_info": {}},
            "verl_datalox_metadata_invalid",
        ),
        (
            {
                "uid": "uid",
                "session_id": 0,
                "extra_info": {"datalox": {"seed": 1, "derived": True}},
            },
            "verl_datalox_metadata_invalid",
        ),
        (
            {"uid": "uid", "session_id": 0, "extra_info": {"datalox": {"seed": 1, 2: 3}}},
            "verl_datalox_metadata_invalid",
        ),
        (
            {"uid": "uid", "session_id": 0, "extra_info": {"datalox": {"seed": True}}},
            "verl_environment_seed_invalid",
        ),
    ],
)
def test_strict_verl_identity_rejects_malformed_values(fields: dict[str, Any], code: str) -> None:
    with pytest.raises(VerlRolloutContractError) as failed:
        extract_verl_rollout_identity(fields)
    assert failed.value.code == code


def test_rollout_n_siblings_share_explicit_seed_but_not_session_identity() -> None:
    siblings = [
        extract_verl_rollout_identity(
            {
                "uid": "trainer-generated-uid",
                "session_id": session_id,
                "extra_info": {"datalox": {"seed": 73}},
            }
        )
        for session_id in range(8)
    ]
    assert {identity.session_id for identity in siblings} == set(range(8))
    assert {identity.environment_seed for identity in siblings} == {73}
    assert len({(identity.uid, identity.session_id) for identity in siblings}) == 8


class _Output:
    def __init__(self) -> None:
        self.prompt_ids = [1, 2]
        self.response_ids = [3, 4]
        self.response_mask = [1, 0]
        self.response_logprobs = [-0.2, -0.3]
        self.reward_score = 0.75
        self.metrics = {"tool_calls": 1.0}
        self.extra_fields = {"owner": "verl"}


class _FakeLease:
    def __init__(self, *, finalize_error: bool = False) -> None:
        self.state = "active"
        self.commands: list[tuple[str, tuple[str, ...]]] = []
        self.finalize_calls = 0
        self.cancel_calls = 0
        self.finalize_error = finalize_error

    async def exec(self, *, task_image: str, command: tuple[str, ...]) -> RolloutExecResult:
        self.commands.append((task_image, command))
        return RolloutExecResult("lease", len(self.commands) - 1, 0, '{"ok":true}', "")

    async def finalize(self) -> object:
        self.finalize_calls += 1
        if self.finalize_error:
            raise RolloutPoolError("finalize_failed", "finalize failed", 500)
        self.state = "finalized"
        return object()

    async def cancel(self) -> None:
        self.cancel_calls += 1
        self.state = "cancelled"


class _FakePoolClient:
    instances: ClassVar[list[_FakePoolClient]] = []
    next_lease: ClassVar[_FakeLease | None] = None

    def __init__(self, *, socket_path: Path, token_path: Path) -> None:
        self.socket_path = socket_path
        self.token_path = token_path
        self.acquisitions: list[tuple[str, int, int]] = []
        self.closed = False
        self.lease = self.__class__.next_lease or _FakeLease()
        self.__class__.next_lease = None
        self.__class__.instances.append(self)

    async def acquire(self, *, uid: str, session_id: int, environment_seed: int) -> _FakeLease:
        self.acquisitions.append((uid, session_id, environment_seed))
        return self.lease

    async def aclose(self) -> None:
        self.closed = True


def _load_adapter(monkeypatch: pytest.MonkeyPatch, behavior: Any) -> Any:
    class FakeToolAgentLoop:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.initialized_with = (args, kwargs)

        async def run(self, sampling_params: dict[str, Any], **dataset_fields: Any) -> Any:
            return await behavior(sampling_params, dataset_fields)

    agent_loop_module = types.ModuleType("verl.experimental.agent_loop.agent_loop")
    agent_loop_module.AgentLoopOutput = _Output
    tool_loop_module = types.ModuleType("verl.experimental.agent_loop.tool_agent_loop")
    tool_loop_module.ToolAgentLoop = FakeToolAgentLoop
    modules = {
        "verl": types.ModuleType("verl"),
        "verl.experimental": types.ModuleType("verl.experimental"),
        "verl.experimental.agent_loop": types.ModuleType("verl.experimental.agent_loop"),
        "verl.experimental.agent_loop.agent_loop": agent_loop_module,
        "verl.experimental.agent_loop.tool_agent_loop": tool_loop_module,
    }
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)
    sys.modules.pop("datalox_gated_runtime.integrations.verl", None)
    adapter = importlib.import_module("datalox_gated_runtime.integrations.verl")
    monkeypatch.setattr(adapter, "RolloutPoolClient", _FakePoolClient)
    _FakePoolClient.instances.clear()
    _FakePoolClient.next_lease = None
    return adapter


def _dataset_fields() -> dict[str, Any]:
    return {
        "uid": "uid-1",
        "session_id": 4,
        "raw_prompt": [{"role": "user", "content": "call provider"}],
        "agent_name": "datalox_tool_agent",
        "extra_info": {"datalox": {"seed": 29}},
    }


def test_adapter_preserves_output_and_context_propagates_to_child_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _Output()
    snapshot = copy.deepcopy(vars(output))

    async def behavior(_: dict[str, Any], __: dict[str, Any]) -> _Output:
        async def tool_task() -> None:
            await current_verl_rollout_execution().exec(("provider-call", "strict-json"))

        await asyncio.create_task(tool_task())
        return output

    adapter = _load_adapter(monkeypatch, behavior)
    loop = adapter.DataloxToolAgentLoop(
        pool_socket_path="/run/datalox/pool.sock",
        pool_token_path="/run/datalox/pool.sock.token",
        task_image="consumer/provider-call:fixed",
    )

    result = asyncio.run(loop.run({"temperature": 1.0}, **_dataset_fields()))

    client = _FakePoolClient.instances[0]
    assert result is output
    assert vars(output) == snapshot
    assert client.acquisitions == [("uid-1", 4, 29)]
    assert client.lease.commands == [
        ("consumer/provider-call:fixed", ("provider-call", "strict-json"))
    ]
    assert client.lease.finalize_calls == 1
    assert client.lease.cancel_calls == 0
    assert client.closed is True
    with pytest.raises(VerlRolloutContractError) as missing:
        current_verl_rollout_execution()
    assert missing.value.code == "verl_rollout_context_missing"


@pytest.mark.parametrize("failure", [RuntimeError("agent failed"), asyncio.CancelledError()])
def test_adapter_cancels_on_super_failure_or_cancellation(
    monkeypatch: pytest.MonkeyPatch, failure: BaseException
) -> None:
    observed_context = False

    async def behavior(_: dict[str, Any], __: dict[str, Any]) -> _Output:
        nonlocal observed_context
        observed_context = current_verl_rollout_execution() is not None
        raise failure

    adapter = _load_adapter(monkeypatch, behavior)
    loop = adapter.DataloxToolAgentLoop(
        pool_socket_path="/run/datalox/pool.sock",
        pool_token_path="/run/datalox/pool.sock.token",
        task_image="consumer/provider-call:fixed",
    )
    with pytest.raises(type(failure)):
        asyncio.run(loop.run({}, **_dataset_fields()))

    client = _FakePoolClient.instances[0]
    assert observed_context is True
    assert client.lease.finalize_calls == 0
    assert client.lease.cancel_calls == 1
    assert client.closed is True
    with pytest.raises(VerlRolloutContractError):
        current_verl_rollout_execution()


def test_adapter_cancels_if_finalize_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    output = _Output()

    async def behavior(_: dict[str, Any], __: dict[str, Any]) -> _Output:
        return output

    adapter = _load_adapter(monkeypatch, behavior)
    _FakePoolClient.next_lease = _FakeLease(finalize_error=True)
    loop = adapter.DataloxToolAgentLoop(
        pool_socket_path="/run/datalox/pool.sock",
        pool_token_path="/run/datalox/pool.sock.token",
        task_image="consumer/provider-call:fixed",
    )
    with pytest.raises(RolloutPoolError, match="finalize failed"):
        asyncio.run(loop.run({}, **_dataset_fields()))
    lease = _FakePoolClient.instances[0].lease
    assert lease.finalize_calls == 1
    assert lease.cancel_calls == 1


def test_adapter_cancellation_during_acquire_settles_then_cleans_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def behavior(_: dict[str, Any], __: dict[str, Any]) -> _Output:
        pytest.fail("veRL loop must not start after acquire cancellation")

    adapter = _load_adapter(monkeypatch, behavior)

    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        class SlowPoolClient(_FakePoolClient):
            async def acquire(
                self, *, uid: str, session_id: int, environment_seed: int
            ) -> _FakeLease:
                started.set()
                await release.wait()
                return await super().acquire(
                    uid=uid,
                    session_id=session_id,
                    environment_seed=environment_seed,
                )

        monkeypatch.setattr(adapter, "RolloutPoolClient", SlowPoolClient)
        loop = adapter.DataloxToolAgentLoop(
            pool_socket_path="/run/datalox/pool.sock",
            pool_token_path="/run/datalox/pool.sock.token",
            task_image="consumer/provider-call:fixed",
        )
        running = asyncio.create_task(loop.run({}, **_dataset_fields()))
        await started.wait()
        running.cancel()
        await asyncio.sleep(0)
        assert running.done() is False
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
        client = _FakePoolClient.instances[0]
        assert client.lease.cancel_calls == 1
        assert client.closed is True

    asyncio.run(scenario())


def test_adapter_cancellation_during_finalize_waits_for_owned_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = _Output()

    async def behavior(_: dict[str, Any], __: dict[str, Any]) -> _Output:
        return output

    adapter = _load_adapter(monkeypatch, behavior)

    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        class SlowFinalizeLease(_FakeLease):
            async def finalize(self) -> object:
                self.finalize_calls += 1
                started.set()
                await release.wait()
                self.state = "finalized"
                return object()

        lease = SlowFinalizeLease()
        _FakePoolClient.next_lease = lease
        loop = adapter.DataloxToolAgentLoop(
            pool_socket_path="/run/datalox/pool.sock",
            pool_token_path="/run/datalox/pool.sock.token",
            task_image="consumer/provider-call:fixed",
        )
        running = asyncio.create_task(loop.run({}, **_dataset_fields()))
        await started.wait()
        running.cancel()
        await asyncio.sleep(0)
        assert running.done() is False
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running
        assert lease.finalize_calls == 1
        assert lease.cancel_calls == 0
        assert lease.state == "finalized"
        assert _FakePoolClient.instances[0].closed is True

    asyncio.run(scenario())


def test_context_execution_rejects_task_image_selection_through_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def behavior(_: dict[str, Any], __: dict[str, Any]) -> _Output:
        execution = current_verl_rollout_execution()
        with pytest.raises(TypeError):
            await execution.exec(task_image="model-selected", command=("call",))
        return _Output()

    adapter = _load_adapter(monkeypatch, behavior)
    loop = adapter.DataloxToolAgentLoop(
        pool_socket_path="/run/datalox/pool.sock",
        pool_token_path="/run/datalox/pool.sock.token",
        task_image="consumer/provider-call:fixed",
    )
    asyncio.run(loop.run({}, **_dataset_fields()))


def _load_provider_dispatcher() -> Any:
    path = EXAMPLE / "provider_call.py"
    spec = importlib.util.spec_from_file_location("datalox_verl_provider_call_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_provider_dispatcher_hard_fails_malformed_input(capsys: pytest.CaptureFixture[str]) -> None:
    dispatcher = _load_provider_dispatcher()
    assert dispatcher.main(["{}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "request fields must be exactly" in captured.err


def test_provider_dispatcher_emits_http_error_as_observation(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    dispatcher = _load_provider_dispatcher()
    headers = Message()
    headers["Content-Type"] = "application/json"
    provider_error = urllib.error.HTTPError(
        "https://api.example.com/v1/records",
        409,
        "Conflict",
        headers,
        io.BytesIO(b'{"error":"duplicate"}'),
    )

    class Opener:
        def open(self, _: object, *, timeout: int) -> object:
            assert timeout == 30
            raise provider_error

    monkeypatch.setattr(dispatcher.urllib.request, "build_opener", lambda *args: Opener())
    request = json.dumps(
        {
            "method": "POST",
            "url": "https://api.example.com/v1/records",
            "headers": {},
            "body_base64": "",
            "timeout_seconds": 30,
        }
    )
    assert dispatcher.main([request]) == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope == {
        "body_base64": "eyJlcnJvciI6ImR1cGxpY2F0ZSJ9",
        "error": None,
        "headers": [["Content-Type", "application/json"]],
        "schema_version": "datalox_provider_https_result_v1",
        "status_code": 409,
        "transport_ok": True,
    }


def test_examples_match_current_verl_agent_loop_and_grpo_contract() -> None:
    agent_loop = (EXAMPLE / "agent_loop.yaml").read_text(encoding="utf-8")
    launch = (EXAMPLE / "launch_fragment.sh").read_text(encoding="utf-8")
    tools = (EXAMPLE / "provider_tools.py").read_text(encoding="utf-8")
    row = json.loads((EXAMPLE / "agent_loop_rows.jsonl").read_text(encoding="utf-8"))

    assert "_target_: datalox_gated_runtime.integrations.verl.DataloxToolAgentLoop" in agent_loop
    assert "pool_socket_path: /run/datalox/rollout-pool.sock" in agent_loop
    assert "pool_token_path: /run/datalox/rollout-pool.sock.token" in agent_loop
    assert "task_image: datalox-verl-provider-call:example" in agent_loop
    for fragment in (
        "trainer.use_v1=true",
        "algorithm.adv_estimator=grpo",
        "actor_rollout_ref.rollout.n=8",
        "actor_rollout_ref.rollout.agent.num_workers=8",
        "actor_rollout_ref.rollout.agent.default_agent_loop=datalox_tool_agent",
        "actor_rollout_ref.rollout.agent.agent_loop_config_path=",
        "actor_rollout_ref.rollout.multi_turn.tool_config_path=null",
        "actor_rollout_ref.rollout.multi_turn.function_tool_path=",
    ):
        assert fragment in launch
    assert "https://api.example.com/v1/records" in tools
    exact_provider_url = "https://api.example.com/v1/records"
    assert "datalox" not in exact_provider_url
    assert set(row) == {"uid", "session_id", "raw_prompt", "agent_name", "extra_info"}
    assert row["session_id"] == 0
    assert isinstance(row["uid"], str) and row["uid"]
    assert set(row["extra_info"]["datalox"]) == {"seed"}


def test_pool_serve_cli_has_exact_current_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    from datalox_gated_runtime import cli

    captured: dict[str, Any] = {}

    class FakePool:
        def __init__(self, **kwargs: Any) -> None:
            captured["pool"] = kwargs

    async def fake_serve(*, pool: object, socket_path: Path) -> None:
        captured["serve"] = (pool, socket_path)

    monkeypatch.setattr(cli, "RolloutPool", FakePool)
    monkeypatch.setattr(cli, "serve_rollout_pool", fake_serve)
    arguments = cli._build_parser().parse_args(
        [
            "rollout",
            "pool-serve",
            "--provider-set",
            "/packs/providers.json",
            "--runtime-image",
            "runtime:fixed",
            "--task-image",
            "task:one",
            "--task-image",
            "task:two",
            "--capacity",
            "32",
            "--artifacts-root",
            "/artifacts",
            "--socket",
            "/run/datalox/pool.sock",
        ]
    )
    assert arguments.func(arguments) == 0
    assert captured["pool"] == {
        "provider_set_path": Path("/packs/providers.json"),
        "runtime_image": "runtime:fixed",
        "allowed_task_images": ("task:one", "task:two"),
        "capacity": 32,
        "artifacts_root": Path("/artifacts"),
    }
    assert captured["serve"][1] == Path("/run/datalox/pool.sock")


def test_pool_serve_cli_emits_structured_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from datalox_gated_runtime import cli

    class FailingPool:
        def __init__(self, **_: Any) -> None:
            raise RolloutPoolError("pool_capacity_invalid", "capacity invalid")

    monkeypatch.setattr(cli, "RolloutPool", FailingPool)
    arguments = cli._build_parser().parse_args(
        [
            "rollout",
            "pool-serve",
            "--provider-set",
            "/packs/providers.json",
            "--runtime-image",
            "runtime:fixed",
            "--task-image",
            "task:one",
            "--capacity",
            "0",
            "--artifacts-root",
            "/artifacts",
            "--socket",
            "/run/datalox/pool.sock",
            "--json",
        ]
    )
    assert arguments.func(arguments) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": {"code": "pool_capacity_invalid", "message": "capacity invalid"}
    }
