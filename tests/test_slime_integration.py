from __future__ import annotations

import asyncio
import copy
import importlib.util
import inspect
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import jsonschema
import pytest

from datalox_gated_runtime.integrations import slime as adapter
from datalox_gated_runtime.rollout.pool import (
    FinalizedRolloutLease,
    RolloutExecResult,
)


@dataclass
class _Sample:
    session_id: str | None = "slime-session-0001"
    metadata: dict[str, Any] = field(
        default_factory=lambda: {
            "task_owner": "consumer",
            "datalox": {"uid": "slime-task-0042", "environment_seed": 17},
        }
    )
    group_index: int | None = 5
    index: int | None = 13
    rollout_id: int | None = 13
    tokens: list[int] = field(default_factory=lambda: [1, 2])
    response: str = ""
    response_length: int = 0
    loss_mask: list[int] | None = None
    rollout_log_probs: list[float] | None = None
    reward: float | None = None
    status: str = "pending"


class _FakeLease:
    def __init__(self, output_dir: Path) -> None:
        self.lease_id = "lease-0001"
        self.initial_provider_fingerprint = f"sha256:{'a' * 64}"
        self.output_dir = output_dir
        self.state = "active"
        self.commands: list[tuple[str, tuple[str, ...]]] = []
        self.finalize_calls = 0
        self.cancel_calls = 0

    async def exec(self, *, task_image: str, command: tuple[str, ...]) -> RolloutExecResult:
        self.commands.append((task_image, command))
        return RolloutExecResult(
            lease_id=self.lease_id,
            execution_index=len(self.commands) - 1,
            consumer_exit_code=0,
            stdout='{"provider":"observation"}',
            stderr="",
        )

    async def finalize(self) -> FinalizedRolloutLease:
        self.finalize_calls += 1
        self.state = "finalized"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return FinalizedRolloutLease(
            lease_id=self.lease_id,
            output_dir=self.output_dir,
            consumer_exit_codes=(0,) * len(self.commands),
        )

    async def cancel(self) -> None:
        self.cancel_calls += 1
        self.state = "cancelled"


class _FakePoolClient:
    instances: ClassVar[list[_FakePoolClient]] = []
    next_lease: ClassVar[_FakeLease | None] = None

    def __init__(self, *, socket_path: Path, token_path: Path) -> None:
        self.socket_path = socket_path
        self.token_path = token_path
        self.acquisitions: list[tuple[str, str, int]] = []
        self.closed = False
        assert self.__class__.next_lease is not None
        self.lease = self.__class__.next_lease
        self.__class__.next_lease = None
        self.__class__.instances.append(self)

    async def acquire(self, *, uid: str, session_id: str, environment_seed: int) -> _FakeLease:
        self.acquisitions.append((uid, session_id, environment_seed))
        return self.lease

    async def aclose(self) -> None:
        self.closed = True


def _args(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        datalox_pool_socket_path="/run/datalox/rollout-pool.sock",
        datalox_pool_token_path="/run/datalox/rollout-pool.sock.token",
        datalox_task_image="consumer/slime-provider-tools@sha256:fixed",
        datalox_evidence_sidecars_root=str(tmp_path / "sidecars"),
    )


@pytest.fixture(autouse=True)
def _fake_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "RolloutPoolClient", _FakePoolClient)
    _FakePoolClient.instances.clear()
    _FakePoolClient.next_lease = None


def test_custom_generate_preserves_exact_sample_and_slime_training_fields(
    tmp_path: Path,
) -> None:
    sample = _Sample()
    expected_after_user_generate: dict[str, Any] = {}
    lease = _FakeLease(tmp_path / "artifacts" / "lease-0001")
    _FakePoolClient.next_lease = lease

    @adapter.datalox_custom_generate
    async def user_generate(
        args: object,
        current: _Sample,
        sampling_params: dict[str, Any],
        evaluation: bool = False,
    ) -> _Sample:
        assert args is not None
        assert sampling_params == {"temperature": 0.7}
        assert evaluation is False

        async def provider_tool() -> None:
            result = await adapter.current_slime_provider_execution().exec(
                ("python3", "/opt/task/provider_tool.py", "create", "record-1")
            )
            assert result.stdout == '{"provider":"observation"}'

        await asyncio.create_task(provider_tool())
        current.tokens = [1, 2, 31, 32, 41]
        current.response = "assistant action\nprovider observation"
        current.response_length = 3
        current.loss_mask = [1, 1, 0]
        current.rollout_log_probs = [-0.1, -0.2, -0.3]
        current.reward = 0.625
        current.status = "completed"
        expected_after_user_generate.update(copy.deepcopy(vars(current)))
        return current

    result = asyncio.run(user_generate(_args(tmp_path), sample, {"temperature": 0.7}))

    client = _FakePoolClient.instances[0]
    assert result is sample
    assert vars(sample) == expected_after_user_generate
    assert client.acquisitions == [("slime-task-0042", "slime-session-0001", 17)]
    assert lease.commands == [
        (
            "consumer/slime-provider-tools@sha256:fixed",
            ("python3", "/opt/task/provider_tool.py", "create", "record-1"),
        )
    ]
    assert lease.finalize_calls == 1
    assert lease.cancel_calls == 0
    assert client.closed is True
    with pytest.raises(adapter.SlimeRolloutContractError) as missing:
        adapter.current_slime_provider_execution()
    assert missing.value.code == "slime_rollout_context_missing"

    runtime = adapter.SlimeDataloxRuntime.from_slime_args(_args(tmp_path))
    evidence = runtime.evidence_for(sample)
    assert evidence.identity.uid == "slime-task-0042"
    assert evidence.identity.session_id == "slime-session-0001"
    assert evidence.identity.environment_seed == 17
    assert evidence.lease_id == "lease-0001"
    assert evidence.artifact_directory == lease.output_dir
    assert evidence.consumer_exit_codes == (0,)


def test_one_lease_preserves_exact_fanout_list_and_sample_objects(tmp_path: Path) -> None:
    original = _Sample()
    segment = _Sample(
        session_id=None,
        metadata={
            "segment": "trajectory-manager-output",
            **adapter.slime_identity_metadata(original),
        },
    )
    segment.tokens = [1, 2, 90]
    segment.response = "segment"
    segment.response_length = 1
    segment.loss_mask = [1]
    fanout = [original, segment]
    expected = copy.deepcopy([vars(item) for item in fanout])
    lease = _FakeLease(tmp_path / "artifacts" / "fanout")
    _FakePoolClient.next_lease = lease

    runtime = adapter.SlimeDataloxRuntime.from_slime_args(_args(tmp_path))

    @runtime.custom_generate
    async def user_generate(_: object, __: _Sample, ___: dict[str, Any]) -> list[_Sample]:
        return fanout

    result = asyncio.run(user_generate(_args(tmp_path), original, {}))

    assert result is fanout
    assert result[0] is original
    assert result[1] is segment
    assert [vars(item) for item in result] == expected
    assert lease.finalize_calls == 1
    assert lease.cancel_calls == 0


def test_config_decorator_preserves_evaluation_keyword_signature(tmp_path: Path) -> None:
    sample = _Sample(
        session_id=None,
        metadata={
            "datalox": {
                "uid": "slime-eval-task",
                "session_id": "slime-eval-session-explicit",
                "environment_seed": 23,
            }
        },
    )
    lease = _FakeLease(tmp_path / "artifacts" / "evaluation")
    _FakePoolClient.next_lease = lease
    observed_evaluation: list[bool] = []

    @adapter.datalox_custom_generate
    async def user_generate(
        _: object,
        current: _Sample,
        __: dict[str, Any],
        evaluation: bool = False,
    ) -> _Sample:
        observed_evaluation.append(evaluation)
        return current

    assert "evaluation" in inspect.signature(user_generate).parameters
    result = asyncio.run(user_generate(_args(tmp_path), sample, {}, evaluation=True))
    assert result is sample
    assert observed_evaluation == [True]
    assert lease.finalize_calls == 1


def test_fresh_fanout_segment_without_explicit_identity_fails_closed(tmp_path: Path) -> None:
    original = _Sample()
    fresh_segment = _Sample(session_id=None, metadata={"segment": "fresh"})
    lease = _FakeLease(tmp_path / "artifacts" / "missing-fanout-identity")
    _FakePoolClient.next_lease = lease

    @adapter.datalox_custom_generate
    async def user_generate(_: object, __: _Sample, ___: dict[str, Any]) -> list[_Sample]:
        return [fresh_segment]

    with pytest.raises(adapter.SlimeRolloutContractError) as failed:
        asyncio.run(user_generate(_args(tmp_path), original, {}))
    assert failed.value.code == "slime_datalox_metadata_invalid"
    assert lease.finalize_calls == 0
    assert lease.cancel_calls == 1


def test_custom_generation_cannot_change_original_rollout_identity(tmp_path: Path) -> None:
    sample = _Sample()
    lease = _FakeLease(tmp_path / "artifacts" / "changed-identity")
    _FakePoolClient.next_lease = lease

    @adapter.datalox_custom_generate
    async def user_generate(_: object, current: _Sample, __: dict[str, Any]) -> _Sample:
        current.session_id = "different-session"
        return current

    with pytest.raises(adapter.SlimeRolloutContractError) as failed:
        asyncio.run(user_generate(_args(tmp_path), sample, {}))
    assert failed.value.code == "slime_identity_changed"
    assert lease.finalize_calls == 0
    assert lease.cancel_calls == 1


def test_custom_generate_requires_three_positional_upstream_arguments(tmp_path: Path) -> None:
    @adapter.datalox_custom_generate
    async def user_generate(_: object, sample: _Sample, __: dict[str, Any]) -> _Sample:
        return sample

    with pytest.raises(adapter.SlimeRolloutContractError) as failed:
        asyncio.run(user_generate(_args(tmp_path), _Sample()))  # type: ignore[call-arg]
    assert failed.value.code == "slime_generate_call_invalid"
    assert _FakePoolClient.instances == []


def test_external_cancellation_waits_for_lease_cleanup_and_writes_no_sidecar(
    tmp_path: Path,
) -> None:
    sample = _Sample()
    lease = _FakeLease(tmp_path / "artifacts" / "cancelled")
    _FakePoolClient.next_lease = lease

    async def scenario() -> None:
        started = asyncio.Event()
        release = asyncio.Event()

        @adapter.datalox_custom_generate
        async def user_generate(_: object, __: _Sample, ___: dict[str, Any]) -> _Sample:
            started.set()
            await release.wait()
            return sample

        running = asyncio.create_task(user_generate(_args(tmp_path), sample, {}))
        await started.wait()
        running.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await running

    asyncio.run(scenario())

    client = _FakePoolClient.instances[0]
    assert lease.finalize_calls == 0
    assert lease.cancel_calls == 1
    assert client.closed is True
    sidecar_root = Path(_args(tmp_path).datalox_evidence_sidecars_root)
    assert not sidecar_root.exists()


def test_aborted_sample_cancels_without_sidecar_and_same_identity_can_rerun(
    tmp_path: Path,
) -> None:
    sample = _Sample()
    attempts = 0

    @adapter.datalox_custom_generate
    async def user_generate(_: object, current: _Sample, __: dict[str, Any]) -> _Sample:
        nonlocal attempts
        attempts += 1
        current.status = "aborted" if attempts == 1 else "completed"
        return current

    aborted_lease = _FakeLease(tmp_path / "artifacts" / "aborted")
    _FakePoolClient.next_lease = aborted_lease
    first = asyncio.run(user_generate(_args(tmp_path), sample, {}))
    assert first is sample
    assert aborted_lease.cancel_calls == 1
    assert aborted_lease.finalize_calls == 0
    assert not Path(_args(tmp_path).datalox_evidence_sidecars_root).exists()

    completed_lease = _FakeLease(tmp_path / "artifacts" / "completed-rerun")
    _FakePoolClient.next_lease = completed_lease
    second = asyncio.run(user_generate(_args(tmp_path), sample, {}))
    assert second is sample
    assert completed_lease.cancel_calls == 0
    assert completed_lease.finalize_calls == 1
    evidence = adapter.SlimeDataloxRuntime.from_slime_args(_args(tmp_path)).evidence_for(sample)
    assert evidence.artifact_directory == completed_lease.output_dir


def test_fresh_aborted_output_cancels_before_fanout_identity_validation(
    tmp_path: Path,
) -> None:
    original = _Sample()
    upstream_aborted = _Sample(session_id=None, metadata={}, status="aborted")
    lease = _FakeLease(tmp_path / "artifacts" / "fresh-aborted")
    _FakePoolClient.next_lease = lease

    @adapter.datalox_custom_generate
    async def user_generate(_: object, __: _Sample, ___: dict[str, Any]) -> _Sample:
        return upstream_aborted

    result = asyncio.run(user_generate(_args(tmp_path), original, {}))
    assert result is upstream_aborted
    assert lease.finalize_calls == 0
    assert lease.cancel_calls == 1
    assert not Path(_args(tmp_path).datalox_evidence_sidecars_root).exists()


@pytest.mark.parametrize(
    ("sample", "code"),
    [
        (_Sample(session_id=None), "slime_session_id_invalid"),
        (_Sample(session_id=""), "slime_session_id_invalid"),
        (_Sample(metadata={}), "slime_datalox_metadata_invalid"),
        (
            _Sample(metadata={"datalox": {"environment_seed": 1}}),
            "slime_datalox_metadata_invalid",
        ),
        (
            _Sample(metadata={"datalox": {"uid": "task", "environment_seed": True}}),
            "slime_environment_seed_invalid",
        ),
        (
            _Sample(metadata={"datalox": {"uid": "task", "environment_seed": 1, "derived": True}}),
            "slime_datalox_metadata_invalid",
        ),
        (
            _Sample(
                session_id="native-session",
                metadata={
                    "datalox": {
                        "uid": "task",
                        "session_id": "different-session",
                        "environment_seed": 1,
                    }
                },
            ),
            "slime_session_id_mismatch",
        ),
    ],
)
def test_missing_or_ambiguous_native_identity_fails_before_acquire(
    tmp_path: Path, sample: _Sample, code: str
) -> None:
    @adapter.datalox_custom_generate
    async def user_generate(_: object, __: _Sample, ___: dict[str, Any]) -> _Sample:
        pytest.fail("user generation must not run with invalid identity")

    with pytest.raises(adapter.SlimeRolloutContractError) as failed:
        asyncio.run(user_generate(_args(tmp_path), sample, {}))
    assert failed.value.code == code
    assert _FakePoolClient.instances == []


def test_evidence_sidecar_is_keyed_by_exact_identity_and_available_to_custom_rm(
    tmp_path: Path,
) -> None:
    sample = _Sample()
    lease = _FakeLease(tmp_path / "artifacts" / "reward")
    _FakePoolClient.next_lease = lease

    @adapter.datalox_custom_generate
    async def user_generate(_: object, current: _Sample, __: dict[str, Any]) -> _Sample:
        return current

    async def custom_rm(args: object, current: _Sample) -> float:
        runtime = adapter.SlimeDataloxRuntime.from_slime_args(args)
        evidence = runtime.evidence_for(current)
        assert evidence.identity_key == adapter.extract_slime_rollout_identity(current).key
        assert evidence.initial_provider_fingerprint == f"sha256:{'a' * 64}"
        return 1.0 if evidence.consumer_exit_codes == () else 0.0

    async def scenario() -> float:
        result = await user_generate(_args(tmp_path), sample, {})
        assert result is sample
        return await custom_rm(_args(tmp_path), result)

    assert asyncio.run(scenario()) == 1.0

    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "schemas" / "slime-evidence-sidecar-v1.schema.json").read_text(encoding="utf-8")
    )
    sidecar_path = (
        Path(_args(tmp_path).datalox_evidence_sidecars_root)
        / f"{adapter.extract_slime_rollout_identity(sample).key}.json"
    )
    payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(payload)

    different_sample = copy.deepcopy(sample)
    different_sample.session_id = "slime-session-0002"
    runtime = adapter.SlimeDataloxRuntime.from_slime_args(_args(tmp_path))
    with pytest.raises(adapter.SlimeRolloutContractError) as missing:
        runtime.evidence_for(different_sample)
    assert missing.value.code == "slime_evidence_missing"


def test_fanout_batch_rm_returns_one_float_per_propagated_sample(tmp_path: Path) -> None:
    original = _Sample()
    identity_metadata = adapter.slime_identity_metadata(original)
    segments = [
        _Sample(
            session_id=None,
            metadata={**identity_metadata, "segment": index},
            response=f"segment-{index}",
            status="completed",
        )
        for index in range(2)
    ]
    lease = _FakeLease(tmp_path / "artifacts" / "batch-reward")
    _FakePoolClient.next_lease = lease

    @adapter.datalox_custom_generate
    async def user_generate(_: object, __: _Sample, ___: dict[str, Any]) -> list[_Sample]:
        return segments

    async def custom_rm(args: object, samples: list[_Sample]) -> list[float]:
        runtime = adapter.SlimeDataloxRuntime.from_slime_args(args)
        evidence = runtime.evidence_for_batch(samples)
        assert len(evidence) == len(samples)
        assert {item.lease_id for item in evidence} == {"lease-0001"}
        return [float(bool(sample.response)) for sample in samples]

    async def scenario() -> list[float]:
        generated = await user_generate(_args(tmp_path), original, {})
        assert generated is segments
        return await custom_rm(_args(tmp_path), generated)

    assert asyncio.run(scenario()) == [1.0, 1.0]


def test_docs_pin_current_slime_interfaces_and_state_boundary() -> None:
    root = Path(__file__).resolve().parents[1]
    docs = (root / "docs" / "slime-rollouts.md").read_text(encoding="utf-8")
    example = (root / "integrations" / "slime" / "README.md").read_text(encoding="utf-8")
    for text in (docs, example):
        assert "a067ce6face6dfee297f219c470c406b8a5025f1" in text
        assert "--custom-generate-function-path" in text
        assert "--custom-rm-path" in text
        assert "--custom-config-path" in text
        assert "sample.session_id" in text
        assert "persistent" in text and "Sandbox" in text
        assert "check_slime_upstream_contract.py" in text
        assert "one-shot/manual" in text

    config = (root / "integrations" / "slime" / "custom_config.yaml").read_text(encoding="utf-8")
    launch = (root / "integrations" / "slime" / "launch_fragment.sh").read_text(encoding="utf-8")
    provider_tool = (root / "integrations" / "slime" / "provider_tool.py").read_text(
        encoding="utf-8"
    )
    assert "datalox_pool_socket_path:" in config
    assert "datalox_task_image:" in config
    assert "SLIME_USER_GENERATE_PATH" in launch
    assert "SLIME_USER_REWARD_PATH" in launch
    assert "current_slime_provider_execution().exec" in provider_tool
    assert 'EXACT_PROVIDER_URL = "https://api.example.com/' in provider_tool
    assert "sample.prompt" not in provider_tool
    assert "user_task" not in launch


def test_slime_upstream_contract_manifest_and_checker_are_strict() -> None:
    root = Path(__file__).resolve().parents[1]
    checker_path = root / "scripts" / "check_slime_upstream_contract.py"
    spec = importlib.util.spec_from_file_location(
        "datalox_slime_contract_checker_test", checker_path
    )
    assert spec is not None and spec.loader is not None
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)

    contract = checker._contract()
    assert contract["schema_version"] == "datalox_slime_upstream_contract_v1"
    assert contract["commit"] == "a067ce6face6dfee297f219c470c406b8a5025f1"
    assert set(contract["files"]) == {
        "slime/agent/trajectory.py",
        "slime/rollout/fully_async_rollout.py",
        "slime/rollout/rm_hub/__init__.py",
        "slime/rollout/sglang_rollout.py",
        "slime/utils/types.py",
    }
    assert all(
        isinstance(digest, str) and digest.startswith("sha256:") and len(digest) == 71
        for digest in contract["files"].values()
    )


def test_slime_provider_dispatcher_fails_closed_on_malformed_request(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = Path(__file__).resolve().parents[1] / "integrations" / "slime" / "provider_call.py"
    spec = importlib.util.spec_from_file_location("datalox_slime_provider_call_test", path)
    assert spec is not None and spec.loader is not None
    dispatcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dispatcher)

    assert dispatcher.main(["{}"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "request fields must be exactly" in captured.err
