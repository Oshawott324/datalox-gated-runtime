from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from pathlib import Path

import jsonschema
import pytest
from referencing import Registry, Resource

from test_interception_composition import INITIAL_TIME, _Artifacts, _artifacts
from test_rollout_pool import FakeLease

from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime import cli
from datalox_gated_runtime.provider_runtime.registry import (
    FilesystemProviderReleaseRegistry,
)
from datalox_gated_runtime.rollout.composition import (
    CompositionRolloutConfig,
    DockerCompositionRolloutLease,
)
from datalox_gated_runtime.rollout.docker import (
    DockerCommandResult,
    DockerRolloutError,
    DockerRolloutStateError,
)
from datalox_gated_runtime.rollout.pool import RolloutPool

ROOT = Path(__file__).resolve().parents[1]
EPISODE_SEED = "operator-fixed-episode"


def _config(tmp_path: Path) -> tuple[CompositionRolloutConfig, _Artifacts]:
    artifacts = _artifacts(tmp_path)
    return (
        CompositionRolloutConfig.load(
            provider_set_v2_path=tmp_path / "provider-set-v2.json",
            registry=FilesystemProviderReleaseRegistry.load(tmp_path / "registry"),
            composition_pack_dir=artifacts.pack_dir,
            composition_admission_path=artifacts.admission_path,
            episode_seed=EPISODE_SEED,
            initial_composition_delivery_time=INITIAL_TIME,
        ),
        artifacts,
    )


class FakeCompositionDockerRunner:
    def __init__(self, artifacts: _Artifacts) -> None:
        self.artifacts = artifacts
        self.calls: list[tuple[tuple[str, ...], bool]] = []
        self.task_runs = 0

    def run(
        self,
        arguments: Sequence[str],
        *,
        capture_output: bool = False,
    ) -> DockerCommandResult:
        command = tuple(arguments)
        self.calls.append((command, capture_output))
        if "intercept" in command and "ready" in command:
            return DockerCommandResult(0, '{"ok": true}\n')
        if "datalox_gated_runtime.rollout.composition_control" in command:
            operation = command[command.index("--operation") + 1]
            return DockerCommandResult(
                0,
                json.dumps(self._composition_export(finalized=operation == "finalize")),
            )
        if command[:3] == ("docker", "start", "--attach"):
            self.task_runs += 1
            return DockerCommandResult(
                0,
                stdout=f"task-run={self.task_runs}\n" if capture_output else "",
            )
        if command[:3] == ("docker", "inspect", "--format"):
            return DockerCommandResult(
                0,
                json.dumps(
                    {
                        "Status": "exited",
                        "Running": False,
                        "ExitCode": 0,
                        "Error": "",
                    }
                ),
            )
        return DockerCommandResult(0)

    def _composition_export(self, *, finalized: bool) -> dict[str, object]:
        digest = f"sha256:{'a' * 64}"
        provider_authorities = {
            self.artifacts.source_provider_id: self.artifacts.source_authority,
            self.artifacts.target_provider_id: self.artifacts.target_authority,
        }
        providers = {
            provider_id: {
                "schema_version": "datalox_provider_run_v1",
                "provider_id": provider_id,
                "bundle_version": "1.0.0",
                "authorities": [authority],
                "provider_state": {"phase": "reset", "counter": 0},
                "call_evidence": {"events": []},
            }
            for provider_id, authority in provider_authorities.items()
        }
        unsigned: dict[str, object] = {
            "schema_version": "datalox_composition_session_export_v1",
            "pack": {
                "pack_id": "test-pack",
                "pack_version": "1.0.0",
                "composition_pack_sha256": digest,
                "composition_admission_sha256": digest,
                "distribution_label": "public",
                "time_scope": "delivery_scheduler_only_v1",
            },
            "provider_profiles": [
                {
                    "provider_id": provider_id,
                    "profile_id": "default",
                    "release_manifest_sha256": digest,
                    "provider_runtime_sha256": digest,
                    "provider_admission_sha256": digest,
                    "operation_contract_sha256": digest,
                    "release_config_sha256": digest,
                }
                for provider_id in sorted(providers)
            ],
            "composition_delivery_time": "2030-01-01T00:00:00.000000Z",
            "providers": providers,
            "events": {
                "schema_version": "datalox_session_event_export_v1",
                "episode_seed": EPISODE_SEED,
                "initial_time": "2030-01-01T00:00:00.000000Z",
                "logical_time": "2030-01-01T00:00:00.000000Z",
                "source_events": [],
                "deliveries": [],
                "post_outcome_effects": [],
                "state_digest": digest,
            },
            "status": "valid",
            "failure": None,
            "finalized": finalized,
        }
        return {**unsigned, "content_sha256": canonical_json_sha256(unsigned)}


def _commands(runner: FakeCompositionDockerRunner) -> list[tuple[str, ...]]:
    return [command for command, _ in runner.calls]


def test_composition_lease_preserves_exact_authorities_and_exports_full_session(
    tmp_path: Path,
) -> None:
    config, artifacts = _config(tmp_path)
    runner = FakeCompositionDockerRunner(artifacts)
    lease = DockerCompositionRolloutLease.start(
        composition_config=config,
        runtime_image="runtime:image",
        uid="grpo-group",
        session_id=17,
        environment_seed=73,
        runner=runner,
    )
    host_root = lease._host_materialization_root

    first = lease.exec(task_image="task:image", consumer_command=("first",))
    second = lease.exec(task_image="task:image", consumer_command=("second",))
    output = tmp_path / "result"
    result = lease.finalize(output_dir=output)

    assert first.stdout == "task-run=1\n"
    assert second.stdout == "task-run=2\n"
    assert result.consumer_exit_code == 0
    assert host_root is not None and not host_root.exists()
    export = json.loads((output / "rollout-export.json").read_text(encoding="utf-8"))
    schema = json.loads(
        (ROOT / "schemas/rollout-composition-execution-export-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    composition_schema = json.loads(
        (ROOT / "schemas/composition-session-export-v1.schema.json").read_text(encoding="utf-8")
    )
    registry = Registry().with_resource(
        "https://datalox.dev/schemas/composition-session-export-v1.schema.json",
        Resource.from_contents(composition_schema),
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema, registry=registry).validate(export)
    assert export["uid"] == "grpo-group"
    assert export["session_id"] == 17
    assert export["environment_seed"] == 73
    assert export["consumer_exit_codes"] == [0, 0]
    assert export["composition"]["episode_seed"] == EPISODE_SEED
    assert export["composition"]["time_scope"] == "delivery_scheduler_only_v1"
    assert (
        export["composition"]["initial_composition_delivery_time"] == "2030-01-01T00:00:00.000000Z"
    )
    assert export["final_composition_export"]["finalized"] is True
    assert set(export["final_composition_export"]["providers"]) == {
        artifacts.source_provider_id,
        artifacts.target_provider_id,
    }

    commands = _commands(runner)
    assert any(command[:4] == ("docker", "network", "create", "--internal") for command in commands)
    prepare = next(command for command in commands if "prepare-composition" in command)
    serve = next(command for command in commands if "serve-composition" in command)
    for command in (prepare, serve):
        assert command[command.index("--episode-seed") + 1] == EPISODE_SEED
        assert (
            command[command.index("--initial-composition-delivery-time") + 1]
            == "2030-01-01T00:00:00.000000Z"
        )
        assert sum(value.endswith(",readonly") for value in command) >= 3
    assert "--prepared" in serve
    aliases = [serve[index + 1] for index, value in enumerate(serve) if value == "--network-alias"]
    assert aliases == [artifacts.source_authority, artifacts.target_authority]

    task = next(command for command in commands if command[:2] == ("docker", "create"))
    task_text = " ".join(task)
    task_mounts = [task[index + 1] for index, value in enumerate(task) if value == "--mount"]
    assert "/opt/datalox/composition" not in task_text
    assert not any(mount.endswith("target=/var/run/datalox") for mount in task_mounts)
    assert "/var/run/docker.sock" not in task_text
    assert "grpo-group" not in task_text
    assert "17" not in task
    task_environment = [task[index + 1] for index, value in enumerate(task) if value == "--env"]
    assert not any("SESSION_ID=" in value or "UID=" in value for value in task_environment)
    control_operations = [
        command[command.index("--operation") + 1]
        for command in commands
        if "datalox_gated_runtime.rollout.composition_control" in command
    ]
    assert control_operations == ["reset", "finalize"]
    with pytest.raises(DockerRolloutStateError):
        lease.exec(task_image="task:image", consumer_command=("again",))


def test_composition_lease_finalizes_without_any_consumer_command(tmp_path: Path) -> None:
    config, artifacts = _config(tmp_path)
    runner = FakeCompositionDockerRunner(artifacts)
    lease = DockerCompositionRolloutLease.start(
        composition_config=config,
        runtime_image="runtime:image",
        uid="zero-tool",
        session_id="0",
        environment_seed=0,
        runner=runner,
    )
    output = tmp_path / "zero-tool-output"

    result = lease.finalize(output_dir=output)

    export = json.loads((output / "rollout-export.json").read_text(encoding="utf-8"))
    assert result.consumer_exit_code is None
    assert export["consumer_exit_codes"] == []
    assert export["consumer_exit_code"] is None
    assert export["final_composition_export"]["finalized"] is True


def test_composition_cancel_destroys_session_without_export(tmp_path: Path) -> None:
    config, artifacts = _config(tmp_path)
    runner = FakeCompositionDockerRunner(artifacts)
    lease = DockerCompositionRolloutLease.start(
        composition_config=config,
        runtime_image="runtime:image",
        uid="cancelled",
        session_id="1",
        environment_seed=9,
        runner=runner,
    )
    host_root = lease._host_materialization_root

    lease.cancel()

    assert lease.state == "cancelled"
    assert host_root is not None and not host_root.exists()
    assert not any(
        "--operation" in command and command[command.index("--operation") + 1] == "finalize"
        for command in _commands(runner)
    )


def test_composition_config_rejects_changed_operator_selection_before_docker(
    tmp_path: Path,
) -> None:
    config, artifacts = _config(tmp_path)
    manifest = json.loads(config.provider_set_v2_path.read_text(encoding="utf-8"))
    config.provider_set_v2_path.chmod(0o600)
    config.provider_set_v2_path.write_text(
        json.dumps(manifest, separators=(",", ":")),
        encoding="utf-8",
    )
    runner = FakeCompositionDockerRunner(artifacts)

    with pytest.raises(DockerRolloutError, match="provider set"):
        DockerCompositionRolloutLease.start(
            composition_config=config,
            runtime_image="runtime:image",
            uid="tampered",
            session_id="0",
            environment_seed=0,
            runner=runner,
        )

    assert runner.calls == []


def test_composition_pool_fixes_operator_selection_across_isolated_siblings(
    tmp_path: Path,
) -> None:
    config, _ = _config(tmp_path)

    async def scenario() -> None:
        FakeLease.instances.clear()
        FakeLease.start_threads.clear()
        pool = RolloutPool.from_composition(
            composition_config=config,
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=2,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=FakeLease.start,
        )
        one, two = await asyncio.gather(
            pool.acquire(uid="grpo-group", session_id="0", environment_seed=44),
            pool.acquire(uid="grpo-group", session_id="1", environment_seed=44),
        )

        assert one.lease_id != two.lease_id
        assert len(FakeLease.instances) == 2
        assert all(lease.metadata["composition_config"] is config for lease in FakeLease.instances)
        assert all(lease.metadata["environment_seed"] == 44 for lease in FakeLease.instances)
        assert config.episode_seed == EPISODE_SEED
        assert config.initial_composition_delivery_time == "2030-01-01T00:00:00.000000Z"
        await asyncio.gather(
            pool.cancel(lease_id=one.lease_id, lease_token=one.lease_token),
            pool.cancel(lease_id=two.lease_id, lease_token=two.lease_token),
        )
        assert all(lease.cancelled for lease in FakeLease.instances)

    asyncio.run(scenario())


def test_composition_pool_cli_uses_the_standard_pool_with_fixed_operator_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    fixed_config = object()
    fixed_pool = object()

    def load_config(**arguments: object) -> object:
        captured["config"] = arguments
        return fixed_config

    def build_pool(**arguments: object) -> object:
        captured["pool"] = arguments
        return fixed_pool

    async def serve_pool(*, pool: object, socket_path: Path) -> None:
        captured["serve"] = {"pool": pool, "socket_path": socket_path}

    monkeypatch.setattr(cli.CompositionRolloutConfig, "load", load_config)
    monkeypatch.setattr(cli.RolloutPool, "from_composition", build_pool)
    monkeypatch.setattr(cli, "serve_rollout_pool", serve_pool)
    args = cli._build_parser().parse_args(
        [
            "rollout",
            "pool-serve-composition",
            "--registry",
            str(tmp_path / "registry"),
            "--provider-set",
            str(tmp_path / "provider-set-v2.json"),
            "--composition-pack",
            str(tmp_path / "pack"),
            "--composition-admission",
            str(tmp_path / "composition-admission.json"),
            "--episode-seed",
            EPISODE_SEED,
            "--initial-composition-delivery-time",
            INITIAL_TIME,
            "--runtime-image",
            "runtime:image",
            "--task-image",
            "task:one",
            "--task-image",
            "task:two",
            "--capacity",
            "32",
            "--artifacts-root",
            str(tmp_path / "artifacts"),
            "--socket",
            str(tmp_path / "pool.sock"),
        ]
    )

    assert args.func(args) == 0
    assert captured["config"] == {
        "provider_set_v2_path": tmp_path / "provider-set-v2.json",
        "registry": tmp_path / "registry",
        "composition_pack_dir": tmp_path / "pack",
        "composition_admission_path": tmp_path / "composition-admission.json",
        "episode_seed": EPISODE_SEED,
        "initial_composition_delivery_time": INITIAL_TIME,
    }
    assert captured["pool"] == {
        "composition_config": fixed_config,
        "runtime_image": "runtime:image",
        "allowed_task_images": ("task:one", "task:two"),
        "capacity": 32,
        "artifacts_root": tmp_path / "artifacts",
    }
    assert captured["serve"] == {
        "pool": fixed_pool,
        "socket_path": tmp_path / "pool.sock",
    }
