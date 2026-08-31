from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

import jsonschema
import pytest
from world_v1_helpers import create_valid_bundle

from test_rollout_provider_set_v2 import _publish_example_release

from datalox_gated_runtime import cli
from datalox_gated_runtime.provider_runtime import build_provider_runtime_from_world
from datalox_gated_runtime.rollout.docker import (
    DockerCommandResult,
    DockerRolloutError,
    DockerRolloutLease,
    DockerRolloutStateError,
    _provider_state_fingerprint,
    run_docker_rollout,
    run_docker_rollout_provider_set_v2,
)
from datalox_gated_runtime.rollout.provider_set import (
    ProviderReleaseSelection,
    write_rollout_provider_set_v2,
)

ROOT = Path(__file__).resolve().parents[1]


def test_provider_state_fingerprint_excludes_run_local_evidence_identity() -> None:
    def observation(run_id: str, created_at: str) -> list[dict[str, object]]:
        return [
            {
                "schema_version": "datalox_provider_run_v1",
                "provider_id": "orders",
                "bundle_version": "1.0.0",
                "authorities": ["api.orders.example"],
                "provider_state": {"state": {"counter": 1}},
                "call_evidence": {
                    "run_id": run_id,
                    "created_at": created_at,
                    "events": [],
                },
            }
        ]

    first = _provider_state_fingerprint(observation("run-a", "2026-01-01T00:00:00Z"))
    second = _provider_state_fingerprint(observation("run-b", "2026-01-02T00:00:00Z"))
    changed = observation("run-c", "2026-01-03T00:00:00Z")
    changed[0]["provider_state"] = {"state": {"counter": 2}}

    assert first == second
    assert first != _provider_state_fingerprint(changed)


def _provider_set(tmp_path: Path) -> Path:
    source = create_valid_bundle(tmp_path / "source")
    bundle = tmp_path / "providers" / "orders"
    build_provider_runtime_from_world(
        source_world_dir=source,
        output_dir=bundle,
        provider_id="orders",
        authorities=("api.orders.example", "events.orders.example"),
        episode_id="episode-1",
    )
    digest = hashlib.sha256((bundle / "provider-runtime.json").read_bytes()).hexdigest()
    manifest = tmp_path / "rollout-providers.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "datalox_rollout_provider_set_v1",
                "providers": [
                    {
                        "provider_id": "orders",
                        "bundle_path": "providers/orders",
                        "provider_runtime_sha256": f"sha256:{digest}",
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


class FakeDockerRunner:
    def __init__(
        self,
        *,
        task_exit_code: int = 0,
        fail_task_create: bool = False,
        fail_admitted_gateway_start: bool = False,
    ) -> None:
        self.task_exit_code = task_exit_code
        self.fail_task_create = fail_task_create
        self.fail_admitted_gateway_start = fail_admitted_gateway_start
        self.calls: list[tuple[tuple[str, ...], bool]] = []

    def run(
        self,
        arguments: Sequence[str],
        *,
        capture_output: bool = False,
    ) -> DockerCommandResult:
        command = tuple(arguments)
        self.calls.append((command, capture_output))
        if "serve-admitted" in command and self.fail_admitted_gateway_start:
            return DockerCommandResult(125, stderr="admitted gateway rejected start")
        if "intercept" in command and "ready" in command:
            return DockerCommandResult(0, '{"ok": true}\n')
        if "intercept" in command and "control" in command:
            operation = command[command.index("--operation") + 1]
            provider_ids = [
                command[index + 1]
                for index, value in enumerate(command)
                if value == "--provider-id"
            ]
            providers = [
                {
                    "schema_version": "datalox_provider_run_v1",
                    "provider_id": provider_id,
                    "bundle_version": "1.0.0",
                    "authorities": ["api.orders.example", "events.orders.example"],
                    "provider_state": {"phase": operation},
                    "call_evidence": {"events": []},
                }
                for provider_id in provider_ids
            ]
            return DockerCommandResult(
                0,
                json.dumps(
                    {
                        "schema_version": "datalox_interception_control_aggregate_v1",
                        "operation": operation,
                        "providers": providers,
                    }
                ),
            )
        if (
            command[:2] == ("docker", "create")
            and "task:image" in command
            and self.fail_task_create
        ):
            return DockerCommandResult(125, stderr="Docker engine rejected create")
        if command[:3] == ("docker", "inspect", "--format"):
            return DockerCommandResult(
                0,
                json.dumps(
                    {
                        "Status": "exited",
                        "Running": False,
                        "ExitCode": self.task_exit_code,
                        "Error": "",
                    }
                ),
            )
        if command[:3] == ("docker", "start", "--attach"):
            return DockerCommandResult(
                0,
                stdout="captured stdout\n" if capture_output else "",
                stderr="captured stderr\n" if capture_output else "",
            )
        return DockerCommandResult(0)


def _commands(runner: FakeDockerRunner) -> list[tuple[str, ...]]:
    return [command for command, _ in runner.calls]


def test_nonzero_consumer_exit_exports_evidence_and_cleans_isolated_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _provider_set(tmp_path)
    output = tmp_path / "result"
    runner = FakeDockerRunner(task_exit_code=42)
    monkeypatch.setattr(
        "datalox_gated_runtime.rollout.docker.secrets.token_hex", lambda _: "a" * 24
    )

    result = run_docker_rollout(
        provider_set_path=manifest,
        runtime_image="runtime:image",
        task_image="task:image",
        uid="raw uid/that must stay metadata only",
        session_id="session-7",
        environment_seed=19,
        output_dir=output,
        consumer_command=("python", "train.py", "--steps", "1"),
        runner=runner,
    )

    assert result.consumer_exit_code == 42
    export = json.loads((output / "rollout-export.json").read_text(encoding="utf-8"))
    schema = json.loads(
        (ROOT / "schemas/rollout-execution-export-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(export)
    assert export["uid"] == "raw uid/that must stay metadata only"
    assert export["session_id"] == "session-7"
    assert export["environment_seed"] == 19
    assert export["consumer_exit_code"] == 42
    assert export["final_provider_exports"][0]["provider_state"] == {"phase": "export"}
    assert export["providers"][0]["provider_id"] == "orders"

    commands = _commands(runner)
    assert any(command[:4] == ("docker", "network", "create", "--internal") for command in commands)
    workspace_prepare = next(
        command
        for command in commands
        if command[:2] == ("docker", "run") and "/bin/chmod" in command
    )
    assert workspace_prepare[workspace_prepare.index("--entrypoint") + 2] == "runtime:image"
    gateway = next(command for command in commands if "serve" in command and "intercept" in command)
    assert gateway.count("--network-alias") == 2
    assert "api.orders.example" in gateway
    assert "events.orders.example" in gateway
    assert "--cap-add" in gateway and "NET_BIND_SERVICE" in gateway
    assert "--read-only" in gateway
    assert any(value.startswith("type=bind,") and value.endswith(",readonly") for value in gateway)

    task = next(
        command
        for command in commands
        if command[:2] == ("docker", "create") and "task:image" in command
    )
    assert task[-5:] == ("task:image", "python", "train.py", "--steps", "1")
    assert "--read-only" in task
    assert "--cap-drop" in task and "ALL" in task
    assert "no-new-privileges" in task
    assert any(value == "NO_PROXY=api.orders.example,events.orders.example" for value in task)
    assert any(value == "no_proxy=api.orders.example,events.orders.example" for value in task)
    task_mounts = [value for value in task if value.startswith("type=")]
    assert len(task_mounts) == 2
    assert any("target=/var/run/datalox-trust,readonly" in value for value in task_mounts)
    assert any("target=/workspace" in value for value in task_mounts)
    assert all("/var/run/datalox/rollout" not in value for value in task)
    assert all("docker.sock" not in value for value in task)
    assert all(
        "raw uid/that must stay metadata only" not in value
        for command in commands
        for value in command
    )

    assert any(command[:3] == ("docker", "start", "--attach") for command in commands)
    assert any(command[:2] == ("docker", "inspect") for command in commands)
    assert sum(command[:3] == ("docker", "volume", "rm") for command in commands) == 3
    assert any(command[:3] == ("docker", "network", "rm") for command in commands)


def test_task_create_failure_is_infrastructure_error_and_still_cleans(tmp_path: Path) -> None:
    runner = FakeDockerRunner(fail_task_create=True)
    output = tmp_path / "result"

    with pytest.raises(DockerRolloutError, match="create consumer task container"):
        run_docker_rollout(
            provider_set_path=_provider_set(tmp_path),
            runtime_image="runtime:image",
            task_image="task:image",
            uid="uid-1",
            session_id="session-1",
            environment_seed=1,
            output_dir=output,
            consumer_command=("true",),
            runner=runner,
        )

    assert not output.exists()
    commands = _commands(runner)
    assert not any("--operation" in command and "export" in command for command in commands)
    assert any(command[:3] == ("docker", "network", "rm") for command in commands)


def test_reusable_lease_runs_multiple_tasks_before_one_final_export(tmp_path: Path) -> None:
    runner = FakeDockerRunner(task_exit_code=23)
    lease = DockerRolloutLease.start(
        provider_set_path=_provider_set(tmp_path),
        runtime_image="runtime:image",
        uid="uid-1",
        session_id="7",
        environment_seed=4,
        runner=runner,
    )

    first = lease.exec(task_image="task:image", consumer_command=("first",))
    second = lease.exec(task_image="task:image", consumer_command=("second",))
    result = lease.finalize(output_dir=tmp_path / "result")

    assert first.returncode == second.returncode == result.consumer_exit_code == 23
    assert first.stdout == second.stdout == "captured stdout\n"
    assert first.stderr == second.stderr == "captured stderr\n"
    assert lease.consumer_exit_codes == (23, 23)
    assert lease.state == "finalized"
    export = json.loads((result.output_dir / "rollout-export.json").read_text())
    assert export["consumer_exit_codes"] == [23, 23]
    commands = _commands(runner)
    assert sum(command[:3] == ("docker", "network", "create") for command in commands) == 1
    assert sum("--operation" in command and "reset" in command for command in commands) == 1
    assert (
        sum(command[:2] == ("docker", "create") and "task:image" in command for command in commands)
        == 2
    )
    assert sum(command[:3] == ("docker", "start", "--attach") for command in commands) == 2
    with pytest.raises(DockerRolloutStateError, match="finalized"):
        lease.exec(task_image="task:image", consumer_command=("third",))


def test_zero_execution_lease_finalizes_without_leaking(tmp_path: Path) -> None:
    runner = FakeDockerRunner()
    lease = DockerRolloutLease.start(
        provider_set_path=_provider_set(tmp_path),
        runtime_image="runtime:image",
        uid="uid-no-tool",
        session_id="0",
        environment_seed=0,
        runner=runner,
    )

    result = lease.finalize(output_dir=tmp_path / "result")

    assert result.consumer_exit_code is None
    export = json.loads((result.output_dir / "rollout-export.json").read_text())
    assert export["consumer_exit_codes"] == []
    assert export["consumer_exit_code"] is None
    assert lease.state == "finalized"


@pytest.mark.parametrize("existing_kind", ["directory", "file"])
def test_output_must_not_exist_before_any_docker_operation(
    tmp_path: Path,
    existing_kind: str,
) -> None:
    output = tmp_path / "result"
    output.mkdir() if existing_kind == "directory" else output.write_text("existing")
    runner = FakeDockerRunner()

    with pytest.raises(DockerRolloutError, match="must not already exist"):
        run_docker_rollout(
            provider_set_path=tmp_path / "unused.json",
            runtime_image="runtime:image",
            task_image="task:image",
            uid="uid",
            session_id="session",
            environment_seed=0,
            output_dir=output,
            consumer_command=("true",),
            runner=runner,
        )
    assert runner.calls == []


def test_empty_consumer_command_fails_before_docker(tmp_path: Path) -> None:
    runner = FakeDockerRunner()
    with pytest.raises(DockerRolloutError, match="consumer command"):
        run_docker_rollout(
            provider_set_path=tmp_path / "unused.json",
            runtime_image="runtime:image",
            task_image="task:image",
            uid="uid",
            session_id="session",
            environment_seed=0,
            output_dir=tmp_path / "result",
            consumer_command=(),
            runner=runner,
        )
    assert runner.calls == []


def test_cli_strips_explicit_separator_and_preserves_consumer_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(**kwargs: object) -> object:
        observed.update(kwargs)
        return type("Result", (), {"output_dir": tmp_path, "consumer_exit_code": 17})()

    monkeypatch.setattr(cli, "run_docker_rollout", fake_run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "datalox-gate",
            "rollout",
            "run",
            "--provider-set",
            "providers.json",
            "--runtime-image",
            "runtime:image",
            "--task-image",
            "task:image",
            "--uid",
            "uid-1",
            "--session-id",
            "session-1",
            "--environment-seed",
            "3",
            "--out",
            str(tmp_path / "out"),
            "--",
            "python",
            "train.py",
        ],
    )

    assert cli.main() == 17
    assert observed["consumer_command"] == ("python", "train.py")


def test_cli_requires_explicit_command_separator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        cli,
        "run_docker_rollout",
        lambda **_: pytest.fail("rollout must not start without the separator"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "datalox-gate",
            "rollout",
            "run",
            "--provider-set",
            "providers.json",
            "--runtime-image",
            "runtime:image",
            "--task-image",
            "task:image",
            "--uid",
            "uid-1",
            "--session-id",
            "session-1",
            "--environment-seed",
            "3",
            "--out",
            str(tmp_path / "out"),
            "python",
            "train.py",
        ],
    )
    assert cli.main() == 1


@pytest.mark.skipif(
    not (os.environ.get("DATALOX_RUNTIME_IMAGE") and os.environ.get("DATALOX_TASK_IMAGE")),
    reason="set DATALOX_RUNTIME_IMAGE and DATALOX_TASK_IMAGE for the opt-in Docker smoke test",
)
def test_real_docker_rollout_opt_in(tmp_path: Path) -> None:
    result = run_docker_rollout(
        provider_set_path=_provider_set(tmp_path),
        runtime_image=os.environ["DATALOX_RUNTIME_IMAGE"],
        task_image=os.environ["DATALOX_TASK_IMAGE"],
        uid="docker-smoke",
        session_id="docker-smoke-1",
        environment_seed=0,
        output_dir=tmp_path / "real-result",
        consumer_command=("true",),
    )
    assert result.consumer_exit_code == 0


def _provider_set_v2(tmp_path: Path) -> tuple[Path, object]:
    registry, reference = _publish_example_release(tmp_path)
    path = tmp_path / "rollout-provider-set-v2.json"
    write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "backlog"),),
        registry=registry,
        output_path=path,
    )
    return path, registry


def _v2_host_materialization_root(runner: FakeDockerRunner) -> Path:
    source = next(
        value.split(",source=", 1)[1].split(",target=", 1)[0]
        for command in _commands(runner)
        for value in command
        if value.startswith("type=bind,source=")
        and "target=/opt/datalox/providers/000-runtime" in value
    )
    runtime_path = Path(source)
    return runtime_path.parents[3]


def test_provider_set_v2_rollout_uses_admitted_mounts_exports_release_provenance_and_cleans(
    tmp_path: Path,
) -> None:
    provider_set, registry = _provider_set_v2(tmp_path)
    runner = FakeDockerRunner(task_exit_code=7)
    output = tmp_path / "result-v2"

    result = run_docker_rollout_provider_set_v2(
        provider_set_v2_path=provider_set,
        registry=registry,
        runtime_image="runtime:image",
        task_image="task:image",
        uid="uid-v2",
        session_id="session-v2",
        environment_seed=9,
        output_dir=output,
        consumer_command=("true",),
        runner=runner,
    )

    assert result.consumer_exit_code == 7
    export = json.loads((output / "rollout-export.json").read_text(encoding="utf-8"))
    schema = json.loads(
        (ROOT / "schemas/rollout-execution-export-v2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(export)
    assert export["schema_version"] == "datalox_rollout_execution_export_v2"
    assert export["provider_set_schema_version"] == "datalox_rollout_provider_set_v2"
    provider = export["providers"][0]
    assert provider["release_reference"] == "example_provider@2026.08.25"
    assert provider["profile_id"] == "backlog"
    for field in (
        "release_manifest_sha256",
        "release_config_sha256",
        "profile_layer_sha256",
        "provider_runtime_sha256",
        "provider_admission_sha256",
        "operation_contract_sha256",
    ):
        assert provider[field].startswith("sha256:")

    commands = _commands(runner)
    prepared = next(command for command in commands if "prepare-admitted" in command)
    gateway = next(command for command in commands if "serve-admitted" in command)
    task = next(
        command
        for command in commands
        if "docker" in command and "create" in command and "task:image" in command
    )
    assert (
        prepared.count("--bundle")
        == prepared.count("--admission")
        == prepared.count("--release-config")
        == 1
    )
    assert (
        gateway.count("--bundle")
        == gateway.count("--admission")
        == gateway.count("--release-config")
        == 1
    )
    assert all(
        value.endswith(",readonly") for value in gateway if value.startswith("type=bind,source=")
    )
    assert not any("/opt/datalox/providers" in value for value in task)
    assert not _v2_host_materialization_root(runner).exists()


def test_provider_set_v2_materialization_lives_for_the_complete_lease(
    tmp_path: Path,
) -> None:
    provider_set, registry = _provider_set_v2(tmp_path)
    runner = FakeDockerRunner()

    lease = DockerRolloutLease.start_provider_set_v2(
        provider_set_v2_path=provider_set,
        registry=registry,
        runtime_image="runtime:image",
        uid="uid-v2",
        session_id="lease-lifetime",
        environment_seed=0,
        runner=runner,
    )
    materialization_root = _v2_host_materialization_root(runner)

    assert materialization_root.exists()
    lease.cancel()
    assert not materialization_root.exists()


def test_provider_set_v2_task_failure_removes_host_materialization(tmp_path: Path) -> None:
    provider_set, registry = _provider_set_v2(tmp_path)
    runner = FakeDockerRunner(fail_task_create=True)

    with pytest.raises(DockerRolloutError, match="create consumer task container"):
        run_docker_rollout_provider_set_v2(
            provider_set_v2_path=provider_set,
            registry=registry,
            runtime_image="runtime:image",
            task_image="task:image",
            uid="uid-v2",
            session_id="failure",
            environment_seed=0,
            output_dir=tmp_path / "failed-output",
            consumer_command=("true",),
            runner=runner,
        )

    assert not _v2_host_materialization_root(runner).exists()


def test_provider_set_v2_start_failure_removes_host_materialization(tmp_path: Path) -> None:
    provider_set, registry = _provider_set_v2(tmp_path)
    runner = FakeDockerRunner(fail_admitted_gateway_start=True)

    with pytest.raises(DockerRolloutError, match="start provider gateway"):
        DockerRolloutLease.start_provider_set_v2(
            provider_set_v2_path=provider_set,
            registry=registry,
            runtime_image="runtime:image",
            uid="uid-v2",
            session_id="start-failure",
            environment_seed=0,
            runner=runner,
        )

    assert not _v2_host_materialization_root(runner).exists()
