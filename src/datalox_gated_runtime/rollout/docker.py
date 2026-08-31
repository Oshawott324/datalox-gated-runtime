"""Reusable Docker leases for task-free provider runtime sets."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.rollout.provider_set import (
    LoadedMaterializedRolloutProviderSetV2,
    LoadedRolloutProviderSet,
    load_materialized_rollout_provider_set_v2,
    load_rollout_provider_set,
    materialize_rollout_provider_set_v2,
)

ROLLOUT_EXECUTION_EXPORT_SCHEMA_VERSION = "datalox_rollout_execution_export_v1"
ROLLOUT_EXECUTION_EXPORT_V2_SCHEMA_VERSION = "datalox_rollout_execution_export_v2"
_RUN_ROOT = "/var/run/datalox/rollout"
_TRUST_ROOT = "/var/run/datalox-trust"
_WORKSPACE_ROOT = "/workspace"

RolloutSessionId = str | int
_LABEL_MANAGED = "ai.datalox.managed=rollout"


@dataclass(frozen=True)
class DockerCommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class DockerCommandRunner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        capture_output: bool = False,
    ) -> DockerCommandResult: ...


class SubprocessDockerCommandRunner:
    """Run Docker directly, preserving the consumer process's terminal streams."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        capture_output: bool = False,
    ) -> DockerCommandResult:
        completed = subprocess.run(
            list(arguments),
            check=False,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
        )
        return DockerCommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


@dataclass(frozen=True)
class DockerRolloutResult:
    output_dir: Path
    consumer_exit_code: int | None


class DockerRolloutError(ValueError):
    """An isolated Docker rollout could not be completed safely."""


class DockerRolloutStateError(DockerRolloutError):
    """A rollout lease operation is invalid for its current state."""


@dataclass(frozen=True)
class _LeaseResources:
    lease_id: str
    network: str
    run_volume: str
    trust_volume: str
    workspace_volume: str
    gateway: str
    task: str
    controller: str
    workspace_exporter: str

    @classmethod
    def create(cls) -> _LeaseResources:
        lease_id = secrets.token_hex(12)
        prefix = f"datalox-rollout-{lease_id}"
        return cls(
            lease_id=lease_id,
            network=prefix,
            run_volume=f"{prefix}-run",
            trust_volume=f"{prefix}-trust",
            workspace_volume=f"{prefix}-workspace",
            gateway=f"{prefix}-gateway",
            task=f"{prefix}-task",
            controller=f"{prefix}-controller",
            workspace_exporter=f"{prefix}-workspace-export",
        )


class DockerRolloutLease:
    """One isolated provider process and workspace shared across sequential calls."""

    def __init__(
        self,
        *,
        provider_set: LoadedRolloutProviderSet,
        runtime_image: str,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
        runner: DockerCommandRunner,
        resources: _LeaseResources,
        admitted_provider_set: LoadedMaterializedRolloutProviderSetV2 | None = None,
        host_materialization_root: Path | None = None,
    ) -> None:
        if (admitted_provider_set is None) != (host_materialization_root is None):
            raise DockerRolloutError(
                "admitted provider metadata and host materialization must be supplied together"
            )
        self._provider_set = provider_set
        self._admitted_provider_set = admitted_provider_set
        self._host_materialization_root = host_materialization_root
        self._runtime_image = runtime_image
        self._uid = uid
        self._session_id = session_id
        self._environment_seed = environment_seed
        self._runner = runner
        self._resources = resources
        self._label = f"ai.datalox.lease-id={resources.lease_id}"
        self._authority_hosts = _authority_hosts(provider_set)
        if admitted_provider_set is None:
            self._bundle_mounts, self._bundle_arguments = _bundle_mounts(provider_set)
            self._prepare_subcommand = "prepare"
            self._serve_subcommand = "serve"
        else:
            self._bundle_mounts, self._bundle_arguments = _admitted_bundle_mounts(
                admitted_provider_set
            )
            self._prepare_subcommand = "prepare-admitted"
            self._serve_subcommand = "serve-admitted"
        self._created_network = False
        self._created_volumes: list[str] = []
        self._gateway_started = False
        self._initial_fingerprint: str | None = None
        self._consumer_exit_codes: list[int] = []
        self._state = "new"

    @classmethod
    def start(
        cls,
        *,
        provider_set_path: Path,
        runtime_image: str,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
        runner: DockerCommandRunner | None = None,
    ) -> DockerRolloutLease:
        """Create, reset, and return an active isolated provider lease."""

        _validate_image(runtime_image, "runtime image")
        _validate_metadata(uid, "uid")
        _validate_session_id(session_id)
        if not isinstance(environment_seed, int) or isinstance(environment_seed, bool):
            raise DockerRolloutError("environment seed must be an integer")
        if environment_seed < 0:
            raise DockerRolloutError("environment seed must be non-negative")
        lease = cls(
            provider_set=load_rollout_provider_set(provider_set_path),
            runtime_image=runtime_image,
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
            runner=runner or SubprocessDockerCommandRunner(),
            resources=_LeaseResources.create(),
        )
        lease._start()
        return lease

    @classmethod
    def start_provider_set_v2(
        cls,
        *,
        provider_set_v2_path: Path,
        registry: FilesystemProviderReleaseRegistry | Path,
        runtime_image: str,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
        runner: DockerCommandRunner | None = None,
    ) -> DockerRolloutLease:
        """Start one admitted lease from an immutable registry-backed provider set."""

        _validate_lease_inputs(
            runtime_image=runtime_image,
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
        )
        host_root = Path(tempfile.mkdtemp(prefix="datalox-rollout-provider-set-v2-"))
        host_root.chmod(0o700)
        lease: DockerRolloutLease | None = None
        try:
            materialized = materialize_rollout_provider_set_v2(
                provider_set=provider_set_v2_path,
                registry=registry,
                output_dir=host_root / "materialized",
            )
            admitted = load_materialized_rollout_provider_set_v2(materialized.root)
            lease = cls(
                provider_set=admitted.provider_set_v1,
                admitted_provider_set=admitted,
                host_materialization_root=host_root,
                runtime_image=runtime_image,
                uid=uid,
                session_id=session_id,
                environment_seed=environment_seed,
                runner=runner or SubprocessDockerCommandRunner(),
                resources=_LeaseResources.create(),
            )
            lease._start()
            return lease
        except BaseException:
            if lease is None or lease._host_materialization_root is not None:
                shutil.rmtree(host_root, ignore_errors=True)
            raise

    @property
    def lease_id(self) -> str:
        """Return the opaque identifier used only for Docker resource ownership."""

        return self._resources.lease_id

    @property
    def state(self) -> str:
        return self._state

    @property
    def initial_provider_fingerprint(self) -> str:
        self._require_state("active")
        if self._initial_fingerprint is None:
            raise DockerRolloutError("active lease is missing its initial fingerprint")
        return self._initial_fingerprint

    @property
    def consumer_exit_codes(self) -> tuple[int, ...]:
        return tuple(self._consumer_exit_codes)

    def exec(
        self,
        *,
        task_image: str,
        consumer_command: tuple[str, ...],
        capture_output: bool = True,
    ) -> DockerCommandResult:
        """Run one command against the lease's existing provider state and workspace."""

        self._require_state("active")
        _validate_image(task_image, "task image")
        _validate_consumer_command(consumer_command)
        result = _run_task(
            runner=self._runner,
            task_image=task_image,
            resources=self._resources,
            label=self._label,
            authority_hosts=self._authority_hosts,
            consumer_command=consumer_command,
            capture_output=capture_output,
        )
        if not 0 <= result.returncode <= 255:
            raise DockerRolloutError(
                f"Docker returned invalid consumer exit code {result.returncode}"
            )
        self._consumer_exit_codes.append(result.returncode)
        return result

    def finalize(self, *, output_dir: Path) -> DockerRolloutResult:
        """Export final provider/workspace evidence, clean resources, and close the lease."""

        self._require_state("active")
        _validate_new_output(output_dir)
        output_parent = output_dir.parent.resolve()
        output_parent.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=output_parent))
        self._state = "finalizing"
        primary_error: BaseException | None = None
        final_exports: list[dict[str, object]] | None = None
        try:
            final = _run_control(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                provider_ids=tuple(item.provider_id for item in self._provider_set.providers),
                operation="export",
            )
            final_exports = final["providers"]
            _export_workspace(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                output_dir=staging_dir / "workspace",
            )
        except (DockerRolloutError, OSError, KeyboardInterrupt, SystemExit) as exc:
            primary_error = exc
        cleanup_error = self._cleanup_resources()
        self._state = "finalizing" if primary_error is None and cleanup_error is None else "failed"
        if primary_error is None and cleanup_error is not None:
            primary_error = cleanup_error
        if primary_error is not None:
            shutil.rmtree(staging_dir, ignore_errors=True)
            _raise_rollout_error(primary_error)
        if final_exports is None or self._initial_fingerprint is None:
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._state = "failed"
            raise DockerRolloutError("rollout execution did not produce complete provider evidence")

        try:
            if self._admitted_provider_set is not None:
                export = self._admitted_rollout_export(final_exports)
            else:
                export = {
                    "schema_version": ROLLOUT_EXECUTION_EXPORT_SCHEMA_VERSION,
                    "uid": self._uid,
                    "session_id": self._session_id,
                    "environment_seed": self._environment_seed,
                    "provider_set_sha256": _sha256_file(self._provider_set.manifest_path),
                    "providers": [
                        {
                            "provider_id": provider.provider_id,
                            "provider_runtime_sha256": provider.provider_runtime_sha256,
                            "authorities": list(provider.authorities),
                        }
                        for provider in self._provider_set.providers
                    ],
                    "initial_provider_fingerprint": self._initial_fingerprint,
                    "final_provider_exports": final_exports,
                    "consumer_exit_codes": list(self._consumer_exit_codes),
                    "consumer_exit_code": (
                        self._consumer_exit_codes[-1] if self._consumer_exit_codes else None
                    ),
                }
            (staging_dir / "rollout-export.json").write_text(
                json.dumps(export, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(staging_dir, output_dir)
        except OSError as exc:
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._state = "failed"
            raise DockerRolloutError(f"could not publish rollout evidence: {exc}") from exc
        self._state = "finalized"
        return DockerRolloutResult(
            output_dir=output_dir.resolve(),
            consumer_exit_code=(
                self._consumer_exit_codes[-1] if self._consumer_exit_codes else None
            ),
        )

    def cancel(self) -> None:
        """Clean an active lease without exporting provider or workspace evidence."""

        self._require_state("active")
        self._state = "cancelling"
        cleanup_error = self._cleanup_resources()
        self._state = "cancelled" if cleanup_error is None else "failed"
        if cleanup_error is not None:
            raise cleanup_error

    def _start(self) -> None:
        self._require_state("new")
        self._state = "starting"
        try:
            _checked(
                self._runner,
                (
                    "docker",
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    _LABEL_MANAGED,
                    "--label",
                    self._label,
                    self._resources.network,
                ),
                "create isolated Docker network",
            )
            self._created_network = True
            for volume in (
                self._resources.run_volume,
                self._resources.trust_volume,
                self._resources.workspace_volume,
            ):
                _checked(
                    self._runner,
                    (
                        "docker",
                        "volume",
                        "create",
                        "--label",
                        _LABEL_MANAGED,
                        "--label",
                        self._label,
                        volume,
                    ),
                    f"create Docker volume {volume}",
                )
                self._created_volumes.append(volume)
            _prepare_workspace(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
            )
            _prepare_interception(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                bundle_mounts=self._bundle_mounts,
                bundle_arguments=self._bundle_arguments,
                subcommand=self._prepare_subcommand,
            )
            _start_gateway(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                authority_hosts=self._authority_hosts,
                bundle_mounts=self._bundle_mounts,
                bundle_arguments=self._bundle_arguments,
                subcommand=self._serve_subcommand,
            )
            self._gateway_started = True
            _wait_until_ready(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
            )
            initial = _run_control(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                provider_ids=tuple(item.provider_id for item in self._provider_set.providers),
                operation="reset",
            )
            self._initial_fingerprint = _provider_state_fingerprint(initial["providers"])
            self._state = "active"
        except (DockerRolloutError, OSError, KeyboardInterrupt, SystemExit) as exc:
            cleanup_error = self._cleanup_resources()
            self._state = "failed"
            if cleanup_error is not None and not isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise cleanup_error from exc
            _raise_rollout_error(exc)

    def _cleanup_resources(self) -> DockerRolloutError | None:
        resource_error = _cleanup(
            runner=self._runner,
            resources=self._resources,
            created_network=self._created_network,
            created_volumes=tuple(self._created_volumes),
        )
        materialization_error = self._remove_host_materialization()
        if resource_error is not None and materialization_error is not None:
            return DockerRolloutError(f"{resource_error}; {materialization_error}")
        return resource_error or materialization_error

    def _remove_host_materialization(self) -> DockerRolloutError | None:
        root = self._host_materialization_root
        if root is None:
            return None
        try:
            shutil.rmtree(root)
        except OSError as exc:
            return DockerRolloutError(f"could not remove provider-set-v2 materialization: {exc}")
        self._host_materialization_root = None
        return None

    def _admitted_rollout_export(
        self,
        final_exports: list[dict[str, object]],
    ) -> dict[str, object]:
        admitted = self._admitted_provider_set
        if admitted is None or self._initial_fingerprint is None:
            raise DockerRolloutError("admitted rollout metadata is incomplete")
        return {
            "schema_version": ROLLOUT_EXECUTION_EXPORT_V2_SCHEMA_VERSION,
            "uid": self._uid,
            "session_id": self._session_id,
            "environment_seed": self._environment_seed,
            "provider_set_sha256": admitted.source_manifest_sha256,
            "provider_set_schema_version": "datalox_rollout_provider_set_v2",
            "providers": [
                {
                    "provider_id": binding.provider.provider_id,
                    "release_reference": binding.provider.release_reference,
                    "release_manifest_sha256": binding.provider.release_manifest_sha256,
                    "release_config_sha256": binding.release_config_sha256,
                    "profile_id": binding.provider.profile_id,
                    "profile_layer_sha256": binding.provider.profile_layer_sha256,
                    "provider_runtime_sha256": binding.provider.provider_runtime_sha256,
                    "provider_admission_sha256": binding.provider.provider_admission_sha256,
                    "operation_contract_sha256": binding.provider.operation_contract_sha256,
                    "authorities": list(binding.provider.authorities),
                }
                for binding in admitted.bindings
            ],
            "initial_provider_fingerprint": self._initial_fingerprint,
            "final_provider_exports": final_exports,
            "consumer_exit_codes": list(self._consumer_exit_codes),
            "consumer_exit_code": (
                self._consumer_exit_codes[-1] if self._consumer_exit_codes else None
            ),
        }

    def _require_state(self, expected: str) -> None:
        if self._state != expected:
            raise DockerRolloutStateError(f"rollout lease is {self._state}; expected {expected}")


def run_docker_rollout(
    *,
    provider_set_path: Path,
    runtime_image: str,
    task_image: str,
    uid: str,
    session_id: RolloutSessionId,
    environment_seed: int,
    output_dir: Path,
    consumer_command: tuple[str, ...],
    runner: DockerCommandRunner | None = None,
) -> DockerRolloutResult:
    """Run one consumer command inside a fresh provider-isolated Docker lease."""

    _validate_new_output(output_dir)
    _validate_image(runtime_image, "runtime image")
    _validate_image(task_image, "task image")
    _validate_metadata(uid, "uid")
    _validate_session_id(session_id)
    _validate_consumer_command(consumer_command)
    lease: DockerRolloutLease | None = None
    try:
        lease = DockerRolloutLease.start(
            provider_set_path=provider_set_path,
            runtime_image=runtime_image,
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
            runner=runner,
        )
        lease.exec(
            task_image=task_image,
            consumer_command=consumer_command,
            capture_output=False,
        )
        return lease.finalize(output_dir=output_dir)
    except BaseException as exc:
        cleanup_error: DockerRolloutError | None = None
        if lease is not None and lease.state == "active":
            try:
                lease.cancel()
            except DockerRolloutError as cancel_error:
                cleanup_error = cancel_error
        if cleanup_error is not None and not isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise cleanup_error from exc
        raise


def run_docker_rollout_provider_set_v2(
    *,
    provider_set_v2_path: Path,
    registry: FilesystemProviderReleaseRegistry | Path,
    runtime_image: str,
    task_image: str,
    uid: str,
    session_id: RolloutSessionId,
    environment_seed: int,
    output_dir: Path,
    consumer_command: tuple[str, ...],
    runner: DockerCommandRunner | None = None,
) -> DockerRolloutResult:
    """Run one command against an admitted immutable provider-set-v2 lease."""

    _validate_new_output(output_dir)
    _validate_image(task_image, "task image")
    _validate_consumer_command(consumer_command)
    lease: DockerRolloutLease | None = None
    try:
        lease = DockerRolloutLease.start_provider_set_v2(
            provider_set_v2_path=provider_set_v2_path,
            registry=registry,
            runtime_image=runtime_image,
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
            runner=runner,
        )
        lease.exec(
            task_image=task_image,
            consumer_command=consumer_command,
            capture_output=False,
        )
        return lease.finalize(output_dir=output_dir)
    except BaseException as exc:
        cleanup_error: DockerRolloutError | None = None
        if lease is not None and lease.state == "active":
            try:
                lease.cancel()
            except DockerRolloutError as cancel_error:
                cleanup_error = cancel_error
        if cleanup_error is not None and not isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise cleanup_error from exc
        raise


def _prepare_workspace(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
) -> None:
    _checked(
        runner,
        (
            "docker",
            "run",
            "--rm",
            "--name",
            resources.controller,
            "--network",
            "none",
            "--user",
            "0",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--label",
            _LABEL_MANAGED,
            "--label",
            label,
            "--mount",
            f"type=volume,source={resources.workspace_volume},target={_WORKSPACE_ROOT}",
            "--entrypoint",
            "/bin/chmod",
            runtime_image,
            "1777",
            _WORKSPACE_ROOT,
        ),
        "prepare rollout workspace",
    )


def _prepare_interception(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    bundle_mounts: tuple[str, ...],
    bundle_arguments: tuple[str, ...],
    subcommand: str,
) -> None:
    arguments = [
        "docker",
        "run",
        "--rm",
        "--name",
        resources.controller,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--label",
        _LABEL_MANAGED,
        "--label",
        label,
        "--mount",
        f"type=volume,source={resources.run_volume},target=/var/run/datalox",
        "--mount",
        f"type=volume,source={resources.trust_volume},target={_TRUST_ROOT}",
        *bundle_mounts,
        runtime_image,
        "intercept",
        subcommand,
        *bundle_arguments,
        "--run",
        _RUN_ROOT,
        "--trust-dir",
        _TRUST_ROOT,
    ]
    _checked(runner, tuple(arguments), "prepare provider interception")


def _start_gateway(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    authority_hosts: tuple[str, ...],
    bundle_mounts: tuple[str, ...],
    bundle_arguments: tuple[str, ...],
    subcommand: str,
) -> None:
    aliases = tuple(value for host in authority_hosts for value in ("--network-alias", host))
    arguments = (
        "docker",
        "run",
        "--detach",
        "--name",
        resources.gateway,
        "--network",
        resources.network,
        *aliases,
        "--cap-drop",
        "ALL",
        "--cap-add",
        "NET_BIND_SERVICE",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m",
        "--label",
        _LABEL_MANAGED,
        "--label",
        label,
        "--mount",
        f"type=volume,source={resources.run_volume},target=/var/run/datalox",
        *bundle_mounts,
        runtime_image,
        "intercept",
        subcommand,
        *bundle_arguments,
        "--run",
        _RUN_ROOT,
        "--host",
        "0.0.0.0",
        "--port",
        "443",
        "--prepared",
    )
    _checked(runner, arguments, "start provider gateway")


def _wait_until_ready(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
) -> None:
    deadline = time.monotonic() + 15
    last_error = "gateway did not become ready"
    while time.monotonic() < deadline:
        result = runner.run(
            _controller_command(
                runtime_image=runtime_image,
                resources=resources,
                label=label,
                control_arguments=("intercept", "ready", "--run", _RUN_ROOT, "--json"),
            ),
            capture_output=True,
        )
        if result.returncode == 0:
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                last_error = "gateway readiness command returned invalid JSON"
            else:
                if isinstance(payload, dict) and payload.get("ok") is True:
                    return
                last_error = "gateway readiness command returned an invalid payload"
        elif result.stderr.strip():
            last_error = result.stderr.strip()
        time.sleep(0.1)
    raise DockerRolloutError(f"provider gateway readiness failed: {last_error}")


def _run_control(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    provider_ids: tuple[str, ...],
    operation: str,
) -> dict[str, object]:
    provider_arguments = tuple(
        value for provider_id in provider_ids for value in ("--provider-id", provider_id)
    )
    result = runner.run(
        _controller_command(
            runtime_image=runtime_image,
            resources=resources,
            label=label,
            control_arguments=(
                "intercept",
                "control",
                "--run",
                _RUN_ROOT,
                "--operation",
                operation,
                *provider_arguments,
                "--json",
            ),
        ),
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no error output"
        raise DockerRolloutError(f"provider control {operation} failed: {detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DockerRolloutError(f"provider control {operation} returned invalid JSON") from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != "datalox_interception_control_aggregate_v1"
        or payload.get("operation") != operation
        or not isinstance(payload.get("providers"), list)
        or not all(isinstance(item, dict) for item in payload["providers"])
        or [item.get("provider_id") for item in payload["providers"]] != list(provider_ids)
    ):
        raise DockerRolloutError(f"provider control {operation} returned an invalid aggregate")
    return payload


def _controller_command(
    *,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    control_arguments: tuple[str, ...],
) -> tuple[str, ...]:
    return (
        "docker",
        "run",
        "--rm",
        "--name",
        resources.controller,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--label",
        _LABEL_MANAGED,
        "--label",
        label,
        "--mount",
        f"type=volume,source={resources.run_volume},target=/var/run/datalox",
        runtime_image,
        *control_arguments,
    )


def _run_task(
    *,
    runner: DockerCommandRunner,
    task_image: str,
    resources: _LeaseResources,
    label: str,
    authority_hosts: tuple[str, ...],
    consumer_command: tuple[str, ...],
    capture_output: bool,
) -> DockerCommandResult:
    runner.run(("docker", "rm", "--force", resources.task), capture_output=True)
    _checked(
        runner,
        _task_create_command(
            task_image=task_image,
            resources=resources,
            label=label,
            authority_hosts=authority_hosts,
            consumer_command=consumer_command,
        ),
        "create consumer task container",
    )
    attached = runner.run(
        ("docker", "start", "--attach", resources.task),
        capture_output=capture_output,
    )
    inspected = _checked(
        runner,
        (
            "docker",
            "inspect",
            "--format",
            "{{json .State}}",
            resources.task,
        ),
        "inspect consumer task container",
    )
    try:
        state = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise DockerRolloutError("Docker returned invalid consumer container state") from exc
    if (
        not isinstance(state, dict)
        or state.get("Status") != "exited"
        or state.get("Running") is not False
        or not isinstance(state.get("ExitCode"), int)
    ):
        raise DockerRolloutError("consumer task container did not reach a valid exited state")
    if state.get("Error"):
        raise DockerRolloutError(f"consumer task container failed to start: {state['Error']}")
    result = DockerCommandResult(
        returncode=state["ExitCode"],
        stdout=attached.stdout,
        stderr=attached.stderr,
    )
    removal = runner.run(("docker", "rm", resources.task), capture_output=True)
    if removal.returncode != 0:
        detail = removal.stderr.strip() or removal.stdout.strip() or "no error output"
        raise DockerRolloutError(f"could not remove consumer task container: {detail}")
    return result


def _task_create_command(
    *,
    task_image: str,
    resources: _LeaseResources,
    label: str,
    authority_hosts: tuple[str, ...],
    consumer_command: tuple[str, ...],
) -> tuple[str, ...]:
    trust_environment = {
        "SSL_CERT_FILE": f"{_TRUST_ROOT}/ca.pem",
        "REQUESTS_CA_BUNDLE": f"{_TRUST_ROOT}/ca.pem",
        "CURL_CA_BUNDLE": f"{_TRUST_ROOT}/ca.pem",
        "NODE_EXTRA_CA_CERTS": f"{_TRUST_ROOT}/ca.pem",
        "AWS_CA_BUNDLE": f"{_TRUST_ROOT}/ca.pem",
        "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH": f"{_TRUST_ROOT}/ca.pem",
        "GIT_SSL_CAINFO": f"{_TRUST_ROOT}/ca.pem",
        "NO_PROXY": ",".join(authority_hosts),
        "no_proxy": ",".join(authority_hosts),
    }
    environment = tuple(
        value for key, item in trust_environment.items() for value in ("--env", f"{key}={item}")
    )
    return (
        "docker",
        "create",
        "--name",
        resources.task,
        "--network",
        resources.network,
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=1g",
        "--label",
        _LABEL_MANAGED,
        "--label",
        label,
        "--mount",
        f"type=volume,source={resources.trust_volume},target={_TRUST_ROOT},readonly",
        "--mount",
        f"type=volume,source={resources.workspace_volume},target={_WORKSPACE_ROOT}",
        "--workdir",
        _WORKSPACE_ROOT,
        *environment,
        task_image,
        *consumer_command,
    )


def _export_workspace(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    output_dir: Path,
) -> None:
    output_dir.mkdir()
    _checked(
        runner,
        (
            "docker",
            "create",
            "--name",
            resources.workspace_exporter,
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--label",
            _LABEL_MANAGED,
            "--label",
            label,
            "--mount",
            f"type=volume,source={resources.workspace_volume},target={_WORKSPACE_ROOT},readonly",
            "--entrypoint",
            "/bin/true",
            runtime_image,
        ),
        "create workspace export container",
    )
    _checked(
        runner,
        (
            "docker",
            "cp",
            f"{resources.workspace_exporter}:{_WORKSPACE_ROOT}/.",
            str(output_dir),
        ),
        "export rollout workspace",
    )


def _cleanup(
    *,
    runner: DockerCommandRunner,
    resources: _LeaseResources,
    created_network: bool,
    created_volumes: tuple[str, ...],
) -> DockerRolloutError | None:
    for container in (
        resources.task,
        resources.controller,
        resources.workspace_exporter,
        resources.gateway,
    ):
        runner.run(("docker", "rm", "--force", container), capture_output=True)
    failures: list[str] = []
    for volume in reversed(created_volumes):
        result = runner.run(("docker", "volume", "rm", volume), capture_output=True)
        if result.returncode != 0:
            failures.append(f"volume {volume}")
    if created_network:
        result = runner.run(("docker", "network", "rm", resources.network), capture_output=True)
        if result.returncode != 0:
            failures.append(f"network {resources.network}")
    if failures:
        return DockerRolloutError(
            "could not clean isolated Docker resources: " + ", ".join(failures)
        )
    return None


def _bundle_mounts(
    provider_set: LoadedRolloutProviderSet,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    mounts: list[str] = []
    bundle_arguments: list[str] = []
    for index, provider in enumerate(provider_set.providers):
        target = f"/opt/datalox/providers/{index:03d}"
        mounts.extend(
            (
                "--mount",
                f"type=bind,source={provider.bundle_dir},target={target},readonly",
            )
        )
        bundle_arguments.extend(("--bundle", target))
    return tuple(mounts), tuple(bundle_arguments)


def _admitted_bundle_mounts(
    provider_set: LoadedMaterializedRolloutProviderSetV2,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    mounts: list[str] = []
    binding_arguments: list[str] = []
    for index, binding in enumerate(provider_set.bindings):
        runtime_target = f"/opt/datalox/providers/{index:03d}-runtime"
        admission_target = f"/opt/datalox/providers/{index:03d}-admission.json"
        release_config_target = f"/opt/datalox/providers/{index:03d}-release-config.json"
        mounts.extend(
            (
                "--mount",
                f"type=bind,source={binding.bundle_dir},target={runtime_target},readonly",
                "--mount",
                f"type=bind,source={binding.admission_path},target={admission_target},readonly",
                "--mount",
                "type=bind,"
                f"source={binding.release_config_path},"
                f"target={release_config_target},readonly",
            )
        )
        binding_arguments.extend(
            (
                "--bundle",
                runtime_target,
                "--admission",
                admission_target,
                "--release-config",
                release_config_target,
            )
        )
    return tuple(mounts), tuple(binding_arguments)


def _authority_hosts(provider_set: LoadedRolloutProviderSet) -> tuple[str, ...]:
    hosts: list[str] = []
    for provider in provider_set.providers:
        for authority in provider.authorities:
            parsed = urlsplit(f"//{authority}")
            if parsed.hostname is None or parsed.port not in {None, 443}:
                raise DockerRolloutError(
                    "Docker rollout interception requires provider authorities on HTTPS port 443"
                )
            host = parsed.hostname
            if host not in hosts:
                hosts.append(host)
    return tuple(hosts)


def _checked(
    runner: DockerCommandRunner,
    arguments: tuple[str, ...],
    action: str,
) -> DockerCommandResult:
    result = runner.run(arguments, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no error output"
        raise DockerRolloutError(f"could not {action}: {detail}")
    return result


def _validate_new_output(output_dir: Path) -> None:
    if output_dir.exists() or output_dir.is_symlink():
        raise DockerRolloutError("rollout output path must not already exist")


def _validate_image(value: str, field: str) -> None:
    if not value or value.strip() != value or any(character.isspace() for character in value):
        raise DockerRolloutError(f"{field} must be a non-empty Docker image reference")


def _validate_consumer_command(consumer_command: tuple[str, ...]) -> None:
    if not consumer_command or any(
        not isinstance(item, str) or not item for item in consumer_command
    ):
        raise DockerRolloutError("consumer command must be non-empty")


def _validate_metadata(value: str, field: str) -> None:
    if (
        not value
        or value.strip() != value
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DockerRolloutError(f"{field} must be a non-empty value of at most 256 characters")


def _validate_session_id(value: object) -> None:
    if isinstance(value, bool):
        raise DockerRolloutError("session_id must be a non-negative integer or non-empty string")
    if isinstance(value, int):
        if value < 0:
            raise DockerRolloutError("integer session_id must be non-negative")
        return
    if isinstance(value, str):
        _validate_metadata(value, "session_id")
        return
    raise DockerRolloutError("session_id must be a non-negative integer or non-empty string")


def _validate_lease_inputs(
    *,
    runtime_image: str,
    uid: str,
    session_id: RolloutSessionId,
    environment_seed: int,
) -> None:
    _validate_image(runtime_image, "runtime image")
    _validate_metadata(uid, "uid")
    _validate_session_id(session_id)
    if not isinstance(environment_seed, int) or isinstance(environment_seed, bool):
        raise DockerRolloutError("environment seed must be an integer")
    if environment_seed < 0:
        raise DockerRolloutError("environment seed must be non-negative")


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _provider_state_fingerprint(providers: object) -> str:
    """Fingerprint reset-visible provider state without run-local evidence IDs."""

    if not isinstance(providers, list) or not providers:
        raise DockerRolloutError("provider reset did not return a non-empty provider array")
    observations: list[dict[str, object]] = []
    for provider in providers:
        if (
            not isinstance(provider, dict)
            or provider.get("schema_version") != "datalox_provider_run_v1"
            or not isinstance(provider.get("provider_id"), str)
            or not isinstance(provider.get("bundle_version"), str)
            or not isinstance(provider.get("authorities"), list)
            or not all(isinstance(item, str) for item in provider["authorities"])
            or not isinstance(provider.get("provider_state"), dict)
        ):
            raise DockerRolloutError("provider reset returned an invalid provider observation")
        observations.append(
            {
                "provider_id": provider["provider_id"],
                "bundle_version": provider["bundle_version"],
                "authorities": provider["authorities"],
                "provider_state": provider["provider_state"],
            }
        )
    return _canonical_digest(observations)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _raise_rollout_error(error: BaseException) -> None:
    if isinstance(error, (KeyboardInterrupt, SystemExit)):
        raise error
    if isinstance(error, DockerRolloutError):
        raise error
    raise DockerRolloutError(str(error)) from error
