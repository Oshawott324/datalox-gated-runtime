"""Docker rollout leases for one operator-selected admitted Composition Pack."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from datalox_gated_runtime.composition.runtime_binding import (
    LoadedRuntimeComposition,
    load_runtime_composition,
)
from datalox_gated_runtime.interception.composition_server import (
    _episode_seed,
    _logical_time,
)
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.rollout.composition_control import (
    CompositionRolloutControlError,
    _validate_export,
)
from datalox_gated_runtime.rollout.docker import (
    _LABEL_MANAGED,
    _RUN_ROOT,
    _TRUST_ROOT,
    DockerCommandRunner,
    DockerRolloutError,
    DockerRolloutLease,
    DockerRolloutResult,
    RolloutSessionId,
    SubprocessDockerCommandRunner,
    _canonical_digest,
    _checked,
    _export_workspace,
    _LeaseResources,
    _prepare_workspace,
    _provider_state_fingerprint,
    _raise_rollout_error,
    _validate_lease_inputs,
    _validate_new_output,
    _wait_until_ready,
)
from datalox_gated_runtime.rollout.provider_set import (
    LoadedMaterializedRolloutProviderSetV2,
    load_materialized_rollout_provider_set_v2,
    load_rollout_provider_set_v2,
    materialize_rollout_provider_set_v2,
)

ROLLOUT_COMPOSITION_EXPORT_SCHEMA_VERSION = "datalox_rollout_composition_execution_export_v1"
_COMPOSITION_PROVIDER_SET = "/opt/datalox/provider-set"
_COMPOSITION_PACK = "/opt/datalox/composition/pack"
_COMPOSITION_ADMISSION = "/opt/datalox/composition/composition-admission.json"


@dataclass(frozen=True)
class CompositionRolloutConfig:
    """Trusted immutable selection shared by every isolated lease in one pool."""

    provider_set_v2_path: Path
    registry: FilesystemProviderReleaseRegistry
    composition_pack_dir: Path
    composition_admission_path: Path
    episode_seed: str
    initial_composition_delivery_time: str
    provider_set_sha256: str
    composition_pack_sha256: str
    composition_admission_sha256: str

    @classmethod
    def load(
        cls,
        *,
        provider_set_v2_path: Path,
        registry: FilesystemProviderReleaseRegistry | Path,
        composition_pack_dir: Path,
        composition_admission_path: Path,
        episode_seed: str,
        initial_composition_delivery_time: str,
    ) -> CompositionRolloutConfig:
        """Revalidate the exact registry, releases, pack, admission, seed, and time."""

        loaded_registry = (
            registry
            if isinstance(registry, FilesystemProviderReleaseRegistry)
            else FilesystemProviderReleaseRegistry.load(registry)
        )
        selected = load_rollout_provider_set_v2(
            provider_set_v2_path,
            registry=loaded_registry,
        )
        pack_dir = composition_pack_dir.resolve(strict=True)
        admission_path = composition_admission_path.resolve(strict=True)
        normalized_seed = _episode_seed(episode_seed)
        normalized_time = _logical_time(initial_composition_delivery_time)
        validation_root = Path(tempfile.mkdtemp(prefix="datalox-composition-config-"))
        validation_root.chmod(0o700)
        try:
            materialized = materialize_rollout_provider_set_v2(
                provider_set=selected,
                registry=loaded_registry,
                output_dir=validation_root / "materialized",
            )
            loaded_composition = load_runtime_composition(
                provider_set=load_materialized_rollout_provider_set_v2(materialized.root),
                pack_dir=pack_dir,
                admission_path=admission_path,
            )
        finally:
            shutil.rmtree(validation_root, ignore_errors=True)
        return cls(
            provider_set_v2_path=selected.manifest_path,
            registry=loaded_registry,
            composition_pack_dir=pack_dir,
            composition_admission_path=admission_path,
            episode_seed=normalized_seed,
            initial_composition_delivery_time=normalized_time,
            provider_set_sha256=selected.manifest_sha256,
            composition_pack_sha256=loaded_composition.pack.canonical_sha256,
            composition_admission_sha256=loaded_composition.admission.canonical_sha256,
        )


class DockerCompositionRolloutLease(DockerRolloutLease):
    """One fresh, non-resumable admitted composition session in Docker."""

    def __init__(
        self,
        *,
        config: CompositionRolloutConfig,
        loaded: LoadedRuntimeComposition,
        host_root: Path,
        runtime_image: str,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
        runner: DockerCommandRunner,
        resources: _LeaseResources,
    ) -> None:
        super().__init__(
            provider_set=loaded.provider_set.provider_set_v1,
            admitted_provider_set=loaded.provider_set,
            host_materialization_root=host_root,
            runtime_image=runtime_image,
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
            runner=runner,
            resources=resources,
        )
        self._composition_config = config
        self._runtime_composition = loaded
        self._composition_mounts = _composition_mounts(
            provider_set=loaded.provider_set,
            pack_dir=loaded.pack.root,
            admission_path=loaded.admission.path,
        )

    @classmethod
    def start(
        cls,
        *,
        composition_config: CompositionRolloutConfig,
        runtime_image: str,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
        runner: DockerCommandRunner | None = None,
    ) -> DockerCompositionRolloutLease:
        """Materialize and start one fresh session from a fixed admitted composition."""

        if not isinstance(composition_config, CompositionRolloutConfig):
            raise DockerRolloutError("composition_config must be a CompositionRolloutConfig")
        _validate_lease_inputs(
            runtime_image=runtime_image,
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
        )
        host_root = Path(tempfile.mkdtemp(prefix="datalox-rollout-composition-"))
        host_root.chmod(0o700)
        lease: DockerCompositionRolloutLease | None = None
        try:
            materialized = materialize_rollout_provider_set_v2(
                provider_set=composition_config.provider_set_v2_path,
                registry=composition_config.registry,
                output_dir=host_root / "materialized",
            )
            pack_dir = host_root / "composition" / "pack"
            pack_dir.parent.mkdir(parents=True)
            shutil.copytree(
                composition_config.composition_pack_dir,
                pack_dir,
                symlinks=True,
            )
            admission_path = host_root / "composition" / "composition-admission.json"
            shutil.copy2(composition_config.composition_admission_path, admission_path)
            loaded = load_runtime_composition(
                provider_set=load_materialized_rollout_provider_set_v2(materialized.root),
                pack_dir=pack_dir,
                admission_path=admission_path,
            )
            _require_fixed_composition(composition_config, loaded)
            lease = cls(
                config=composition_config,
                loaded=loaded,
                host_root=host_root,
                runtime_image=runtime_image,
                uid=uid,
                session_id=session_id,
                environment_seed=environment_seed,
                runner=runner or SubprocessDockerCommandRunner(),
                resources=_LeaseResources.create(),
            )
            lease._start_composition()
            return lease
        except BaseException:
            if lease is None or lease._host_materialization_root is not None:
                shutil.rmtree(host_root, ignore_errors=True)
            raise

    def finalize(self, *, output_dir: Path) -> DockerRolloutResult:
        """Finalize the composition, export all evidence and workspace, then destroy it."""

        self._require_state("active")
        _validate_new_output(output_dir)
        output_parent = output_dir.parent.resolve()
        output_parent.mkdir(parents=True, exist_ok=True)
        staging_dir = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.tmp-", dir=output_parent))
        self._state = "finalizing"
        primary_error: BaseException | None = None
        final_export: dict[str, object] | None = None
        try:
            final_export = _run_composition_control(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                operation="finalize",
            )
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
        if final_export is None or self._initial_fingerprint is None:
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._state = "failed"
            raise DockerRolloutError("composition rollout did not produce complete evidence")
        try:
            export = self._composition_rollout_export(final_export)
            (staging_dir / "rollout-export.json").write_text(
                json.dumps(export, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            os.replace(staging_dir, output_dir)
        except OSError as exc:
            shutil.rmtree(staging_dir, ignore_errors=True)
            self._state = "failed"
            raise DockerRolloutError(f"could not publish composition evidence: {exc}") from exc
        self._state = "finalized"
        return DockerRolloutResult(
            output_dir=output_dir.resolve(),
            consumer_exit_code=(
                self._consumer_exit_codes[-1] if self._consumer_exit_codes else None
            ),
        )

    def _start_composition(self) -> None:
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
            _prepare_composition(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                mounts=self._composition_mounts,
                config=self._composition_config,
            )
            _start_composition_gateway(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                authority_hosts=self._authority_hosts,
                mounts=self._composition_mounts,
                config=self._composition_config,
            )
            self._gateway_started = True
            _wait_until_ready(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
            )
            initial = _run_composition_control(
                runner=self._runner,
                runtime_image=self._runtime_image,
                resources=self._resources,
                label=self._label,
                operation="reset",
            )
            self._initial_fingerprint = _composition_state_fingerprint(initial)
            self._state = "active"
        except (DockerRolloutError, OSError, KeyboardInterrupt, SystemExit) as exc:
            cleanup_error = self._cleanup_resources()
            self._state = "failed"
            if cleanup_error is not None and not isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise cleanup_error from exc
            _raise_rollout_error(exc)

    def _composition_rollout_export(
        self,
        final_export: dict[str, object],
    ) -> dict[str, object]:
        admitted = self._runtime_composition.provider_set
        pack = self._runtime_composition.pack
        admission = self._runtime_composition.admission
        if self._initial_fingerprint is None:
            raise DockerRolloutError("composition rollout metadata is incomplete")
        return {
            "schema_version": ROLLOUT_COMPOSITION_EXPORT_SCHEMA_VERSION,
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
            "composition": {
                "pack_id": pack.pack_id,
                "pack_version": pack.pack_version,
                "composition_pack_sha256": pack.canonical_sha256,
                "composition_admission_sha256": admission.canonical_sha256,
                "episode_seed": self._composition_config.episode_seed,
                "time_scope": "delivery_scheduler_only_v1",
                "initial_composition_delivery_time": (
                    self._composition_config.initial_composition_delivery_time
                ),
            },
            "initial_composition_fingerprint": self._initial_fingerprint,
            "final_composition_export": final_export,
            "consumer_exit_codes": list(self._consumer_exit_codes),
            "consumer_exit_code": (
                self._consumer_exit_codes[-1] if self._consumer_exit_codes else None
            ),
        }


def run_docker_composition_rollout(
    *,
    composition_config: CompositionRolloutConfig,
    runtime_image: str,
    task_image: str,
    uid: str,
    session_id: RolloutSessionId,
    environment_seed: int,
    output_dir: Path,
    consumer_command: tuple[str, ...],
    runner: DockerCommandRunner | None = None,
) -> DockerRolloutResult:
    """Run one command in a fresh admitted composition lease and export it."""

    _validate_new_output(output_dir)
    lease: DockerCompositionRolloutLease | None = None
    try:
        lease = DockerCompositionRolloutLease.start(
            composition_config=composition_config,
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


def _composition_mounts(
    *,
    provider_set: LoadedMaterializedRolloutProviderSetV2,
    pack_dir: Path,
    admission_path: Path,
) -> tuple[str, ...]:
    return (
        "--mount",
        f"type=bind,source={provider_set.root},target={_COMPOSITION_PROVIDER_SET},readonly",
        "--mount",
        f"type=bind,source={pack_dir},target={_COMPOSITION_PACK},readonly",
        "--mount",
        f"type=bind,source={admission_path},target={_COMPOSITION_ADMISSION},readonly",
    )


def _composition_arguments(config: CompositionRolloutConfig) -> tuple[str, ...]:
    return (
        "--materialized-provider-set",
        _COMPOSITION_PROVIDER_SET,
        "--composition-pack",
        _COMPOSITION_PACK,
        "--composition-admission",
        _COMPOSITION_ADMISSION,
        "--episode-seed",
        config.episode_seed,
        "--initial-composition-delivery-time",
        config.initial_composition_delivery_time,
    )


def _require_fixed_composition(
    config: CompositionRolloutConfig,
    loaded: LoadedRuntimeComposition,
) -> None:
    observed = {
        "provider set": loaded.provider_set.source_manifest_sha256,
        "composition pack": loaded.pack.canonical_sha256,
        "composition admission": loaded.admission.canonical_sha256,
    }
    expected = {
        "provider set": config.provider_set_sha256,
        "composition pack": config.composition_pack_sha256,
        "composition admission": config.composition_admission_sha256,
    }
    changed = [name for name in expected if observed[name] != expected[name]]
    if changed:
        raise DockerRolloutError(
            "operator-selected composition changed after configuration: " + ", ".join(changed)
        )


def _prepare_composition(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    mounts: tuple[str, ...],
    config: CompositionRolloutConfig,
) -> None:
    command = (
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
        *mounts,
        runtime_image,
        "intercept",
        "prepare-composition",
        *_composition_arguments(config),
        "--run-root",
        _RUN_ROOT,
        "--trust-dir",
        _TRUST_ROOT,
    )
    _checked(runner, command, "prepare composition interception")


def _start_composition_gateway(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    authority_hosts: tuple[str, ...],
    mounts: tuple[str, ...],
    config: CompositionRolloutConfig,
) -> None:
    aliases = tuple(value for host in authority_hosts for value in ("--network-alias", host))
    command = (
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
        *mounts,
        runtime_image,
        "intercept",
        "serve-composition",
        *_composition_arguments(config),
        "--run-root",
        _RUN_ROOT,
        "--host",
        "0.0.0.0",
        "--port",
        "443",
        "--prepared",
    )
    _checked(runner, command, "start composition gateway")


def _run_composition_control(
    *,
    runner: DockerCommandRunner,
    runtime_image: str,
    resources: _LeaseResources,
    label: str,
    operation: str,
) -> dict[str, object]:
    command = (
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
        "--entrypoint",
        "python",
        runtime_image,
        "-m",
        "datalox_gated_runtime.rollout.composition_control",
        "--run-root",
        _RUN_ROOT,
        "--operation",
        operation,
    )
    result = runner.run(command, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no error output"
        raise DockerRolloutError(f"composition control {operation} failed: {detail}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise DockerRolloutError(f"composition control {operation} returned invalid JSON") from exc
    try:
        _validate_export(payload, operation=operation)
    except CompositionRolloutControlError as exc:
        raise DockerRolloutError(str(exc)) from exc
    return payload


def _composition_state_fingerprint(export: dict[str, object]) -> str:
    providers = export.get("providers")
    if not isinstance(providers, dict) or not providers:
        raise DockerRolloutError("composition reset returned invalid provider state")
    provider_exports = [providers[key] for key in sorted(providers)]
    provider_fingerprint = _provider_state_fingerprint(provider_exports)
    stable = {
        key: value for key, value in export.items() if key not in {"content_sha256", "providers"}
    }
    stable["providers"] = provider_fingerprint
    return _canonical_digest(stable)
