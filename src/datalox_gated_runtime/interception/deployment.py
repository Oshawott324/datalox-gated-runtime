"""Generate provider-runtime injection artifacts for Docker and Kubernetes."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from datalox_gated_runtime.composition.admission import (
    COMPOSITION_ADMISSION_MAX_JSON_BYTES,
    LoadedCompositionAdmission,
    load_composition_admission,
)
from datalox_gated_runtime.composition.pack import LoadedCompositionPack, load_composition_pack
from datalox_gated_runtime.provider_runtime import load_provider_runtime_bundle
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.provider_runtime.release import LoadedProviderRelease
from datalox_gated_runtime.rollout.provider_set import (
    LoadedMaterializedRolloutProviderSetV2,
    LoadedRolloutProviderSetV2,
    load_materialized_rollout_provider_set_v2,
    load_rollout_provider_set_v2,
    materialize_rollout_provider_set_v2,
)


ADMITTED_INTERCEPTION_DEPLOYMENT_SCHEMA_VERSION = "datalox_admitted_interception_deployment_v1"
ADMITTED_COMPOSITION_DEPLOYMENT_SCHEMA_VERSION = "datalox_admitted_composition_deployment_v1"
_COMPOSITION_EPISODE_SEED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")


def export_interception_deployment(
    *,
    bundle_dirs: tuple[Path, ...],
    output_dir: Path,
    target: str,
    runtime_image: str,
    provider_image: str,
    agent_container: str | None = None,
) -> Path:
    if target not in {"docker", "kubernetes"}:
        raise ValueError("target must be docker or kubernetes")
    _container_image(runtime_image, "runtime_image")
    _container_image(provider_image, "provider_image")
    if target == "kubernetes" and not agent_container:
        raise ValueError("kubernetes export requires agent_container")
    if output_dir.exists():
        raise ValueError("deployment output directory already exists")

    bundles = [load_provider_runtime_bundle(path) for path in bundle_dirs]
    authorities = [authority for bundle in bundles for authority in bundle.manifest.authorities]
    hosts = [_default_https_host(authority) for authority in authorities]
    if len(set(authorities)) != len(authorities):
        raise ValueError("provider authorities must be unique")

    output_dir.mkdir(parents=True)
    copied_paths: list[str] = []
    for bundle in bundles:
        destination = output_dir / "bundles" / bundle.manifest.provider_id
        shutil.copytree(bundle.root, destination)
        copied_paths.append(f"/opt/datalox/bundles/{bundle.manifest.provider_id}")
    _write_text(
        output_dir / "Dockerfile.provider-runtimes",
        _provider_image_dockerfile(runtime_image),
    )
    _write_json(
        output_dir / "deployment.json",
        {
            "schema_version": "datalox_interception_deployment_v1",
            "target": target,
            "provider_ids": [bundle.manifest.provider_id for bundle in bundles],
            "authorities": authorities,
            "runtime_image": runtime_image,
            "provider_image": provider_image,
            "agent_container": agent_container,
        },
    )
    if target == "docker":
        artifact = output_dir / "docker-compose.datalox.json"
        _write_json(artifact, _docker_compose(provider_image, copied_paths, hosts))
        _write_json(output_dir / "agent-service.fragment.json", _docker_agent_fragment(hosts))
    else:
        artifact = output_dir / "kubernetes-sidecar-patch.json"
        _write_json(
            artifact,
            _kubernetes_sidecar_patch(
                image=provider_image,
                bundle_paths=copied_paths,
                hosts=hosts,
                agent_container=str(agent_container),
            ),
        )
        _write_json(
            output_dir / "kubernetes-network-policy.json",
            _kubernetes_network_policy(),
        )
    _write_text(output_dir / "README.md", _deployment_readme(target))
    return artifact


def export_admitted_interception_deployment(
    *,
    provider_set_v2_path: Path,
    registry: FilesystemProviderReleaseRegistry | Path,
    output_dir: Path,
    target: str,
    runtime_image: str,
    provider_image: str,
    agent_container: str | None = None,
) -> Path:
    """Export one immutable Provider Set v2 as an admitted interception deployment.

    The generic runtime image remains separate from the selected provider releases.
    This function creates a provider-image build context containing the exact
    materialized runtime, admission, and release-config triples and emits only
    CA/DNS injection for the consumer-owned agent workload.
    """

    if target not in {"docker", "kubernetes"}:
        raise ValueError("target must be docker or kubernetes")
    _container_image(runtime_image, "runtime_image")
    _container_image(provider_image, "provider_image")
    if target == "kubernetes" and not agent_container:
        raise ValueError("kubernetes export requires agent_container")

    destination, parent = _new_deployment_destination(output_dir)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.export-", dir=parent))
    try:
        provider_set_root = staging / "provider-set"
        materialize_rollout_provider_set_v2(
            provider_set=provider_set_v2_path,
            registry=registry,
            output_dir=provider_set_root,
        )
        loaded = load_materialized_rollout_provider_set_v2(provider_set_root)
        authorities = [
            authority for binding in loaded.bindings for authority in binding.provider.authorities
        ]
        hosts = [_default_https_host(authority) for authority in authorities]
        if len(set(authorities)) != len(authorities):
            raise ValueError("provider authorities must be unique")

        bindings = _container_admitted_bindings(loaded)
        _exclusive_write_text(
            staging / "Dockerfile.provider-runtimes",
            _admitted_provider_image_dockerfile(runtime_image),
        )
        if target == "docker":
            artifact_name = "docker-compose.datalox.json"
            _exclusive_write_json(
                staging / artifact_name,
                _docker_compose_admitted(provider_image, bindings, hosts),
            )
            _exclusive_write_json(
                staging / "agent-service.fragment.json",
                _docker_agent_fragment(hosts),
            )
        else:
            artifact_name = "kubernetes-sidecar-patch.json"
            _exclusive_write_json(
                staging / artifact_name,
                _kubernetes_sidecar_patch_admitted(
                    image=provider_image,
                    bindings=bindings,
                    hosts=hosts,
                    agent_container=str(agent_container),
                ),
            )
            _exclusive_write_json(
                staging / "kubernetes-network-policy.json",
                _kubernetes_network_policy(),
            )
        _exclusive_write_text(staging / "README.md", _admitted_deployment_readme(target))
        _exclusive_write_json(
            staging / "deployment.json",
            _admitted_deployment_metadata(
                loaded=loaded,
                target=target,
                runtime_image=runtime_image,
                provider_image=provider_image,
                agent_container=agent_container,
            ),
        )
        _validate_admitted_deployment_staging(staging, artifact_name=artifact_name)
        _publish_admitted_deployment(staged=staging, destination=destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return destination / artifact_name


def export_admitted_composition_deployment(
    *,
    provider_set_v2_path: Path,
    registry: FilesystemProviderReleaseRegistry | Path,
    composition_pack_dir: Path,
    composition_admission_path: Path,
    output_dir: Path,
    target: str,
    runtime_image: str,
    provider_image: str,
    episode_seed: str,
    initial_time: str,
    agent_container: str | None = None,
) -> Path:
    """Export one admitted provider-mediated composition deployment.

    The caller supplies only immutable Provider Set v2 selection plus a strictly
    loaded Composition Pack and its derived admission. The resulting provider
    image contains those controller-owned artifacts, while the agent projection
    remains identical to independent provider interception: exact DNS and the
    public run CA only.
    """

    if target not in {"docker", "kubernetes"}:
        raise ValueError("target must be docker or kubernetes")
    _container_image(runtime_image, "runtime_image")
    _container_image(provider_image, "provider_image")
    _composition_episode_seed(episode_seed)
    _composition_initial_time(initial_time)
    if target == "kubernetes" and not agent_container:
        raise ValueError("kubernetes export requires agent_container")

    selected, releases, source_pack, source_admission = _load_composition_inputs(
        provider_set_v2_path=provider_set_v2_path,
        registry=registry,
        composition_pack_dir=composition_pack_dir,
        composition_admission_path=composition_admission_path,
    )
    destination, parent = _new_deployment_destination(output_dir)
    staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.export-", dir=parent))
    try:
        provider_set_root = staging / "provider-set"
        materialize_rollout_provider_set_v2(
            provider_set=selected,
            registry=registry,
            output_dir=provider_set_root,
        )
        loaded = load_materialized_rollout_provider_set_v2(provider_set_root)
        _validate_composition_provider_bindings(
            selected=selected,
            admission=source_admission,
        )
        copied_pack, copied_admission = _copy_and_revalidate_composition_inputs(
            staging=staging,
            source_pack=source_pack,
            source_admission=source_admission,
            releases=releases,
        )
        authorities = [
            authority for binding in loaded.bindings for authority in binding.provider.authorities
        ]
        hosts = [_default_https_host(authority) for authority in authorities]
        if len(set(authorities)) != len(authorities):
            raise ValueError("provider authorities must be unique")

        _exclusive_write_text(
            staging / "Dockerfile.provider-runtimes",
            _composition_provider_image_dockerfile(runtime_image),
        )
        composition_args = _composition_controller_args(
            episode_seed=episode_seed,
            initial_time=initial_time,
        )
        if target == "docker":
            artifact_name = "docker-compose.datalox.json"
            _exclusive_write_json(
                staging / artifact_name,
                _docker_compose_bound(
                    image=provider_image,
                    hosts=hosts,
                    prepare_command="prepare-composition",
                    serve_command="serve-composition",
                    controller_args=composition_args,
                    run_flag="--run-root",
                    ready_command="check-ready",
                    ready_run_flag="--run-root",
                ),
            )
            _exclusive_write_json(
                staging / "agent-service.fragment.json",
                _docker_agent_fragment(hosts),
            )
        else:
            artifact_name = "kubernetes-sidecar-patch.json"
            _exclusive_write_json(
                staging / artifact_name,
                _kubernetes_sidecar_patch_bound(
                    image=provider_image,
                    hosts=hosts,
                    agent_container=str(agent_container),
                    prepare_command="prepare-composition",
                    serve_command="serve-composition",
                    controller_args=composition_args,
                    run_flag="--run-root",
                ),
            )
            _exclusive_write_json(
                staging / "kubernetes-network-policy.json",
                _kubernetes_network_policy(),
            )
        _exclusive_write_text(staging / "README.md", _composition_deployment_readme(target))
        _exclusive_write_json(
            staging / "deployment.json",
            _composition_deployment_metadata(
                loaded=loaded,
                pack=copied_pack,
                admission=copied_admission,
                target=target,
                runtime_image=runtime_image,
                provider_image=provider_image,
                agent_container=agent_container,
                episode_seed=episode_seed,
                initial_time=initial_time,
            ),
        )
        _validate_composition_deployment_staging(
            staging,
            artifact_name=artifact_name,
            releases=releases,
        )
        _publish_admitted_deployment(staged=staging, destination=destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return destination / artifact_name


def _load_composition_inputs(
    *,
    provider_set_v2_path: Path,
    registry: FilesystemProviderReleaseRegistry | Path,
    composition_pack_dir: Path,
    composition_admission_path: Path,
) -> tuple[
    LoadedRolloutProviderSetV2,
    dict[str, LoadedProviderRelease],
    LoadedCompositionPack,
    LoadedCompositionAdmission,
]:
    loaded_registry = (
        registry
        if isinstance(registry, FilesystemProviderReleaseRegistry)
        else FilesystemProviderReleaseRegistry.load(registry)
    )
    selected = load_rollout_provider_set_v2(provider_set_v2_path, registry=loaded_registry)
    releases = {
        provider.provider_id: loaded_registry.resolve(provider.release_reference)
        for provider in selected.providers
    }
    pack = load_composition_pack(composition_pack_dir, provider_releases=releases)
    admission = load_composition_admission(
        composition_admission_path,
        pack=pack,
        provider_releases=releases,
    )
    _validate_composition_provider_bindings(selected=selected, admission=admission)
    return selected, releases, pack, admission


def _validate_composition_provider_bindings(
    *,
    selected: LoadedRolloutProviderSetV2,
    admission: LoadedCompositionAdmission,
) -> None:
    selected_profiles = {
        provider.provider_id: {
            "provider_id": provider.provider_id,
            "profile_id": provider.profile_id,
            "release_manifest_sha256": provider.release_manifest_sha256,
            "provider_runtime_sha256": provider.provider_runtime_sha256,
            "provider_admission_sha256": provider.provider_admission_sha256,
            "operation_contract_sha256": provider.operation_contract_sha256,
        }
        for provider in selected.providers
    }
    admitted_profiles = {
        profile.provider_id: {
            "provider_id": profile.provider_id,
            "profile_id": profile.profile_id,
            "release_manifest_sha256": profile.release_manifest_sha256,
            "provider_runtime_sha256": profile.provider_runtime_sha256,
            "provider_admission_sha256": profile.provider_admission_sha256,
            "operation_contract_sha256": profile.operation_contract_sha256,
        }
        for profile in admission.provider_profiles
    }
    if len(admitted_profiles) != len(admission.provider_profiles) or (
        admitted_profiles != selected_profiles
    ):
        raise ValueError(
            "composition admission provider profiles do not match the selected Provider Set v2"
        )


def _copy_and_revalidate_composition_inputs(
    *,
    staging: Path,
    source_pack: LoadedCompositionPack,
    source_admission: LoadedCompositionAdmission,
    releases: dict[str, LoadedProviderRelease],
) -> tuple[LoadedCompositionPack, LoadedCompositionAdmission]:
    composition_root = staging / "composition"
    composition_root.mkdir(mode=0o700)
    pack_root = composition_root / "pack"
    shutil.copytree(source_pack.root, pack_root, symlinks=True)
    admission_path = composition_root / "composition-admission.json"
    _copy_bounded_regular_file(
        source_admission.path,
        admission_path,
        max_bytes=COMPOSITION_ADMISSION_MAX_JSON_BYTES,
    )
    copied_pack = load_composition_pack(pack_root, provider_releases=releases)
    copied_admission = load_composition_admission(
        admission_path,
        pack=copied_pack,
        provider_releases=releases,
    )
    if (
        copied_pack.canonical_sha256 != source_pack.canonical_sha256
        or copied_admission.canonical_sha256 != source_admission.canonical_sha256
    ):
        raise ValueError("composition pack or admission changed while building the deployment")
    return copied_pack, copied_admission


def _container_admitted_bindings(
    loaded: LoadedMaterializedRolloutProviderSetV2,
) -> list[tuple[str, str, str]]:
    root = loaded.root
    prefix = "/opt/datalox/provider-set"
    return [
        (
            f"{prefix}/{binding.bundle_dir.relative_to(root).as_posix()}",
            f"{prefix}/{binding.admission_path.relative_to(root).as_posix()}",
            f"{prefix}/{binding.release_config_path.relative_to(root).as_posix()}",
        )
        for binding in loaded.bindings
    ]


def _admitted_binding_args(bindings: list[tuple[str, str, str]]) -> list[str]:
    result: list[str] = []
    for bundle, admission, release_config in bindings:
        result.extend(
            [
                "--bundle",
                bundle,
                "--admission",
                admission,
                "--release-config",
                release_config,
            ]
        )
    return result


def _composition_controller_args(*, episode_seed: str, initial_time: str) -> list[str]:
    return [
        "--materialized-provider-set",
        "/opt/datalox/provider-set",
        "--composition-pack",
        "/opt/datalox/composition/pack",
        "--composition-admission",
        "/opt/datalox/composition/composition-admission.json",
        "--episode-seed",
        episode_seed,
        "--initial-time",
        initial_time,
    ]


def _admitted_provider_image_dockerfile(runtime_image: str) -> str:
    return f"""FROM {runtime_image}

COPY --chown=65532:65532 provider-set/ /opt/datalox/provider-set/
"""


def _composition_provider_image_dockerfile(runtime_image: str) -> str:
    return f"""FROM {runtime_image}

COPY --chown=65532:65532 provider-set/ /opt/datalox/provider-set/
COPY --chown=65532:65532 composition/ /opt/datalox/composition/
"""


def _admitted_deployment_metadata(
    *,
    loaded: LoadedMaterializedRolloutProviderSetV2,
    target: str,
    runtime_image: str,
    provider_image: str,
    agent_container: str | None,
) -> dict:
    return {
        "schema_version": ADMITTED_INTERCEPTION_DEPLOYMENT_SCHEMA_VERSION,
        "target": target,
        "provider_set_sha256": loaded.source_manifest_sha256,
        "runtime_image": runtime_image,
        "provider_image": provider_image,
        "agent_container": agent_container,
        "providers": [
            {
                "provider_id": binding.provider.provider_id,
                "release_reference": binding.provider.release_reference,
                "release_manifest_sha256": binding.provider.release_manifest_sha256,
                "profile_id": binding.provider.profile_id,
                "profile_layer_sha256": binding.provider.profile_layer_sha256,
                "provider_runtime_sha256": binding.provider.provider_runtime_sha256,
                "provider_admission_sha256": binding.provider.provider_admission_sha256,
                "release_config_sha256": binding.release_config_sha256,
                "operation_claims_sha256": binding.release_config["operation_claims_sha256"],
                "operation_contract_sha256": binding.provider.operation_contract_sha256,
                "authorities": list(binding.provider.authorities),
            }
            for binding in loaded.bindings
        ],
    }


def _composition_deployment_metadata(
    *,
    loaded: LoadedMaterializedRolloutProviderSetV2,
    pack: LoadedCompositionPack,
    admission: LoadedCompositionAdmission,
    target: str,
    runtime_image: str,
    provider_image: str,
    agent_container: str | None,
    episode_seed: str,
    initial_time: str,
) -> dict:
    metadata = _admitted_deployment_metadata(
        loaded=loaded,
        target=target,
        runtime_image=runtime_image,
        provider_image=provider_image,
        agent_container=agent_container,
    )
    metadata["schema_version"] = ADMITTED_COMPOSITION_DEPLOYMENT_SCHEMA_VERSION
    metadata["session"] = {
        "episode_seed": episode_seed,
        "initial_time": initial_time,
    }
    metadata["composition"] = {
        "pack_id": pack.pack_id,
        "pack_version": pack.pack_version,
        "distribution_label": admission.distribution_label,
        "composition_pack_sha256": pack.canonical_sha256,
        "composition_admission_sha256": admission.canonical_sha256,
        "composition_operation_claims_sha256": admission.payload[
            "composition_operation_claims_sha256"
        ],
    }
    return metadata


def _provider_image_dockerfile(runtime_image: str) -> str:
    return f"""FROM {runtime_image}

COPY bundles/ /opt/datalox/bundles/
"""


def _bundle_args(paths: list[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        result.extend(["--bundle", path])
    return result


def _docker_compose(image: str, bundle_paths: list[str], hosts: list[str]) -> dict:
    security = {
        "image": image,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "networks": {"datalox-provider": {}},
    }
    return {
        "name": "datalox-interception",
        "services": {
            "datalox-prepare": {
                **security,
                "command": [
                    "intercept",
                    "prepare",
                    *_bundle_args(bundle_paths),
                    "--run",
                    "/var/run/datalox/run",
                    "--trust-dir",
                    "/var/run/datalox-trust",
                ],
                "volumes": [
                    "datalox-run:/var/run/datalox",
                    "datalox-trust:/var/run/datalox-trust",
                ],
                "restart": "no",
            },
            "datalox-gateway": {
                **security,
                "command": [
                    "intercept",
                    "serve",
                    *_bundle_args(bundle_paths),
                    "--run",
                    "/var/run/datalox/run",
                    "--prepared",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "443",
                ],
                "cap_add": ["NET_BIND_SERVICE"],
                "healthcheck": {
                    "test": [
                        "CMD",
                        "datalox-gate",
                        "intercept",
                        "ready",
                        "--run",
                        "/var/run/datalox/run",
                    ],
                    "interval": "1s",
                    "timeout": "3s",
                    "retries": 30,
                },
                "depends_on": {"datalox-prepare": {"condition": "service_completed_successfully"}},
                "networks": {"datalox-provider": {"aliases": hosts}},
                "tmpfs": ["/tmp:rw,noexec,nosuid,size=16m"],
                "volumes": ["datalox-run:/var/run/datalox"],
            },
        },
        "networks": {"datalox-provider": {"internal": True}},
        "volumes": {"datalox-run": {}, "datalox-trust": {}},
    }


def _docker_compose_admitted(
    image: str,
    bindings: list[tuple[str, str, str]],
    hosts: list[str],
) -> dict:
    return _docker_compose_bound(
        image=image,
        hosts=hosts,
        prepare_command="prepare-admitted",
        serve_command="serve-admitted",
        controller_args=_admitted_binding_args(bindings),
    )


def _docker_compose_bound(
    *,
    image: str,
    hosts: list[str],
    prepare_command: str,
    serve_command: str,
    controller_args: list[str],
    run_flag: str = "--run",
    ready_command: str = "ready",
    ready_run_flag: str = "--run",
) -> dict:
    security = {
        "image": image,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "networks": {"datalox-provider": {}},
    }
    return {
        "name": "datalox-interception",
        "services": {
            "datalox-prepare": {
                **security,
                "command": [
                    "intercept",
                    prepare_command,
                    *controller_args,
                    run_flag,
                    "/var/run/datalox/run",
                    "--trust-dir",
                    "/var/run/datalox-trust",
                ],
                "volumes": [
                    "datalox-run:/var/run/datalox",
                    "datalox-trust:/var/run/datalox-trust",
                ],
                "restart": "no",
            },
            "datalox-gateway": {
                **security,
                "command": [
                    "intercept",
                    serve_command,
                    *controller_args,
                    run_flag,
                    "/var/run/datalox/run",
                    "--prepared",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "443",
                ],
                "cap_add": ["NET_BIND_SERVICE"],
                "healthcheck": {
                    "test": [
                        "CMD",
                        "datalox-gate",
                        "intercept",
                        ready_command,
                        ready_run_flag,
                        "/var/run/datalox/run",
                    ],
                    "interval": "1s",
                    "timeout": "3s",
                    "retries": 30,
                },
                "depends_on": {"datalox-prepare": {"condition": "service_completed_successfully"}},
                "networks": {"datalox-provider": {"aliases": hosts}},
                "tmpfs": ["/tmp:rw,noexec,nosuid,size=16m"],
                "volumes": ["datalox-run:/var/run/datalox"],
            },
        },
        "networks": {"datalox-provider": {"internal": True}},
        "volumes": {"datalox-run": {}, "datalox-trust": {}},
    }


def _docker_agent_fragment(hosts: list[str]) -> dict:
    return {
        "services": {
            "YOUR_AGENT_SERVICE": {
                "depends_on": {"datalox-gateway": {"condition": "service_healthy"}},
                "environment": {
                    **_trust_environment(hosts),
                },
                "networks": ["datalox-provider"],
                "volumes": ["datalox-trust:/var/run/datalox-trust:ro"],
            }
        }
    }


def _kubernetes_sidecar_patch(
    *, image: str, bundle_paths: list[str], hosts: list[str], agent_container: str
) -> dict:
    private_mount = {"name": "datalox-run", "mountPath": "/var/run/datalox"}
    trust_mount = {"name": "datalox-trust", "mountPath": "/var/run/datalox-trust"}
    return {
        "spec": {
            "template": {
                "metadata": {"labels": {"datalox-intercept": "enabled"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "fsGroup": 65532,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "hostAliases": [{"ip": "127.0.0.1", "hostnames": hosts}],
                    "volumes": [
                        {"name": "datalox-run", "emptyDir": {}},
                        {"name": "datalox-trust", "emptyDir": {}},
                    ],
                    "initContainers": [
                        {
                            "name": "datalox-prepare",
                            "image": image,
                            "args": [
                                "intercept",
                                "prepare",
                                *_bundle_args(bundle_paths),
                                "--run",
                                "/var/run/datalox/run",
                                "--trust-dir",
                                "/var/run/datalox-trust",
                            ],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                            },
                            "volumeMounts": [private_mount, trust_mount],
                        },
                        {
                            "name": "datalox-gateway",
                            "image": image,
                            "restartPolicy": "Always",
                            "args": [
                                "intercept",
                                "serve",
                                *_bundle_args(bundle_paths),
                                "--run",
                                "/var/run/datalox/run",
                                "--prepared",
                                "--host",
                                "0.0.0.0",
                                "--port",
                                "443",
                            ],
                            "ports": [{"name": "datalox-https", "containerPort": 443}],
                            "startupProbe": {
                                "tcpSocket": {"port": 443},
                                "periodSeconds": 1,
                                "failureThreshold": 30,
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {
                                    "drop": ["ALL"],
                                    "add": ["NET_BIND_SERVICE"],
                                },
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                            },
                            "volumeMounts": [private_mount],
                        },
                    ],
                    "containers": [
                        {
                            "name": agent_container,
                            "env": [
                                {"name": name, "value": value}
                                for name, value in _trust_environment(hosts).items()
                            ],
                            "volumeMounts": [
                                {
                                    "name": "datalox-trust",
                                    "mountPath": "/var/run/datalox-trust",
                                    "readOnly": True,
                                }
                            ],
                        }
                    ],
                },
            }
        }
    }


def _kubernetes_sidecar_patch_admitted(
    *,
    image: str,
    bindings: list[tuple[str, str, str]],
    hosts: list[str],
    agent_container: str,
) -> dict:
    return _kubernetes_sidecar_patch_bound(
        image=image,
        hosts=hosts,
        agent_container=agent_container,
        prepare_command="prepare-admitted",
        serve_command="serve-admitted",
        controller_args=_admitted_binding_args(bindings),
    )


def _kubernetes_sidecar_patch_bound(
    *,
    image: str,
    hosts: list[str],
    agent_container: str,
    prepare_command: str,
    serve_command: str,
    controller_args: list[str],
    run_flag: str = "--run",
) -> dict:
    private_mount = {"name": "datalox-run", "mountPath": "/var/run/datalox"}
    trust_mount = {"name": "datalox-trust", "mountPath": "/var/run/datalox-trust"}
    return {
        "spec": {
            "template": {
                "metadata": {"labels": {"datalox-intercept": "enabled"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "fsGroup": 65532,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "hostAliases": [{"ip": "127.0.0.1", "hostnames": hosts}],
                    "volumes": [
                        {"name": "datalox-run", "emptyDir": {}},
                        {"name": "datalox-trust", "emptyDir": {}},
                    ],
                    "initContainers": [
                        {
                            "name": "datalox-prepare",
                            "image": image,
                            "args": [
                                "intercept",
                                prepare_command,
                                *controller_args,
                                run_flag,
                                "/var/run/datalox/run",
                                "--trust-dir",
                                "/var/run/datalox-trust",
                            ],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"]},
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                            },
                            "volumeMounts": [private_mount, trust_mount],
                        },
                        {
                            "name": "datalox-gateway",
                            "image": image,
                            "restartPolicy": "Always",
                            "args": [
                                "intercept",
                                serve_command,
                                *controller_args,
                                run_flag,
                                "/var/run/datalox/run",
                                "--prepared",
                                "--host",
                                "0.0.0.0",
                                "--port",
                                "443",
                            ],
                            "ports": [{"name": "datalox-https", "containerPort": 443}],
                            "startupProbe": {
                                "tcpSocket": {"port": 443},
                                "periodSeconds": 1,
                                "failureThreshold": 30,
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "capabilities": {
                                    "drop": ["ALL"],
                                    "add": ["NET_BIND_SERVICE"],
                                },
                                "readOnlyRootFilesystem": True,
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                            },
                            "volumeMounts": [private_mount],
                        },
                    ],
                    "containers": [
                        {
                            "name": agent_container,
                            "env": [
                                {"name": name, "value": value}
                                for name, value in _trust_environment(hosts).items()
                            ],
                            "volumeMounts": [
                                {
                                    "name": "datalox-trust",
                                    "mountPath": "/var/run/datalox-trust",
                                    "readOnly": True,
                                }
                            ],
                        }
                    ],
                },
            }
        }
    }


def _kubernetes_network_policy() -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "datalox-intercept-egress"},
        "spec": {
            "podSelector": {"matchLabels": {"datalox-intercept": "enabled"}},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": "kube-system"}
                            },
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                        }
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53},
                    ],
                },
                {
                    "to": [
                        {
                            "namespaceSelector": {},
                            "podSelector": {
                                "matchLabels": {"app.kubernetes.io/name": "model-gateway"}
                            },
                        }
                    ],
                    "ports": [{"protocol": "TCP", "port": 443}],
                },
            ],
        },
    }


def _default_https_host(authority: str) -> str:
    parsed = urlsplit(f"//{authority}")
    if parsed.hostname is None or parsed.port not in {None, 443}:
        raise ValueError(
            "Docker/Kubernetes transparent injection requires the provider's default HTTPS port"
        )
    return parsed.hostname


def _trust_environment(hosts: list[str]) -> dict[str, str]:
    ca_path = "/var/run/datalox-trust/ca.pem"
    no_proxy = ",".join(hosts)
    return {
        "SSL_CERT_FILE": ca_path,
        "REQUESTS_CA_BUNDLE": ca_path,
        "CURL_CA_BUNDLE": ca_path,
        "NODE_EXTRA_CA_CERTS": ca_path,
        "AWS_CA_BUNDLE": ca_path,
        "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH": ca_path,
        "GIT_SSL_CAINFO": ca_path,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
    }


def _container_image(value: str, field: str) -> str:
    if not value or value.strip() != value or any(char.isspace() for char in value):
        raise ValueError(f"{field} must be a non-empty container image reference")
    return value


def _composition_episode_seed(value: str) -> str:
    if not isinstance(value, str) or _COMPOSITION_EPISODE_SEED.fullmatch(value) is None:
        raise ValueError("episode_seed must be a canonical composition identifier")
    return value


def _composition_initial_time(value: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("initial_time must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("initial_time must be a valid RFC 3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("initial_time must use UTC")
    return value


def _deployment_readme(target: str) -> str:
    if target == "docker":
        return """# Datalox Docker injection

Build `Dockerfile.provider-runtimes`, merge the agent service fragment into the
consumer's Compose project, and keep the agent on the internal
`datalox-provider` network. Supply model access through an explicit gateway on
that internal network. Do not attach the agent directly to an unrestricted
egress network or the no-provider-egress guarantee no longer holds.

The agent receives only the public run CA. Control credentials, state, and the
gateway private key remain on a separate volume. The fragment configures common
OpenSSL, Python, curl, Node, AWS, gRPC, and Git trust variables; other language
runtimes must import the same CA through their native trust-store mechanism.
Intercepted provider hosts are placed in `NO_PROXY` and `no_proxy` so a model
proxy cannot receive provider requests.
"""
    return """# Datalox Kubernetes injection

Apply `kubernetes-sidecar-patch.json` to the consumer-owned Deployment and
apply `kubernetes-network-policy.json` in the same namespace. The patch uses a
native sidecar init container (`restartPolicy: Always`), requiring Kubernetes
1.29 or newer. Label the only allowed in-cluster model relay
`app.kubernetes.io/name=model-gateway`; all other pod egress is denied.

The agent mounts only the public run CA. It cannot read the control token,
provider state, or gateway private key. Intercepted provider hosts are placed
in `NO_PROXY` and `no_proxy` so a model proxy cannot receive provider requests.
"""


def _admitted_deployment_readme(target: str) -> str:
    heading = "Docker" if target == "docker" else "Kubernetes"
    artifact = (
        "merge `agent-service.fragment.json` into the consumer-owned Compose project"
        if target == "docker"
        else "apply the sidecar patch and deny-by-default NetworkPolicy to the consumer workload"
    )
    return f"""# Datalox admitted {heading} injection

Build `Dockerfile.provider-runtimes` as the declared provider image, then {artifact}.
The image contains the exact immutable Provider Set v2 runtime, admission, and
Provider Release config bindings. The generic Datalox runtime image remains a
separate base image.

The agent keeps each provider's original HTTPS authority. It receives only the
public run CA and provider DNS routing; it receives no provider bundle,
admission, release metadata, controller token, state, verifier, reward, task,
or harness artifact. Provider egress remains denied by the isolated deployment
boundary.
"""


def _composition_deployment_readme(target: str) -> str:
    heading = "Docker" if target == "docker" else "Kubernetes"
    artifact = (
        "merge `agent-service.fragment.json` into the consumer-owned Compose project"
        if target == "docker"
        else "apply the sidecar patch and deny-by-default NetworkPolicy to the consumer workload"
    )
    return f"""# Datalox admitted Composition {heading} injection

Build `Dockerfile.provider-runtimes` as the declared provider image, then {artifact}.
The image contains the exact immutable Provider Set v2 plus one strictly loaded
Composition Pack and its derived admission. The pack and admission remain on
the controller side of the provider image.

The agent keeps every original provider HTTPS authority and receives only the
public run CA and provider DNS routing. It receives no provider bundle,
Composition Pack, admission, controller token, state, verifier, reward, task,
or harness artifact. Reset, logical time, delivery, resolution, export, and
finalization remain available only through the private composition control
plane. Provider egress remains denied by the isolated deployment boundary.
"""


def _new_deployment_destination(path: Path) -> tuple[Path, Path]:
    if path.name in {"", ".", ".."}:
        raise ValueError("deployment output name is invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("deployment output parent is unavailable") from exc
    if not parent.is_dir():
        raise ValueError("deployment output parent must be a directory")
    destination = parent / path.name
    if destination.exists() or destination.is_symlink():
        raise ValueError("deployment output directory already exists")
    return destination, parent


def _validate_admitted_deployment_staging(staging: Path, *, artifact_name: str) -> None:
    loaded = load_materialized_rollout_provider_set_v2(staging / "provider-set")
    if not loaded.bindings:
        raise ValueError("admitted deployment requires at least one provider")
    required = (
        staging / "Dockerfile.provider-runtimes",
        staging / artifact_name,
        staging / "README.md",
        staging / "deployment.json",
    )
    if any(path.is_symlink() or not path.is_file() for path in required):
        raise ValueError("admitted deployment staging is incomplete")
    metadata = json.loads((staging / "deployment.json").read_text(encoding="utf-8"))
    if (
        metadata.get("schema_version") != ADMITTED_INTERCEPTION_DEPLOYMENT_SCHEMA_VERSION
        or metadata.get("provider_set_sha256") != loaded.source_manifest_sha256
        or len(metadata.get("providers", [])) != len(loaded.bindings)
    ):
        raise ValueError("admitted deployment metadata is inconsistent")


def _validate_composition_deployment_staging(
    staging: Path,
    *,
    artifact_name: str,
    releases: dict[str, LoadedProviderRelease],
) -> None:
    loaded = load_materialized_rollout_provider_set_v2(staging / "provider-set")
    pack = load_composition_pack(staging / "composition/pack", provider_releases=releases)
    admission = load_composition_admission(
        staging / "composition/composition-admission.json",
        pack=pack,
        provider_releases=releases,
    )
    _validate_composition_provider_bindings(
        selected=LoadedRolloutProviderSetV2(
            manifest_path=loaded.source_manifest_path,
            manifest_sha256=loaded.source_manifest_sha256,
            manifest_bytes=loaded.source_manifest_path.read_bytes(),
            providers=tuple(binding.provider for binding in loaded.bindings),
        ),
        admission=admission,
    )
    required = (
        staging / "Dockerfile.provider-runtimes",
        staging / artifact_name,
        staging / "README.md",
        staging / "deployment.json",
    )
    if any(path.is_symlink() or not path.is_file() for path in required):
        raise ValueError("admitted composition deployment staging is incomplete")
    metadata = json.loads((staging / "deployment.json").read_text(encoding="utf-8"))
    session = metadata.get("session")
    if not isinstance(session, dict):
        raise ValueError("admitted composition deployment session metadata is invalid")
    expected = _composition_deployment_metadata(
        loaded=loaded,
        pack=pack,
        admission=admission,
        target=metadata.get("target"),
        runtime_image=metadata.get("runtime_image"),
        provider_image=metadata.get("provider_image"),
        agent_container=metadata.get("agent_container"),
        episode_seed=session.get("episode_seed"),
        initial_time=session.get("initial_time"),
    )
    if metadata != expected:
        raise ValueError("admitted composition deployment metadata is inconsistent")


def _publish_admitted_deployment(*, staged: Path, destination: Path) -> None:
    marker = staged / "deployment.json"
    if marker.is_symlink() or not marker.is_file():
        raise ValueError("admitted deployment validity marker is missing")
    reserved = False
    try:
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise ValueError("deployment output directory already exists") from exc
        reserved = True
        for child in sorted(staged.iterdir(), key=lambda item: item.name):
            if child.name == marker.name:
                continue
            os.rename(child, destination / child.name)
        _fsync_directory(destination)
        os.rename(marker, destination / marker.name)
        _fsync_directory(destination)
        _fsync_directory(destination.parent)
    except BaseException:
        if reserved:
            shutil.rmtree(destination, ignore_errors=True)
            _fsync_directory(destination.parent)
        raise


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def _exclusive_write_json(path: Path, value: object) -> None:
    _exclusive_write_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )


def _exclusive_write_text(path: Path, value: str) -> None:
    _exclusive_write_bytes(path, value.encode("utf-8"))


def _exclusive_write_bytes(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)


def _copy_bounded_regular_file(source: Path, destination: Path, *, max_bytes: int) -> None:
    source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    destination_descriptor: int | None = None
    try:
        metadata = os.fstat(source_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("composition admission must be a regular file")
        if metadata.st_size > max_bytes:
            raise ValueError("composition admission exceeds its size limit")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o444,
        )
        copied = 0
        while chunk := os.read(source_descriptor, min(1024 * 1024, max_bytes + 1 - copied)):
            copied += len(chunk)
            if copied > max_bytes:
                raise ValueError("composition admission exceeds its size limit")
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("composition admission copy made no progress")
                view = view[written:]
        if copied != metadata.st_size:
            raise ValueError("composition admission changed while it was copied")
        os.fsync(destination_descriptor)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        os.close(source_descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
