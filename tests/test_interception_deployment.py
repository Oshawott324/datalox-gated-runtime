import json
from pathlib import Path

import pytest
from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    build_stateful_provider_bundle,
)
from test_composition_admission import NOW, _Runner, _claims, _loaded_pack, _write_claims
from test_provider_release_registry import _profile

from datalox_gated_runtime.composition.admission import admit_composition_pack
from datalox_gated_runtime.interception import deployment
from datalox_gated_runtime.interception.deployment import (
    ADMITTED_COMPOSITION_DEPLOYMENT_SCHEMA_VERSION,
    ADMITTED_INTERCEPTION_DEPLOYMENT_SCHEMA_VERSION,
    export_admitted_composition_deployment,
    export_admitted_interception_deployment,
    export_interception_deployment,
)
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.provider_runtime.release import build_provider_release
from datalox_gated_runtime.rollout.provider_set import (
    ProviderReleaseSelection,
    write_rollout_provider_set_v2,
)


def _bundle(tmp_path: Path, *, authority: str = PROVIDER_AUTHORITY) -> Path:
    return build_stateful_provider_bundle(tmp_path, authority=authority)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _admitted_provider_set(
    tmp_path: Path,
) -> tuple[Path, FilesystemProviderReleaseRegistry, dict]:
    release = build_provider_release(
        profiles=(_profile(tmp_path / "profile", profile_id="default"),),
        release_version="2026.08.25",
        output_dir=tmp_path / "release",
    )
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")
    reference = registry.publish(release).reference
    provider_set = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=tmp_path / "provider-set.json",
    )
    return provider_set.manifest_path, registry, _read(provider_set.manifest_path)


def _admitted_composition(
    tmp_path: Path,
) -> tuple[Path, FilesystemProviderReleaseRegistry, Path, Path, dict]:
    release, pack = _loaded_pack(tmp_path / "composition-source")
    claims = _write_claims(
        tmp_path / "composition-claims.json",
        _claims(release, pack),
    )
    admission_path = tmp_path / "composition-admission.json"
    admit_composition_pack(
        pack=pack,
        provider_releases={release.provider_id: release},
        claims_path=claims,
        runner=_Runner(),
        output_path=admission_path,
        admitted_at=NOW,
    )
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "composition-registry")
    reference = registry.publish(release).reference
    provider_set = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=tmp_path / "composition-provider-set.json",
    )
    return (
        provider_set.manifest_path,
        registry,
        pack.root,
        admission_path,
        _read(provider_set.manifest_path),
    )


def test_docker_export_is_internal_and_injects_provider_dns_and_ca(tmp_path: Path) -> None:
    output = tmp_path / "docker"
    artifact = export_interception_deployment(
        bundle_dirs=(_bundle(tmp_path),),
        output_dir=output,
        target="docker",
        runtime_image="ghcr.io/example/datalox@sha256:" + "1" * 64,
        provider_image="ghcr.io/example/datalox-openlmis:test",
    )

    compose = _read(artifact)
    assert compose["networks"]["datalox-provider"]["internal"] is True
    gateway = compose["services"]["datalox-gateway"]
    assert gateway["networks"]["datalox-provider"]["aliases"] == [PROVIDER_AUTHORITY]
    assert gateway["cap_drop"] == ["ALL"]
    assert "--prepared" in gateway["command"]
    assert compose["services"]["datalox-prepare"]["command"][0:2] == [
        "intercept",
        "prepare",
    ]
    fragment = _read(output / "agent-service.fragment.json")
    agent = fragment["services"]["YOUR_AGENT_SERVICE"]
    assert agent["environment"]["SSL_CERT_FILE"] == "/var/run/datalox-trust/ca.pem"
    assert agent["environment"]["NO_PROXY"] == PROVIDER_AUTHORITY
    assert agent["environment"]["no_proxy"] == PROVIDER_AUTHORITY
    assert agent["networks"] == ["datalox-provider"]
    assert agent["depends_on"] == {"datalox-gateway": {"condition": "service_healthy"}}
    assert agent["volumes"] == ["datalox-trust:/var/run/datalox-trust:ro"]
    assert compose["services"]["datalox-gateway"]["volumes"] == ["datalox-run:/var/run/datalox"]
    assert compose["services"]["datalox-gateway"]["healthcheck"]["test"][0:3] == [
        "CMD",
        "datalox-gate",
        "intercept",
    ]
    assert not any(
        path.name in {"task.json", "episodes.jsonl", "verifier.json", "reward.json"}
        for path in (output / "bundles").rglob("*")
    )


def test_kubernetes_export_uses_native_sidecar_and_deny_by_default_egress(
    tmp_path: Path,
) -> None:
    output = tmp_path / "kubernetes"
    artifact = export_interception_deployment(
        bundle_dirs=(_bundle(tmp_path),),
        output_dir=output,
        target="kubernetes",
        runtime_image="ghcr.io/example/datalox@sha256:" + "2" * 64,
        provider_image="ghcr.io/example/datalox-openlmis:test",
        agent_container="agent",
    )

    pod = _read(artifact)["spec"]["template"]["spec"]
    assert pod["securityContext"] == {
        "fsGroup": 65532,
        "fsGroupChangePolicy": "OnRootMismatch",
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    assert pod["hostAliases"] == [{"ip": "127.0.0.1", "hostnames": [PROVIDER_AUTHORITY]}]
    assert [container["name"] for container in pod["initContainers"]] == [
        "datalox-prepare",
        "datalox-gateway",
    ]
    gateway = pod["initContainers"][1]
    assert gateway["restartPolicy"] == "Always"
    assert gateway["startupProbe"]["tcpSocket"] == {"port": 443}
    agent = pod["containers"][0]
    assert agent["name"] == "agent"
    assert {item["name"] for item in agent["env"]} == {
        "AWS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
        "NODE_EXTRA_CA_CERTS",
        "NO_PROXY",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_FILE",
        "no_proxy",
    }
    assert agent["volumeMounts"] == [
        {
            "name": "datalox-trust",
            "mountPath": "/var/run/datalox-trust",
            "readOnly": True,
        }
    ]
    assert gateway["volumeMounts"] == [{"name": "datalox-run", "mountPath": "/var/run/datalox"}]

    policy = _read(output / "kubernetes-network-policy.json")
    assert policy["spec"]["policyTypes"] == ["Egress"]
    assert all(
        "ipBlock" not in destination
        for rule in policy["spec"]["egress"]
        for destination in rule["to"]
    )
    assert policy["spec"]["egress"][1]["to"][0]["podSelector"] == {
        "matchLabels": {"app.kubernetes.io/name": "model-gateway"}
    }


def test_deployment_export_rejects_nondefault_https_authority(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="default HTTPS port"):
        export_interception_deployment(
            bundle_dirs=(_bundle(tmp_path, authority="api.provider.example:8443"),),
            output_dir=tmp_path / "deployment",
            target="docker",
            runtime_image="datalox:test",
            provider_image="datalox-provider:test",
        )


def test_admitted_docker_export_materializes_exact_v2_bindings_and_hides_them_from_agent(
    tmp_path: Path,
) -> None:
    provider_set_path, registry, provider_set = _admitted_provider_set(tmp_path)
    output = tmp_path / "admitted-docker"

    artifact = export_admitted_interception_deployment(
        provider_set_v2_path=provider_set_path,
        registry=registry,
        output_dir=output,
        target="docker",
        runtime_image="ghcr.io/example/datalox-runtime@sha256:" + "3" * 64,
        provider_image="ghcr.io/example/datalox-provider-set@sha256:" + "4" * 64,
    )

    compose = _read(artifact)
    prepare = compose["services"]["datalox-prepare"]["command"]
    gateway = compose["services"]["datalox-gateway"]["command"]
    assert prepare[0:2] == ["intercept", "prepare-admitted"]
    assert gateway[0:2] == ["intercept", "serve-admitted"]
    for flag in ("--bundle", "--admission", "--release-config"):
        assert prepare.count(flag) == 1
        assert gateway.count(flag) == 1
    assert compose["networks"]["datalox-provider"]["internal"] is True
    assert compose["services"]["datalox-gateway"]["networks"]["datalox-provider"]["aliases"] == [
        PROVIDER_AUTHORITY
    ]

    agent = _read(output / "agent-service.fragment.json")["services"]["YOUR_AGENT_SERVICE"]
    assert agent["volumes"] == ["datalox-trust:/var/run/datalox-trust:ro"]
    assert agent["environment"]["NO_PROXY"] == PROVIDER_AUTHORITY
    assert all("provider-set" not in mount for mount in agent["volumes"])
    assert "datalox-run" not in agent["volumes"]

    dockerfile = (output / "Dockerfile.provider-runtimes").read_text(encoding="utf-8")
    assert dockerfile.startswith("FROM ghcr.io/example/datalox-runtime@sha256:")
    assert "COPY --chown=65532:65532 provider-set/ /opt/datalox/provider-set/" in dockerfile
    assert "registry" not in dockerfile
    assert (output / "provider-set/controller-provider-releases.json").is_file()

    metadata = _read(output / "deployment.json")
    selected = provider_set["providers"][0]
    assert metadata["schema_version"] == ADMITTED_INTERCEPTION_DEPLOYMENT_SCHEMA_VERSION
    assert metadata["provider_set_sha256"].startswith("sha256:")
    assert metadata["providers"][0] == {
        **selected,
        "release_config_sha256": metadata["providers"][0]["release_config_sha256"],
        "operation_claims_sha256": metadata["providers"][0]["operation_claims_sha256"],
    }
    assert metadata["providers"][0]["release_config_sha256"].startswith("sha256:")
    assert metadata["providers"][0]["operation_claims_sha256"].startswith("sha256:")
    assert not any(
        path.name in {"task.json", "episodes.jsonl", "verifier.json", "reward.json"}
        for path in output.rglob("*")
    )


def test_admitted_kubernetes_export_uses_exact_bindings_and_ca_only_agent_mount(
    tmp_path: Path,
) -> None:
    provider_set_path, registry, _ = _admitted_provider_set(tmp_path)
    output = tmp_path / "admitted-kubernetes"

    artifact = export_admitted_interception_deployment(
        provider_set_v2_path=provider_set_path,
        registry=registry.root,
        output_dir=output,
        target="kubernetes",
        runtime_image="datalox-runtime:local",
        provider_image="datalox-provider-set:local",
        agent_container="agent",
    )

    pod = _read(artifact)["spec"]["template"]["spec"]
    prepare, gateway = pod["initContainers"]
    assert prepare["args"][0:2] == ["intercept", "prepare-admitted"]
    assert gateway["args"][0:2] == ["intercept", "serve-admitted"]
    assert prepare["args"].count("--bundle") == prepare["args"].count("--admission") == 1
    assert prepare["args"].count("--release-config") == 1
    assert gateway["volumeMounts"] == [{"name": "datalox-run", "mountPath": "/var/run/datalox"}]
    assert pod["containers"] == [
        {
            "name": "agent",
            "env": pod["containers"][0]["env"],
            "volumeMounts": [
                {
                    "name": "datalox-trust",
                    "mountPath": "/var/run/datalox-trust",
                    "readOnly": True,
                }
            ],
        }
    ]
    assert all(item["name"] != "datalox-run" for item in pod["containers"][0]["volumeMounts"])
    policy = _read(output / "kubernetes-network-policy.json")
    assert policy["spec"]["policyTypes"] == ["Egress"]
    assert all(
        "ipBlock" not in destination
        for rule in policy["spec"]["egress"]
        for destination in rule["to"]
    )


def test_admitted_export_rejects_tampered_provider_set_without_publishing_output(
    tmp_path: Path,
) -> None:
    provider_set_path, registry, provider_set = _admitted_provider_set(tmp_path)
    provider_set["providers"][0]["provider_admission_sha256"] = "sha256:" + "0" * 64
    provider_set_path.chmod(0o600)
    provider_set_path.write_text(
        json.dumps(provider_set, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    provider_set_path.chmod(0o444)
    output = tmp_path / "tampered-output"

    with pytest.raises(ValueError):
        export_admitted_interception_deployment(
            provider_set_v2_path=provider_set_path,
            registry=registry,
            output_dir=output,
            target="docker",
            runtime_image="datalox-runtime:local",
            provider_image="datalox-provider-set:local",
        )

    assert not output.exists()
    assert not any(tmp_path.glob(f".{output.name}.export-*"))


def test_admitted_export_preserves_existing_output_and_cleans_failed_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider_set_path, registry, _ = _admitted_provider_set(tmp_path)
    existing = tmp_path / "existing"
    existing.mkdir()
    sentinel = existing / "owned-by-user"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        export_admitted_interception_deployment(
            provider_set_v2_path=provider_set_path,
            registry=registry,
            output_dir=existing,
            target="docker",
            runtime_image="datalox-runtime:local",
            provider_image="datalox-provider-set:local",
        )
    assert sentinel.read_text(encoding="utf-8") == "keep"

    original = deployment._exclusive_write_json

    def fail_artifact(path: Path, value: object) -> None:
        if path.name == "docker-compose.datalox.json":
            raise OSError("injected write failure")
        original(path, value)

    monkeypatch.setattr(deployment, "_exclusive_write_json", fail_artifact)
    failed = tmp_path / "failed"
    with pytest.raises(OSError, match="injected write failure"):
        export_admitted_interception_deployment(
            provider_set_v2_path=provider_set_path,
            registry=registry,
            output_dir=failed,
            target="docker",
            runtime_image="datalox-runtime:local",
            provider_image="datalox-provider-set:local",
        )
    assert not failed.exists()
    assert not any(tmp_path.glob(f".{failed.name}.export-*"))


def test_legacy_export_remains_non_admitted_v1_projection(tmp_path: Path) -> None:
    output = tmp_path / "legacy"
    artifact = export_interception_deployment(
        bundle_dirs=(_bundle(tmp_path),),
        output_dir=output,
        target="docker",
        runtime_image="datalox-runtime:legacy",
        provider_image="datalox-provider:legacy",
    )

    compose = _read(artifact)
    assert compose["services"]["datalox-prepare"]["command"][0:2] == [
        "intercept",
        "prepare",
    ]
    assert "--admission" not in compose["services"]["datalox-prepare"]["command"]
    assert _read(output / "deployment.json")["schema_version"] == (
        "datalox_interception_deployment_v1"
    )


def test_admitted_composition_docker_export_is_controller_only_and_fully_bound(
    tmp_path: Path,
) -> None:
    provider_set, registry, pack, admission, selected = _admitted_composition(tmp_path)
    output = tmp_path / "composition-docker"

    artifact = export_admitted_composition_deployment(
        provider_set_v2_path=provider_set,
        registry=registry,
        composition_pack_dir=pack,
        composition_admission_path=admission,
        output_dir=output,
        target="docker",
        runtime_image="datalox-runtime:local",
        provider_image="datalox-composition:local",
        episode_seed="episode-0042",
        initial_time="2030-01-01T00:00:00Z",
    )

    compose = _read(artifact)
    prepare = compose["services"]["datalox-prepare"]["command"]
    serve = compose["services"]["datalox-gateway"]["command"]
    assert prepare[0:2] == ["intercept", "prepare-composition"]
    assert serve[0:2] == ["intercept", "serve-composition"]
    for command in (prepare, serve):
        assert command[command.index("--materialized-provider-set") + 1] == (
            "/opt/datalox/provider-set"
        )
        assert command[command.index("--composition-pack") + 1] == ("/opt/datalox/composition/pack")
        assert command[command.index("--composition-admission") + 1] == (
            "/opt/datalox/composition/composition-admission.json"
        )
        assert command[command.index("--episode-seed") + 1] == "episode-0042"
        assert command[command.index("--initial-time") + 1] == "2030-01-01T00:00:00Z"
        assert command[command.index("--run-root") + 1] == "/var/run/datalox/run"
        assert "--bundle" not in command
    assert compose["services"]["datalox-gateway"]["healthcheck"]["test"] == [
        "CMD",
        "datalox-gate",
        "intercept",
        "check-ready",
        "--run-root",
        "/var/run/datalox/run",
    ]
    assert compose["networks"]["datalox-provider"]["internal"] is True

    agent = _read(output / "agent-service.fragment.json")["services"]["YOUR_AGENT_SERVICE"]
    assert agent["volumes"] == ["datalox-trust:/var/run/datalox-trust:ro"]
    assert agent["environment"]["NO_PROXY"] == PROVIDER_AUTHORITY
    assert all("composition" not in value for value in agent["volumes"])

    dockerfile = (output / "Dockerfile.provider-runtimes").read_text(encoding="utf-8")
    assert "COPY --chown=65532:65532 provider-set/ /opt/datalox/provider-set/" in dockerfile
    assert "COPY --chown=65532:65532 composition/ /opt/datalox/composition/" in dockerfile
    assert (output / "composition/pack/composition-pack.json").is_file()
    assert (output / "composition/composition-admission.json").is_file()

    metadata = _read(output / "deployment.json")
    assert metadata["schema_version"] == ADMITTED_COMPOSITION_DEPLOYMENT_SCHEMA_VERSION
    assert metadata["provider_set_sha256"].startswith("sha256:")
    assert (
        metadata["providers"][0]["release_manifest_sha256"]
        == selected["providers"][0]["release_manifest_sha256"]
    )
    assert metadata["composition"]["composition_pack_sha256"].startswith("sha256:")
    assert metadata["composition"]["composition_admission_sha256"].startswith("sha256:")
    assert metadata["composition"]["composition_operation_claims_sha256"].startswith("sha256:")
    assert metadata["session"] == {
        "episode_seed": "episode-0042",
        "initial_time": "2030-01-01T00:00:00Z",
    }
    assert not any(
        path.name in {"task.json", "episodes.jsonl", "verifier.json", "reward.json"}
        for path in output.rglob("*")
    )


def test_admitted_composition_kubernetes_keeps_control_artifacts_out_of_agent(
    tmp_path: Path,
) -> None:
    provider_set, registry, pack, admission, _ = _admitted_composition(tmp_path)
    output = tmp_path / "composition-kubernetes"

    artifact = export_admitted_composition_deployment(
        provider_set_v2_path=provider_set,
        registry=registry,
        composition_pack_dir=pack,
        composition_admission_path=admission,
        output_dir=output,
        target="kubernetes",
        runtime_image="datalox-runtime:local",
        provider_image="datalox-composition:local",
        episode_seed="episode-0042",
        initial_time="2030-01-01T00:00:00Z",
        agent_container="agent",
    )

    pod = _read(artifact)["spec"]["template"]["spec"]
    prepare, serve = pod["initContainers"]
    assert prepare["args"][0:2] == ["intercept", "prepare-composition"]
    assert serve["args"][0:2] == ["intercept", "serve-composition"]
    assert "--prepared" in serve["args"]
    assert pod["hostAliases"] == [{"ip": "127.0.0.1", "hostnames": [PROVIDER_AUTHORITY]}]
    agent = pod["containers"][0]
    assert agent["name"] == "agent"
    assert agent["volumeMounts"] == [
        {
            "name": "datalox-trust",
            "mountPath": "/var/run/datalox-trust",
            "readOnly": True,
        }
    ]
    assert all(item["name"] != "datalox-run" for item in agent["volumeMounts"])
    assert _read(output / "kubernetes-network-policy.json")["spec"]["policyTypes"] == ["Egress"]


def test_admitted_composition_rejects_tamper_and_existing_output_atomically(
    tmp_path: Path,
) -> None:
    provider_set, registry, pack, admission, _ = _admitted_composition(tmp_path)
    existing = tmp_path / "composition-existing"
    existing.mkdir()
    sentinel = existing / "user-owned"
    sentinel.write_text("keep", encoding="utf-8")

    with pytest.raises(ValueError, match="already exists"):
        export_admitted_composition_deployment(
            provider_set_v2_path=provider_set,
            registry=registry,
            composition_pack_dir=pack,
            composition_admission_path=admission,
            output_dir=existing,
            target="docker",
            runtime_image="datalox-runtime:local",
            provider_image="datalox-composition:local",
            episode_seed="episode-0042",
            initial_time="2030-01-01T00:00:00Z",
        )
    assert sentinel.read_text(encoding="utf-8") == "keep"

    admission_payload = _read(admission)
    admission_payload["composition_pack_sha256"] = "sha256:" + "0" * 64
    admission.chmod(0o600)
    admission.write_text(
        json.dumps(admission_payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    admission.chmod(0o444)
    output = tmp_path / "composition-tampered"
    with pytest.raises(ValueError):
        export_admitted_composition_deployment(
            provider_set_v2_path=provider_set,
            registry=registry,
            composition_pack_dir=pack,
            composition_admission_path=admission,
            output_dir=output,
            target="docker",
            runtime_image="datalox-runtime:local",
            provider_image="datalox-composition:local",
            episode_seed="episode-0042",
            initial_time="2030-01-01T00:00:00Z",
        )
    assert not output.exists()
    assert not any(tmp_path.glob(f".{output.name}.export-*"))
