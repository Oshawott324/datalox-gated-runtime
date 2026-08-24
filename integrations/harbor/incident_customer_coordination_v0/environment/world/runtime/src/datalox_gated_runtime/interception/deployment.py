"""Generate provider-runtime injection artifacts for Docker and Kubernetes."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from datalox_gated_runtime.provider_runtime import load_provider_runtime_bundle


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


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")
