from __future__ import annotations

import json
import shlex
import shutil
from pathlib import Path
from typing import Any

from datalox_gated_runtime.harness_adapters._shared import (
    atomic_output,
    public_result,
    task_prompt,
    write_adapter_manifest,
)
from datalox_gated_runtime.harness_adapters.contracts import (
    HARBOR_VERSION,
    HarnessAdapterError,
)
from datalox_gated_runtime.world_package import build_world_package
from datalox_gated_runtime.world_package.contracts import PYTHON_BASE_IMAGE
from datalox_gated_runtime.world_v1.bundle import validate_world_bundle


def build_harbor_adapter(
    *,
    env_dir: Path,
    out_dir: Path,
    episode_id: str | None = None,
    project_root: Path | None = None,
    actor_roles: tuple[str, ...] | None = None,
    readme_text: str | None = None,
    solution_dir: Path | None = None,
) -> dict[str, Any]:
    """Wrap one canonical world package as a Harbor task."""

    bundle = validate_world_bundle(env_dir)
    configured_roles = _configured_roles(bundle, actor_roles)
    repository = (
        project_root.resolve() if project_root is not None else Path(__file__).resolve().parents[3]
    )
    license_path = repository / "LICENSE"
    if not license_path.is_file():
        raise HarnessAdapterError("project_root must contain LICENSE")

    with atomic_output(out_dir) as temporary:
        world_root = temporary / "environment" / "world"
        result = build_world_package(
            env_dir=env_dir,
            out_dir=world_root,
            episode_id=episode_id,
            project_root=repository,
        )
        package_manifest = {key: value for key, value in result.items() if key != "out_dir"}
        prompt = task_prompt(world_root, package_manifest)
        _write_harbor_files(
            temporary,
            package_manifest,
            prompt,
            actor_roles=configured_roles,
            readme_text=readme_text,
            solution_dir=solution_dir,
        )
        shutil.copyfile(license_path, temporary / "LICENSE")
        manifest = write_adapter_manifest(
            root=temporary,
            harness="harbor",
            harness_version=HARBOR_VERSION,
            canonical_package_path="environment/world",
            package_manifest=package_manifest,
        )
    return public_result(manifest, out_dir)


def _write_harbor_files(
    root: Path,
    package_manifest: dict[str, Any],
    prompt: str,
    *,
    actor_roles: tuple[str, ...],
    readme_text: str | None,
    solution_dir: Path | None,
) -> None:
    (root / "instruction.md").write_text(prompt, encoding="utf-8")
    controller = package_manifest["controller"]
    verdict_path = "/var/lib/datalox/verdict.json"
    finalize_parts = list(controller["finalize_command"])
    try:
        output_index = finalize_parts.index("--out") + 1
    except (ValueError, IndexError) as exc:
        raise HarnessAdapterError("world finalize command has no --out value") from exc
    finalize_parts[output_index] = verdict_path
    finalize_command = shlex.join(finalize_parts)
    world_id = package_manifest["world"]["id"]
    bundle_version = package_manifest["world"]["bundle_version"]
    episode_id = package_manifest["world"]["episode_id"]
    task_id = package_manifest["task"]["task_id"]
    actor_config = json.dumps(
        [{"actor_id": f"harbor-{role}", "role": role} for role in actor_roles],
        separators=(",", ":"),
    )
    mcp_servers = "\n\n".join(
        f'''[[environment.mcp_servers]]
name = "datalox-{role.replace("_", "-")}"
transport = "streamable-http"
url = "http://world:8000/actors/{role}/mcp"'''
        for role in actor_roles
    )
    task_toml = f'''schema_version = "1.4"

[task]
name = "datalox/{world_id}"
version = "{bundle_version}"
description = "A resettable, stateful cross-provider workflow with hidden verification."
authors = [{{ name = "Datalox" }}]
keywords = ["agents", "mcp", "stateful", "cross-provider", "verification"]

[metadata]
datalox_world_id = "{world_id}"
datalox_episode_id = "{episode_id}"
datalox_task_id = "{task_id}"
grounding = "source-grounded synthetic behavior"

[agent]
timeout_sec = 1800

[verifier]
timeout_sec = 120
environment_mode = "separate"

[verifier.environment]
cpus = 1
memory_mb = 512
build_timeout_sec = 300

[[verifier.collect]]
service = "world"
command = {finalize_command!r}
timeout_sec = 120

[environment]
docker_image = "{PYTHON_BASE_IMAGE}"
cpus = 2
memory_mb = 2048
build_timeout_sec = 900

[environment.healthcheck]
command = "python -c \\"import socket; socket.create_connection(('world', 8000), 2).close()\\""
interval_sec = 1.0
timeout_sec = 2.0
retries = 30

{mcp_servers}

[[artifacts]]
source = "{verdict_path}"
destination = "datalox/verdict.json"
service = "world"
'''
    (root / "task.toml").write_text(task_toml, encoding="utf-8")
    (root / "README.md").write_text(
        readme_text or _default_readme(world_id, episode_id, actor_roles),
        encoding="utf-8",
    )

    environment = root / "environment"
    (environment / "docker-compose.yaml").write_text(
        f"""services:
  main:
    depends_on:
      world:
        condition: service_healthy
    networks:
      - datalox-internal
  world:
    build:
      context: ./world
    environment:
      DATALOX_ALLOWED_HOSTS: "world:*,localhost:*,127.0.0.1:*"
      DATALOX_HOST: "0.0.0.0"
      DATALOX_PORT: "8000"
      DATALOX_WORLD_PACKAGE_ACTORS: '{actor_config}'
    networks:
      - datalox-internal
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777
      - /var/lib/datalox/run:rw,noexec,nosuid,nodev,size=256m,mode=1777
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
networks:
  datalox-internal:
    internal: true
""",
        encoding="utf-8",
    )

    tests = root / "tests"
    tests.mkdir()
    (tests / "Dockerfile").write_text(
        f"""FROM {PYTHON_BASE_IMAGE}

COPY grade.py test.sh /tests/
RUN chmod 0555 /tests/test.sh && chmod 0444 /tests/grade.py
""",
        encoding="utf-8",
    )
    expected = {
        "package_content_sha256": package_manifest["package_content_sha256"],
        "source_manifest_sha256": package_manifest["world"]["source_manifest_sha256"],
        "world_id": package_manifest["world"]["id"],
        "bundle_version": package_manifest["world"]["bundle_version"],
        "episode_id": package_manifest["world"]["episode_id"],
        "task_id": package_manifest["task"]["task_id"],
    }
    (tests / "grade.py").write_text(
        _GRADER.replace("__EXPECTED__", repr(expected)),
        encoding="utf-8",
    )
    test_script = tests / "test.sh"
    test_script.write_text("#!/bin/sh\nset -eu\npython /tests/grade.py\n", encoding="utf-8")
    test_script.chmod(0o755)
    if solution_dir is not None:
        _copy_solution(solution_dir, root / "solution")


def _configured_roles(bundle: Any, requested: tuple[str, ...] | None) -> tuple[str, ...]:
    available = {role.id for role in bundle.roles}
    roles = (bundle.manifest.default_actor_role,) if requested is None else requested
    if not roles:
        raise HarnessAdapterError("Harbor actor_roles must not be empty")
    if len(set(roles)) != len(roles):
        raise HarnessAdapterError("Harbor actor_roles must not contain duplicates")
    unknown = set(roles) - available
    if unknown:
        raise HarnessAdapterError(
            "Harbor actor_roles are not declared by the world: " + ", ".join(sorted(unknown))
        )
    return roles


def _copy_solution(source: Path, destination: Path) -> None:
    root = source.resolve(strict=True)
    if not root.is_dir() or not (root / "solve.sh").is_file():
        raise HarnessAdapterError("Harbor solution_dir must contain solve.sh")
    symlinks = [path for path in root.rglob("*") if path.is_symlink()]
    if symlinks:
        raise HarnessAdapterError("Harbor solution_dir must not contain symlinks")
    shutil.copytree(root, destination)
    (destination / "solve.sh").chmod(0o755)


def _default_readme(world_id: str, episode_id: str, actor_roles: tuple[str, ...]) -> str:
    servers = "\n".join(f"- `datalox-{role.replace('_', '-')}`" for role in actor_roles)
    return f"""# {world_id}

Harbor task for Datalox world episode `{episode_id}`.

## Run

```bash
uv tool install harbor=={HARBOR_VERSION}
harbor run -p . -a <agent> -m <model>
```

Harbor mounts these controller-authorized MCP principals:

{servers}

The verifier runs separately and reads only the finalized world verdict.
"""


_GRADER = """from __future__ import annotations

import json
import math
from pathlib import Path


VERDICT_PATH = Path("/var/lib/datalox/verdict.json")
OUTPUT_DIR = Path("/logs/verifier")
EXPECTED = __EXPECTED__


def _valid_digest(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


def _reward(verdict: object) -> float:
    if not isinstance(verdict, dict):
        return 0.0
    required_text = ("schema_version", "world_id", "bundle_version", "episode_id", "task_id")
    if any(not isinstance(verdict.get(field), str) or not verdict[field] for field in required_text):
        return 0.0
    if verdict["schema_version"] != "datalox_world_package_verdict_v1":
        return 0.0
    if any(verdict.get(field) != expected for field, expected in EXPECTED.items()):
        return 0.0
    if not _valid_digest(verdict.get("package_content_sha256")):
        return 0.0
    if not _valid_digest(verdict.get("source_manifest_sha256")):
        return 0.0
    if not _valid_digest(verdict.get("run_export_sha256")):
        return 0.0
    audit = verdict.get("audit")
    if not isinstance(audit, dict):
        return 0.0
    if not isinstance(audit.get("passed"), bool):
        return 0.0
    if not _valid_digest(audit.get("sha256")):
        return 0.0
    if audit.get("reward_source") not in {"binary_audit", "world_verifier"}:
        return 0.0
    failure_codes = audit.get("failure_codes")
    if not isinstance(failure_codes, list) or any(not isinstance(code, str) for code in failure_codes):
        return 0.0
    reward = audit.get("reward")
    if isinstance(reward, bool) or not isinstance(reward, (int, float)):
        return 0.0
    score = float(reward)
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        return 0.0
    if audit["passed"] and score <= 0.0:
        return 0.0
    if not audit["passed"] and score >= 1.0:
        return 0.0
    return score


def grade(
    verdict_path: Path = VERDICT_PATH,
    output_dir: Path = OUTPUT_DIR,
) -> float:
    try:
        verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        verdict = None
    score = _reward(verdict)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "reward.json").write_text(
        json.dumps({"datalox": score}, sort_keys=True) + "\\n",
        encoding="utf-8",
    )
    return score


if __name__ == "__main__":
    grade()
"""
