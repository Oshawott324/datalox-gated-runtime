from __future__ import annotations

from pathlib import Path
from typing import Any

from datalox_gated_runtime.harness_adapters._shared import (
    atomic_output,
    public_result,
    task_prompt,
    write_adapter_manifest,
)
from datalox_gated_runtime.harness_adapters.contracts import HUD_VERSION
from datalox_gated_runtime.world_package import build_world_package


def build_hud_adapter(
    *,
    env_dir: Path,
    out_dir: Path,
    episode_id: str | None = None,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """Wrap one canonical world package as a HUD 0.6.12 environment."""

    with atomic_output(out_dir) as temporary:
        canonical = temporary / "world"
        result = build_world_package(
            env_dir=env_dir,
            out_dir=canonical,
            episode_id=episode_id,
            project_root=project_root,
        )
        package_manifest = {key: value for key, value in result.items() if key != "out_dir"}
        prompt = task_prompt(canonical, package_manifest)
        _write_hud_files(temporary, package_manifest, prompt)
        manifest = write_adapter_manifest(
            root=temporary,
            harness="hud",
            harness_version=HUD_VERSION,
            canonical_package_path="world",
            package_manifest=package_manifest,
        )
    return public_result(manifest, out_dir)


def _write_hud_files(
    root: Path,
    package_manifest: dict[str, Any],
    prompt: str,
) -> None:
    hud = root / "hud"
    hud.mkdir()
    world = package_manifest["world"]
    task = package_manifest["task"]
    env_source = f"""from __future__ import annotations

import asyncio
from pathlib import Path

import uvicorn
from hud import Environment
from hud.capabilities import Capability

from datalox_gated_runtime.world_package.entrypoint import (
    create_packaged_world_app,
    finalize_packaged_world,
)


PACKAGE_ROOT = Path("/opt/datalox")
RUN_DIR = Path("/var/lib/datalox/run")
VERDICT_PATH = RUN_DIR / "verdict.json"
WORLD_PORT = 8000
TASK_PROMPT = {prompt!r}

env = Environment({world["id"]!r}, version={world["bundle_version"]!r})
_world_server: uvicorn.Server | None = None
_world_task: asyncio.Task[None] | None = None


async def _wait_for_world() -> None:
    for _ in range(100):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", WORLD_PORT)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        await writer.wait_closed()
        return
    raise RuntimeError("Datalox MCP server did not become ready")


@env.initialize
async def _start_world() -> None:
    global _world_server, _world_task
    app = create_packaged_world_app(package_root=PACKAGE_ROOT, run_dir=RUN_DIR)
    _world_server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=WORLD_PORT, log_level="warning")
    )
    _world_task = asyncio.create_task(asyncio.to_thread(_world_server.run))
    await _wait_for_world()
    if _world_task.done():
        await _world_task
        raise RuntimeError("Datalox MCP server stopped during startup")
    env.add_capability(
        Capability.mcp(name="datalox", url="http://127.0.0.1:8000/mcp")
    )


@env.shutdown
async def _stop_world() -> None:
    global _world_server, _world_task
    if _world_server is not None:
        _world_server.should_exit = True
    if _world_task is not None:
        await _world_task
    _world_server = None
    _world_task = None


@env.template(id={task["task_id"]!r})
async def datalox_task():
    yield TASK_PROMPT
    verdict = await asyncio.to_thread(
        finalize_packaged_world,
        package_root=PACKAGE_ROOT,
        run_dir=RUN_DIR,
        out_path=VERDICT_PATH,
    )
    yield float(verdict["audit"]["reward"])
"""
    (hud / "env.py").write_text(env_source, encoding="utf-8")
    (hud / "tasks.py").write_text(
        "from env import datalox_task\n\n\ntasks = [datalox_task()]\n",
        encoding="utf-8",
    )
    (hud / "pyproject.toml").write_text(
        "[project]\n"
        f'name = "datalox-{world["id"]}-hud"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.11"\n'
        f'dependencies = ["hud=={HUD_VERSION}"]\n',
        encoding="utf-8",
    )
    canonical_dockerfile = (root / "world" / "Dockerfile").read_text(encoding="utf-8")
    canonical_dockerfile = canonical_dockerfile.replace(
        "COPY runtime/pyproject.toml runtime/uv.lock /opt/datalox/runtime/",
        "COPY world/runtime/pyproject.toml world/runtime/uv.lock /opt/datalox/runtime/",
    ).replace("COPY . /opt/datalox", "COPY world/. /opt/datalox")
    extension = f"""
USER root
COPY hud /opt/datalox-hud
RUN uv pip install --python /opt/datalox-venv/bin/python "hud=={HUD_VERSION}" \\
    && chmod -R a-w /opt/datalox/runtime /opt/datalox-venv /opt/datalox-hud
USER datalox:datalox
WORKDIR /opt/datalox-hud
ENTRYPOINT []
CMD ["hud", "serve", "env:env", "--host", "0.0.0.0", "--port", "8765"]
HEALTHCHECK --interval=5s --timeout=2s --start-period=10s --retries=12 \\
    CMD python -c "import socket; socket.create_connection(('127.0.0.1', 8765), 1).close()" || exit 1
"""
    (root / "Dockerfile").write_text(canonical_dockerfile + extension, encoding="utf-8")
