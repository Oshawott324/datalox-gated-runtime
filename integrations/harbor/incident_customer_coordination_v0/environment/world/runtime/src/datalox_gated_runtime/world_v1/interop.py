from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from datalox_gated_runtime.harness_adapters import (
    HARBOR_VERSION,
    HUD_VERSION,
    HarnessAdapterError,
    build_harbor_adapter,
    build_hud_adapter,
)
from datalox_gated_runtime.world_package import WorldPackageError, build_world_package

WorldExportFormat = Literal["oci", "hud", "harbor"]


class WorldInteropExportError(ValueError):
    """A canonical world package or harness adapter could not be built."""


def export_world_interop(
    *,
    env_dir: Path,
    out_dir: Path,
    format: WorldExportFormat,
    episode_id: str | None = None,
) -> dict[str, Any]:
    """Build the canonical package or one thin harness adapter over it."""

    try:
        if format == "oci":
            return build_world_package(
                env_dir=env_dir,
                out_dir=out_dir,
                episode_id=episode_id,
            )
        if format == "hud":
            return build_hud_adapter(
                env_dir=env_dir,
                out_dir=out_dir,
                episode_id=episode_id,
            )
        if format == "harbor":
            return build_harbor_adapter(
                env_dir=env_dir,
                out_dir=out_dir,
                episode_id=episode_id,
            )
    except (HarnessAdapterError, WorldPackageError) as error:
        raise WorldInteropExportError(str(error)) from error
    raise WorldInteropExportError(f"unsupported interop format: {format}")


__all__ = [
    "HARBOR_VERSION",
    "HUD_VERSION",
    "WorldExportFormat",
    "WorldInteropExportError",
    "export_world_interop",
]
