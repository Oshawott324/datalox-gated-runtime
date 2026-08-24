"""Stable contracts for a portable gated-world package."""

WORLD_PACKAGE_SCHEMA_VERSION = "datalox_world_package_v1"
WORLD_PACKAGE_VERDICT_SCHEMA_VERSION = "datalox_world_package_verdict_v1"
WORLD_PACKAGE_MANIFEST = "DATALOX_WORLD.json"
WORLD_PACKAGE_PORT = 8000
WORLD_PACKAGE_RUNS_ROOT = "/var/lib/datalox/run"
PYTHON_BASE_IMAGE = (
    "python:3.12-slim-bookworm"
    "@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b"
)


class WorldPackageError(ValueError):
    """An admitted world cannot be materialized as a canonical package."""
