from __future__ import annotations

from typing import Any


class WorldV1Error(ValueError):
    """Base class for stable, agent-readable world-v1 failures."""

    def __init__(self, code: str, message: str, **context: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.context = context

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "context": self.context,
        }


class WorldBundleError(WorldV1Error):
    """A compiled bundle is structurally invalid or cannot be loaded."""


class WorldAuthorizationError(WorldV1Error):
    """An actor or tool authorization check failed closed."""


class WorldSessionError(WorldV1Error):
    """A session operation violates the world-v1 runtime contract."""
