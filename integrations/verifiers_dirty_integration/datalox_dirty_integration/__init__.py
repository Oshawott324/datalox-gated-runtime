"""Verifiers compatibility fixture for paired Datalox intervention experiments."""

from __future__ import annotations

from typing import Any


def load_environment(*args: Any, **kwargs: Any) -> Any:
    """Load the pinned Verifiers compatibility environment lazily."""

    from datalox_dirty_integration.environment import load_environment as load

    return load(*args, **kwargs)


__all__ = ["load_environment"]
