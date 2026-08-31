"""Trusted client for the interception gateway's Unix-socket control plane."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import httpx

CONTROL_AGGREGATE_SCHEMA_VERSION = "datalox_interception_control_aggregate_v1"


class InterceptionControlError(ValueError):
    """The private interception control plane could not complete an operation."""


def export_provider_runs(
    *,
    run_root: Path,
    provider_ids: tuple[str, ...],
) -> dict[str, Any]:
    """Export all declared providers in caller-supplied stable order."""

    return _aggregate(run_root=run_root, provider_ids=provider_ids, operation="export")


def reset_provider_runs(
    *,
    run_root: Path,
    provider_ids: tuple[str, ...],
) -> dict[str, Any]:
    """Reset all declared providers and return their post-reset exports."""

    return _aggregate(run_root=run_root, provider_ids=provider_ids, operation="reset")


def _aggregate(
    *,
    run_root: Path,
    provider_ids: tuple[str, ...],
    operation: Literal["export", "reset"],
) -> dict[str, Any]:
    if not provider_ids:
        raise InterceptionControlError("at least one provider id is required")
    if len(set(provider_ids)) != len(provider_ids):
        raise InterceptionControlError("provider ids must be unique")

    token = _read_token(run_root)
    socket_path = run_root / "control.sock"
    if not socket_path.is_socket():
        raise InterceptionControlError("interception control socket is unavailable")
    transport = httpx.HTTPTransport(uds=str(socket_path))
    method = "GET" if operation == "export" else "POST"
    providers: list[dict[str, Any]] = []
    try:
        with httpx.Client(transport=transport, timeout=5.0) as client:
            for provider_id in provider_ids:
                _validate_provider_id(provider_id)
                response = client.request(
                    method,
                    f"http://localhost/v1/providers/{provider_id}/{operation}",
                    headers={"x-datalox-control-token": token},
                )
                if response.status_code != 200:
                    raise InterceptionControlError(
                        f"control {operation} failed for provider {provider_id!r} "
                        f"with HTTP {response.status_code}"
                    )
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise InterceptionControlError(
                        f"control {operation} returned invalid JSON for provider {provider_id!r}"
                    ) from exc
                if not isinstance(payload, dict) or payload.get("provider_id") != provider_id:
                    raise InterceptionControlError(
                        f"control {operation} returned the wrong provider export for "
                        f"{provider_id!r}"
                    )
                providers.append(payload)
    except httpx.HTTPError as exc:
        raise InterceptionControlError("interception control plane is unavailable") from exc

    return {
        "schema_version": CONTROL_AGGREGATE_SCHEMA_VERSION,
        "operation": operation,
        "providers": providers,
    }


def _read_token(run_root: Path) -> str:
    try:
        token = (run_root / "control-token").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise InterceptionControlError("interception control token is unavailable") from exc
    if not token:
        raise InterceptionControlError("interception control token is empty")
    return token


def _validate_provider_id(provider_id: str) -> None:
    if (
        not provider_id
        or not provider_id[0].isascii()
        or not provider_id[0].isalnum()
        or any(
            not (character.isascii() and (character.isalnum() or character in "_-"))
            for character in provider_id
        )
    ):
        raise InterceptionControlError(f"invalid provider id: {provider_id!r}")
