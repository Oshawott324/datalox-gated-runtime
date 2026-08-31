"""Trusted Unix-socket control client for an admitted composition session."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Literal

import httpx

from datalox_gated_runtime.json_digest import canonical_json_sha256


class CompositionRolloutControlError(ValueError):
    """The private composition control plane returned an invalid result."""


def control_composition_session(
    *,
    run_root: Path,
    operation: Literal["reset", "export", "finalize"],
) -> dict[str, Any]:
    """Run one atomic composition lifecycle operation through its private UDS."""

    token = _read_token(run_root)
    socket_path = run_root / "control.sock"
    if not socket_path.is_socket():
        raise CompositionRolloutControlError("composition control socket is unavailable")
    method, path, body = {
        "reset": ("POST", "/v1/composition/reset", {}),
        "export": ("GET", "/v1/composition/export", None),
        "finalize": ("POST", "/v1/composition/finalize", {}),
    }[operation]
    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=str(socket_path)),
            timeout=5.0,
        ) as client:
            request_arguments: dict[str, Any] = {"headers": {"x-datalox-control-token": token}}
            if body is not None:
                request_arguments["json"] = body
            response = client.request(method, f"http://localhost{path}", **request_arguments)
    except httpx.HTTPError as exc:
        raise CompositionRolloutControlError("composition control plane is unavailable") from exc
    if response.status_code != 200:
        raise CompositionRolloutControlError(
            f"composition control {operation} failed with HTTP {response.status_code}"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise CompositionRolloutControlError(
            f"composition control {operation} returned invalid JSON"
        ) from exc
    _validate_export(payload, operation=operation)
    return payload


def _read_token(run_root: Path) -> str:
    token_path = run_root / "control-token"
    if token_path.is_symlink():
        raise CompositionRolloutControlError("composition control token is unavailable")
    try:
        token = token_path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise CompositionRolloutControlError("composition control token is unavailable") from exc
    if not token:
        raise CompositionRolloutControlError("composition control token is empty")
    return token


def _validate_export(value: object, *, operation: str) -> None:
    if not isinstance(value, dict):
        raise CompositionRolloutControlError(
            f"composition control {operation} returned a non-object export"
        )
    required = {
        "schema_version",
        "pack",
        "provider_profiles",
        "providers",
        "events",
        "status",
        "failure",
        "finalized",
        "content_sha256",
    }
    if not required.issubset(value):
        raise CompositionRolloutControlError(
            f"composition control {operation} omitted required export fields"
        )
    if (
        value["schema_version"] != "datalox_composition_session_export_v1"
        or not isinstance(value["pack"], dict)
        or not isinstance(value["provider_profiles"], list)
        or not isinstance(value["providers"], dict)
        or not value["providers"]
        or not isinstance(value["events"], dict)
        or value["status"] not in {"valid", "invalid"}
        or not isinstance(value["finalized"], bool)
        or not isinstance(value["content_sha256"], str)
    ):
        raise CompositionRolloutControlError(
            f"composition control {operation} returned an invalid export"
        )
    unsigned = {key: item for key, item in value.items() if key != "content_sha256"}
    if value["content_sha256"] != canonical_json_sha256(unsigned):
        raise CompositionRolloutControlError(
            f"composition control {operation} returned an invalid content digest"
        )
    if operation == "finalize" and value["finalized"] is not True:
        raise CompositionRolloutControlError(
            "composition control finalize did not finalize the session"
        )
    if operation in {"reset", "export"} and value["finalized"] is not False:
        raise CompositionRolloutControlError(
            f"composition control {operation} unexpectedly finalized the session"
        )


def main(argv: tuple[str, ...] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", required=True)
    parser.add_argument("--operation", choices=("reset", "export", "finalize"), required=True)
    args = parser.parse_args(argv)
    try:
        payload = control_composition_session(
            run_root=Path(args.run_root),
            operation=args.operation,
        )
    except CompositionRolloutControlError as exc:
        parser.exit(1, f"{exc}\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
