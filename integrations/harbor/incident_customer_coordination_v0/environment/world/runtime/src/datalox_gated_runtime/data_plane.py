"""Provider-shaped HTTP data plane with authority-based routing."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from starlette.responses import Response

from datalox_gated_runtime.models import CallRequest, GateResponse
from datalox_gated_runtime.wire import (
    ProviderWireCodec,
    StandardProviderWireCodec,
    WireDecodeError,
    WireRequest,
    WireResponse,
)


class ProviderRequestHandler(Protocol):
    def handle(self, request: CallRequest) -> GateResponse: ...


@dataclass
class ProviderBinding:
    handler: ProviderRequestHandler
    codec: ProviderWireCodec = field(default_factory=StandardProviderWireCodec)
    lock: threading.Lock = field(default_factory=threading.Lock)


def create_data_plane_app(bindings: dict[str, ProviderBinding]) -> FastAPI:
    normalized: dict[str, ProviderBinding] = {}
    for authority, binding in bindings.items():
        key = normalize_authority(authority, scheme="https")
        if key in normalized:
            raise ValueError(f"duplicate provider authority: {key}")
        normalized[key] = binding
    if not normalized:
        raise ValueError("at least one provider authority is required")

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route(
        "/{path:path}",
        methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    )
    async def dispatch(path: str, request: Request) -> Response:
        del path
        try:
            authority = authority_from_scope(request)
        except WireDecodeError as exc:
            return _error_response(exc)
        binding = normalized.get(authority)
        if binding is None:
            return _error_response(
                WireDecodeError(
                    code="authority_not_configured",
                    message="This provider authority is not present in the runtime bundle.",
                    status_code=421,
                )
            )

        scope = request.scope
        raw_path = scope.get("raw_path")
        if not isinstance(raw_path, bytes):
            raw_path = request.url.path.encode("utf-8")
        decoded_path = scope.get("path")
        if not isinstance(decoded_path, str):
            raise TypeError("ASGI path must be a string")
        raw_query = scope.get("query_string", b"")
        if not isinstance(raw_query, bytes):
            raise TypeError("ASGI query_string must be bytes")
        raw_headers = scope.get("headers", [])
        if not isinstance(raw_headers, list) or any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], bytes)
            or not isinstance(item[1], bytes)
            for item in raw_headers
        ):
            raise RuntimeError("ASGI headers must be byte pairs")

        wire_request = WireRequest(
            scheme=request.url.scheme,
            authority=authority,
            method=request.method,
            raw_path=raw_path,
            decoded_path=decoded_path,
            raw_query=raw_query,
            headers=tuple(raw_headers),
            body=await request.body(),
        )
        try:
            call_request = binding.codec.decode(wire_request)
        except WireDecodeError as exc:
            return _error_response(exc)
        with binding.lock:
            gate_response = binding.handler.handle(call_request)
        return _raw_response(binding.codec.encode(gate_response))

    return app


def authority_from_scope(request: Request) -> str:
    values = [value for name, value in request.scope.get("headers", []) if name.lower() == b"host"]
    if len(values) != 1:
        raise WireDecodeError(
            code="invalid_authority",
            message="Exactly one Host authority is required.",
        )
    try:
        authority = values[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise WireDecodeError(
            code="invalid_authority",
            message="Provider authority must be ASCII.",
        ) from exc
    return normalize_authority(authority, scheme=request.url.scheme)


def normalize_authority(authority: str, *, scheme: str) -> str:
    if not authority or authority.strip() != authority or any(char in authority for char in "/?#@"):
        raise WireDecodeError(
            code="invalid_authority",
            message="Provider authority is invalid.",
        )
    try:
        parsed = urlsplit(f"//{authority}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise WireDecodeError(
            code="invalid_authority",
            message="Provider authority is invalid.",
        ) from exc
    if host is None or parsed.username is not None or parsed.password is not None:
        raise WireDecodeError(
            code="invalid_authority",
            message="Provider authority is invalid.",
        )
    canonical_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    default_port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return canonical_host if port in {None, default_port} else f"{canonical_host}:{port}"


def _error_response(error: WireDecodeError) -> Response:
    body = json.dumps(
        {"error": {"code": error.code, "message": error.message}},
        separators=(",", ":"),
    ).encode("utf-8")
    return _raw_response(
        WireResponse(
            status_code=error.status_code,
            headers=((b"content-type", b"application/json"),),
            body=body,
        )
    )


def _raw_response(wire: WireResponse) -> Response:
    response = Response(content=wire.body, status_code=wire.status_code)
    raw_headers = list(wire.headers)
    if wire.status_code not in {204, 304} and not any(
        name.lower() == b"content-length" for name, _value in raw_headers
    ):
        raw_headers.append((b"content-length", str(len(wire.body)).encode("ascii")))
    response.raw_headers = raw_headers
    return response
