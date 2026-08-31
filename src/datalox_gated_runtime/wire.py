"""Byte-preserving HTTP wire contract for transparent provider interception."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol
from urllib.parse import parse_qsl

from datalox_gated_runtime.binary_response import (
    decode_binary_response_body,
    inspect_binary_response_body,
)
from datalox_gated_runtime.models import CallRequest, GateResponse
from datalox_gated_runtime.query import query_from_items


@dataclass(frozen=True)
class WireRequest:
    """An inbound HTTP request before provider-specific decoding.

    ASGI supplies headers, path, query, and body independently. Keeping each as
    bytes prevents the transparent gateway from silently changing a provider
    request before the selected provider codec sees it.
    """

    scheme: str
    authority: str
    method: str
    raw_path: bytes
    decoded_path: str
    raw_query: bytes
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes

    @property
    def path(self) -> str:
        return self.decoded_path

    @property
    def media_type(self) -> str | None:
        value = self.header("content-type")
        return value.split(";", 1)[0].strip().lower() if value else None

    @property
    def body_sha256(self) -> str:
        return sha256(self.body).hexdigest()

    def header_values(self, name: str) -> tuple[str, ...]:
        encoded = name.casefold().encode("ascii")
        return tuple(
            value.decode("latin-1")
            for header_name, value in self.headers
            if header_name.lower() == encoded
        )

    def header(self, name: str) -> str | None:
        values = self.header_values(name)
        return values[-1] if values else None


@dataclass(frozen=True)
class WireResponse:
    status_code: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes


@dataclass(frozen=True)
class WireDecodeError(ValueError):
    code: str
    message: str
    status_code: int = 400

    def __str__(self) -> str:
        return self.message


class ProviderWireCodec(Protocol):
    def decode(self, request: WireRequest) -> CallRequest: ...

    def encode(self, response: GateResponse) -> WireResponse: ...


class StandardProviderWireCodec:
    """Strict codec for JSON, form, text, and explicitly enveloped binary data."""

    def decode(self, request: WireRequest) -> CallRequest:
        body = self._decode_body(request)
        try:
            query_items = parse_qsl(
                request.raw_query.decode("ascii"),
                keep_blank_values=True,
                strict_parsing=False,
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise WireDecodeError(
                code="invalid_query_string",
                message="Request query string is not valid form-encoded ASCII.",
            ) from exc

        return CallRequest(
            scheme=request.scheme,
            authority=request.authority,
            method=request.method,
            path=request.path,
            query=query_from_items(query_items),
            body=body,
            headers=self._decoded_headers(request),
            raw_body_sha256=request.body_sha256,
        )

    def encode(self, response: GateResponse) -> WireResponse:
        binary = inspect_binary_response_body(
            response.body,
            headers=response.headers,
            status_code=response.status_code,
        )
        headers = self._response_headers(response.headers)
        content_type = _last_header(headers, b"content-type")

        if response.status_code in {204, 304}:
            body = b""
        elif binary is not None:
            body = decode_binary_response_body(binary)
            headers = _replace_header(
                headers,
                b"content-type",
                binary.content_type.encode("latin-1"),
            )
        elif (
            content_type is not None
            and b"json" not in content_type.lower()
            and (response.body is None or isinstance(response.body, str))
        ):
            body = (response.body or "").encode("utf-8")
        else:
            body = json.dumps(
                response.body,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            if content_type is None:
                headers = (*headers, (b"content-type", b"application/json"))

        return WireResponse(
            status_code=response.status_code,
            headers=headers,
            body=body,
        )

    def _decode_body(self, request: WireRequest) -> Any | None:
        if not request.body:
            return None

        media_type = request.media_type
        if media_type is None:
            raise WireDecodeError(
                code="content_type_required",
                message="A non-empty request body requires Content-Type.",
                status_code=415,
            )
        if media_type == "application/json" or media_type.endswith("+json"):
            try:
                return json.loads(request.body.decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise WireDecodeError(
                    code="invalid_json_body",
                    message="JSON request body is not valid UTF-8.",
                ) from exc
            except json.JSONDecodeError as exc:
                raise WireDecodeError(
                    code="invalid_json_body",
                    message="Request body is not valid JSON.",
                ) from exc
        if media_type == "application/x-www-form-urlencoded":
            try:
                pairs = parse_qsl(
                    request.body.decode("ascii"),
                    keep_blank_values=True,
                    strict_parsing=False,
                )
            except (UnicodeDecodeError, ValueError) as exc:
                raise WireDecodeError(
                    code="invalid_form_body",
                    message="Request body is not valid form encoding.",
                ) from exc
            return _form_object(pairs)
        if media_type.startswith("text/"):
            try:
                return request.body.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WireDecodeError(
                    code="invalid_text_body",
                    message="Text request body is not valid UTF-8.",
                ) from exc
        if media_type == "application/vnd.datalox.bytes+json":
            return {"base64": base64.b64encode(request.body).decode("ascii")}
        raise WireDecodeError(
            code="unsupported_media_type",
            message=f"No provider wire codec is declared for {media_type}.",
            status_code=415,
        )

    @staticmethod
    def _decoded_headers(request: WireRequest) -> dict[str, str]:
        decoded: dict[str, str] = {}
        for name, value in request.headers:
            decoded[name.decode("ascii").lower()] = value.decode("latin-1")
        return decoded

    @staticmethod
    def _response_headers(headers: dict[str, str]) -> tuple[tuple[bytes, bytes], ...]:
        return tuple(
            (name.lower().encode("ascii"), value.encode("latin-1"))
            for name, value in headers.items()
            if name.lower() not in {"connection", "content-length", "transfer-encoding"}
        )


def _form_object(pairs: list[tuple[str, str]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        existing = result.get(name)
        if existing is None:
            result[name] = value
        elif isinstance(existing, list):
            existing.append(value)
        else:
            result[name] = [existing, value]
    return result


def _last_header(headers: tuple[tuple[bytes, bytes], ...], name: bytes) -> bytes | None:
    values = [value for header_name, value in headers if header_name.lower() == name]
    return values[-1] if values else None


def _replace_header(
    headers: tuple[tuple[bytes, bytes], ...], name: bytes, value: bytes
) -> tuple[tuple[bytes, bytes], ...]:
    return (*tuple(item for item in headers if item[0].lower() != name), (name, value))
