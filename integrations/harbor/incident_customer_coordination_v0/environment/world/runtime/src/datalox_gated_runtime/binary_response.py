"""JSON-safe binary response bodies for world and gated-runtime responses.

The envelope is deliberately an ordinary JSON object so direct tool calls,
MCP projections, ledgers, and run exports retain the same evidence:

{
    "$datalox_binary_response": {
        "schema_version": "datalox_binary_response_v1",
        "content_type": "image/png",
        "data_base64": "iVBORw0KGgo..."
    }
}

Only the HTTP adapter projects a validated envelope back to response bytes.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import re
from typing import Any, Mapping

BINARY_RESPONSE_ENVELOPE_KEY = "$datalox_binary_response"
BINARY_RESPONSE_SCHEMA_VERSION = "datalox_binary_response_v1"
BINARY_RESPONSE_ERROR_CODE = "binary_response_envelope_invalid"

_PAYLOAD_FIELDS = frozenset({"schema_version", "content_type", "data_base64"})
_HTTP_TOKEN = r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+"
_QUOTED_PARAMETER = r'"(?:[ !#-\[\]-~]|\\[ -~])*"'
_CONTENT_TYPE = re.compile(
    rf"{_HTTP_TOKEN}/{_HTTP_TOKEN}"
    rf"(?: *; *{_HTTP_TOKEN}=(?:{_HTTP_TOKEN}|{_QUOTED_PARAMETER}))*"
)
_CANONICAL_CONTENT_LENGTH = re.compile(r"0|[1-9][0-9]*")
_CANONICAL_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


class BinaryResponseEnvelopeError(ValueError):
    """A stable, agent-readable binary-envelope contract failure."""

    code = BINARY_RESPONSE_ERROR_CODE

    def __init__(self, *, reason: str, message: str, field: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.field = field

    @property
    def details(self) -> dict[str, str]:
        return {"reason": self.reason, "field": self.field}


@dataclass(frozen=True)
class BinaryResponseEnvelope:
    """Validated envelope metadata; encoded bytes remain JSON-safe."""

    content_type: str
    data_base64: str


def make_binary_response_body(
    content: bytes,
    *,
    content_type: str,
) -> dict[str, Any]:
    """Build one canonical JSON-serializable binary response envelope."""

    if not isinstance(content, bytes):
        raise TypeError("binary response content must be bytes")
    _validate_content_type(content_type)
    return {
        BINARY_RESPONSE_ENVELOPE_KEY: {
            "schema_version": BINARY_RESPONSE_SCHEMA_VERSION,
            "content_type": content_type,
            "data_base64": base64.b64encode(content).decode("ascii"),
        }
    }


def inspect_binary_response_body(
    body: object,
    *,
    headers: Mapping[str, str] | None = None,
    status_code: int | None = None,
) -> BinaryResponseEnvelope | None:
    """Validate and describe a reserved envelope without changing the body."""

    if not isinstance(body, dict) or BINARY_RESPONSE_ENVELOPE_KEY not in body:
        return None
    if set(body) != {BINARY_RESPONSE_ENVELOPE_KEY}:
        raise BinaryResponseEnvelopeError(
            reason="envelope_fields_invalid",
            message="Binary response envelope must contain only its reserved top-level field.",
            field="$",
        )

    payload = body[BINARY_RESPONSE_ENVELOPE_KEY]
    if not isinstance(payload, dict):
        raise BinaryResponseEnvelopeError(
            reason="payload_type_invalid",
            message="Binary response envelope payload must be an object.",
            field=BINARY_RESPONSE_ENVELOPE_KEY,
        )
    if set(payload) != _PAYLOAD_FIELDS:
        raise BinaryResponseEnvelopeError(
            reason="payload_fields_invalid",
            message="Binary response envelope payload fields do not match its schema.",
            field=BINARY_RESPONSE_ENVELOPE_KEY,
        )

    schema_version = payload["schema_version"]
    if schema_version != BINARY_RESPONSE_SCHEMA_VERSION:
        raise BinaryResponseEnvelopeError(
            reason="schema_version_invalid",
            message="Binary response envelope schema_version is unsupported.",
            field=f"{BINARY_RESPONSE_ENVELOPE_KEY}.schema_version",
        )

    content_type = payload["content_type"]
    _validate_content_type(content_type)

    data_base64 = payload["data_base64"]
    if not isinstance(data_base64, str):
        raise BinaryResponseEnvelopeError(
            reason="base64_type_invalid",
            message="Binary response envelope data_base64 must be a string.",
            field=f"{BINARY_RESPONSE_ENVELOPE_KEY}.data_base64",
        )
    if not _CANONICAL_BASE64.fullmatch(data_base64):
        raise BinaryResponseEnvelopeError(
            reason="base64_invalid",
            message="Binary response envelope data_base64 is not valid base64.",
            field=f"{BINARY_RESPONSE_ENVELOPE_KEY}.data_base64",
        )
    if data_base64.endswith("==") and _BASE64_ALPHABET.index(data_base64[-3]) % 16:
        raise BinaryResponseEnvelopeError(
            reason="base64_noncanonical",
            message="Binary response envelope data_base64 must use canonical RFC 4648 base64.",
            field=f"{BINARY_RESPONSE_ENVELOPE_KEY}.data_base64",
        )
    if data_base64.endswith("=") and not data_base64.endswith("=="):
        if _BASE64_ALPHABET.index(data_base64[-2]) % 4:
            raise BinaryResponseEnvelopeError(
                reason="base64_noncanonical",
                message=(
                    "Binary response envelope data_base64 must use canonical RFC 4648 base64."
                ),
                field=f"{BINARY_RESPONSE_ENVELOPE_KEY}.data_base64",
            )

    _validate_content_type_header(content_type, headers)
    _validate_content_length_header(data_base64, headers)
    if status_code is not None and (100 <= status_code < 200 or status_code in {204, 205, 304}):
        raise BinaryResponseEnvelopeError(
            reason="status_code_forbids_body",
            message="Binary response envelope is not allowed for a bodyless HTTP status code.",
            field="status_code",
        )
    return BinaryResponseEnvelope(content_type=content_type, data_base64=data_base64)


def decode_binary_response_body(envelope: BinaryResponseEnvelope) -> bytes:
    """Decode a previously validated envelope at the HTTP projection boundary."""

    return base64.b64decode(envelope.data_base64, validate=True)


def _validate_content_type(content_type: object) -> None:
    field = f"{BINARY_RESPONSE_ENVELOPE_KEY}.content_type"
    if not isinstance(content_type, str):
        raise BinaryResponseEnvelopeError(
            reason="content_type_type_invalid",
            message="Binary response envelope content_type must be a string.",
            field=field,
        )
    if not _CONTENT_TYPE.fullmatch(content_type):
        raise BinaryResponseEnvelopeError(
            reason="content_type_invalid",
            message="Binary response envelope content_type must be a valid ASCII media type.",
            field=field,
        )


def _validate_content_type_header(
    content_type: str,
    headers: Mapping[str, str] | None,
) -> None:
    if headers is None:
        return
    declared = [value for name, value in headers.items() if name.lower() == "content-type"]
    if not declared:
        return
    if len(declared) != 1 or declared[0] != content_type:
        raise BinaryResponseEnvelopeError(
            reason="content_type_header_conflict",
            message="Binary response envelope content_type conflicts with response headers.",
            field="headers.content-type",
        )


def _validate_content_length_header(
    data_base64: str,
    headers: Mapping[str, str] | None,
) -> None:
    if headers is None:
        return
    declared = [value for name, value in headers.items() if name.lower() == "content-length"]
    if not declared:
        return
    if len(declared) != 1:
        raise BinaryResponseEnvelopeError(
            reason="content_length_header_duplicate",
            message="Binary response envelope must not declare Content-Length more than once.",
            field="headers.content-length",
        )

    value = declared[0]
    if not isinstance(value, str) or not _CANONICAL_CONTENT_LENGTH.fullmatch(value):
        raise BinaryResponseEnvelopeError(
            reason="content_length_header_invalid",
            message="Binary response envelope Content-Length must be a canonical decimal integer.",
            field="headers.content-length",
        )

    padding = len(data_base64) - len(data_base64.rstrip("="))
    decoded_length = len(data_base64) // 4 * 3 - padding
    if int(value) != decoded_length:
        raise BinaryResponseEnvelopeError(
            reason="content_length_header_mismatch",
            message="Binary response envelope Content-Length does not match its encoded bytes.",
            field="headers.content-length",
        )
