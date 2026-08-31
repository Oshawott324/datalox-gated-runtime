import json

import pytest

from datalox_gated_runtime.models import GateDecision, GateResponse
from datalox_gated_runtime.wire import (
    StandardProviderWireCodec,
    WireDecodeError,
    WireRequest,
)


def _request(
    *,
    body: bytes = b"",
    content_type: bytes | None = None,
    query: bytes = b"expand[]=customer&expand[]=invoice",
) -> WireRequest:
    headers = [(b"host", b"api.stripe.com"), (b"authorization", b"Bearer sk_test")]
    if content_type is not None:
        headers.append((b"content-type", content_type))
    return WireRequest(
        scheme="https",
        authority="api.stripe.com",
        method="POST",
        raw_path=b"/v1/customers",
        decoded_path="/v1/customers",
        raw_query=query,
        headers=tuple(headers),
        body=body,
    )


def test_wire_request_preserves_authority_query_headers_and_body_digest() -> None:
    wire = _request(
        body=b"name=Unmodified+SDK&metadata%5Bteam%5D=eval",
        content_type=b"application/x-www-form-urlencoded",
    )
    request = StandardProviderWireCodec().decode(wire)

    assert request.scheme == "https"
    assert request.authority == "api.stripe.com"
    assert request.path == "/v1/customers"
    assert request.query == {"expand[]": ("customer", "invoice")}
    assert request.body == {"name": "Unmodified SDK", "metadata[team]": "eval"}
    assert request.headers["authorization"] == "Bearer sk_test"
    assert request.raw_body_sha256 == wire.body_sha256


def test_wire_request_keeps_raw_and_asgi_decoded_path_distinct() -> None:
    wire = WireRequest(
        scheme="https",
        authority="api.provider.example",
        method="GET",
        raw_path=b"/records/a%20b",
        decoded_path="/records/a b",
        raw_query=b"",
        headers=((b"host", b"api.provider.example"),),
        body=b"",
    )

    request = StandardProviderWireCodec().decode(wire)

    assert wire.raw_path == b"/records/a%20b"
    assert request.path == "/records/a b"


def test_wire_codec_preserves_duplicate_form_values() -> None:
    request = StandardProviderWireCodec().decode(
        _request(
            body=b"item=first&item=second",
            content_type=b"application/x-www-form-urlencoded",
            query=b"",
        )
    )
    assert request.body == {"item": ["first", "second"]}


def test_wire_codec_rejects_undeclared_binary_instead_of_corrupting_it() -> None:
    with pytest.raises(WireDecodeError, match="No provider wire codec") as error:
        StandardProviderWireCodec().decode(
            _request(body=b"\xff\x00", content_type=b"application/octet-stream")
        )
    assert error.value.status_code == 415
    assert error.value.code == "unsupported_media_type"


def test_wire_response_has_provider_headers_and_no_datalox_headers() -> None:
    response = GateResponse(
        status_code=201,
        body={"id": "cus_123"},
        decision=GateDecision(
            kind="shadow_write",
            reason_code="world_state_write",
            message="state changed",
        ),
        event_id="evt_private",
        response_case_id="case_private",
        headers={"Request-Id": "req_provider"},
    )
    wire = StandardProviderWireCodec().encode(response)

    headers = {name.decode(): value.decode() for name, value in wire.headers}
    assert wire.status_code == 201
    assert json.loads(wire.body) == {"id": "cus_123"}
    assert headers == {
        "request-id": "req_provider",
        "content-type": "application/json",
    }
    assert all(not name.startswith("x-datalox") for name in headers)
