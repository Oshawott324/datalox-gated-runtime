from __future__ import annotations

import hashlib

import pytest

from datalox_gated_runtime.json_digest import canonical_json_bytes, canonical_json_sha256
from datalox_gated_runtime.models import GateDecision, GateResponse
from datalox_gated_runtime.serializer import gate_response_envelope


def test_canonical_json_digest_is_order_stable_and_covers_arrays_null_and_unicode() -> None:
    first = {"z": [1, None, {"文字": "雪"}], "a": "é"}
    second = {"a": "é", "z": [1, None, {"文字": "雪"}]}
    expected_bytes = '{"a":"é","z":[1,null,{"文字":"雪"}]}'.encode()
    expected_digest = f"sha256:{hashlib.sha256(expected_bytes).hexdigest()}"

    assert canonical_json_bytes(first) == expected_bytes
    assert canonical_json_sha256(first) == expected_digest
    assert canonical_json_sha256(second) == expected_digest


@pytest.mark.parametrize(
    "body",
    [
        {"not": {"json"}},
        ("array",),
        {1: "non-string key"},
        b"bytes",
        object(),
        float("nan"),
        float("inf"),
        -float("inf"),
    ],
)
def test_canonical_json_digest_rejects_non_json_and_non_finite_values(body: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        canonical_json_sha256(body)


def test_gate_response_envelope_digests_its_body_snapshot_after_mutation() -> None:
    body = ["雪", None, {"b": 2, "a": [1]}]
    response = GateResponse(
        status_code=200,
        body=body,
        decision=GateDecision(kind="replay", reason_code="matched", message="Matched."),
        event_id="evt_test",
    )

    body[2]["a"].append(3)
    envelope = gate_response_envelope(response)

    assert envelope["body"] == body
    assert envelope["body_sha256"] == canonical_json_sha256(envelope["body"])
