"""Provider tool callback for a consumer-owned Slime agent loop.

Register :func:`get_example_record` with the agent framework already used by
the custom generator. The provider call occurs only when the model invokes the
tool. This module does not read or mutate Slime prompts, samples, or rewards.
"""

from __future__ import annotations

import base64
import json

from datalox_gated_runtime.integrations.slime import current_slime_provider_execution

EXACT_PROVIDER_URL = "https://api.example.com/v1/records/example-record"
RESULT_FIELDS = {
    "schema_version",
    "transport_ok",
    "status_code",
    "headers",
    "body_base64",
    "error",
}


async def get_example_record() -> dict[str, object]:
    """Return the provider observation produced by one model-selected GET."""

    request = json.dumps(
        {
            "method": "GET",
            "url": EXACT_PROVIDER_URL,
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer datalox-simulated-token",
            },
            "body_base64": "",
            "timeout_seconds": 30,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    result = await current_slime_provider_execution().exec(
        ("python3", "/opt/datalox/provider_call.py", request)
    )
    if result.consumer_exit_code != 0:
        raise RuntimeError(f"provider dispatcher failed: {result.stderr.strip()}")
    envelope = json.loads(result.stdout)
    if not isinstance(envelope, dict) or set(envelope) != RESULT_FIELDS:
        raise RuntimeError("provider dispatcher returned an invalid result envelope")
    if envelope["schema_version"] != "datalox_provider_https_result_v1":
        raise RuntimeError("provider dispatcher returned an unsupported result schema")
    if envelope["transport_ok"] is not True:
        raise RuntimeError(f"provider transport failed: {envelope['error']!r}")
    status_code = envelope["status_code"]
    headers = envelope["headers"]
    if (
        not isinstance(status_code, int)
        or isinstance(status_code, bool)
        or not 100 <= status_code <= 599
        or not isinstance(headers, list)
        or any(
            not isinstance(item, list)
            or len(item) != 2
            or any(not isinstance(value, str) for value in item)
            for item in headers
        )
        or envelope["error"] is not None
        or not isinstance(envelope["body_base64"], str)
    ):
        raise RuntimeError("provider dispatcher returned invalid HTTP result fields")

    body_bytes = base64.b64decode(envelope["body_base64"], validate=True)
    body_text = body_bytes.decode("utf-8")
    return {
        "status_code": status_code,
        "headers": headers,
        "body": body_text,
    }
