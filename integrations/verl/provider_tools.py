"""veRL function tool that submits only argv to the current Datalox lease."""

from __future__ import annotations

import base64
import json

from verl.tools.function_tool import function_tool

from datalox_gated_runtime.rollout.verl import current_verl_rollout_execution

# Replace this with an authority declared by the selected provider set.  It is
# still the provider's exact URL; the task container resolves it to Datalox.
EXACT_PROVIDER_URL = "https://api.example.com/v1/records"
RESULT_FIELDS = {
    "schema_version",
    "transport_ok",
    "status_code",
    "headers",
    "body_base64",
    "error",
}


@function_tool("create_provider_record")
async def create_provider_record(record_name: str) -> dict:
    """Create one record through the provider's normal HTTPS API.

    Args:
        record_name: Name of the provider record to create.
    """

    if not record_name or record_name.strip() != record_name:
        raise ValueError("record_name must be a non-empty trimmed string")
    body = json.dumps({"name": record_name}, sort_keys=True, separators=(",", ":")).encode()
    request = json.dumps(
        {
            "method": "POST",
            "url": EXACT_PROVIDER_URL,
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer datalox-simulated-token",
                "Content-Type": "application/json",
            },
            "body_base64": base64.b64encode(body).decode("ascii"),
            "timeout_seconds": 30,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    result = await current_verl_rollout_execution().exec(
        ("python3", "/opt/datalox/provider_call.py", request)
    )
    if result.consumer_exit_code != 0:
        raise RuntimeError(f"provider dispatcher failed: {result.stderr.strip()}")
    envelope = json.loads(result.stdout)
    if not isinstance(envelope, dict) or set(envelope) != RESULT_FIELDS:
        raise RuntimeError("provider dispatcher returned an invalid result envelope")
    return envelope
