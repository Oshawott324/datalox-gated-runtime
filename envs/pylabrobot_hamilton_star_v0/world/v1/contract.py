from __future__ import annotations

from typing import Any


WORLD_ID = "pylabrobot_hamilton_star_v0"
DEFAULT_ROLE = "lab_operator"
ROLES = (
    {
        "id": "lab_operator",
        "description": "Operates the standard eight-channel Hamilton STAR dry-run backend.",
    },
    {
        "id": "auditor",
        "description": "Reads isolated Hamilton STAR lifecycle, tip, and liquid state.",
    },
)
ROLE_IDS = tuple(item["id"] for item in ROLES)


def schema(properties: dict[str, Any], required: tuple[str, ...] = ()) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        result["required"] = list(required)
    return result


STRING = {"type": "string", "minLength": 1}
NONNEGATIVE = {"type": "number", "minimum": 0}
POSITIVE = {"type": "number", "exclusiveMinimum": 0}
OFFSET = schema(
    {"x": {"type": "number"}, "y": {"type": "number"}, "z": {"type": "number"}},
    ("x", "y", "z"),
)
TIP_SPOT = schema(
    {
        "name": STRING,
        "has_tip": {"type": "boolean"},
        "max_volume_ul": {"type": ["number", "null"], "exclusiveMinimum": 0},
    },
    ("name", "has_tip", "max_volume_ul"),
)
CONTAINER = schema(
    {"name": STRING, "volume_ul": NONNEGATIVE, "max_volume_ul": POSITIVE},
    ("name", "volume_ul", "max_volume_ul"),
)
SETUP = schema(
    {
        "num_channels": {"type": "integer", "const": 8},
        "tip_spots": {"type": "array", "items": TIP_SPOT},
        "containers": {"type": "array", "items": CONTAINER},
        "waste_names": {"type": "array", "items": STRING},
    },
    ("num_channels", "tip_spots", "containers", "waste_names"),
)
PICKUP = schema(
    {
        "channel": {"type": "integer", "minimum": 0, "maximum": 7},
        "tip_spot": STRING,
        "offset": OFFSET,
    },
    ("channel", "tip_spot", "offset"),
)
DROP = schema(
    {
        "channel": {"type": "integer", "minimum": 0, "maximum": 7},
        "destination": STRING,
        "destination_kind": {"type": "string", "enum": ["tip_spot", "waste"]},
        "offset": OFFSET,
    },
    ("channel", "destination", "destination_kind", "offset"),
)
LIQUID = schema(
    {
        "channel": {"type": "integer", "minimum": 0, "maximum": 7},
        "container": STRING,
        "volume_ul": POSITIVE,
        "flow_rate": {"type": ["number", "null"], "exclusiveMinimum": 0},
        "liquid_height": {"type": ["number", "null"]},
        "blow_out_air_volume": {"type": ["number", "null"], "minimum": 0},
        "offset": OFFSET,
    },
    ("channel", "container", "volume_ul", "flow_rate", "liquid_height", "blow_out_air_volume", "offset"),
)


def command(items: dict[str, Any]) -> dict[str, Any]:
    return schema(
        {"operations": {"type": "array", "minItems": 1, "maxItems": 8, "items": items}},
        ("operations",),
    )


ROUTES: dict[str, tuple[str, str, str, dict[str, Any]]] = {
    "system.get": ("GET", "/v1/liquid-handler", "lifecycle", schema({})),
    "system.setup": ("POST", "/v1/liquid-handler/setup", "lifecycle", SETUP),
    "system.stop": ("POST", "/v1/liquid-handler/stop", "lifecycle", schema({})),
    "tips.get": ("GET", "/v1/liquid-handler/tips", "tip_handling", schema({})),
    "tips.pick_up": (
        "POST",
        "/v1/liquid-handler/commands/pick-up-tips",
        "tip_handling",
        command(PICKUP),
    ),
    "tips.drop": (
        "POST",
        "/v1/liquid-handler/commands/drop-tips",
        "tip_handling",
        command(DROP),
    ),
    "liquids.get": ("GET", "/v1/liquid-handler/liquids", "liquid_handling", schema({})),
    "liquids.aspirate": (
        "POST",
        "/v1/liquid-handler/commands/aspirate",
        "liquid_handling",
        command(LIQUID),
    ),
    "liquids.dispense": (
        "POST",
        "/v1/liquid-handler/commands/dispense",
        "liquid_handling",
        command(LIQUID),
    ),
}
WRITE_OPERATIONS = frozenset(
    {
        "system.setup",
        "system.stop",
        "tips.pick_up",
        "tips.drop",
        "liquids.aspirate",
        "liquids.dispense",
    }
)
OBSERVED_OPERATIONS = WRITE_OPERATIONS
REWARD_ATOMS = (
    "transfer_completed",
    "tip_returned",
    "handler_stopped",
    "all_operations_exercised",
    "no_denied_operations",
)


def tool(
    tool_id: str,
    method: str,
    path: str,
    family: str,
    input_schema: dict[str, Any],
) -> dict[str, Any]:
    sources = ["pylabrobot_0_2_1_official"]
    if tool_id in OBSERVED_OPERATIONS:
        sources.append("pylabrobot_chatterbox_reference_20260810")
    return {
        "id": tool_id,
        "description": f"{method} {path} against isolated PyLabRobot-backed Hamilton STAR state.",
        "input_schema": input_schema,
        "list_roles": list(ROLE_IDS),
        "invoke_roles": ["lab_operator"] if tool_id in WRITE_OPERATIONS else list(ROLE_IDS),
        "operation_family": family,
        "source_refs": sources,
    }


TOOLS = tuple(
    tool(tool_id, method, path, family, input_schema)
    for tool_id, (method, path, family, input_schema) in ROUTES.items()
)
TOOLS_BY_ID = {item["id"]: item for item in TOOLS}
