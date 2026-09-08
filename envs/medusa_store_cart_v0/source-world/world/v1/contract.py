from __future__ import annotations

from typing import Any


WORLD_ID = "medusa_store_cart_v0"
DEFAULT_ROLE = "store_operator"
AUTHORITY = "api.medusa.local"
REGION_ID = "region_datalox_us"
PUBLISHABLE_KEY = "pk_datalox_local_store"

LIST_PRODUCTS = "medusa.store.products.list"
CREATE_CART = "medusa.store.carts.create"
RETRIEVE_CART = "medusa.store.carts.retrieve"
ADD_LINE_ITEM = "medusa.store.carts.line_items.add"
UPDATE_LINE_ITEM = "medusa.store.carts.line_items.update"
DELETE_LINE_ITEM = "medusa.store.carts.line_items.delete"


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
POSITIVE_INTEGER = {"type": "integer", "minimum": 1}

TOOLS = (
    {
        "id": LIST_PRODUCTS,
        "description": "List products through Medusa Store API limit/offset pagination.",
        "input_schema": schema(
            {
                "limit": {"type": "integer", "minimum": 0, "maximum": 100},
                "offset": {"type": "integer", "minimum": 0},
            }
        ),
        "operation_family": "catalog",
    },
    {
        "id": CREATE_CART,
        "description": "Create a Medusa Store cart.",
        "input_schema": schema({"email": STRING, "region_id": STRING}, ("region_id",)),
        "operation_family": "cart_lifecycle",
    },
    {
        "id": RETRIEVE_CART,
        "description": "Retrieve a Medusa Store cart by its provider-issued id.",
        "input_schema": schema({"cart_id": STRING}, ("cart_id",)),
        "operation_family": "cart_lifecycle",
    },
    {
        "id": ADD_LINE_ITEM,
        "description": "Add a provider-issued product variant to a Medusa Store cart.",
        "input_schema": schema(
            {"cart_id": STRING, "variant_id": STRING, "quantity": POSITIVE_INTEGER},
            ("cart_id", "variant_id", "quantity"),
        ),
        "operation_family": "cart_line_items",
    },
    {
        "id": UPDATE_LINE_ITEM,
        "description": "Set a Medusa Store cart line item's quantity; zero removes it.",
        "input_schema": schema(
            {
                "cart_id": STRING,
                "line_item_id": STRING,
                "quantity": {"type": "integer", "minimum": 0},
            },
            ("cart_id", "line_item_id", "quantity"),
        ),
        "operation_family": "cart_line_items",
    },
    {
        "id": DELETE_LINE_ITEM,
        "description": "Delete a Medusa Store cart line item.",
        "input_schema": schema(
            {"cart_id": STRING, "line_item_id": STRING}, ("cart_id", "line_item_id")
        ),
        "operation_family": "cart_line_items",
    },
)

TOOLS_BY_ID = {item["id"]: item for item in TOOLS}
WRITE_OPERATIONS = frozenset({CREATE_CART, ADD_LINE_ITEM, UPDATE_LINE_ITEM, DELETE_LINE_ITEM})
REWARD_ATOMS = ("cart_created", "line_item_quantity_set", "no_denied_operations")


def tool_declaration(item: dict[str, Any]) -> dict[str, Any]:
    return {
        **item,
        "list_roles": [DEFAULT_ROLE],
        "invoke_roles": [DEFAULT_ROLE],
        "source_refs": ["medusa_2_16_0_store_cart_g2"],
    }
