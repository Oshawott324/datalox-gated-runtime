"""Downstream task contract and immutable Medusa provider-release binding."""

from pathlib import Path

PAGE_SIZE = 10
MEDUSA_LOCAL_PUBLISHABLE_KEY = "pk_datalox_local_store"
TASK_EMAIL = "rollout.customer@example.test"
TASK_REGION_ID = "region_datalox_us"
TASK_FINAL_QUANTITY = 3

LIST_PRODUCTS_OPERATION = "medusa.store.products.list"
CREATE_CART_OPERATION = "medusa.store.carts.create"
RETRIEVE_CART_OPERATION = "medusa.store.carts.retrieve"
ADD_LINE_ITEM_OPERATION = "medusa.store.carts.line_items.add"
UPDATE_LINE_ITEM_OPERATION = "medusa.store.carts.line_items.update"
DELETE_LINE_ITEM_OPERATION = "medusa.store.carts.line_items.delete"

TASK_INSTRUCTIONS = f"""\
You are integrating with the Medusa Store API.

Discover the complete product collection with list_products. Successful list
responses contain `products`, `count`, `limit`, and `offset`. Use limit
{PAGE_SIZE}, start at offset 0, and continue until the provider returns an empty
`products` array. Choose the variant with the lowest integer
`calculated_price.calculated_amount` across the complete collection.

Create exactly one cart for `{TASK_EMAIL}` in region `{TASK_REGION_ID}`. Add one
unit of the chosen variant, update that same line item to quantity
{TASK_FINAL_QUANTITY}, and retrieve the cart to confirm the resulting provider
state. Use identifiers returned by provider observations. Finish only after the
retrieved cart reflects the requested email, region, variant, and quantity.
"""


def repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def provider_grounding_path() -> Path:
    return repository_root() / "envs" / "medusa_store_cart_v0" / "evidence" / "observations.json"


def provider_admission_path() -> Path:
    return repository_root() / "envs" / "medusa_store_cart_v0" / "provider-admission.json"


def provider_runtime_bundle_path() -> Path:
    return repository_root() / "envs" / "medusa_store_cart_v0" / "provider-runtime"


def provider_release_path() -> Path:
    return repository_root() / "envs" / "medusa_store_cart_v0" / "provider-release"
