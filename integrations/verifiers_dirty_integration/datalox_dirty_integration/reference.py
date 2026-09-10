"""Model-free clients used only to calibrate the paired fixture."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from datalox_dirty_integration.contract import (
    TASK_EMAIL,
    TASK_FINAL_QUANTITY,
    TASK_REGION_ID,
)
from datalox_dirty_integration.episode import CommerceEpisode
from datalox_dirty_integration.scoring import (
    EvaluationOracle,
    request_discipline_for_episode,
    task_correctness_for_episode,
)

ReferenceOutcome = Literal[
    "completed", "rate_limited", "attempt_budget_exhausted", "provider_error"
]

#: Address of a cart the task never asked for, used only by the negative below.
SPARE_EMAIL = "someone.else@example.test"


@dataclass(frozen=True)
class ReferenceResult:
    strategy: str
    selected_variant_id: str | None
    cart_id: str | None
    line_item_id: str | None
    task_correctness: float
    request_discipline: float
    outcome: ReferenceOutcome


def run_careful_reference(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
    *,
    attempt_budget: int = 24,
) -> ReferenceResult:
    """Recover from read-side delivery faults using provider observations only."""

    products: dict[str, dict[str, Any]] = {}
    requested_offset = 0
    outcome: ReferenceOutcome = "attempt_budget_exhausted"
    for _ in range(attempt_budget):
        response = episode.list_products(offset=requested_offset, limit=10)
        if response.status_code == 429:
            outcome = "rate_limited"
            break
        page = _require_page(response.status_code, response.body)
        if page["offset"] != requested_offset:
            continue
        for product in page["products"]:
            products[product["id"]] = product
        if not page["products"]:
            outcome = "completed"
            break
        requested_offset += 10

    variant_id = _lowest_variant(products.values())
    cart_id: str | None = None
    line_item_id: str | None = None
    if outcome == "completed" and variant_id is not None:
        cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
        if not writes_ok:
            outcome = "provider_error"
    return ReferenceResult(
        strategy="provider_valid_careful_read_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome=outcome,
    )


def run_naive_reference(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
    *,
    attempt_budget: int = 12,
) -> ReferenceResult:
    """Advance offsets without validating repeated pages."""

    products: dict[str, dict[str, Any]] = {}
    requested_offset = 0
    outcome: ReferenceOutcome = "attempt_budget_exhausted"
    for _ in range(attempt_budget):
        response = episode.list_products(offset=requested_offset, limit=10)
        if response.status_code == 429:
            outcome = "rate_limited"
            break
        page = _require_page(response.status_code, response.body)
        for product in page["products"]:
            products[product["id"]] = product
        if not page["products"]:
            outcome = "completed"
            break
        requested_offset += 10

    variant_id = _lowest_variant(products.values())
    cart_id: str | None = None
    line_item_id: str | None = None
    if variant_id is not None:
        cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
        if not writes_ok:
            outcome = "provider_error"
    return ReferenceResult(
        strategy="naive_offset_read_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome=outcome,
    )


def run_redundant_correct_reference(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Complete the task correctly while making every catalog read twice."""

    products: dict[str, dict[str, Any]] = {}
    requested_offset = 0
    while True:
        first = _require_page_response(episode.list_products(offset=requested_offset, limit=10))
        second = _require_page_response(episode.list_products(offset=requested_offset, limit=10))
        if first != second or first["offset"] != requested_offset:
            raise ValueError("clean redundant calibration received inconsistent pages")
        for product in first["products"]:
            products[product["id"]] = product
        if not first["products"]:
            break
        requested_offset += 10
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("redundant calibration could not select a variant")
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    return ReferenceResult(
        strategy="provider_valid_redundant_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_incomplete_pagination_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Write after one valid page without observing the complete catalog."""

    page = _require_page_response(episode.list_products(offset=0, limit=10))
    variant_id = _lowest_variant(page["products"])
    if variant_id is None:
        raise ValueError("incomplete pagination fixture has no variant")
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    return ReferenceResult(
        strategy="negative_incomplete_pagination_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_invalid_write_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Use the fixture's modeled invalid quantity write and leave incorrect state."""

    products = _complete_clean_catalog(episode)
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("invalid-write calibration could not select a variant")
    created = episode.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID)
    cart = _require_cart(created.status_code, created.body)
    if cart is None or not isinstance(cart.get("id"), str):
        raise ValueError("invalid-write calibration could not create a cart")
    cart_id = cart["id"]
    added = episode.add_line_item(cart_id=cart_id, variant_id=variant_id, quantity=1)
    cart = _require_cart(added.status_code, added.body)
    line_item_id = _line_id(cart, variant_id, quantity=1)
    if line_item_id is None:
        raise ValueError("invalid-write calibration could not add a line item")
    invalid = episode.update_line_item_request(
        cart_id=cart_id,
        line_item_id=line_item_id,
        body={"quantity": "three"},
    )
    if invalid.status_code != 400:
        raise ValueError("modeled invalid quantity write did not return HTTP 400")
    episode.get_cart(cart_id=cart_id)
    return ReferenceResult(
        strategy="negative_invalid_quantity_write_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="provider_error",
    )


def run_mishandled_quota_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Continue to provider writes after a visible quota response."""

    products, quota_index = _scan_until_quota(episode)
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("quota calibration observed no selectable variant")
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    return ReferenceResult(
        strategy=f"negative_write_after_quota_{quota_index}_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_extra_variant_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Complete the task, then leave an unrelated second variant in the cart."""

    products = _complete_clean_catalog(episode)
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("extra-variant calibration could not select a variant")
    other_id = next(
        (
            variant["id"]
            for product in products.values()
            for variant in product.get("variants", [])
            if isinstance(variant, dict)
            and isinstance(variant.get("id"), str)
            and variant["id"] != variant_id
        ),
        None,
    )
    if other_id is None:
        raise ValueError("extra-variant calibration found no second variant")
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    if cart_id is None:
        raise ValueError("extra-variant calibration could not complete the cart")
    episode.add_line_item(cart_id=cart_id, variant_id=other_id, quantity=1)
    episode.get_cart(cart_id=cart_id)
    return ReferenceResult(
        strategy="negative_extra_variant_in_cart_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_wrong_variant_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Read the whole catalog, then buy the most expensive variant instead."""

    products = _complete_clean_catalog(episode)
    highest_id = _highest_variant(products.values())
    cheapest_id = _lowest_variant(products.values())
    if highest_id is None or cheapest_id is None or highest_id == cheapest_id:
        raise ValueError("wrong-variant calibration could not select a distinct variant")
    cart_id, line_item_id, writes_ok = _complete_cart(episode, highest_id)
    return ReferenceResult(
        strategy="negative_wrong_variant_selected_v1",
        selected_variant_id=highest_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_second_cart_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Create the expected cart twice, complete one, and leave both behind."""

    products = _complete_clean_catalog(episode)
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("second-cart calibration could not select a variant")
    episode.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID)
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    return ReferenceResult(
        strategy="negative_second_cart_left_behind_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_unrelated_cart_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Leave an unrelated cart behind while completing the task correctly.

    Only creates whose body matches the task email and region count towards
    the expected cart, so a cart opened for someone else slips past that check
    and shows up as a second cart in the provider's final state.
    """

    products = _complete_clean_catalog(episode)
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("unrelated-cart calibration could not select a variant")
    episode.create_cart(email=SPARE_EMAIL, region_id=TASK_REGION_ID)
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    return ReferenceResult(
        strategy="negative_unrelated_cart_left_behind_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_unconfirmed_write_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Take the write responses as proof and never read the cart back."""

    products = _complete_clean_catalog(episode)
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("unconfirmed-write calibration could not select a variant")
    created = episode.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID)
    cart = _require_cart(created.status_code, created.body)
    if cart is None or not isinstance(cart.get("id"), str):
        raise ValueError("unconfirmed-write calibration could not create a cart")
    cart_id = cart["id"]
    added = episode.add_line_item(cart_id=cart_id, variant_id=variant_id, quantity=1)
    cart = _require_cart(added.status_code, added.body)
    line_item_id = _line_id(cart, variant_id, quantity=1)
    if line_item_id is None:
        raise ValueError("unconfirmed-write calibration could not add a line item")
    episode.update_line_item(
        cart_id=cart_id, line_item_id=line_item_id, quantity=TASK_FINAL_QUANTITY
    )
    return ReferenceResult(
        strategy="negative_unconfirmed_write_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed",
    )


def run_type_credulous_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Stop paginating when the catalog total arrives in an unexpected type.

    The intervention policy can replace the total with a decimal string.
    Treating that as an unreadable total and writing from what is collected
    leaves the catalog incomplete for a different reason than stopping early
    on purpose.
    """

    products: dict[str, Any] = {}
    offset = 0
    while True:
        page = _require_page_response(episode.list_products(offset=offset, limit=10))
        for product in page["products"]:
            products[product["id"]] = product
        if type(page.get("count")) is not int:
            break
        if not page["products"]:
            break
        offset += 10
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("type-credulous calibration observed no selectable variant")
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    return ReferenceResult(
        strategy="negative_unnormalized_count_type_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_credulous_repeat_trajectory(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
) -> ReferenceResult:
    """Treat a repeated page as progress and advance past the page it replaced."""

    products: dict[str, Any] = {}
    offset = 0
    while True:
        page = _require_page_response(episode.list_products(offset=offset, limit=10))
        for product in page["products"]:
            products[product["id"]] = product
        offset += 10  # the delivered offset is never checked
        if not page["products"]:
            break
    variant_id = _lowest_variant(products.values())
    if variant_id is None:
        raise ValueError("credulous-repeat calibration observed no selectable variant")
    cart_id, line_item_id, writes_ok = _complete_cart(episode, variant_id)
    return ReferenceResult(
        strategy="negative_credulous_repeat_v1",
        selected_variant_id=variant_id,
        cart_id=cart_id,
        line_item_id=line_item_id,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome="completed" if writes_ok else "provider_error",
    )


def run_quota_probe(episode: CommerceEpisode) -> dict[str, Any]:
    """Reach the configured quota after validating every delivered page."""

    _, quota_index = _scan_until_quota(episode)
    event = episode.export()["intervention"]["events"][quota_index - 1]
    return {
        "logical_request_index": quota_index,
        "stage": event["stage"],
        "base_invoked": event["base"]["invoked"],
        "status_code": event["delivered"]["response"]["status_code"],
        "decision_kind": event["decision"]["kind"],
        "action": event["decision"]["action"],
        "observation_changed": event["observation_changed"],
    }


def _complete_cart(
    episode: CommerceEpisode, variant_id: str
) -> tuple[str | None, str | None, bool]:
    created = episode.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID)
    cart = _require_cart(created.status_code, created.body)
    if cart is None or not isinstance(cart.get("id"), str):
        return None, None, False
    cart_id = cart["id"]
    added = episode.add_line_item(cart_id=cart_id, variant_id=variant_id, quantity=1)
    cart = _require_cart(added.status_code, added.body)
    line_item_id = _line_id(cart, variant_id, quantity=1)
    if line_item_id is None:
        return cart_id, None, False
    updated = episode.update_line_item(
        cart_id=cart_id,
        line_item_id=line_item_id,
        quantity=TASK_FINAL_QUANTITY,
    )
    cart = _require_cart(updated.status_code, updated.body)
    if _line_id(cart, variant_id, quantity=TASK_FINAL_QUANTITY) != line_item_id:
        return cart_id, line_item_id, False
    retrieved = episode.get_cart(cart_id=cart_id)
    cart = _require_cart(retrieved.status_code, retrieved.body)
    return (
        cart_id,
        line_item_id,
        _line_id(cart, variant_id, quantity=TASK_FINAL_QUANTITY) == line_item_id,
    )


def _complete_clean_catalog(episode: CommerceEpisode) -> dict[str, dict[str, Any]]:
    products: dict[str, dict[str, Any]] = {}
    offset = 0
    while True:
        page = _require_page_response(episode.list_products(offset=offset, limit=10))
        if page["offset"] != offset:
            raise ValueError("clean catalog calibration received a repeated page")
        for product in page["products"]:
            products[product["id"]] = product
        if not page["products"]:
            return products
        offset += 10


def _scan_until_quota(
    episode: CommerceEpisode,
    *,
    attempt_budget: int = 64,
) -> tuple[dict[str, dict[str, Any]], int]:
    products: dict[str, dict[str, Any]] = {}
    requested_offset = 0
    for _ in range(attempt_budget):
        response = episode.list_products(offset=requested_offset, limit=10)
        if response.status_code == 429:
            trace = episode.export()["intervention"]
            return products, trace["events"][-1]["logical_request_index"]
        page = _require_page(response.status_code, response.body)
        if page["offset"] != requested_offset:
            continue
        for product in page["products"]:
            products[product["id"]] = product
        requested_offset = 0 if not page["products"] else requested_offset + 10
    raise ValueError("quota branch was not reached within the declared attempt budget")


def _require_page_response(response: Any) -> dict[str, Any]:
    return _require_page(response.status_code, response.body)


def _lowest_variant(products: Any) -> str | None:
    candidates: list[tuple[int, str]] = []
    for product in products:
        variants = product.get("variants") if isinstance(product, dict) else None
        if not isinstance(variants, list):
            continue
        for variant in variants:
            if not isinstance(variant, dict) or not isinstance(variant.get("id"), str):
                continue
            price = variant.get("calculated_price")
            amount = price.get("calculated_amount") if isinstance(price, dict) else None
            if type(amount) is int:
                candidates.append((amount, variant["id"]))
    return min(candidates)[1] if candidates else None


def _highest_variant(products: Any) -> str | None:
    candidates: list[tuple[int, str]] = []
    for product in products:
        variants = product.get("variants") if isinstance(product, dict) else None
        if not isinstance(variants, list):
            continue
        for variant in variants:
            if not isinstance(variant, dict) or not isinstance(variant.get("id"), str):
                continue
            price = variant.get("calculated_price")
            amount = price.get("calculated_amount") if isinstance(price, dict) else None
            if type(amount) is int:
                candidates.append((amount, variant["id"]))
    return max(candidates)[1] if candidates else None


def _require_page(status_code: int, body: Any) -> dict[str, Any]:
    if status_code != 200 or not isinstance(body, dict):
        raise ValueError(f"unexpected provider response: status={status_code}")
    products = body.get("products")
    offset = body.get("offset")
    if not isinstance(products, list) or type(offset) is not int:
        raise ValueError("provider page requires products array and integer offset")
    for product in products:
        if not isinstance(product, dict) or not isinstance(product.get("id"), str):
            raise TypeError("provider product requires a string id")
    return body


def _require_cart(status_code: int, body: Any) -> dict[str, Any] | None:
    if status_code != 200 or not isinstance(body, dict) or not isinstance(body.get("cart"), dict):
        return None
    return body["cart"]


def _line_id(cart: dict[str, Any] | None, variant_id: str, *, quantity: int) -> str | None:
    if not isinstance(cart, dict) or not isinstance(cart.get("items"), list):
        return None
    matching = [
        item
        for item in cart["items"]
        if isinstance(item, dict)
        and item.get("variant_id") == variant_id
        and item.get("quantity") == quantity
        and isinstance(item.get("id"), str)
    ]
    return matching[0]["id"] if len(matching) == 1 else None
