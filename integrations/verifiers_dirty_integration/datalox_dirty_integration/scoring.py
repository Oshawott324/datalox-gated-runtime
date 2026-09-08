"""Consumer-owned provider-state and request-discipline rewards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from datalox_dirty_integration.contract import (
    ADD_LINE_ITEM_OPERATION,
    CREATE_CART_OPERATION,
    LIST_PRODUCTS_OPERATION,
    PAGE_SIZE,
    RETRIEVE_CART_OPERATION,
    TASK_EMAIL,
    TASK_FINAL_QUANTITY,
    TASK_REGION_ID,
    UPDATE_LINE_ITEM_OPERATION,
)
from datalox_dirty_integration.episode import CommerceEpisode


@dataclass(frozen=True)
class EvaluationOracle:
    """Task outcome constraints available only to consumer-owned reward code."""

    email: str = TASK_EMAIL
    region_id: str = TASK_REGION_ID
    final_quantity: int = TASK_FINAL_QUANTITY
    page_size: int = PAGE_SIZE


@dataclass(frozen=True)
class VerificationCheck:
    check_id: str
    passed: bool
    evidence: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "passed": self.passed,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class TaskVerificationReport:
    checks: tuple[VerificationCheck, ...]

    @property
    def score(self) -> float:
        return 1.0 if self.checks and all(check.passed for check in self.checks) else 0.0

    @property
    def failed_check_ids(self) -> tuple[str, ...]:
        return tuple(check.check_id for check in self.checks if not check.passed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "passed": self.score == 1.0,
            "failed_check_ids": list(self.failed_check_ids),
            "checks": [check.to_dict() for check in self.checks],
        }


@dataclass(frozen=True)
class RequestDisciplineReport:
    score: float
    minimum_call_count: int | None
    actual_call_count: int
    failed_call_count: int
    efficiency: float
    failure_factor: float
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "minimum_call_count": self.minimum_call_count,
            "actual_call_count": self.actual_call_count,
            "failed_call_count": self.failed_call_count,
            "efficiency": self.efficiency,
            "failure_factor": self.failure_factor,
            "reason_codes": list(self.reason_codes),
        }


def verify_task_for_episode(
    episode: CommerceEpisode, oracle: EvaluationOracle
) -> TaskVerificationReport:
    """Explain every task-correctness decision in controller-only evidence."""

    checks: list[VerificationCheck] = []

    def check(check_id: str, passed: bool, **evidence: Any) -> bool:
        checks.append(VerificationCheck(check_id, passed, evidence))
        return passed

    def report() -> TaskVerificationReport:
        return TaskVerificationReport(tuple(checks))

    exported = episode.provider.export()
    provider_state = exported.get("provider_state")
    if not check(
        "provider_state_available",
        isinstance(provider_state, dict),
        observed_type=type(provider_state).__name__,
    ):
        return report()
    state = provider_state.get("state")
    if not check(
        "provider_state_shape_valid",
        isinstance(state, dict),
        observed_type=type(state).__name__,
    ):
        return report()
    catalog = state.get("catalog")
    catalog_valid = isinstance(catalog, dict) and type(catalog.get("product_count")) is int
    if not check("catalog_metadata_available", catalog_valid):
        return report()
    expected_product_count = catalog["product_count"]

    calls = episode.delivered_calls
    create_indexes = [
        index
        for index, call in enumerate(calls)
        if call.get("operation_id") == CREATE_CART_OPERATION
        and _status(call) == 200
        and _request_body(call) == {"email": oracle.email, "region_id": oracle.region_id}
    ]
    if not check(
        "single_expected_cart_created",
        len(create_indexes) == 1,
        matching_create_count=len(create_indexes),
    ):
        return report()
    create_index = create_indexes[0]

    unresolved_read_failures = [
        index
        for index, call in enumerate(calls[:create_index])
        if call.get("operation_id") == LIST_PRODUCTS_OPERATION
        and (_status(call) is None or not 200 <= _status(call) < 300)
    ]
    if not check(
        "no_write_after_unresolved_read_failure",
        not unresolved_read_failures,
        failed_read_indexes=unresolved_read_failures,
    ):
        return report()

    observed = _complete_catalog_before(
        calls,
        before_index=create_index,
        expected_product_count=expected_product_count,
        page_size=oracle.page_size,
    )
    if not check(
        "complete_catalog_before_write",
        observed is not None,
        expected_product_count=expected_product_count,
        calls_before_create=create_index,
    ):
        return report()
    assert observed is not None
    expected_variant_id = min(observed, key=lambda item: (item[0], item[1]))[1]

    create_cart = _response_cart(calls[create_index])
    cart_id_valid = create_cart is not None and isinstance(create_cart.get("id"), str)
    if not check("provider_cart_id_observed", cart_id_valid):
        return report()
    assert create_cart is not None
    cart_id = create_cart["id"]

    add_matches: list[tuple[int, str]] = []
    for index, call in enumerate(calls[create_index + 1 :], start=create_index + 1):
        if (
            call.get("operation_id") != ADD_LINE_ITEM_OPERATION
            or _status(call) != 200
            or call.get("request", {}).get("path") != f"/store/carts/{cart_id}/line-items"
            or _request_body(call) != {"variant_id": expected_variant_id, "quantity": 1}
        ):
            continue
        response_cart = _response_cart(call)
        line_id = _single_line_id(response_cart, expected_variant_id, quantity=1)
        if line_id is not None:
            add_matches.append((index, line_id))
    if not check(
        "lowest_price_variant_added_once",
        len(add_matches) == 1,
        matching_add_count=len(add_matches),
    ):
        return report()
    add_index, line_item_id = add_matches[0]

    update_indexes = [
        index
        for index, call in enumerate(calls[add_index + 1 :], start=add_index + 1)
        if call.get("operation_id") == UPDATE_LINE_ITEM_OPERATION
        and _status(call) == 200
        and call.get("request", {}).get("path")
        == f"/store/carts/{cart_id}/line-items/{line_item_id}"
        and _request_body(call) == {"quantity": oracle.final_quantity}
        and _single_line_id(
            _response_cart(call), expected_variant_id, quantity=oracle.final_quantity
        )
        == line_item_id
    ]
    if not check(
        "quantity_transition_correct",
        len(update_indexes) == 1,
        matching_update_count=len(update_indexes),
    ):
        return report()
    update_index = update_indexes[0]

    confirmation = next(
        (
            _response_cart(call)
            for call in calls[update_index + 1 :]
            if call.get("operation_id") == RETRIEVE_CART_OPERATION
            and _status(call) == 200
            and call.get("request", {}).get("path") == f"/store/carts/{cart_id}"
        ),
        None,
    )
    confirmation_matches = _cart_matches(
        confirmation,
        cart_id=cart_id,
        email=oracle.email,
        region_id=oracle.region_id,
        line_item_id=line_item_id,
        variant_id=expected_variant_id,
        quantity=oracle.final_quantity,
    )
    if not check("confirmation_read_matches", confirmation_matches):
        return report()

    carts = state.get("carts")
    if not check(
        "single_final_cart",
        isinstance(carts, dict) and set(carts) == {cart_id},
        final_cart_count=len(carts) if isinstance(carts, dict) else None,
    ):
        return report()
    assert isinstance(carts, dict)
    check(
        "final_provider_state_matches",
        _cart_matches(
            carts[cart_id],
            cart_id=cart_id,
            email=oracle.email,
            region_id=oracle.region_id,
            line_item_id=line_item_id,
            variant_id=expected_variant_id,
            quantity=oracle.final_quantity,
        ),
    )
    return report()


def task_correctness_for_episode(episode: CommerceEpisode, oracle: EvaluationOracle) -> float:
    """Project the detailed controller-only verification to Verifiers' scalar API."""

    return verify_task_for_episode(episode, oracle).score


def request_discipline_report_for_episode(
    episode: CommerceEpisode, oracle: EvaluationOracle
) -> RequestDisciplineReport:
    """Return the scalar reward and the exact evidence that produced it."""

    state = episode.provider.export().get("provider_state", {}).get("state", {})
    catalog = state.get("catalog") if isinstance(state, dict) else None
    product_count = catalog.get("product_count") if isinstance(catalog, dict) else None
    if type(product_count) is not int or product_count < 1:
        return RequestDisciplineReport(
            score=0.0,
            minimum_call_count=None,
            actual_call_count=len(episode.delivered_calls),
            failed_call_count=episode.failed_calls,
            efficiency=0.0,
            failure_factor=0.0,
            reason_codes=("provider_catalog_unavailable",),
        )
    minimum_reads = (product_count + oracle.page_size - 1) // oracle.page_size + 1
    minimum_calls = minimum_reads + 4  # create, add, update, retrieve
    calls = len(episode.delivered_calls)
    efficiency = calls / minimum_calls if calls < minimum_calls else minimum_calls / max(calls, 1)
    failure_factor = 1.0 / (1.0 + episode.failed_calls)
    reasons: list[str] = []
    if calls == minimum_calls:
        reasons.append("minimum_call_path")
    elif calls > minimum_calls:
        reasons.append("redundant_calls")
    else:
        reasons.append("fewer_than_complete_path")
    if episode.failed_calls:
        reasons.append("failed_calls")
    return RequestDisciplineReport(
        score=efficiency * failure_factor,
        minimum_call_count=minimum_calls,
        actual_call_count=calls,
        failed_call_count=episode.failed_calls,
        efficiency=efficiency,
        failure_factor=failure_factor,
        reason_codes=tuple(reasons),
    )


def request_discipline_for_episode(episode: CommerceEpisode, oracle: EvaluationOracle) -> float:
    return request_discipline_report_for_episode(episode, oracle).score


def _complete_catalog_before(
    calls: list[dict[str, Any]],
    *,
    before_index: int,
    expected_product_count: int,
    page_size: int,
) -> list[tuple[int, str]] | None:
    variants: dict[str, int] = {}
    product_ids: set[str] = set()
    delivered_offsets: set[int] = set()
    terminal_offsets: set[int] = set()
    for call in calls[:before_index]:
        if call.get("operation_id") != LIST_PRODUCTS_OPERATION or _status(call) != 200:
            continue
        body = call.get("observation", {}).get("body")
        if not isinstance(body, dict):
            return None
        products = body.get("products")
        offset = body.get("offset")
        limit = body.get("limit")
        if not isinstance(products, list) or type(offset) is not int or limit != page_size:
            return None
        delivered_offsets.add(offset)
        if not products:
            terminal_offsets.add(offset)
        for product in products:
            if not isinstance(product, dict) or not isinstance(product.get("id"), str):
                return None
            product_ids.add(product["id"])
            rows = product.get("variants")
            if not isinstance(rows, list) or not rows:
                return None
            for variant in rows:
                if not isinstance(variant, dict) or not isinstance(variant.get("id"), str):
                    return None
                calculated = variant.get("calculated_price")
                amount = (
                    calculated.get("calculated_amount") if isinstance(calculated, dict) else None
                )
                if type(amount) is not int:
                    return None
                previous = variants.get(variant["id"])
                if previous is not None and previous != amount:
                    return None
                variants[variant["id"]] = amount
    expected_offsets = set(range(0, expected_product_count, page_size))
    if len(product_ids) != expected_product_count:
        return None
    if not expected_offsets.issubset(delivered_offsets):
        return None
    if not any(offset >= expected_product_count for offset in terminal_offsets):
        return None
    return [(amount, variant_id) for variant_id, amount in variants.items()]


def _status(call: dict[str, Any]) -> int | None:
    return call.get("observation", {}).get("status_code")


def _request_body(call: dict[str, Any]) -> Any:
    return call.get("request", {}).get("body")


def _response_cart(call: dict[str, Any]) -> dict[str, Any] | None:
    body = call.get("observation", {}).get("body")
    if not isinstance(body, dict) or not isinstance(body.get("cart"), dict):
        return None
    return body["cart"]


def _single_line_id(cart: dict[str, Any] | None, variant_id: str, *, quantity: int) -> str | None:
    if not isinstance(cart, dict) or not isinstance(cart.get("items"), list):
        return None
    items = cart["items"]
    if len(items) != 1 or not isinstance(items[0], dict):
        return None
    line = items[0]
    if line.get("variant_id") != variant_id or line.get("quantity") != quantity:
        return None
    return line.get("id") if isinstance(line.get("id"), str) else None


def _cart_matches(
    cart: Any,
    *,
    cart_id: str,
    email: str,
    region_id: str,
    line_item_id: str,
    variant_id: str,
    quantity: int,
) -> bool:
    if not isinstance(cart, dict):
        return False
    return (
        cart.get("id") == cart_id
        and cart.get("email") == email
        and cart.get("region_id") == region_id
        and _single_line_id(cart, variant_id, quantity=quantity) == line_item_id
    )
