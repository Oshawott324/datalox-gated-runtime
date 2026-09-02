"""Model-free clients used to calibrate the paired fixture."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from datalox_dirty_integration.episode import CommerceEpisode
from datalox_dirty_integration.scoring import (
    EvaluationOracle,
    request_discipline_for_episode,
    task_correctness_for_episode,
)


@dataclass(frozen=True)
class ReferenceResult:
    strategy: str
    submitted: tuple[dict[str, str], ...]
    reported_count: int | str | None
    task_correctness: float
    request_discipline: float
    outcome: Literal["submitted", "rate_limited", "attempt_budget_exhausted"]


def run_careful_reference(
    episode: CommerceEpisode,
    oracle: EvaluationOracle,
    *,
    attempt_budget: int = 24,
) -> ReferenceResult:
    """Recover using only the requested and provider-returned offsets.

    The client never decodes or manufactures a pagination cursor. A response
    with an unexpected offset is treated as a repeated page, and the exact
    provider-supported request is retried.
    """

    rows: dict[str, str] = {}
    requested_offset = 0
    reported_count: int | None = None
    outcome: Literal["submitted", "rate_limited", "attempt_budget_exhausted"] = (
        "attempt_budget_exhausted"
    )
    for _ in range(attempt_budget):
        response = episode.list_products(offset=requested_offset, limit=10)
        if response.status_code == 429:
            outcome = "rate_limited"
            break
        page = _require_page(response.status_code, response.body)
        raw_count = page.get("count")
        if type(raw_count) is int:
            reported_count = raw_count
        elif isinstance(raw_count, str) and raw_count.isdecimal():
            reported_count = int(raw_count)
        else:
            raise ValueError("provider count must be an integer or decimal string")
        if page["offset"] != requested_offset:
            continue
        products = page["products"]
        for product in products:
            rows[product["id"]] = product["title"]
        if not products:
            outcome = "submitted"
            break
        requested_offset += 10

    submitted = tuple({"id": product_id, "title": rows[product_id]} for product_id in sorted(rows))
    if reported_count is None:
        reported_count = -1
    episode.submit_products(json.dumps(submitted), reported_count=reported_count)
    return ReferenceResult(
        strategy="provider_valid_careful_v1",
        submitted=submitted,
        reported_count=reported_count,
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
    rows: list[dict[str, str]] = []
    requested_offset = 0
    reported_count: int | str | None = None
    outcome: Literal["submitted", "rate_limited", "attempt_budget_exhausted"] = (
        "attempt_budget_exhausted"
    )
    for _ in range(attempt_budget):
        response = episode.list_products(offset=requested_offset, limit=10)
        if response.status_code == 429:
            outcome = "rate_limited"
            break
        page = _require_page(response.status_code, response.body)
        if reported_count is None:
            reported_count = page.get("count")
        rows.extend(page["products"])
        if not page["products"]:
            outcome = "submitted"
            break
        requested_offset += 10
    episode.submit_products(json.dumps(rows), reported_count=reported_count)
    return ReferenceResult(
        strategy="naive_offset_v1",
        submitted=tuple(rows),
        reported_count=reported_count,
        task_correctness=task_correctness_for_episode(episode, oracle),
        request_discipline=request_discipline_for_episode(episode, oracle),
        outcome=outcome,
    )


def _require_page(status_code: int, body: Any) -> dict[str, Any]:
    if status_code != 200 or not isinstance(body, dict):
        raise ValueError(f"unexpected provider response: status={status_code}")
    products = body.get("products")
    offset = body.get("offset")
    if not isinstance(products, list) or type(offset) is not int:
        raise ValueError("provider page requires products array and integer offset")
    normalized: list[dict[str, str]] = []
    for product in products:
        if not isinstance(product, dict):
            raise TypeError("provider product must be an object")
        product_id = product.get("id")
        title = product.get("title")
        if not isinstance(product_id, str) or not isinstance(title, str):
            raise TypeError("provider product requires string id and title")
        normalized.append({"id": product_id, "title": title})
    return {**body, "products": normalized, "offset": offset}
