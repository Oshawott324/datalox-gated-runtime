"""Consumer-owned task and request-discipline rewards."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from datalox_dirty_integration.episode import CommerceEpisode


@dataclass(frozen=True)
class EvaluationOracle:
    """Ground truth available only to consumer-owned reward code."""

    products: tuple[dict[str, str], ...]
    reported_count: int
    minimum_provider_calls: int

    @classmethod
    def from_provider_config(cls, provider_config: Path) -> EvaluationOracle:
        raw = json.loads(provider_config.read_text(encoding="utf-8"))
        products: dict[str, str] = {}
        offsets: set[int] = set()
        reported_counts: set[int] = set()
        for case in raw.get("response_cases", []):
            if case.get("method") != "GET" or case.get("path") != "/store/products":
                continue
            body = case.get("body")
            if not isinstance(body, dict):
                continue
            offset = body.get("offset")
            count = body.get("count")
            rows = body.get("products")
            if type(offset) is int:
                offsets.add(offset)
            if type(count) is int:
                reported_counts.add(count)
            if not isinstance(rows, list):
                continue
            for row in rows:
                if not isinstance(row, dict):
                    raise TypeError("provider product must be an object")
                product_id = row.get("id")
                title = row.get("title")
                if not isinstance(product_id, str) or not isinstance(title, str):
                    raise TypeError("provider product requires string id and title")
                if product_id in products and products[product_id] != title:
                    raise ValueError(f"conflicting product fixture for {product_id!r}")
                products[product_id] = title
        if not products or len(reported_counts) != 1:
            raise ValueError("provider config has incomplete product evaluation truth")
        expected_offsets = set(range(0, next(iter(reported_counts)) + 1, 10))
        if not expected_offsets.issubset(offsets):
            raise ValueError("provider config must include every page and the terminal empty page")
        return cls(
            products=tuple(
                {"id": product_id, "title": products[product_id]} for product_id in sorted(products)
            ),
            reported_count=next(iter(reported_counts)),
            minimum_provider_calls=len(expected_offsets),
        )


def task_correctness_for_episode(episode: CommerceEpisode, oracle: EvaluationOracle) -> float:
    truth = {row["id"]: row["title"] for row in oracle.products}
    submission = episode.submitted
    if not isinstance(submission, dict):
        return 0.0
    raw = submission.get("products")
    if not isinstance(raw, list) or not raw:
        return 0.0
    submitted: list[tuple[str, str]] = []
    for row in raw:
        if not isinstance(row, Mapping):
            continue
        product_id = row.get("id")
        title = row.get("title")
        if isinstance(product_id, str) and isinstance(title, str):
            submitted.append((product_id, title))
    if not submitted:
        return 0.0
    submitted_set = set(submitted)
    truth_set = set(truth.items())
    union = truth_set | submitted_set
    duplicate_penalty = (len(submitted) - len(submitted_set)) / len(submitted)
    product_score = max(0.0, len(truth_set & submitted_set) / len(union) - duplicate_penalty)
    count_score = float(submission.get("reported_count") == oracle.reported_count)
    return 0.8 * product_score + 0.2 * count_score


def request_discipline_for_episode(episode: CommerceEpisode, oracle: EvaluationOracle) -> float:
    calls = len(episode.delivered_calls)
    efficiency = min(1.0, oracle.minimum_provider_calls / max(calls, 1))
    return efficiency / (1.0 + episode.rate_limited_calls)
