"""Exact token-spend admission for one native Verifiers Responses rollout.

This controller covers model-token charges only, for the pinned short-context
Sol/default lane. It counts the exact request before reserving its maximum cost.
Provider functions and the native model loop remain unchanged.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import tempfile
from copy import deepcopy
from datetime import UTC, date, datetime
from fractions import Fraction
from pathlib import Path
from typing import Any

from verifiers.legacy.clients.openai_responses_client import OpenAIResponsesClient

MODEL = "gpt-5.6-sol"
MAX_INPUT_TOKENS = 272_000
RATES = {"input": "4", "cached_input": "0.4", "cache_write": "5", "output": "20"}
SCHEMA = "datalox_repeat_token_budget_v1"
AUTHORITY = "https://api.openai.com/v1"
PRICING_VERIFIED_AT = "2026-09-12"
PRICING_SOURCE = "https://developers.openai.com/api/docs/pricing"
PRICING_VALID_THROUGH = "2026-11-21"


def _utc_today() -> date:
    return datetime.now(UTC).date()


class TokenBudgetError(RuntimeError):
    """The request cannot enter the admitted token-spend lane."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise TokenBudgetError(reason)


def _json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_json(value).encode()).hexdigest()


def _money(value: Any) -> Fraction:
    _require(type(value) in (str, int, float, Fraction), "invalid_money")
    try:
        amount = value if isinstance(value, Fraction) else Fraction(str(value))
    except (ValueError, ZeroDivisionError, OverflowError) as error:
        raise TokenBudgetError("invalid_money") from error
    _require(amount >= 0, "invalid_money")
    return amount


def _tokens(value: Any, label: str) -> int:
    _require(type(value) is int and value >= 0, f"invalid_{label}_tokens")
    return value


def _field(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, dict) else getattr(value, key, None)


def _raw(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        result = deepcopy(value)
    elif hasattr(value, "model_dump"):
        result = value.model_dump(mode="json", exclude_none=True)
    else:
        raise TokenBudgetError("missing_raw_usage")
    _require(isinstance(result, dict), "invalid_raw_usage")
    _json(result)
    return result


def _reservation(input_tokens: int, output_tokens: int) -> Fraction:
    return Fraction(input_tokens * 5 + output_tokens * 20, 1_000_000)


def _actual(usage: dict[str, Any], held: dict[str, Any]) -> Fraction:
    inputs = _tokens(usage.get("input_tokens"), "input")
    outputs = _tokens(usage.get("output_tokens"), "output")
    total = _tokens(usage.get("total_tokens"), "total")
    _require(total == inputs + outputs, "usage_total_mismatch")
    _require(inputs <= held["input_tokens"] <= MAX_INPUT_TOKENS, "input_count_exceeded")
    _require(outputs <= held["max_output_tokens"], "output_limit_exceeded")
    details = usage.get("input_tokens_details")
    _require(isinstance(details, dict), "missing_input_token_details")
    cached = _tokens(details.get("cached_tokens"), "cached")
    written = _tokens(details.get("cache_write_tokens"), "cache_write")
    _require(cached + written <= inputs, "cache_token_overlap")
    output_details = usage.get("output_tokens_details")
    if output_details is not None:
        _require(isinstance(output_details, dict), "invalid_output_token_details")
        if "reasoning_tokens" in output_details:
            reasoning = _tokens(output_details["reasoning_tokens"], "reasoning")
            _require(reasoning <= outputs, "reasoning_token_overlap")
    return (
        Fraction((inputs - cached - written) * 4 + written * 5 + outputs * 20)
        + cached * Fraction("0.4")
    ) / 1_000_000


def audit_budget(ledger: dict[str, Any]) -> dict[str, Any]:
    """Recompute the ledger; evidence consumers bind settled IDs to native outputs."""
    _require(isinstance(ledger, dict), "invalid_budget_ledger")
    for name, expected in {
        "schema_version": SCHEMA,
        "model": MODEL,
        "service_tier": "default",
        "rates_usd_per_million": RATES,
        "max_input_tokens": MAX_INPUT_TOKENS,
        "authority": AUTHORITY,
        "pricing_verified_at": PRICING_VERIFIED_AT,
        "pricing_source": PRICING_SOURCE,
        "pricing_valid_through": PRICING_VALID_THROUGH,
    }.items():
        _require(_json(ledger.get(name)) == _json(expected), f"budget_{name}_mismatch")
    limit = _money(ledger.get("limit_usd"))
    _require(limit > 0, "budget_must_be_positive")
    spent = Fraction()
    holds: dict[int, dict[str, Any]] = {}
    blocked = False
    events = ledger.get("events")
    _require(isinstance(events, list), "invalid_budget_events")
    settled = []
    for sequence, event in enumerate(events, 1):
        _require(
            isinstance(event, dict)
            and type(event.get("sequence")) is int
            and event["sequence"] == sequence,
            "budget_sequence_mismatch",
        )
        kind = event.get("kind")
        if kind == "reserved":
            _require(not blocked and not holds, "reservation_after_block_or_inflight")
            count = _tokens(event.get("input_tokens"), "counted_input")
            maximum = _tokens(event.get("max_output_tokens"), "maximum_output")
            _require(count <= MAX_INPUT_TOKENS and 16 <= maximum <= 128_000, "request_token_bound")
            _require(
                isinstance(event.get("request_sha256"), str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", event["request_sha256"]) is not None,
                "invalid_request_digest",
            )
            _require(isinstance(event.get("counted_on"), str), "missing_count_date")
            try:
                counted_on = date.fromisoformat(event["counted_on"])
            except ValueError as error:
                raise TokenBudgetError("invalid_count_date") from error
            _require(
                date.fromisoformat(PRICING_VERIFIED_AT)
                <= counted_on
                <= date.fromisoformat(PRICING_VALID_THROUGH),
                "expired_rate_card",
            )
            cost = _reservation(count, maximum)
            _require(
                _money(event.get("hold_usd")) == cost and spent + cost <= limit,
                "invalid_budget_reservation",
            )
            holds[sequence] = event
        elif kind == "settled":
            _require(not blocked, "settlement_after_block")
            _require(type(event.get("request_sequence")) is int, "invalid_request_sequence")
            held = holds.get(event.get("request_sequence"))
            _require(held is not None, "unknown_reservation")
            _require(
                event.get("request_sha256") == held["request_sha256"], "settlement_request_mismatch"
            )
            _require(
                event.get("model") == MODEL and event.get("service_tier") == "default",
                "settlement_model_or_tier_mismatch",
            )
            _require(
                event.get("status") in {"completed", "incomplete"}, "settlement_status_mismatch"
            )
            _require(
                isinstance(event.get("response_id"), str) and bool(event["response_id"]),
                "missing_response_identity",
            )
            actual = _actual(event["usage"], held)
            _require(
                actual == _money(event.get("actual_cost_usd"))
                and actual <= _money(held["hold_usd"]),
                "settlement_cost_mismatch",
            )
            spent += actual
            del holds[event["request_sequence"]]
            settled.append(event)
        elif kind == "blocked":
            _require(
                isinstance(event.get("reason_code"), str) and bool(event["reason_code"]),
                "missing_block_reason",
            )
            blocked = True
        else:
            raise TokenBudgetError("invalid_budget_event_kind")
    pending = sum((_money(event["hold_usd"]) for event in holds.values()), Fraction())
    _require(
        type(ledger.get("blocked")) is bool and ledger["blocked"] is blocked,
        "blocked_state_mismatch",
    )
    _require(
        _money(ledger.get("spent_usd")) == spent
        and _money(ledger.get("held_usd")) == pending
        and spent + pending <= limit,
        "budget_total_mismatch",
    )
    _require(not holds or blocked, "unresolved_live_reservation")
    return {
        "passed": True,
        "spent_usd": str(spent),
        "held_usd": str(pending),
        "limit_usd": str(limit),
        "blocked": blocked,
        "settled_requests": deepcopy(settled),
        "settled_count": len(settled),
    }


class BudgetedOpenAIResponsesClient(OpenAIResponsesClient):
    """Native Responses client with an exact, durable, per-slot spending guard."""

    def __init__(self, client_or_config: Any, *, budget_usd: Any, ledger_path: Path) -> None:
        limit = _money(budget_usd)
        _require(limit > 0, "budget_must_be_positive")
        self.ledger_path = Path(ledger_path)
        self.ledger = {
            "schema_version": SCHEMA,
            "model": MODEL,
            "service_tier": "default",
            "rates_usd_per_million": dict(RATES),
            "max_input_tokens": MAX_INPUT_TOKENS,
            "authority": AUTHORITY,
            "pricing_verified_at": PRICING_VERIFIED_AT,
            "pricing_source": PRICING_SOURCE,
            "pricing_valid_through": PRICING_VALID_THROUGH,
            "limit_usd": str(limit),
            "spent_usd": "0",
            "held_usd": "0",
            "blocked": False,
            "events": [],
        }
        self._active = False
        descriptor = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(_json(self.ledger) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        super().__init__(client_or_config)
        _require(
            type(self.client.max_retries) is int and self.client.max_retries == 0,
            "budget_requires_zero_sdk_retries",
        )
        _require(str(self.client.base_url).rstrip("/") == AUTHORITY, "unsupported_budget_authority")

    def _save(self) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".budget-", dir=self.ledger_path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(_json(self.ledger) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.ledger_path)
            directory = os.open(self.ledger_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _event(self, kind: str, **fields: Any) -> None:
        self.ledger["events"].append(
            {"sequence": len(self.ledger["events"]) + 1, "kind": kind, **fields}
        )

    def _block(self, reason: str, request_sha256: str | None) -> None:
        self.ledger["blocked"] = True
        self._event("blocked", reason_code=reason, request_sha256=request_sha256)
        self._save()

    async def get_native_response(
        self,
        prompt: Any,
        model: str,
        sampling_args: dict[str, Any],
        tools: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> Any:
        _require(not self.ledger["blocked"], "slot_budget_blocked")
        _require(not self._active, "concurrent_model_request_forbidden")
        self._active = True
        request_sha256 = None
        try:
            _require(model == MODEL, "unsupported_budget_model")
            counted_on = _utc_today()
            _require(
                date.fromisoformat(PRICING_VERIFIED_AT)
                <= counted_on
                <= date.fromisoformat(PRICING_VALID_THROUGH),
                "expired_rate_card",
            )
            _require(
                type(self.client.max_retries) is int and self.client.max_retries == 0,
                "budget_requires_zero_sdk_retries",
            )
            _require(
                str(self.client.base_url).rstrip("/") == AUTHORITY, "unsupported_budget_authority"
            )
            _require(
                set(kwargs) <= {"state", "extra_headers"}
                and kwargs.get("extra_headers") in (None, {}),
                "unsupported_request_kwargs",
            )
            allowed = {
                "n",
                "extra_body",
                "reasoning",
                "max_output_tokens",
                "parallel_tool_calls",
                "store",
                "include",
                "service_tier",
                "temperature",
            }
            _require(
                isinstance(sampling_args, dict) and set(sampling_args) <= allowed,
                "unsupported_sampling_fields",
            )
            _require(
                type(sampling_args.get("n", 1)) is int
                and sampling_args.get("n", 1) == 1
                and sampling_args.get("extra_body", {}) == {},
                "unsupported_native_defaults",
            )
            if "temperature" in sampling_args:
                temperature = sampling_args["temperature"]
                _require(
                    type(temperature) in (int, float)
                    and math.isfinite(temperature)
                    and 0 <= temperature <= 2,
                    "invalid_temperature",
                )
            _require(
                sampling_args.get("service_tier") == "default"
                and sampling_args.get("store") is False
                and sampling_args.get("parallel_tool_calls") is False
                and sampling_args.get("include") == ["reasoning.encrypted_content"],
                "unsupported_responses_controls",
            )
            reasoning = sampling_args.get("reasoning")
            _require(
                isinstance(reasoning, dict)
                and set(reasoning) == {"effort"}
                and reasoning["effort"] in {"none", "low", "medium", "high", "xhigh", "max"},
                "unsupported_reasoning_controls",
            )
            maximum = _tokens(sampling_args.get("max_output_tokens"), "maximum_output")
            _require(16 <= maximum <= 128_000, "output_token_bound")
            _require(isinstance(prompt, list) and bool(prompt), "unsupported_prompt")
            for item in prompt:
                _require(
                    isinstance(item, dict)
                    and item.get("type")
                    in {"message", "function_call", "function_call_output", "reasoning"},
                    "unsupported_input_item",
                )
                if item["type"] == "message":
                    content = item.get("content")
                    _require(
                        isinstance(content, str)
                        or (
                            isinstance(content, list)
                            and all(
                                isinstance(part, dict)
                                and part.get("type") in {"input_text", "output_text"}
                                for part in content
                            )
                        ),
                        "nontext_input_outside_budget",
                    )
                if item["type"] == "function_call_output":
                    _require(
                        isinstance(item.get("output"), str), "nontext_tool_output_outside_budget"
                    )
            _require(
                tools is None
                or (
                    isinstance(tools, list)
                    and all(
                        isinstance(tool, dict) and tool.get("type") == "function" for tool in tools
                    )
                ),
                "hosted_tools_outside_budget",
            )
            frozen_prompt = deepcopy(prompt)
            frozen_tools = deepcopy(tools)
            frozen_sampling = deepcopy(sampling_args)
            frozen_kwargs = dict(kwargs)
            if "extra_headers" in frozen_kwargs:
                frozen_kwargs["extra_headers"] = deepcopy(frozen_kwargs["extra_headers"])
            # Count exactly the supported input-bearing fields used by native VF.
            count_request = {
                "model": model,
                "input": frozen_prompt,
                "reasoning": deepcopy(reasoning),
                "parallel_tool_calls": False,
            }
            if frozen_tools:
                count_request["tools"] = frozen_tools
            request_sha256 = _digest({**count_request, "sampling_args": frozen_sampling})
            count_response = await self.client.responses.input_tokens.count(**count_request)
            _require(
                _field(count_response, "object") == "response.input_tokens",
                "invalid_count_response",
            )
            count = _tokens(_field(count_response, "input_tokens"), "counted_input")
            _require(count <= MAX_INPUT_TOKENS, "long_context_outside_budget")
            hold = _reservation(count, maximum)
            _require(
                _money(self.ledger["spent_usd"]) + hold <= _money(self.ledger["limit_usd"]),
                "slot_budget_exhausted",
            )
            self.ledger["held_usd"] = str(hold)
            self._event(
                "reserved",
                request_sha256=request_sha256,
                input_tokens=count,
                max_output_tokens=maximum,
                hold_usd=str(hold),
                counted_on=counted_on.isoformat(),
            )
            held = self.ledger["events"][-1]
            self._save()  # The charge hold is durable before generation dispatch.
            response = await super().get_native_response(
                frozen_prompt, model, frozen_sampling, frozen_tools, **frozen_kwargs
            )
            _require(_field(response, "model") == MODEL, "unexpected_response_model")
            _require(_field(response, "service_tier") == "default", "unexpected_response_tier")
            status = _field(response, "status")
            _require(status in {"completed", "incomplete"}, "unexpected_response_status")
            response_id = _field(response, "id")
            _require(
                isinstance(response_id, str) and bool(response_id), "missing_response_identity"
            )
            usage = _raw(_field(response, "usage"))
            actual = _actual(usage, held)
            _require(actual <= hold, "actual_charge_exceeds_hold")
            self.ledger["spent_usd"] = str(_money(self.ledger["spent_usd"]) + actual)
            self.ledger["held_usd"] = "0"
            self._event(
                "settled",
                request_sequence=held["sequence"],
                request_sha256=request_sha256,
                response_id=response_id,
                model=MODEL,
                service_tier="default",
                status=status,
                usage=usage,
                actual_cost_usd=str(actual),
            )
            self._save()
            return response
        except BaseException as error:
            reason = str(error) if isinstance(error, TokenBudgetError) else type(error).__name__
            self._block(reason, request_sha256)
            raise
        finally:
            self._active = False
