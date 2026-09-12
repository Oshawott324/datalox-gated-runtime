"""Exact per-slot accounting tests with a model-free, credential-free client."""

from __future__ import annotations

import asyncio
import importlib
import json
import stat
import sys
from copy import deepcopy
from datetime import date
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("verifiers")
sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "integrations" / "verifiers_dirty_integration")
)
budget = importlib.import_module("datalox_dirty_integration.repeat_budget")


def _sampling():
    return {
        "n": 1,
        "extra_body": {},
        "reasoning": {"effort": "medium"},
        "max_output_tokens": 1024,
        "parallel_tool_calls": False,
        "store": False,
        "include": ["reasoning.encrypted_content"],
        "service_tier": "default",
    }


def _prompt():
    return [{"type": "message", "role": "user", "content": "Use the provider tools."}]


def _tools():
    return [
        {
            "type": "function",
            "name": "list_products",
            "description": "Read a page.",
            "parameters": {"type": "object", "properties": {"offset": {"type": "integer"}}},
        }
    ]


def _response(**changes):
    response = SimpleNamespace(
        id="resp-test",
        model="gpt-5.6-sol",
        service_tier="default",
        status="completed",
        usage={
            "input_tokens": 1200,
            "output_tokens": 200,
            "total_tokens": 1400,
            "input_tokens_details": {"cached_tokens": 400, "cache_write_tokens": 500},
            "output_tokens_details": {"reasoning_tokens": 123},
        },
        output=[{"type": "message", "content": [{"type": "output_text", "text": "Test only"}]}],
    )
    for key, value in changes.items():
        setattr(response, key, value)
    return response


class FakeAPI:
    max_retries = 0
    base_url = "https://api.openai.com/v1/"

    def __init__(self, *, response=None, count=1200, failure=None, after_count=None):
        self.response = _response() if response is None else response
        self.count_value = count
        self.failure = failure
        self.after_count = after_count
        self.counts = []
        self.generations = []
        self.count_input_ids = []
        self.create_input_ids = []
        self.ledger_path = None
        self.responses = SimpleNamespace(
            input_tokens=SimpleNamespace(count=self.count), create=self.create
        )

    async def count(self, **kwargs):
        self.counts.append(deepcopy(kwargs))
        self.count_input_ids.append(id(kwargs["input"]))
        if self.after_count:
            self.after_count()
        return SimpleNamespace(object="response.input_tokens", input_tokens=self.count_value)

    async def create(self, **kwargs):
        self.generations.append(deepcopy(kwargs))
        self.create_input_ids.append(id(kwargs["input"]))
        if self.ledger_path:
            persisted = json.loads(self.ledger_path.read_text())
            assert Fraction(persisted["held_usd"]) > 0
            assert persisted["events"][-1]["kind"] == "reserved"
            assert stat.S_IMODE(self.ledger_path.stat().st_mode) == 0o600
        if self.failure:
            raise self.failure
        return self.response


@pytest.fixture(autouse=True)
def rate_card_day(monkeypatch):
    monkeypatch.setattr(budget, "_utc_today", lambda: date(2026, 9, 12))


def _client(tmp_path, api=None, cap="0.10"):
    api = FakeAPI() if api is None else api
    path = tmp_path / "budget.json"
    api.ledger_path = path
    client = budget.BudgetedOpenAIResponsesClient(api, budget_usd=cap, ledger_path=path)
    return client, api, path


def _run(client, *, prompt=None, sampling=None, tools=None, **kwargs):
    return asyncio.run(
        client.get_native_response(
            _prompt() if prompt is None else prompt,
            "gpt-5.6-sol",
            _sampling() if sampling is None else sampling,
            _tools() if tools is None else tools,
            **kwargs,
        )
    )


def test_exact_count_reserve_and_settle_preserve_native_response(tmp_path):
    client, api, path = _client(tmp_path)
    response = _run(client, state={"controller_only": "never count or send"})
    assert response is api.response
    for key in ("model", "input", "tools", "reasoning", "parallel_tool_calls"):
        assert api.counts[0][key] == api.generations[0][key]
    assert api.count_input_ids == api.create_input_ids
    assert "state" not in api.counts[0] and "state" not in api.generations[0]
    for key in ("max_output_tokens", "store", "include", "service_tier"):
        assert key not in api.counts[0]
    ledger = json.loads(path.read_text())
    audit = budget.audit_budget(ledger)
    assert Fraction(audit["spent_usd"]) == Fraction("0.00786")
    assert audit["held_usd"] == "0" and audit["blocked"] is False
    assert audit["settled_count"] == 1
    assert ledger["events"][1]["usage"] == api.response.usage
    assert "controller_only" not in path.read_text()


def test_remaining_budget_blocks_next_generation_and_keeps_verified_cost(tmp_path):
    client, api, path = _client(tmp_path, cap="0.02648")
    _run(client)
    with pytest.raises(budget.TokenBudgetError, match="exhausted"):
        _run(client)
    assert len(api.generations) == 1
    audit = budget.audit_budget(json.loads(path.read_text()))
    assert audit["blocked"] is True and audit["held_usd"] == "0"
    assert Fraction(audit["spent_usd"]) == Fraction("0.00786")
    with pytest.raises(budget.TokenBudgetError, match="blocked"):
        _run(client)
    assert len(api.counts) == 2


def test_budget_smaller_than_request_maximum_never_dispatches(tmp_path):
    client, api, path = _client(tmp_path, cap="0.01")
    with pytest.raises(budget.TokenBudgetError, match="exhausted"):
        _run(client)
    assert api.generations == []
    assert budget.audit_budget(json.loads(path.read_text()))["spent_usd"] == "0"


@pytest.mark.parametrize("failure", [TimeoutError("secret not logged"), asyncio.CancelledError()])
def test_unknown_charge_holds_reservation_and_permanently_blocks(tmp_path, failure):
    client, api, path = _client(tmp_path, FakeAPI(failure=failure))
    with pytest.raises(type(failure)):
        _run(client)
    audit = budget.audit_budget(json.loads(path.read_text()))
    assert audit["blocked"] is True
    assert Fraction(audit["held_usd"]) == Fraction("0.02648")
    assert audit["spent_usd"] == "0"
    assert "secret not logged" not in path.read_text()
    with pytest.raises(budget.TokenBudgetError, match="blocked"):
        _run(client)
    assert len(api.counts) == len(api.generations) == 1


def test_known_incomplete_usage_is_settled_and_raw_response_returned(tmp_path):
    client, api, path = _client(tmp_path, FakeAPI(response=_response(status="incomplete")))
    assert _run(client) is api.response
    audit = budget.audit_budget(json.loads(path.read_text()))
    assert audit["blocked"] is False and audit["held_usd"] == "0"
    assert Fraction(audit["spent_usd"]) == Fraction("0.00786")
    assert audit["settled_requests"][0]["status"] == "incomplete"


def test_settled_incomplete_tool_call_allows_native_continuation(tmp_path):
    call = {
        "type": "function_call",
        "id": "fc-1",
        "call_id": "call-1",
        "name": "list_products",
        "arguments": '{"offset":0}',
    }
    first = _response(id="resp-first", status="incomplete", output=[call])
    client, api, path = _client(tmp_path, FakeAPI(response=first))
    assert _run(client) is first
    continuation = _prompt() + [
        call,
        {"type": "function_call_output", "call_id": "call-1", "output": '{"items":[]}'},
    ]
    second = _response(id="resp-second")
    api.response = second
    assert _run(client, prompt=continuation) is second
    assert api.generations[1]["input"] == continuation
    audit = budget.audit_budget(json.loads(path.read_text()))
    assert audit["blocked"] is False and audit["held_usd"] == "0"
    assert audit["settled_count"] == 2
    assert Fraction(audit["spent_usd"]) == Fraction("0.01572")


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "cache_write",
        "total",
        "over_input",
        "over_output",
        "bool",
        "overlap",
        "model",
        "tier",
        "status",
    ],
)
def test_invalid_charge_evidence_keeps_hold_and_blocks(tmp_path, change):
    response = _response()
    if change == "missing":
        response.usage = None
    elif change == "cache_write":
        response.usage["input_tokens_details"].pop("cache_write_tokens")
    elif change == "total":
        response.usage["total_tokens"] = 1
    elif change == "over_input":
        response.usage.update(input_tokens=1201, total_tokens=1401)
    elif change == "over_output":
        response.usage.update(output_tokens=1025, total_tokens=2225)
    elif change == "bool":
        response.usage["input_tokens_details"]["cached_tokens"] = True
    elif change == "overlap":
        response.usage["input_tokens_details"]["cached_tokens"] = 800
    elif change == "model":
        response.model = "gpt-5.6-terra"
    elif change == "tier":
        response.service_tier = "priority"
    else:
        response.status = "queued"
    client, _api, path = _client(tmp_path, FakeAPI(response=response))
    with pytest.raises(budget.TokenBudgetError):
        _run(client)
    audit = budget.audit_budget(json.loads(path.read_text()))
    assert audit["blocked"] and audit["settled_count"] == 0
    assert Fraction(audit["held_usd"]) == Fraction("0.02648")


@pytest.mark.parametrize("count", [True, -1, 1.5, "100", 272001])
def test_invalid_or_long_context_count_never_dispatches(tmp_path, count):
    client, api, path = _client(tmp_path, FakeAPI(count=count))
    with pytest.raises(budget.TokenBudgetError):
        _run(client)
    assert api.generations == []
    assert budget.audit_budget(json.loads(path.read_text()))["held_usd"] == "0"


@pytest.mark.parametrize(
    "field,value",
    [
        ("stream", True),
        ("background", True),
        ("extra_body", {"service_tier": "priority"}),
        ("n", True),
        ("temperature", True),
    ],
)
def test_unsupported_request_fields_fail_before_count(tmp_path, field, value):
    client, api, _path = _client(tmp_path)
    sampling = {**_sampling(), field: value}
    with pytest.raises(budget.TokenBudgetError):
        _run(client, sampling=sampling)
    assert api.counts == api.generations == []


def test_temperature_is_preserved_and_excluded_only_from_token_count(tmp_path):
    client, api, _path = _client(tmp_path)
    _run(client, sampling={**_sampling(), "temperature": 0.6})
    assert "temperature" not in api.counts[0]
    assert api.generations[0]["temperature"] == 0.6


def test_hosted_tools_and_hidden_request_kwargs_fail_before_count(tmp_path):
    client, api, _path = _client(tmp_path)
    with pytest.raises(budget.TokenBudgetError, match="hosted"):
        _run(client, tools=[{"type": "web_search"}])
    assert api.counts == []
    other = tmp_path / "other"
    other.mkdir()
    client, api, _ = _client(other)
    with pytest.raises(budget.TokenBudgetError, match="kwargs"):
        _run(client, previous_response_id="server-history-unaccounted")
    assert api.counts == []


def test_frozen_counted_objects_survive_external_mutation_during_await(tmp_path):
    prompt, tools, sampling = _prompt(), _tools(), _sampling()
    headers = {}
    original = deepcopy((prompt, tools, sampling))

    def mutate():
        prompt[0]["content"] = "changed"
        tools[0]["description"] = "changed"
        sampling["max_output_tokens"] = 128000
        headers["arbitrary"] = "later mutation"

    client, api, _ = _client(tmp_path, FakeAPI(after_count=mutate))
    _run(client, prompt=prompt, tools=tools, sampling=sampling, extra_headers=headers)
    assert api.generations[0]["input"] == original[0]
    assert api.generations[0]["tools"] == original[1]
    assert api.generations[0]["max_output_tokens"] == original[2]["max_output_tokens"]
    assert api.generations[0]["extra_headers"] == {}


def test_expired_price_card_stops_before_count(tmp_path, monkeypatch):
    client, api, _ = _client(tmp_path)
    monkeypatch.setattr(budget, "_utc_today", lambda: date(2026, 11, 22))
    with pytest.raises(budget.TokenBudgetError, match="expired"):
        _run(client)
    assert api.counts == api.generations == []


@pytest.mark.parametrize(
    "attribute,value",
    [
        ("max_retries", 1),
        ("max_retries", False),
        ("base_url", "https://region.api.openai.com/v1"),
        ("base_url", "https://other.example/v1"),
    ],
)
def test_nonadmitted_clients_are_rejected(tmp_path, attribute, value):
    api = FakeAPI()
    setattr(api, attribute, value)
    with pytest.raises(budget.TokenBudgetError):
        _client(tmp_path, api)
    assert api.counts == api.generations == []


@pytest.mark.parametrize(
    "change", ["spent", "hold", "price", "digest", "bool_sequence", "date", "usage"]
)
def test_audit_recomputes_rates_sequences_holds_and_settlements(tmp_path, change):
    client, _api, path = _client(tmp_path)
    _run(client)
    ledger = json.loads(path.read_text())
    if change == "spent":
        ledger["spent_usd"] = "0"
    elif change == "hold":
        ledger["events"][0]["hold_usd"] = "0"
    elif change == "price":
        ledger["rates_usd_per_million"]["input"] = "0.4"
    elif change == "digest":
        ledger["events"][0]["request_sha256"] = "sha256:" + "z" * 64
    elif change == "bool_sequence":
        ledger["events"][1]["request_sequence"] = True
    elif change == "date":
        ledger["events"][0]["counted_on"] = "2026-11-22"
    else:
        ledger["events"][1]["usage"]["output_tokens"] += 1
    with pytest.raises(budget.TokenBudgetError):
        budget.audit_budget(ledger)


def test_fresh_ledger_is_exclusive(tmp_path):
    _client_instance, _api, path = _client(tmp_path)
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        _client(tmp_path)
    assert path.read_bytes() == before
