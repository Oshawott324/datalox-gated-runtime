from __future__ import annotations

import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from datalox_gated_runtime.provider_probe import load_probe_config


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "probes" / "shopify_admin.json"
HELPER = ROOT / "scripts" / "providers" / "shopify-admin-sandbox.sh"
TEMPLATE_BASE_URL = "https://{shop}.myshopify.com/admin/api/2026-07"
SHOP = "datalox-probe-dev"
TOKEN = "shpat_test_secret_that_must_not_be_echoed"
FIXTURE_IDS = {
    "carrier_service_id": "1001",
    "customer_id": "1002",
    "discount_code_id": "1003",
    "dispute_id": "1004",
    "draft_order_id": "1005",
    "fulfillment_id": "1006",
    "fulfillment_order_id": "1007",
    "inventory_item_id": "1008",
    "location_id": "1009",
    "order_id": "1010",
    "payout_id": "1011",
    "price_rule_id": "1012",
    "product_id": "1013",
    "refund_id": "1014",
    "variant_id": "1015",
}


def test_probe_schema_and_helper_validation_agree() -> None:
    payload = _payload()
    config = load_probe_config(PROBE)
    result = _run("validate")

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "get_only": True,
        "kind": "shopify_admin_probe_validation_v0",
        "request_counts": {
            "base": 8,
            "fixture": 20,
            "plans": {"carrier_services": 2, "shopify_payments": 6},
        },
        "status": "completed",
    }
    assert payload["provider_id"] == config.provider_id == "shopify_admin"
    assert config.base_url == TEMPLATE_BASE_URL
    assert len(config.probe_requests) == config.rate_budget.max_requests == 8


def test_all_sections_are_get_only_and_cover_core_workflow_reads() -> None:
    payload = _payload()
    sections = [
        payload["probe_requests"],
        payload["fixture_expansions"]["probe_requests"],
        *(section["probe_requests"] for section in payload["plan_expansions"].values()),
    ]
    requests = [request for section in sections for request in section]
    assert {request["method"] for request in requests} == {"GET"}
    assert all(isinstance(request["query"], dict) for request in requests)
    paths = {request["path"] for request in requests}
    for family in (
        "/orders",
        "/customers",
        "/products",
        "/variants",
        "/inventory_",
        "/fulfillment_",
        "/fulfillments",
        "/refunds",
        "/price_rules",
        "/locations",
        "/draft_orders",
        "/carrier_services",
        "/shopify_payments",
    ):
        assert any(family in path for path in paths), family
    assert "/graphql.json" not in paths


def test_render_base_is_concrete_private_and_secret_free(tmp_path: Path) -> None:
    out = tmp_path / "shopify.json"
    result = _run("render", "--out", str(out), env=_env())

    assert result.returncode == 0, result.stderr
    text = out.read_text(encoding="utf-8")
    rendered = json.loads(text)
    assert rendered["base_url"] == f"https://{SHOP}.myshopify.com/admin/api/2026-07"
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 8
    assert "fixture_expansions" not in rendered
    assert "plan_expansions" not in rendered
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    _assert_no_placeholders(rendered)
    _assert_secret_absent(result, text)


def test_render_fixture_and_plan_surfaces_have_exact_budget(tmp_path: Path) -> None:
    seed = tmp_path / "seed.json"
    seed.write_text(
        json.dumps(
            {
                "ids": FIXTURE_IDS,
                "kind": "shopify_admin_probe_seed_v0",
                "shop": f"{SHOP}.myshopify.com",
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "shopify-full.json"
    result = _run(
        "render",
        "--out",
        str(out),
        "--seed-manifest",
        str(seed),
        "--include-plan-surface",
        "carrier_services",
        "--include-plan-surface",
        "shopify_payments",
        env=_env(),
    )

    assert result.returncode == 0, result.stderr
    rendered = json.loads(out.read_text(encoding="utf-8"))
    assert len(rendered["probe_requests"]) == rendered["rate_budget"]["max_requests"] == 36
    _assert_no_placeholders(rendered)
    assert all(value in out.read_text(encoding="utf-8") for value in FIXTURE_IDS.values())
    _assert_secret_absent(result, out.read_text(encoding="utf-8"))


def test_partial_seed_only_adds_fully_resolved_requests(tmp_path: Path) -> None:
    seed = tmp_path / "seed.json"
    seed.write_text(
        json.dumps(
            {
                "ids": {"order_id": 42},
                "kind": "shopify_admin_probe_seed_v0",
                "shop": f"{SHOP}.myshopify.com",
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "partial.json"
    result = _run("render", "--out", str(out), "--seed-manifest", str(seed), env=_env())

    assert result.returncode == 0, result.stderr
    rendered = json.loads(out.read_text(encoding="utf-8"))
    assert len(rendered["probe_requests"]) == 13
    _assert_no_placeholders(rendered)


@pytest.mark.parametrize(
    ("shop", "code"),
    [
        ("https://example.com", "unsupported_shopify_shop"),
        ("store.myshopify.com.example.com", "unsupported_shopify_shop"),
        ("bad/store", "unsupported_shopify_shop"),
    ],
)
def test_arbitrary_shop_hosts_are_rejected_without_secret_echo(
    tmp_path: Path, shop: str, code: str
) -> None:
    env = _env()
    env["SHOPIFY_SHOP"] = shop
    result = _run("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_blocked(result, code)
    _assert_secret_absent(result)


@pytest.mark.parametrize("missing", ["SHOPIFY_SHOP", "SHOPIFY_ADMIN_ACCESS_TOKEN"])
def test_missing_required_environment_is_structured_and_secret_free(
    tmp_path: Path, missing: str
) -> None:
    env = _env()
    env.pop(missing)
    result = _run("render", "--out", str(tmp_path / "blocked.json"), env=env)

    _assert_blocked(result, "missing_env")
    _assert_secret_absent(result)


def test_discovery_requires_exact_development_store_confirmation_before_network(
    tmp_path: Path,
) -> None:
    result = _run(
        "discover",
        "--fixture-id",
        "fixture-1",
        "--confirm-development-store",
        "wrong.myshopify.com",
        "--out",
        str(tmp_path / "seed.json"),
        env=_env(),
    )

    _assert_blocked(result, "development_store_confirmation_required")
    assert not (tmp_path / "seed.json").exists()
    _assert_secret_absent(result)


def test_helper_routes_only_auth_preflight_and_probe_through_runtime() -> None:
    source = HELPER.read_text(encoding="utf-8")
    assert 'if args.command in {"auth-preflight", "probe"}:' in source
    assert "return run_datalox(args.command, args)" in source
    assert not re.search(r"run_datalox\(\s*['\"](?:post|put|patch|delete|write)", source, re.I)
    assert 'method="GET"' in source
    assert 'method="POST"' not in source


def test_helper_has_valid_bash_syntax() -> None:
    result = subprocess.run(
        ["bash", "-n", str(HELPER)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _payload() -> dict[str, Any]:
    payload = json.loads(PROBE.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _env() -> dict[str, str]:
    return {"SHOPIFY_ADMIN_ACCESS_TOKEN": TOKEN, "SHOPIFY_SHOP": SHOP}


def _assert_no_placeholders(value: Any) -> None:
    assert re.search(r"\{[a-z][a-z0-9_]*\}", json.dumps(value, sort_keys=True)) is None


def _assert_secret_absent(result: subprocess.CompletedProcess[str], rendered: str = "") -> None:
    assert TOKEN not in result.stdout
    assert TOKEN not in result.stderr
    assert TOKEN not in rendered


def _assert_blocked(result: subprocess.CompletedProcess[str], code: str) -> None:
    assert result.returncode == 1
    payload = json.loads(result.stderr)
    assert payload["status"] == "blocked"
    assert payload["blocker"]["code"] == code


def _run(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    child = os.environ.copy()
    child.pop("SHOPIFY_ADMIN_ACCESS_TOKEN", None)
    child.pop("SHOPIFY_SHOP", None)
    child.update(env or {})
    return subprocess.run(
        ["bash", str(HELPER), *args],
        cwd=ROOT,
        env=child,
        text=True,
        capture_output=True,
        check=False,
    )
