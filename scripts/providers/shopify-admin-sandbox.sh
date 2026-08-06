#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

exec "${DATALOX_PYTHON:-python3}" - "$ROOT_DIR" "$@" <<'PY'
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "shopify_admin.json"
SRC = ROOT / "src"
API_VERSION = "2026-07"
TEMPLATE_BASE_URL = f"https://{{shop}}.myshopify.com/admin/api/{API_VERSION}"
SHOP_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
FIXTURE_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
BASE_COUNT = 8
FIXTURE_COUNT = 20
PLAN_COUNTS = {"carrier_services": 2, "shopify_payments": 6}


class PrepError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise PrepError("missing_env", f"Set {name} before running this command.")
    return value


def configured_shop() -> str:
    value = require_env("SHOPIFY_SHOP").lower()
    suffix = ".myshopify.com"
    shop = value[: -len(suffix)] if value.endswith(suffix) else value
    if not SHOP_RE.fullmatch(shop):
        raise PrepError(
            "unsupported_shopify_shop",
            "SHOPIFY_SHOP must be one canonical myshopify subdomain or <shop>.myshopify.com.",
        )
    return shop


def base_url(shop: str) -> str:
    return f"https://{shop}.myshopify.com/admin/api/{API_VERSION}"


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrepError("invalid_json_file", f"Could not read valid JSON from {path}.") from exc


def write_json(path: Path, payload: Any) -> None:
    temporary_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", dir=path.parent, encoding="utf-8", delete=False
        ) as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            temporary_path = Path(handle.name)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise PrepError("write_failed", f"Could not atomically write {path}.") from exc


def validate_runtime_schema(path: Path) -> Any:
    sys.path.insert(0, str(SRC))
    try:
        from datalox_gated_runtime.provider_probe import load_probe_config

        return load_probe_config(path)
    except ImportError as exc:
        raise PrepError(
            "runtime_import_failed",
            "Install repository dependencies or set DATALOX_PYTHON to the project virtualenv Python.",
        ) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise PrepError("invalid_probe_config", f"Probe config failed runtime validation: {path}") from exc
    finally:
        if sys.path and sys.path[0] == str(SRC):
            sys.path.pop(0)


def validate_requests(requests: Any, expected: int) -> None:
    if not isinstance(requests, list) or len(requests) != expected:
        raise PrepError("invalid_probe_request_count", f"Expected exactly {expected} requests.")
    for request in requests:
        if not isinstance(request, dict) or request.get("method") != "GET":
            raise PrepError("non_get_probe_request", "Every Shopify probe request must use GET.")
        if not isinstance(request.get("path"), str) or not isinstance(request.get("query"), dict):
            raise PrepError("invalid_probe_request", "Every request needs a string path and object query.")


def sections(payload: dict[str, Any]) -> tuple[list[Any], list[Any], dict[str, list[Any]]]:
    base = payload.get("probe_requests")
    fixture = payload.get("fixture_expansions", {}).get("probe_requests")
    raw_plans = payload.get("plan_expansions")
    if not isinstance(base, list) or not isinstance(fixture, list) or not isinstance(raw_plans, dict):
        raise PrepError("invalid_probe_template", "Probe request sections are malformed.")
    plans: dict[str, list[Any]] = {}
    for name, expected in PLAN_COUNTS.items():
        requests = raw_plans.get(name, {}).get("probe_requests")
        validate_requests(requests, expected)
        plans[name] = requests
    return base, fixture, plans


def validate_auth(payload: dict[str, Any]) -> None:
    expected = {
        "env": "SHOPIFY_ADMIN_ACCESS_TOKEN",
        "in": "header",
        "name": "X-Shopify-Access-Token",
        "scheme": "",
    }
    profiles = payload.get("auth_profiles")
    profile = profiles.get("shopify_admin_access_token") if isinstance(profiles, dict) else None
    if (
        payload.get("auth_profile") != "shopify_admin_access_token"
        or not isinstance(profile, dict)
        or profile.get("kind") != "env_static"
        or profile.get("inject") != [expected]
    ):
        raise PrepError("invalid_auth_profiles", "Shopify auth must use the access-token header profile.")


def placeholders(value: Any) -> set[str]:
    return set(PLACEHOLDER_RE.findall(json.dumps(value, sort_keys=True)))


def substitute(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except KeyError as exc:
            raise PrepError("unresolved_probe_placeholder", f"Missing placeholder {exc.args[0]!r}.") from exc
    if isinstance(value, list):
        return [substitute(item, context) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, context) for key, item in value.items()}
    return value


def resolvable(requests: list[Any], context: dict[str, str]) -> list[Any]:
    return [substitute(item, context) for item in requests if placeholders(item) <= context.keys()]


def load_seed(path: Path, shop: str) -> dict[str, str]:
    payload = load_json(path)
    if (
        not isinstance(payload, dict)
        or payload.get("kind") != "shopify_admin_probe_seed_v0"
        or payload.get("shop") != f"{shop}.myshopify.com"
        or not isinstance(payload.get("ids"), dict)
    ):
        raise PrepError("invalid_seed_manifest", "Seed manifest kind, shop, or ids is invalid.")
    allowed = placeholders(load_json(TEMPLATE)) - {"shop"}
    if not set(payload["ids"]) <= allowed:
        raise PrepError("invalid_seed_manifest", "Seed manifest contains an unknown ID key.")
    context: dict[str, str] = {}
    for key, value in payload["ids"].items():
        if not isinstance(value, (str, int)) or isinstance(value, bool) or str(value) == "":
            raise PrepError("invalid_seed_manifest", "Seed IDs must be non-empty strings or integers.")
        context[key] = str(value)
    return context


def validate_template() -> dict[str, Any]:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict) or payload.get("base_url") != TEMPLATE_BASE_URL:
        raise PrepError("invalid_probe_template", "Tracked Shopify base_url is not the 2026-07 template.")
    validate_auth(payload)
    base, fixture, plans = sections(payload)
    validate_requests(base, BASE_COUNT)
    validate_requests(fixture, FIXTURE_COUNT)
    if payload.get("rate_budget", {}).get("max_requests") != BASE_COUNT:
        raise PrepError("invalid_probe_budget", "Tracked request budget must equal the base count.")
    validate_runtime_schema(TEMPLATE)
    return {"base": len(base), "fixture": len(fixture), "plans": {k: len(v) for k, v in plans.items()}}


def render_probe(out: Path, seed_manifest: Path | None, plan_surfaces: list[str]) -> int:
    shop = configured_shop()
    require_env("SHOPIFY_ADMIN_ACCESS_TOKEN")
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError("invalid_probe_template", "Shopify probe template must be an object.")
    validate_auth(payload)
    base, fixture, plans = sections(payload)
    validate_requests(base, BASE_COUNT)
    validate_requests(fixture, FIXTURE_COUNT)
    context = {"shop": shop}
    if seed_manifest is not None:
        context.update(load_seed(seed_manifest, shop))
    requests = substitute(base, context)
    requests.extend(resolvable(fixture, context))
    for name in dict.fromkeys(plan_surfaces):
        requests.extend(resolvable(plans[name], context))
    payload.pop("fixture_expansions")
    payload.pop("plan_expansions")
    payload["base_url"] = base_url(shop)
    payload["probe_requests"] = requests
    payload["safe_read_prefixes"] = resolvable(payload["safe_read_prefixes"], context)
    payload["rate_budget"]["max_requests"] = len(requests)
    if placeholders(payload):
        raise PrepError("unresolved_probe_placeholder", "Rendered probe still contains a placeholder.")
    write_json(out, payload)
    validate_runtime_schema(out)
    return len(requests)


def datalox_env() -> dict[str, str]:
    token = require_env("SHOPIFY_ADMIN_ACCESS_TOKEN")
    child = os.environ.copy()
    child.pop("SHOPIFY_ADMIN_ACCESS_TOKEN", None)
    child["SHOPIFY_ADMIN_ACCESS_TOKEN"] = token
    prior = child.get("PYTHONPATH")
    child["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    return child


def run_datalox(action: str, args: argparse.Namespace) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        config = args.config
        if config is None:
            temporary = tempfile.TemporaryDirectory(prefix="datalox_shopify_config_")
            config = Path(temporary.name) / "shopify.probe.json"
            render_probe(config, args.seed_manifest, args.include_plan_surface)
        else:
            parsed = validate_runtime_schema(config)
            if parsed.provider_id != "shopify_admin" or parsed.base_url != base_url(configured_shop()):
                raise PrepError("probe_shop_mismatch", "Probe config does not match SHOPIFY_SHOP.")
        command = [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "provider",
            action,
            "--config",
            str(config),
        ]
        if action == "probe":
            if args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())):
                raise PrepError("probe_output_not_empty", f"Probe output must be absent or empty: {args.out}")
            command.extend(["--out", str(args.out)])
        command.append("--json")
        return subprocess.run(command, cwd=ROOT, env=datalox_env(), check=False).returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def provider_get(shop: str, path: str, query: dict[str, str] | None = None) -> Any:
    url = base_url(shop) + path
    if query:
        url += "?" + urlencode(query)
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "datalox-shopify-probe-prep/1",
            "X-Shopify-Access-Token": require_env("SHOPIFY_ADMIN_ACCESS_TOKEN"),
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        raise PrepError("shopify_discovery_http_error", f"GET {path} returned HTTP {exc.code}.") from exc
    except (URLError, json.JSONDecodeError) as exc:
        raise PrepError("shopify_discovery_failed", f"GET {path} did not return valid JSON.") from exc


def exact_one(items: Any, key: str, value: str, resource: str) -> dict[str, Any]:
    matches = [item for item in items or [] if isinstance(item, dict) and item.get(key) == value]
    if len(matches) != 1:
        raise PrepError(
            "fixture_not_unique",
            f"Expected exactly one {resource} with {key}={value!r}; found {len(matches)}.",
        )
    return matches[0]


def discover_fixture(fixture_id: str, confirmation: str, out: Path) -> int:
    shop = configured_shop()
    canonical = f"{shop}.myshopify.com"
    if confirmation.lower() != canonical:
        raise PrepError(
            "development_store_confirmation_required",
            f"Pass --confirm-development-store {canonical} to permit direct fixture discovery.",
        )
    if not FIXTURE_RE.fullmatch(fixture_id):
        raise PrepError("invalid_fixture_id", "--fixture-id must be 1-32 lowercase letters, digits, or hyphens.")
    marker = f"Datalox Shopify Probe {fixture_id}"
    handle = f"datalox-probe-{fixture_id}"
    email = f"datalox-shopify-{fixture_id}@example.invalid"
    code = f"DATALOX-{fixture_id.upper()}"

    shop_payload = provider_get(shop, "/shop.json").get("shop")
    if not isinstance(shop_payload, dict) or shop_payload.get("myshopify_domain") != canonical:
        raise PrepError("shop_identity_mismatch", "Shop response did not match the confirmed myshopify domain.")
    product = exact_one(
        provider_get(shop, "/products.json", {"handle": handle, "limit": "250"}).get("products"),
        "handle",
        handle,
        "product",
    )
    customer = exact_one(
        provider_get(shop, "/customers/search.json", {"query": f"email:{email}", "limit": "250"}).get("customers"),
        "email",
        email,
        "customer",
    )
    order = exact_one(
        provider_get(shop, "/orders.json", {"limit": "250", "status": "any"}).get("orders"),
        "note",
        marker,
        "order",
    )
    draft = exact_one(
        provider_get(shop, "/draft_orders.json", {"limit": "250", "status": "any"}).get("draft_orders"),
        "note",
        marker,
        "draft order",
    )
    rule = exact_one(
        provider_get(shop, "/price_rules.json", {"limit": "250"}).get("price_rules"),
        "title",
        code,
        "price rule",
    )
    variants = product.get("variants")
    if not isinstance(variants, list) or len(variants) != 1:
        raise PrepError("fixture_not_unique", "The deterministic product must contain exactly one variant.")
    variant = variants[0]
    ids: dict[str, str | int] = {
        "customer_id": customer["id"],
        "draft_order_id": draft["id"],
        "inventory_item_id": variant["inventory_item_id"],
        "location_id": shop_payload["primary_location_id"],
        "order_id": order["id"],
        "price_rule_id": rule["id"],
        "product_id": product["id"],
        "variant_id": variant["id"],
    }
    linked = {
        "discount_code_id": (provider_get(shop, f"/price_rules/{rule['id']}/discount_codes.json").get("discount_codes") or []),
        "fulfillment_order_id": (provider_get(shop, f"/orders/{order['id']}/fulfillment_orders.json").get("fulfillment_orders") or []),
        "fulfillment_id": (provider_get(shop, f"/orders/{order['id']}/fulfillments.json").get("fulfillments") or []),
        "refund_id": (provider_get(shop, f"/orders/{order['id']}/refunds.json").get("refunds") or []),
    }
    for name, values in linked.items():
        if len(values) == 1 and isinstance(values[0], dict) and "id" in values[0]:
            ids[name] = values[0]["id"]
        elif len(values) > 1:
            raise PrepError("fixture_not_unique", f"Expected at most one linked {name}; found {len(values)}.")
    manifest = {
        "fixture_id": fixture_id,
        "ids": ids,
        "kind": "shopify_admin_probe_seed_v0",
        "shop": canonical,
    }
    write_json(out, manifest)
    return len(ids)


def add_render_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--seed-manifest", type=Path)
    parser.add_argument(
        "--include-plan-surface",
        action="append",
        choices=sorted(PLAN_COUNTS),
        default=[],
    )


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Prepare Shopify Admin GET-only provider probes.")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    render = commands.add_parser("render")
    render.add_argument("--out", type=Path, required=True)
    add_render_inputs(render)
    for name in ("auth-preflight", "probe"):
        item = commands.add_parser(name)
        item.add_argument("--config", type=Path)
        add_render_inputs(item)
        if name == "probe":
            item.add_argument("--out", type=Path, required=True)
    discover = commands.add_parser("discover")
    discover.add_argument("--confirm-development-store", required=True)
    discover.add_argument("--fixture-id", required=True)
    discover.add_argument("--out", type=Path, required=True)
    return root


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "validate":
            counts = validate_template()
            print(json.dumps({"get_only": True, "kind": "shopify_admin_probe_validation_v0", "request_counts": counts, "status": "completed"}, indent=2, sort_keys=True))
            return 0
        if args.command == "render":
            count = render_probe(args.out, args.seed_manifest, args.include_plan_surface)
            print(json.dumps({"kind": "shopify_admin_probe_render_v0", "path": str(args.out), "probe_request_count": count, "status": "completed"}, indent=2, sort_keys=True))
            return 0
        if args.command in {"auth-preflight", "probe"}:
            if args.config is not None and args.seed_manifest is not None:
                raise PrepError("ambiguous_probe_input", "Use either --config or --seed-manifest, not both.")
            return run_datalox(args.command, args)
        if args.command == "discover":
            count = discover_fixture(args.fixture_id, args.confirm_development_store, args.out)
            print(json.dumps({"discovered_id_count": count, "kind": "shopify_admin_probe_discovery_v0", "path": str(args.out), "status": "completed"}, indent=2, sort_keys=True))
            return 0
        raise PrepError("unknown_command", f"Unknown command: {args.command}")
    except PrepError as exc:
        print(json.dumps({"blocker": {"code": exc.code, "message": exc.message}, "status": "blocked"}, indent=2, sort_keys=True), file=sys.stderr)
        return 1


raise SystemExit(main())
PY
