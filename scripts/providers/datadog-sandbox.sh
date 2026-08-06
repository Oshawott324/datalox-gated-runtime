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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "datadog.json"
SRC = ROOT / "src"
TEMPLATE_API_URL = "https://api.{dd_site}"
SITE_URLS = {
    "datadoghq.com": "https://api.datadoghq.com",
    "us3.datadoghq.com": "https://api.us3.datadoghq.com",
    "us5.datadoghq.com": "https://api.us5.datadoghq.com",
    "datadoghq.eu": "https://api.datadoghq.eu",
    "ap1.datadoghq.com": "https://api.ap1.datadoghq.com",
    "ap2.datadoghq.com": "https://api.ap2.datadoghq.com",
    "uk1.datadoghq.com": "https://api.uk1.datadoghq.com",
    "ddog-gov.com": "https://api.ddog-gov.com",
    "us2.ddog-gov.com": "https://api.us2.ddog-gov.com",
}
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
BASE_REQUEST_COUNT = 42
FIXTURE_REQUEST_COUNT = 57
BASE_CONTEXT = frozenset(
    {"dd_site", "from_epoch", "from_iso", "from_ms", "metric_query", "to_epoch", "to_iso", "to_ms"}
)


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


def configured_site() -> tuple[str, str]:
    site = os.environ.get("DD_SITE", "datadoghq.com")
    api_url = SITE_URLS.get(site)
    if api_url is None:
        raise PrepError(
            "unsupported_dd_site",
            "DD_SITE must be an official Datadog API site supported by this probe helper.",
        )
    return site, api_url


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
        raise PrepError("render_write_failed", f"Could not atomically write {path}.") from exc


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


def request_sections(payload: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    base = payload.get("probe_requests")
    fixtures = payload.get("fixture_expansions")
    fixture = fixtures.get("probe_requests") if isinstance(fixtures, dict) else None
    if not isinstance(base, list) or not isinstance(fixture, list):
        raise PrepError(
            "invalid_probe_template",
            "probe_requests and fixture_expansions.probe_requests must be lists.",
        )
    return base, fixture


def validate_requests(requests: Any, *, expected_count: int, concrete: bool) -> None:
    if not isinstance(requests, list) or len(requests) != expected_count:
        raise PrepError(
            "invalid_probe_request_count", f"Expected exactly {expected_count} probe requests."
        )
    for request in requests:
        if not isinstance(request, dict) or request.get("method") != "GET":
            raise PrepError("non_get_probe_request", "Every Datadog probe request must use GET.")
        if not isinstance(request.get("path"), str) or not isinstance(request.get("query"), dict):
            raise PrepError(
                "invalid_probe_request",
                "Every Datadog probe request needs a string path and object query.",
            )
    if concrete and PLACEHOLDER_RE.search(json.dumps(requests, sort_keys=True)):
        raise PrepError("unresolved_probe_placeholder", "Rendered requests contain a placeholder.")


def placeholders(value: Any) -> frozenset[str]:
    return frozenset(PLACEHOLDER_RE.findall(json.dumps(value, sort_keys=True)))


def substitute(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except KeyError as exc:
            raise PrepError(
                "unresolved_probe_placeholder",
                f"No render value was provided for placeholder {exc.args[0]!r}.",
            ) from exc
    if isinstance(value, list):
        return [substitute(item, context) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, context) for key, item in value.items()}
    return value


def resolved_values(values: Any, context: dict[str, str]) -> list[Any]:
    if not isinstance(values, list):
        raise PrepError("invalid_probe_template", "Expected a list of template values.")
    return [
        substitute(value, context)
        for value in values
        if placeholders(value).issubset(context.keys())
    ]


def fixture_id_keys(payload: dict[str, Any]) -> frozenset[str]:
    _, fixture = request_sections(payload)
    return placeholders(fixture) - BASE_CONTEXT


def load_seed_context(path: Path, payload: dict[str, Any]) -> dict[str, str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict) or manifest.get("kind") != "datadog_probe_seed_v0":
        raise PrepError("invalid_seed_manifest", "Seed manifest kind must be datadog_probe_seed_v0.")
    ids = manifest.get("ids")
    if not isinstance(ids, dict) or not set(ids).issubset(fixture_id_keys(payload)):
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest ids must be a subset of Datadog fixture placeholders.",
        )
    context: dict[str, str] = {}
    for key, value in ids.items():
        if not isinstance(value, str) or not value:
            raise PrepError("invalid_seed_manifest", "Seed manifest IDs must be non-empty strings.")
        context[key] = value
    return context


def validate_auth_profile(payload: dict[str, Any]) -> None:
    profiles = payload.get("auth_profiles")
    profile = profiles.get("datadog_keys") if isinstance(profiles, dict) else None
    expected = [
        {"env": "DD_API_KEY", "in": "header", "name": "DD-API-KEY", "scheme": ""},
        {
            "env": "DD_APPLICATION_KEY",
            "in": "header",
            "name": "DD-APPLICATION-KEY",
            "scheme": "",
        },
    ]
    if (
        payload.get("auth_profile") != "datadog_keys"
        or not isinstance(profile, dict)
        or profile.get("kind") != "env_static"
        or profile.get("inject") != expected
    ):
        raise PrepError(
            "invalid_auth_profiles",
            "Datadog auth must inject DD_API_KEY and DD_APPLICATION_KEY through the auth broker.",
        )


def render_context(site: str, seed: dict[str, str]) -> dict[str, str]:
    now = datetime.now(UTC).replace(microsecond=0)
    start = now - timedelta(days=14)
    return {
        "dd_site": site,
        "from_epoch": str(int(start.timestamp())),
        "from_iso": start.isoformat().replace("+00:00", "Z"),
        "from_ms": str(int(start.timestamp() * 1000)),
        "metric_query": os.environ.get("DATADOG_METRIC_QUERY") or "avg:system.cpu.user{*}",
        "to_epoch": str(int(now.timestamp())),
        "to_iso": now.isoformat().replace("+00:00", "Z"),
        "to_ms": str(int(now.timestamp() * 1000)),
        **seed,
    }


def validate_rendered(payload: Any, api_url: str) -> int:
    if not isinstance(payload, dict) or payload.get("provider_id") != "datadog":
        raise PrepError("invalid_probe_config", "Rendered config must be a Datadog probe object.")
    validate_auth_profile(payload)
    if payload.get("base_url") != api_url:
        raise PrepError("probe_api_url_mismatch", "Rendered base_url does not match DD_SITE.")
    if "fixture_expansions" in payload:
        raise PrepError("unresolved_fixture_expansions", "Rendered config must omit fixture expansions.")
    requests = payload.get("probe_requests")
    if not isinstance(requests, list) or not (
        BASE_REQUEST_COUNT <= len(requests) <= BASE_REQUEST_COUNT + FIXTURE_REQUEST_COUNT
    ):
        raise PrepError("invalid_probe_request_count", "Rendered request count is outside template bounds.")
    validate_requests(requests, expected_count=len(requests), concrete=True)
    budget = payload.get("rate_budget")
    if not isinstance(budget, dict) or budget.get("max_requests") != len(requests):
        raise PrepError("invalid_probe_budget", "max_requests must equal the rendered request count.")
    if PLACEHOLDER_RE.search(json.dumps(payload, sort_keys=True)):
        raise PrepError("unresolved_probe_placeholder", "Rendered config contains a placeholder.")
    return len(requests)


def render_probe(out_path: Path, seed_manifest: Path | None) -> int:
    require_env("DD_API_KEY")
    require_env("DD_APPLICATION_KEY")
    site, api_url = configured_site()
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError("invalid_probe_template", "Datadog probe template must be an object.")
    base, fixture = request_sections(payload)
    validate_requests(base, expected_count=BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture, expected_count=FIXTURE_REQUEST_COUNT, concrete=False)
    validate_auth_profile(payload)
    seed = load_seed_context(seed_manifest, payload) if seed_manifest else {}
    context = render_context(site, seed)
    payload.pop("fixture_expansions")
    payload["base_url"] = api_url
    payload["probe_requests"] = substitute(base, context) + resolved_values(fixture, context)
    payload["rate_budget"]["max_requests"] = len(payload["probe_requests"])
    count = validate_rendered(payload, api_url)
    write_json(out_path, payload)
    validate_runtime_schema(out_path)
    return count


def validate_template() -> dict[str, int]:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict) or payload.get("base_url") != TEMPLATE_API_URL:
        raise PrepError("invalid_probe_template", "Tracked Datadog base_url template is invalid.")
    validate_auth_profile(payload)
    base, fixture = request_sections(payload)
    validate_requests(base, expected_count=BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture, expected_count=FIXTURE_REQUEST_COUNT, concrete=False)
    if payload.get("rate_budget", {}).get("max_requests") != BASE_REQUEST_COUNT:
        raise PrepError("invalid_probe_budget", "Tracked max_requests must equal base requests.")
    validate_runtime_schema(TEMPLATE)
    return {"base": len(base), "fixture": len(fixture)}


def datalox_env() -> dict[str, str]:
    api_key = require_env("DD_API_KEY")
    app_key = require_env("DD_APPLICATION_KEY")
    child = os.environ.copy()
    child["DD_API_KEY"] = api_key
    child["DD_APPLICATION_KEY"] = app_key
    prior = child.get("PYTHONPATH")
    child["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    return child


def run_datalox(action: str, args: argparse.Namespace) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        config_path = args.config
        if config_path is None:
            temporary = tempfile.TemporaryDirectory(prefix="datalox_datadog_config_")
            config_path = Path(temporary.name) / "datadog.probe.json"
            render_probe(config_path, args.seed_manifest)
        else:
            _, api_url = configured_site()
            validate_rendered(load_json(config_path), api_url)
            validate_runtime_schema(config_path)
        command = [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "provider",
            action,
            "--config",
            str(config_path),
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


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Prepare Datadog authenticated GET probes without persisting credentials."
    )
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    render = commands.add_parser("render")
    render.add_argument("--out", type=Path, required=True)
    render.add_argument("--seed-manifest", type=Path)
    preflight = commands.add_parser("auth-preflight")
    probe = commands.add_parser("probe")
    for item in (preflight, probe):
        item.add_argument("--config", type=Path)
        item.add_argument("--seed-manifest", type=Path)
    probe.add_argument("--out", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "validate":
            counts = validate_template()
            print(json.dumps({
                "get_only": True,
                "kind": "datadog_probe_validation_v0",
                "request_counts": counts,
                "status": "completed",
            }, indent=2, sort_keys=True))
            return 0
        if args.command == "render":
            count = render_probe(args.out, args.seed_manifest)
            print(json.dumps({
                "kind": "datadog_probe_render_v0",
                "path": str(args.out),
                "probe_request_count": count,
                "status": "completed",
            }, indent=2, sort_keys=True))
            return 0
        if args.command in {"auth-preflight", "probe"}:
            if args.config is not None and args.seed_manifest is not None:
                raise PrepError("ambiguous_probe_input", "Use either --config or --seed-manifest, not both.")
            return run_datalox(args.command, args)
        raise PrepError("unknown_command", f"Unknown command: {args.command}")
    except PrepError as exc:
        print(json.dumps({
            "blocker": {"code": exc.code, "message": exc.message},
            "status": "blocked",
        }, indent=2, sort_keys=True), file=sys.stderr)
        return 1


raise SystemExit(main())
PY
