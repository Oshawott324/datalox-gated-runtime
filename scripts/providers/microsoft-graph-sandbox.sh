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
from urllib.parse import quote, urlsplit


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "microsoft_graph.json"
SRC = ROOT / "src"
CANONICAL_API_URL = "https://graph.microsoft.com/v1.0"
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
BASE_REQUEST_COUNT = 20
FIXTURE_REQUEST_COUNT = 47
SEED_ID_KEYS = frozenset(
    {
        "calendar_id",
        "channel_id",
        "channel_message_id",
        "chat_id",
        "chat_message_id",
        "drive_item_id",
        "event_id",
        "group_id",
        "mail_folder_id",
        "message_id",
        "planner_bucket_id",
        "planner_plan_id",
        "planner_task_id",
        "site_drive_item_id",
        "site_id",
        "team_id",
        "todo_list_id",
        "todo_task_id",
        "user_id",
    }
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


def configured_api_url() -> str:
    value = os.environ.get("MICROSOFT_GRAPH_API_URL", CANONICAL_API_URL)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PrepError(
            "invalid_microsoft_graph_api_url",
            "MICROSOFT_GRAPH_API_URL is not a valid URL.",
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "graph.microsoft.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path != "/v1.0"
        or parsed.query
        or parsed.fragment
    ):
        raise PrepError(
            "unsupported_microsoft_graph_api_url",
            "MICROSOFT_GRAPH_API_URL must be exactly https://graph.microsoft.com/v1.0.",
        )
    return CANONICAL_API_URL


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
            "Install repository dependencies or set DATALOX_PYTHON to the repository Python.",
        ) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise PrepError(
            "invalid_probe_config",
            f"Probe config failed runtime validation: {path}",
        ) from exc
    finally:
        if sys.path and sys.path[0] == str(SRC):
            sys.path.pop(0)


def request_sections(payload: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    base_requests = payload.get("probe_requests")
    fixture_section = payload.get("fixture_expansions")
    fixture_requests = (
        fixture_section.get("probe_requests") if isinstance(fixture_section, dict) else None
    )
    if not isinstance(base_requests, list) or not isinstance(fixture_requests, list):
        raise PrepError(
            "invalid_probe_template",
            "probe_requests and fixture_expansions.probe_requests must be lists.",
        )
    return base_requests, fixture_requests


def validate_requests(requests: Any, *, expected_count: int, concrete: bool) -> None:
    if not isinstance(requests, list) or len(requests) != expected_count:
        raise PrepError(
            "invalid_probe_request_count",
            f"Expected exactly {expected_count} probe requests.",
        )
    for request in requests:
        if not isinstance(request, dict) or request.get("method") != "GET":
            raise PrepError(
                "non_get_probe_request",
                "Every Microsoft Graph probe request must use GET.",
            )
        if not isinstance(request.get("path"), str) or not isinstance(request.get("query"), dict):
            raise PrepError(
                "invalid_probe_request",
                "Every Microsoft Graph probe request needs a string path and object query.",
            )
    if concrete and PLACEHOLDER_RE.search(json.dumps(requests, sort_keys=True)):
        raise PrepError(
            "unresolved_probe_placeholder",
            "Rendered probe requests still contain a placeholder.",
        )


def placeholders(value: Any) -> set[str]:
    return set(PLACEHOLDER_RE.findall(json.dumps(value, sort_keys=True)))


def substitute(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except KeyError as exc:
            raise PrepError(
                "missing_render_context",
                f"Render context is missing {exc.args[0]!r}.",
            ) from exc
    if isinstance(value, list):
        return [substitute(item, context) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, context) for key, item in value.items()}
    return value


def resolved_values(values: Any, context: dict[str, str]) -> list[Any]:
    if not isinstance(values, list):
        raise PrepError("invalid_probe_template", "Expected a list of probe values.")
    return [
        substitute(value, context)
        for value in values
        if placeholders(value).issubset(context)
    ]


def load_seed_context(path: Path) -> dict[str, str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict) or manifest.get("kind") != "microsoft_graph_probe_seed_v0":
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest kind must be microsoft_graph_probe_seed_v0.",
        )
    ids = manifest.get("ids")
    if not isinstance(ids, dict) or not ids or not set(ids).issubset(SEED_ID_KEYS):
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest ids must be a non-empty subset of the documented Microsoft Graph ID keys.",
        )
    context: dict[str, str] = {}
    for key, value in ids.items():
        if not isinstance(value, str) or not value or len(value) > 2048:
            raise PrepError(
                "invalid_seed_manifest",
                "Seed manifest IDs must be non-empty strings of at most 2048 characters.",
            )
        context[key] = quote(value, safe="")
    return context


def render_context() -> dict[str, str]:
    now = datetime.now(UTC).replace(microsecond=0)
    start = os.environ.get("MICROSOFT_GRAPH_CALENDAR_START") or (
        now - timedelta(days=30)
    ).isoformat().replace("+00:00", "Z")
    end = os.environ.get("MICROSOFT_GRAPH_CALENDAR_END") or (
        now + timedelta(days=90)
    ).isoformat().replace("+00:00", "Z")
    for name, value in (("start", start), ("end", end)):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PrepError(
                "invalid_calendar_window",
                f"Microsoft Graph calendar {name} must be an ISO 8601 date-time.",
            ) from exc
        if parsed.tzinfo is None:
            raise PrepError(
                "invalid_calendar_window",
                f"Microsoft Graph calendar {name} must include a UTC offset.",
            )
    if datetime.fromisoformat(start.replace("Z", "+00:00")) >= datetime.fromisoformat(
        end.replace("Z", "+00:00")
    ):
        raise PrepError(
            "invalid_calendar_window",
            "Microsoft Graph calendar start must be earlier than end.",
        )
    site_search = os.environ.get("MICROSOFT_GRAPH_SITE_SEARCH") or "datalox"
    if not site_search.strip() or len(site_search) > 128:
        raise PrepError(
            "invalid_site_search",
            "MICROSOFT_GRAPH_SITE_SEARCH must be 1 to 128 non-whitespace characters.",
        )
    return {
        "calendar_end": end,
        "calendar_start": start,
        "site_search": site_search,
    }


def validate_rendered_payload(payload: Any, api_url: str) -> int:
    if not isinstance(payload, dict) or payload.get("provider_id") != "microsoft_graph":
        raise PrepError(
            "invalid_probe_config",
            "Rendered config must be a Microsoft Graph probe object.",
        )
    if payload.get("base_url") != api_url:
        raise PrepError(
            "probe_api_url_mismatch",
            "Rendered config base_url does not match MICROSOFT_GRAPH_API_URL.",
        )
    if "fixture_expansions" in payload:
        raise PrepError(
            "unresolved_fixture_expansions",
            "Rendered config must not contain fixture_expansions.",
        )
    requests = payload.get("probe_requests")
    if not isinstance(requests, list) or not (
        BASE_REQUEST_COUNT <= len(requests) <= BASE_REQUEST_COUNT + FIXTURE_REQUEST_COUNT
    ):
        raise PrepError(
            "invalid_probe_request_count",
            "Rendered config must contain 20 base requests and at most 47 linked requests.",
        )
    validate_requests(requests, expected_count=len(requests), concrete=True)
    budget = payload.get("rate_budget")
    if not isinstance(budget, dict) or budget.get("max_requests") != len(requests):
        raise PrepError(
            "invalid_probe_budget",
            "rate_budget.max_requests must exactly equal the rendered request count.",
        )
    if PLACEHOLDER_RE.search(json.dumps(payload, sort_keys=True)):
        raise PrepError(
            "unresolved_probe_placeholder",
            "Rendered probe config still contains a placeholder.",
        )
    return len(requests)


def render_probe(out_path: Path, seed_manifest: Path | None) -> int:
    api_url = configured_api_url()
    require_env("MICROSOFT_GRAPH_ACCESS_TOKEN")
    context = render_context()
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError(
            "invalid_probe_template",
            "Microsoft Graph probe template must be an object.",
        )
    base_requests, fixture_requests = request_sections(payload)
    validate_requests(base_requests, expected_count=BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture_requests, expected_count=FIXTURE_REQUEST_COUNT, concrete=False)
    if seed_manifest is not None:
        context.update(load_seed_context(seed_manifest))

    payload.pop("fixture_expansions")
    payload["base_url"] = api_url
    rendered_requests = substitute(base_requests, context)
    rendered_requests.extend(resolved_values(fixture_requests, context))
    payload["probe_requests"] = rendered_requests
    budget = payload.get("rate_budget")
    if not isinstance(budget, dict):
        raise PrepError("invalid_probe_template", "rate_budget must be an object.")
    budget["max_requests"] = len(rendered_requests)
    count = validate_rendered_payload(payload, api_url)
    write_json(out_path, payload)
    validate_runtime_schema(out_path)
    return count


def validate_template() -> dict[str, int]:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError(
            "invalid_probe_template",
            "Microsoft Graph probe template must be an object.",
        )
    if payload.get("base_url") != CANONICAL_API_URL:
        raise PrepError(
            "invalid_probe_template",
            "Tracked Microsoft Graph base_url must be https://graph.microsoft.com/v1.0.",
        )
    base_requests, fixture_requests = request_sections(payload)
    validate_requests(base_requests, expected_count=BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture_requests, expected_count=FIXTURE_REQUEST_COUNT, concrete=False)
    budget = payload.get("rate_budget")
    if not isinstance(budget, dict) or budget.get("max_requests") != BASE_REQUEST_COUNT:
        raise PrepError(
            "invalid_probe_budget",
            "Tracked max_requests must exactly equal the 20 base requests.",
        )
    validate_runtime_schema(TEMPLATE)
    return {"base": len(base_requests), "fixture": len(fixture_requests)}


def datalox_env() -> dict[str, str]:
    token = require_env("MICROSOFT_GRAPH_ACCESS_TOKEN")
    child_env = os.environ.copy()
    child_env.pop("MICROSOFT_GRAPH_ACCESS_TOKEN", None)
    child_env["MICROSOFT_GRAPH_ACCESS_TOKEN"] = token
    prior = child_env.get("PYTHONPATH")
    child_env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    return child_env


def run_datalox(action: str, args: argparse.Namespace) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        config_path = args.config
        if config_path is None:
            temporary = tempfile.TemporaryDirectory(prefix="datalox_microsoft_graph_config_")
            config_path = Path(temporary.name) / "microsoft_graph.probe.json"
            render_probe(config_path, args.seed_manifest)
        else:
            payload = load_json(config_path)
            validate_rendered_payload(payload, configured_api_url())
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
                raise PrepError(
                    "probe_output_not_empty",
                    f"Probe output must be absent or empty: {args.out}",
                )
            command.extend(["--out", str(args.out)])
        command.append("--json")
        return subprocess.run(command, cwd=ROOT, env=datalox_env(), check=False).returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Prepare Microsoft Graph delegated-auth probes without persisting tokens."
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
            print(
                json.dumps(
                    {
                        "get_only": True,
                        "kind": "microsoft_graph_probe_validation_v0",
                        "request_counts": counts,
                        "status": "completed",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "render":
            count = render_probe(args.out, args.seed_manifest)
            print(
                json.dumps(
                    {
                        "kind": "microsoft_graph_probe_render_v0",
                        "path": str(args.out),
                        "probe_request_count": count,
                        "status": "completed",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.command in {"auth-preflight", "probe"}:
            if args.config is not None and args.seed_manifest is not None:
                raise PrepError(
                    "ambiguous_probe_input",
                    "Use either --config or --seed-manifest, not both.",
                )
            return run_datalox(args.command, args)
        raise PrepError("unknown_command", f"Unknown command: {args.command}")
    except PrepError as exc:
        print(
            json.dumps(
                {
                    "blocker": {"code": exc.code, "message": exc.message},
                    "status": "blocked",
                },
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1


raise SystemExit(main())
PY
