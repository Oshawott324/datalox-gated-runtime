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
from urllib.parse import urlsplit


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "hubspot_crm.json"
SRC = ROOT / "src"
CANONICAL_API_URL = "https://api.hubapi.com"
BASE_REQUEST_COUNT = 38
FIXTURE_REQUEST_COUNT = 45
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
SEED_ID_KEYS = frozenset(
    {
        "call_id",
        "communication_id",
        "company_id",
        "contact_id",
        "deal_id",
        "deal_line_item_id",
        "deal_pipeline_id",
        "deal_stage_id",
        "email_id",
        "meeting_id",
        "note_id",
        "owner_id",
        "product_id",
        "quote_id",
        "quote_line_item_id",
        "task_id",
        "ticket_id",
        "ticket_pipeline_id",
        "ticket_stage_id",
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
    value = os.environ.get("HUBSPOT_API_URL", CANONICAL_API_URL)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PrepError("invalid_hubspot_api_url", "HUBSPOT_API_URL is not a valid URL.") from exc
    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower() != "api.hubapi.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise PrepError(
            "unsupported_hubspot_api_url",
            "HUBSPOT_API_URL must be https://api.hubapi.com with no port, path, query, fragment, or userinfo.",
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
            "Install repository dependencies or set DATALOX_PYTHON to the project virtualenv Python.",
        ) from exc
    except (OSError, TypeError, ValueError) as exc:
        raise PrepError("invalid_probe_config", f"Probe config failed runtime validation: {path}") from exc
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
                "non_get_probe_request", "Every HubSpot probe request must use GET."
            )
        if not isinstance(request.get("path"), str) or not isinstance(request.get("query"), dict):
            raise PrepError(
                "invalid_probe_request",
                "Every HubSpot probe request needs a string path and object query.",
            )
    if concrete and PLACEHOLDER_RE.search(json.dumps(requests, sort_keys=True)):
        raise PrepError(
            "unresolved_probe_placeholder",
            "Rendered probe requests still contain a placeholder.",
        )


def substitute(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except KeyError as exc:
            raise PrepError(
                "invalid_seed_manifest",
                f"Seed manifest is missing fixture ID {exc.args[0]!r}.",
            ) from exc
    if isinstance(value, list):
        return [substitute(item, context) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, context) for key, item in value.items()}
    return value


def load_seed_context(path: Path) -> dict[str, str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict) or manifest.get("kind") != "hubspot_crm_probe_seed_v0":
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest kind must be hubspot_crm_probe_seed_v0.",
        )
    if manifest.get("base_url") != CANONICAL_API_URL:
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest base_url must be https://api.hubapi.com.",
        )
    ids = manifest.get("ids")
    if not isinstance(ids, dict) or set(ids) != SEED_ID_KEYS:
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest ids must contain exactly the documented HubSpot fixture ID keys.",
        )
    context: dict[str, str] = {}
    for key, value in ids.items():
        if not isinstance(value, str) or not value or any(char in value for char in "/?#{}"):
            raise PrepError(
                "invalid_seed_manifest",
                "Seed manifest IDs must be non-empty path-segment strings.",
            )
        context[key] = value
    return context


def validate_rendered_payload(payload: Any, api_url: str) -> int:
    if not isinstance(payload, dict) or payload.get("provider_id") != "hubspot_crm":
        raise PrepError(
            "invalid_probe_config", "Rendered config must be a HubSpot CRM probe object."
        )
    if payload.get("base_url") != api_url:
        raise PrepError(
            "probe_api_url_mismatch",
            "Rendered config base_url does not match HUBSPOT_API_URL.",
        )
    if "fixture_expansions" in payload:
        raise PrepError(
            "unresolved_fixture_expansions",
            "Rendered config must not contain fixture_expansions.",
        )
    requests = payload.get("probe_requests")
    allowed_counts = {BASE_REQUEST_COUNT, BASE_REQUEST_COUNT + FIXTURE_REQUEST_COUNT}
    if not isinstance(requests, list) or len(requests) not in allowed_counts:
        raise PrepError(
            "invalid_probe_request_count",
            "Rendered config must contain either 38 base requests or 83 seeded requests.",
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
    require_env("HUBSPOT_ACCESS_TOKEN")
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError("invalid_probe_template", "HubSpot probe template must be an object.")
    base_requests, fixture_requests = request_sections(payload)
    validate_requests(base_requests, expected_count=BASE_REQUEST_COUNT, concrete=True)
    validate_requests(
        fixture_requests, expected_count=FIXTURE_REQUEST_COUNT, concrete=False
    )

    payload.pop("fixture_expansions")
    payload["base_url"] = api_url
    rendered_requests = list(base_requests)
    if seed_manifest is not None:
        rendered_requests.extend(substitute(fixture_requests, load_seed_context(seed_manifest)))
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
    if not isinstance(payload, dict) or payload.get("base_url") != CANONICAL_API_URL:
        raise PrepError(
            "invalid_probe_template",
            "Tracked HubSpot base_url must be https://api.hubapi.com.",
        )
    base_requests, fixture_requests = request_sections(payload)
    validate_requests(base_requests, expected_count=BASE_REQUEST_COUNT, concrete=True)
    validate_requests(
        fixture_requests, expected_count=FIXTURE_REQUEST_COUNT, concrete=False
    )
    budget = payload.get("rate_budget")
    if not isinstance(budget, dict) or budget.get("max_requests") != BASE_REQUEST_COUNT:
        raise PrepError(
            "invalid_probe_budget",
            "Tracked max_requests must exactly equal the 38 base requests.",
        )
    validate_runtime_schema(TEMPLATE)
    return {"base": len(base_requests), "fixture": len(fixture_requests)}


def datalox_env() -> dict[str, str]:
    token = require_env("HUBSPOT_ACCESS_TOKEN")
    child_env = os.environ.copy()
    child_env.pop("HUBSPOT_ACCESS_TOKEN", None)
    child_env["HUBSPOT_ACCESS_TOKEN"] = token
    prior = child_env.get("PYTHONPATH")
    child_env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    return child_env


def run_datalox(action: str, args: argparse.Namespace) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        config_path = args.config
        if config_path is None:
            temporary = tempfile.TemporaryDirectory(prefix="datalox_hubspot_crm_config_")
            config_path = Path(temporary.name) / "hubspot-crm.probe.json"
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
            if args.out.exists() and (
                not args.out.is_dir() or any(args.out.iterdir())
            ):
                raise PrepError(
                    "probe_output_not_empty",
                    f"Probe output must be absent or empty: {args.out}",
                )
            command.extend(["--out", str(args.out)])
        command.append("--json")
        return subprocess.run(
            command, cwd=ROOT, env=datalox_env(), check=False
        ).returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Prepare HubSpot developer-test-account CRM probes without persisting credentials."
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
                        "kind": "hubspot_crm_probe_validation_v0",
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
                        "kind": "hubspot_crm_probe_render_v0",
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
