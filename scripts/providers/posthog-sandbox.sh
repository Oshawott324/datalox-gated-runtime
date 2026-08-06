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
from urllib.parse import urlsplit


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "posthog.json"
SRC = ROOT / "src"
DEFAULT_API_URL = "https://us.posthog.com/api"
TEMPLATE_API_URL = "https://{posthog_region}.posthog.com/api"
ALLOWED_API_URLS = frozenset(
    {"https://us.posthog.com/api", "https://eu.posthog.com/api"}
)
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
BASE_REQUEST_COUNT = 24
FIXTURE_REQUEST_COUNT = 30
BASE_CONTEXT_PLACEHOLDERS = frozenset(
    {
        "posthog_region",
        "organization_id",
        "project_id",
        "person_search",
        "group_type_index",
        "event_name",
        "date_from",
        "date_to",
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
    value = os.environ.get("POSTHOG_API_URL", DEFAULT_API_URL)
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise PrepError(
            "invalid_posthog_api_url", "POSTHOG_API_URL is not a valid URL."
        ) from exc
    if value not in ALLOWED_API_URLS or parsed.geturl() != value:
        raise PrepError(
            "unsupported_posthog_api_url",
            "POSTHOG_API_URL must be exactly https://us.posthog.com/api or https://eu.posthog.com/api.",
        )
    return value


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrepError("invalid_json_file", f"Could not read valid JSON from {path}.") from exc


def write_json(path: Path, payload: Any) -> None:
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
        try:
            temporary_path.unlink(missing_ok=True)
        except (OSError, UnboundLocalError):
            pass
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
            raise PrepError("non_get_probe_request", "Every PostHog probe request must use GET.")
        if not isinstance(request.get("path"), str) or not isinstance(request.get("query"), dict):
            raise PrepError(
                "invalid_probe_request",
                "Every PostHog probe request needs a string path and object query.",
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
        raise PrepError("invalid_probe_template", "safe_read_prefixes must be a list.")
    resolved: list[Any] = []
    for value in values:
        placeholders = set(PLACEHOLDER_RE.findall(json.dumps(value, sort_keys=True)))
        if placeholders - context.keys():
            continue
        resolved.append(substitute(value, context))
    return resolved


def placeholders(value: Any) -> frozenset[str]:
    return frozenset(PLACEHOLDER_RE.findall(json.dumps(value, sort_keys=True)))


def seed_id_keys(payload: dict[str, Any]) -> frozenset[str]:
    return placeholders(payload) - BASE_CONTEXT_PLACEHOLDERS


def load_seed_context(path: Path, payload: dict[str, Any]) -> dict[str, str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict) or manifest.get("kind") != "posthog_probe_seed_v0":
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest kind must be posthog_probe_seed_v0.",
        )
    ids = manifest.get("ids")
    allowed_keys = seed_id_keys(payload)
    if not isinstance(ids, dict) or not set(ids).issubset(allowed_keys):
        raise PrepError(
            "invalid_seed_manifest",
            "Seed manifest ids must be a subset of the non-environment placeholders in probes/posthog.json.",
        )
    context: dict[str, str] = {}
    for key, value in ids.items():
        if not isinstance(value, str) or not value:
            raise PrepError("invalid_seed_manifest", "Seed manifest IDs must be non-empty strings.")
        context[key] = value
    return context


def validate_auth_profiles(payload: dict[str, Any]) -> None:
    profiles = payload.get("auth_profiles")
    profile_name = payload.get("auth_profile")
    profile = (
        profiles.get(profile_name)
        if isinstance(profiles, dict) and isinstance(profile_name, str)
        else None
    )
    inject = profile.get("inject") if isinstance(profile, dict) else None
    if (
        profile_name != "posthog_bearer"
        or not isinstance(profile, dict)
        or profile.get("kind") != "env_static"
        or not isinstance(inject, list)
        or len(inject) != 1
        or inject[0]
        != {
            "env": "POSTHOG_PERSONAL_API_KEY",
            "in": "header",
            "name": "Authorization",
            "scheme": "Bearer",
        }
    ):
        raise PrepError(
            "invalid_auth_profiles",
            "PostHog auth_profiles must define posthog_bearer using POSTHOG_PERSONAL_API_KEY.",
        )


def validate_rendered_payload(payload: Any, api_url: str) -> int:
    if not isinstance(payload, dict) or payload.get("provider_id") != "posthog":
        raise PrepError("invalid_probe_config", "Rendered config must be a PostHog probe object.")
    validate_auth_profiles(payload)
    if payload.get("base_url") != api_url:
        raise PrepError(
            "probe_api_url_mismatch",
            "Rendered config base_url does not match POSTHOG_API_URL.",
        )
    if "fixture_expansions" in payload:
        raise PrepError(
            "unresolved_fixture_expansions",
            "Rendered config must not contain fixture_expansions.",
        )
    requests = payload.get("probe_requests")
    if not isinstance(requests, list) or not (
        BASE_REQUEST_COUNT
        <= len(requests)
        <= BASE_REQUEST_COUNT + FIXTURE_REQUEST_COUNT
    ):
        raise PrepError(
            "invalid_probe_request_count",
            "Rendered config must contain 24 base requests and at most 30 resolvable linked requests.",
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
    require_env("POSTHOG_PERSONAL_API_KEY")
    now = datetime.now(UTC).replace(microsecond=0)
    context = {
        "organization_id": require_env("POSTHOG_ORGANIZATION_ID"),
        "project_id": require_env("POSTHOG_PROJECT_ID"),
        "person_search": os.environ.get("POSTHOG_PERSON_SEARCH") or "datalox",
        "group_type_index": os.environ.get("POSTHOG_GROUP_TYPE_INDEX") or "0",
        "event_name": os.environ.get("POSTHOG_EVENT_NAME") or "$pageview",
        "date_from": os.environ.get("POSTHOG_DATE_FROM")
        or (now - timedelta(days=14)).isoformat().replace("+00:00", "Z"),
        "date_to": os.environ.get("POSTHOG_DATE_TO")
        or now.isoformat().replace("+00:00", "Z"),
    }
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError("invalid_probe_template", "PostHog probe template must be an object.")
    base_requests, fixture_requests = request_sections(payload)
    validate_requests(base_requests, expected_count=BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture_requests, expected_count=FIXTURE_REQUEST_COUNT, concrete=False)
    validate_auth_profiles(payload)

    if seed_manifest is not None:
        context.update(load_seed_context(seed_manifest, payload))
    unresolved_base = placeholders(base_requests) - context.keys()
    if unresolved_base:
        raise PrepError(
            "missing_seed_ids",
            "Seed manifest ids must provide base request placeholders: "
            + ", ".join(sorted(unresolved_base)),
        )

    payload.pop("fixture_expansions")
    payload["base_url"] = api_url
    rendered_requests = substitute(base_requests, context)
    rendered_requests.extend(resolved_values(fixture_requests, context))
    payload["probe_requests"] = rendered_requests
    payload["safe_read_prefixes"] = resolved_values(payload.get("safe_read_prefixes"), context)
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
        raise PrepError("invalid_probe_template", "PostHog probe template must be an object.")
    if payload.get("base_url") != TEMPLATE_API_URL:
        raise PrepError(
            "invalid_probe_template",
            "Tracked PostHog base_url must be https://{posthog_region}.posthog.com/api.",
        )
    validate_auth_profiles(payload)
    base_requests, fixture_requests = request_sections(payload)
    validate_requests(base_requests, expected_count=BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture_requests, expected_count=FIXTURE_REQUEST_COUNT, concrete=False)
    budget = payload.get("rate_budget")
    if not isinstance(budget, dict) or budget.get("max_requests") != BASE_REQUEST_COUNT:
        raise PrepError(
            "invalid_probe_budget",
            "Tracked max_requests must exactly equal the 24 base requests.",
        )
    validate_runtime_schema(TEMPLATE)
    return {"base": len(base_requests), "fixture": len(fixture_requests)}


def datalox_env() -> dict[str, str]:
    token = require_env("POSTHOG_PERSONAL_API_KEY")
    require_env("POSTHOG_ORGANIZATION_ID")
    require_env("POSTHOG_PROJECT_ID")
    child_env = os.environ.copy()
    child_env.pop("POSTHOG_PERSONAL_API_KEY", None)
    child_env["POSTHOG_PERSONAL_API_KEY"] = token
    prior = child_env.get("PYTHONPATH")
    child_env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    return child_env


def run_datalox(action: str, args: argparse.Namespace) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        config_path = args.config
        if config_path is None:
            temporary = tempfile.TemporaryDirectory(prefix="datalox_posthog_config_")
            config_path = Path(temporary.name) / "posthog.probe.json"
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


def promote(run_dir: Path, out_dir: Path) -> int:
    if not run_dir.is_dir():
        raise PrepError("missing_probe_run", f"Probe run directory does not exist: {run_dir}")
    if out_dir.exists():
        raise PrepError("promote_output_exists", f"Promotion output already exists: {out_dir}")
    env = os.environ.copy()
    env.pop("POSTHOG_PERSONAL_API_KEY", None)
    prior = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    command = [
        sys.executable,
        "-m",
        "datalox_gated_runtime.cli",
        "session",
        "promote",
        "--run",
        str(run_dir),
        "--out",
        str(out_dir),
        "--json",
    ]
    return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Prepare PostHog cloud provider probes without persisting credentials."
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
    promotion = commands.add_parser("promote")
    promotion.add_argument("--run", type=Path, required=True)
    promotion.add_argument("--out", type=Path, required=True)
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
                        "kind": "posthog_probe_validation_v0",
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
                        "kind": "posthog_probe_render_v0",
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
        if args.command == "promote":
            return promote(args.run, args.out)
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
