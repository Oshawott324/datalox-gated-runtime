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


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "google_workspace.json"
SRC = ROOT / "src"
APPS = ("drive-calendar", "gmail", "docs", "sheets")
APP_CONTRACTS = {
    "drive-calendar": {
        "base_url": "https://www.googleapis.com",
        "path_prefixes": ("/calendar/v3", "/drive/v3"),
        "provider_id": "google_workspace",
    },
    "gmail": {
        "base_url": "https://gmail.googleapis.com",
        "path_prefixes": ("/gmail/v1/users/me",),
        "provider_id": "google_workspace_gmail",
    },
    "docs": {
        "base_url": "https://docs.googleapis.com",
        "path_prefixes": ("/v1/documents",),
        "provider_id": "google_workspace_docs",
    },
    "sheets": {
        "base_url": "https://sheets.googleapis.com",
        "path_prefixes": ("/v4/spreadsheets",),
        "provider_id": "google_workspace_sheets",
    },
}
FIXTURE_IDS = {
    "calendar_event_id",
    "document_id",
    "drive_folder_id",
    "gmail_draft_id",
    "gmail_message_id",
    "gmail_thread_id",
    "spreadsheet_id",
}
OPAQUE_ID_RE = re.compile(r"[A-Za-z0-9_-]+")
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")


class PrepError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrepError("invalid_json_file", f"Could not read valid JSON from {path}.") from exc


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
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


def runtime_load(path: Path) -> Any:
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


def template_payload() -> dict[str, Any]:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError("invalid_probe_template", "Google Workspace probe template must be an object.")
    return payload


def app_payload(template: dict[str, Any], app: str) -> dict[str, Any]:
    shared_keys = (
        "access_class",
        "auth_profile",
        "auth_profiles",
        "probe_status",
        "rate_budget",
        "tos_note",
    )
    if app == "drive-calendar":
        payload = {
            key: value
            for key, value in template.items()
            if key not in {"oauth", "service_probes"}
        }
    else:
        services = template.get("service_probes")
        if not isinstance(services, dict) or not isinstance(services.get(app), dict):
            raise PrepError("invalid_probe_template", f"service_probes.{app} must be an object.")
        payload = {key: template[key] for key in shared_keys}
        payload.update(services[app])
    return payload


def request_sections(payload: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    base = payload.get("probe_requests")
    fixture_section = payload.get("fixture_expansions", {})
    fixture = fixture_section.get("probe_requests", []) if isinstance(fixture_section, dict) else None
    if not isinstance(base, list) or not isinstance(fixture, list):
        raise PrepError(
            "invalid_probe_template",
            "probe_requests and fixture_expansions.probe_requests must be lists.",
        )
    return base, fixture


def validate_app_payload(payload: dict[str, Any], app: str, *, concrete: bool) -> None:
    contract = APP_CONTRACTS[app]
    if payload.get("provider_id") != contract["provider_id"]:
        raise PrepError("invalid_provider_id", f"Unexpected provider_id for {app}.")
    if payload.get("base_url") != contract["base_url"]:
        raise PrepError("unsupported_google_api_host", f"Unexpected Google API host for {app}.")

    base, fixture = request_sections(payload)
    requests = [*base, *fixture]
    if not requests:
        raise PrepError("invalid_probe_requests", f"{app} must contain at least one request.")
    for request in requests:
        if not isinstance(request, dict) or request.get("method") != "GET":
            raise PrepError("non_get_probe_request", "Every Google Workspace probe request must use GET.")
        path = request.get("path")
        if not isinstance(path, str) or not path.startswith(contract["path_prefixes"]):
            raise PrepError("unsupported_google_api_path", f"Unexpected Google API path for {app}.")
        if not isinstance(request.get("query"), dict):
            raise PrepError("invalid_probe_request", "Every probe request must have an object query.")
    if concrete and PLACEHOLDER_RE.search(json.dumps(requests, sort_keys=True)):
        raise PrepError("unresolved_probe_placeholder", "Rendered probe requests contain a placeholder.")


def load_fixture_context(path: Path) -> dict[str, str]:
    payload = load_json(path)
    if not isinstance(payload, dict) or payload.get("kind") != "google_workspace_probe_fixture_v0":
        raise PrepError(
            "invalid_fixture_manifest",
            "Fixture manifest kind must be google_workspace_probe_fixture_v0.",
        )
    workspace_user = payload.get("workspace_user")
    if not isinstance(workspace_user, str) or "@" not in workspace_user:
        raise PrepError("invalid_fixture_manifest", "Fixture manifest workspace_user must be an email address.")
    ids = payload.get("ids")
    if not isinstance(ids, dict) or set(ids) != FIXTURE_IDS:
        raise PrepError(
            "invalid_fixture_manifest",
            "Fixture manifest ids must exactly match the linked Google Workspace fixture contract.",
        )
    context: dict[str, str] = {}
    for name, value in ids.items():
        if not isinstance(value, str) or not OPAQUE_ID_RE.fullmatch(value):
            raise PrepError(
                "invalid_fixture_manifest",
                f"Fixture ID {name} must use Google opaque-ID URL characters only.",
            )
        context[name] = value
    return context


def substitute(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except KeyError as exc:
            raise PrepError(
                "invalid_fixture_manifest",
                f"Fixture manifest is missing ID {exc.args[0]!r}.",
            ) from exc
    if isinstance(value, list):
        return [substitute(item, context) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, context) for key, item in value.items()}
    return value


def render_probe(app: str, out_path: Path, fixture_manifest: Path | None) -> int:
    payload = app_payload(template_payload(), app)
    base, fixture = request_sections(payload)
    requires_fixture = payload.pop("requires_fixture_manifest", False)
    if requires_fixture and fixture_manifest is None:
        raise PrepError(
            "fixture_manifest_required",
            f"{app} metadata capture requires --fixture-manifest.",
        )

    context = load_fixture_context(fixture_manifest) if fixture_manifest is not None else None
    rendered_base = substitute(base, context) if context is not None else base
    rendered_fixture = substitute(fixture, context) if context is not None else []
    payload.pop("fixture_expansions", None)
    payload["probe_requests"] = [*rendered_base, *rendered_fixture]
    payload["rate_budget"] = {
        **payload["rate_budget"],
        "max_requests": len(payload["probe_requests"]),
    }
    validate_app_payload(payload, app, concrete=True)
    write_json(out_path, payload)
    runtime_load(out_path)
    return len(payload["probe_requests"])


def validate_template() -> dict[str, dict[str, int]]:
    template = template_payload()
    counts: dict[str, dict[str, int]] = {}
    for app in APPS:
        payload = app_payload(template, app)
        validate_app_payload(payload, app, concrete=False)
        base, fixture = request_sections(payload)
        counts[app] = {"base": len(base), "fixture": len(fixture)}
    runtime_load(TEMPLATE)
    return counts


def identify_config_app(path: Path) -> str:
    config = runtime_load(path)
    for app, contract in APP_CONTRACTS.items():
        if config.provider_id == contract["provider_id"]:
            payload = load_json(path)
            if not isinstance(payload, dict):
                break
            validate_app_payload(payload, app, concrete=True)
            return app
    raise PrepError("unsupported_probe_config", "Config is not a supported Google Workspace app probe.")


def resolve_config(
    app: str,
    config_path: Path | None,
    fixture_manifest: Path | None,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if config_path is not None and fixture_manifest is not None:
        raise PrepError("ambiguous_probe_input", "Use either --config or --fixture-manifest, not both.")
    if config_path is not None:
        detected_app = identify_config_app(config_path)
        if detected_app != app:
            raise PrepError("probe_app_mismatch", f"Config belongs to {detected_app}, not {app}.")
        return config_path, None
    temporary = tempfile.TemporaryDirectory(prefix="datalox_google_workspace_")
    rendered = Path(temporary.name) / f"{app}.json"
    render_probe(app, rendered, fixture_manifest)
    return rendered, temporary


def datalox_env() -> dict[str, str]:
    child_env = os.environ.copy()
    prior_pythonpath = child_env.get("PYTHONPATH")
    child_env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior_pythonpath if prior_pythonpath else "")
    return child_env


def run_datalox(
    action: str,
    app: str,
    config_path: Path | None,
    fixture_manifest: Path | None,
    out_dir: Path | None,
) -> int:
    resolved, temporary = resolve_config(app, config_path, fixture_manifest)
    try:
        command = [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "provider",
            action,
            "--config",
            str(resolved),
        ]
        if action == "probe":
            if out_dir is None:
                raise PrepError("missing_probe_out", "probe requires --out.")
            if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
                raise PrepError("probe_output_not_empty", f"Probe output must be absent or empty: {out_dir}")
            command.extend(["--out", str(out_dir)])
        command.append("--json")
        return subprocess.run(command, cwd=ROOT, env=datalox_env(), check=False).returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def add_probe_inputs(parser: argparse.ArgumentParser, *, include_out: bool) -> None:
    parser.add_argument("--app", choices=APPS, default="drive-calendar")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--fixture-manifest", type=Path)
    if include_out:
        parser.add_argument("--out", type=Path, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare Google Workspace OAuth probes without acquiring or persisting bearer tokens."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("validate", help="Validate the template or a rendered config.")
    validate.add_argument("--config", type=Path)

    render = subcommands.add_parser("render", help="Render one official Google API host config.")
    render.add_argument("--app", choices=APPS, required=True)
    render.add_argument("--fixture-manifest", type=Path)
    render.add_argument("--out", type=Path, required=True)

    preflight = subcommands.add_parser("auth-preflight", help="Run Datalox OAuth env preflight.")
    add_probe_inputs(preflight, include_out=False)

    probe = subcommands.add_parser("probe", help="Run one GET-only Datalox live probe.")
    add_probe_inputs(probe, include_out=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "validate":
            if args.config is not None:
                app = identify_config_app(args.config)
                receipt = {
                    "app": app,
                    "get_only": True,
                    "kind": "google_workspace_probe_validation_v0",
                    "status": "completed",
                }
            else:
                receipt = {
                    "get_only": True,
                    "kind": "google_workspace_probe_validation_v0",
                    "request_counts": validate_template(),
                    "status": "completed",
                }
            print(json.dumps(receipt, indent=2, sort_keys=True))
            return 0
        if args.command == "render":
            count = render_probe(args.app, args.out, args.fixture_manifest)
            print(
                json.dumps(
                    {
                        "app": args.app,
                        "kind": "google_workspace_probe_render_v0",
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
            return run_datalox(
                args.command,
                args.app,
                args.config,
                args.fixture_manifest,
                getattr(args, "out", None),
            )
        raise PrepError("unsupported_command", f"Unsupported command: {args.command}")
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
