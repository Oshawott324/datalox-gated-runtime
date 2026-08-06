#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

exec "${DATALOX_PYTHON:-python3}" - "$ROOT_DIR" "$@" <<'PY'
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "freshdesk.json"
SRC = ROOT / "src"
FIXTURE_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")


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


def normalize_base_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PrepError("invalid_freshdesk_base_url", "FRESHDESK_BASE_URL is not a valid URL.") from exc

    host = (parsed.hostname or "").lower()
    labels = host.split(".")
    valid_labels = all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    )
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or host == "freshdesk.com"
        or not host.endswith(".freshdesk.com")
        or not valid_labels
    ):
        raise PrepError(
            "invalid_freshdesk_base_url",
            "FRESHDESK_BASE_URL must be an HTTPS tenant URL under *.freshdesk.com with no path, port, query, fragment, or userinfo.",
        )
    return f"https://{host}"


def configured_base_url() -> str:
    return normalize_base_url(require_env("FRESHDESK_BASE_URL"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        dir=path.parent,
        encoding="utf-8",
        delete=False,
    ) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary_path = Path(handle.name)
    os.replace(temporary_path, path)


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrepError("invalid_json_file", f"Could not read valid JSON from {path}.") from exc


def validate_probe(path: Path) -> Any:
    sys.path.insert(0, str(SRC))
    try:
        from datalox_gated_runtime.provider_probe import load_probe_config

        return load_probe_config(path)
    except ImportError as exc:
        raise PrepError(
            "runtime_import_failed",
            "Install the repository dependencies or set DATALOX_PYTHON to the project virtualenv Python.",
        ) from exc
    finally:
        if sys.path and sys.path[0] == str(SRC):
            sys.path.pop(0)


def format_fixture_value(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except KeyError as exc:
            raise PrepError(
                "invalid_seed_manifest",
                f"Seed manifest is missing fixture value {exc.args[0]!r}.",
            ) from exc
    if isinstance(value, list):
        return [format_fixture_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: format_fixture_value(item, context) for key, item in value.items()}
    return value


def load_seed_context(path: Path, base_url: str) -> dict[str, str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict) or manifest.get("kind") != "freshdesk_probe_seed_v0":
        raise PrepError("invalid_seed_manifest", "Seed manifest kind must be freshdesk_probe_seed_v0.")
    manifest_base_url = manifest.get("base_url")
    if not isinstance(manifest_base_url, str) or normalize_base_url(manifest_base_url) != base_url:
        raise PrepError(
            "seed_tenant_mismatch",
            "Seed manifest base_url does not match FRESHDESK_BASE_URL.",
        )

    context: dict[str, str] = {}
    for section in ("ids", "names"):
        values = manifest.get(section)
        if not isinstance(values, dict):
            raise PrepError("invalid_seed_manifest", f"Seed manifest {section} must be an object.")
        for key, value in values.items():
            if not isinstance(key, str) or not isinstance(value, (str, int)):
                raise PrepError(
                    "invalid_seed_manifest",
                    f"Seed manifest {section} values must be strings or integers.",
                )
            context[key] = str(value)
    return context


def render_probe(out_path: Path, seed_manifest: Path | None = None) -> int:
    base_url = configured_base_url()
    config = load_json(TEMPLATE)
    if not isinstance(config, dict):
        raise PrepError("invalid_probe_template", "Freshdesk probe template must be an object.")

    fixture_section = config.pop("fixture_expansions", {})
    expansions: list[dict[str, Any]] = []
    if seed_manifest is not None:
        context = load_seed_context(seed_manifest, base_url)
        if not isinstance(fixture_section, dict) or not isinstance(
            fixture_section.get("probe_requests"), list
        ):
            raise PrepError(
                "invalid_probe_template",
                "fixture_expansions.probe_requests must be a list.",
            )
        expansions = format_fixture_value(fixture_section["probe_requests"], context)

    probe_requests = config.get("probe_requests")
    if not isinstance(probe_requests, list):
        raise PrepError("invalid_probe_template", "probe_requests must be a list.")
    config["base_url"] = base_url
    config["probe_requests"] = [*probe_requests, *expansions]
    config["rate_budget"]["max_requests"] = len(config["probe_requests"])
    write_json(out_path, config)
    validate_probe(out_path)
    return len(config["probe_requests"])


def ensure_id(payload: Any, resource: str) -> str | int:
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), (str, int)):
        raise PrepError(
            "freshdesk_seed_response_invalid",
            f"Freshdesk {resource} response did not contain an id.",
        )
    return payload["id"]


class FreshdeskClient:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url
        credential = base64.b64encode(f"{api_key}:X".encode()).decode("ascii")
        self.authorization = f"Basic {credential}"

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        data = None
        headers = {
            "Accept": "application/json",
            "Authorization": self.authorization,
            "User-Agent": "datalox-freshdesk-probe-prep/1",
        }
        if payload is not None:
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=30) as response:
                body = response.read()
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:1000]
            raise PrepError(
                "freshdesk_seed_request_failed",
                f"{method} {path} returned HTTP {exc.code}: {body}",
            ) from exc
        except URLError as exc:
            raise PrepError(
                "freshdesk_seed_transport_failed",
                f"{method} {path} failed: {exc.reason}",
            ) from exc

        if not body:
            return None
        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise PrepError(
                "freshdesk_seed_response_invalid",
                f"{method} {path} returned a non-JSON response.",
            ) from exc


def normalized_fixture_id(value: str | None) -> str:
    fixture_id = value or (
        datetime.now(UTC).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    )
    if not FIXTURE_ID_RE.fullmatch(fixture_id):
        raise PrepError(
            "invalid_fixture_id",
            "--fixture-id must be 1-32 lowercase letters, digits, or hyphens and must start and end alphanumeric.",
        )
    return fixture_id


def seed_fixture(out_dir: Path | None, requested_fixture_id: str | None) -> dict[str, Any]:
    base_url = configured_base_url()
    api_key = require_env("FRESHDESK_API_KEY")
    fixture_id = normalized_fixture_id(requested_fixture_id)
    target_dir = out_dir or Path(tempfile.gettempdir()) / "datalox-freshdesk" / fixture_id
    if target_dir.exists():
        if not target_dir.is_dir():
            raise PrepError("seed_output_not_directory", f"Seed output path is not a directory: {target_dir}")
        if any(target_dir.iterdir()):
            raise PrepError("seed_output_not_empty", f"Seed output directory is not empty: {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)

    client = FreshdeskClient(base_url, api_key)
    company_name = f"Datalox Freshdesk Probe {fixture_id}"
    contact_email = f"datalox-freshdesk-{fixture_id}@example.invalid"
    ticket_tag = f"datalox-freshdesk-{fixture_id}"
    solution_title = f"Datalox probe article {fixture_id}"

    company = client.request(
        "POST",
        "/api/v2/companies",
        {
            "description": "Explicit Freshdesk authenticated probe fixture.",
            "name": company_name,
            "note": "Created outside Datalox by scripts/providers/freshdesk-sandbox.sh seed.",
        },
    )
    company_id = ensure_id(company, "company")
    contact = client.request(
        "POST",
        "/api/v2/contacts",
        {
            "company_id": company_id,
            "email": contact_email,
            "name": f"Datalox Probe Contact {fixture_id}",
        },
    )
    contact_id = ensure_id(contact, "contact")
    agent = client.request("GET", "/api/v2/agents/me")
    agent_id = ensure_id(agent, "authenticated agent")

    ticket_payload = {
        "company_id": company_id,
        "description": "Linked state for Freshdesk authenticated GET capture preparation.",
        "priority": 2,
        "requester_id": contact_id,
        "source": 2,
        "status": 2,
        "tags": [ticket_tag],
    }
    ticket = client.request(
        "POST",
        "/api/v2/tickets",
        {**ticket_payload, "subject": f"Datalox Freshdesk parent {fixture_id}"},
    )
    ticket_id = ensure_id(ticket, "parent ticket")
    child_ticket = client.request(
        "POST",
        "/api/v2/tickets",
        {
            **ticket_payload,
            "parent_id": ticket_id,
            "subject": f"Datalox Freshdesk child {fixture_id}",
        },
    )
    child_ticket_id = ensure_id(child_ticket, "child ticket")
    conversation = client.request(
        "POST",
        f"/api/v2/tickets/{ticket_id}/notes",
        {
            "body": "<div>Datalox authenticated provider probe fixture note.</div>",
            "private": True,
        },
    )
    conversation_id = ensure_id(conversation, "conversation")
    time_entry = client.request(
        "POST",
        f"/api/v2/tickets/{ticket_id}/time_entries",
        {
            "agent_id": agent_id,
            "billable": False,
            "note": "Datalox authenticated provider probe fixture time entry.",
            "time_spent": "00:05",
        },
    )
    time_entry_id = ensure_id(time_entry, "time entry")

    category = client.request(
        "POST",
        "/api/v2/solutions/categories",
        {
            "description": "Explicit Freshdesk authenticated probe fixture.",
            "name": f"Datalox Probe Category {fixture_id}",
        },
    )
    solution_category_id = ensure_id(category, "solution category")
    folder = client.request(
        "POST",
        f"/api/v2/solutions/categories/{solution_category_id}/folders",
        {
            "description": "Explicit Freshdesk authenticated probe fixture.",
            "name": f"Datalox Probe Folder {fixture_id}",
            "visibility": 1,
        },
    )
    solution_folder_id = ensure_id(folder, "solution folder")
    article = client.request(
        "POST",
        f"/api/v2/solutions/folders/{solution_folder_id}/articles",
        {
            "description": "Draft solution article for Freshdesk GET capture preparation.",
            "status": 1,
            "tags": [ticket_tag],
            "title": solution_title,
        },
    )
    solution_article_id = ensure_id(article, "solution article")

    manifest = {
        "base_url": base_url,
        "created_at": datetime.now(UTC).isoformat(),
        "fixture_id": fixture_id,
        "ids": {
            "agent_id": agent_id,
            "child_ticket_id": child_ticket_id,
            "company_id": company_id,
            "contact_id": contact_id,
            "conversation_id": conversation_id,
            "solution_article_id": solution_article_id,
            "solution_category_id": solution_category_id,
            "solution_folder_id": solution_folder_id,
            "ticket_id": ticket_id,
            "time_entry_id": time_entry_id,
        },
        "kind": "freshdesk_probe_seed_v0",
        "names": {
            "company_name": company_name,
            "contact_email": contact_email,
            "solution_title": solution_title,
            "ticket_tag": ticket_tag,
        },
    }
    manifest_path = target_dir / "freshdesk.seed.json"
    config_path = target_dir / "freshdesk.probe.json"
    write_json(manifest_path, manifest)
    request_count = render_probe(config_path, manifest_path)
    return {
        "fixture_id": fixture_id,
        "kind": "freshdesk_seed_receipt_v0",
        "probe_request_count": request_count,
        "rendered_probe_config": str(config_path),
        "seed_manifest": str(manifest_path),
        "status": "completed",
    }


def validated_config_path(
    stack: tempfile.TemporaryDirectory[str] | None,
    config_path: Path | None,
    seed_manifest: Path | None,
) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if config_path is not None:
        config = validate_probe(config_path)
        if normalize_base_url(config.base_url) != configured_base_url():
            raise PrepError(
                "probe_tenant_mismatch",
                "Probe config base_url does not match FRESHDESK_BASE_URL.",
            )
        return config_path, stack

    stack = tempfile.TemporaryDirectory(prefix="datalox_freshdesk_config_")
    rendered = Path(stack.name) / "freshdesk.probe.json"
    render_probe(rendered, seed_manifest)
    return rendered, stack


def datalox_env() -> dict[str, str]:
    api_key = require_env("FRESHDESK_API_KEY")
    token = base64.b64encode(f"{api_key}:X".encode()).decode("ascii")
    child_env = os.environ.copy()
    child_env.pop("FRESHDESK_API_KEY", None)
    child_env["FRESHDESK_BASIC_TOKEN"] = token
    prior_pythonpath = child_env.get("PYTHONPATH")
    child_env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior_pythonpath if prior_pythonpath else "")
    return child_env


def run_datalox(
    action: str,
    config_path: Path | None,
    seed_manifest: Path | None,
    out_dir: Path | None,
) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        resolved_config, temporary = validated_config_path(
            temporary,
            config_path,
            seed_manifest,
        )
        command = [
            sys.executable,
            "-m",
            "datalox_gated_runtime.cli",
            "provider",
            action,
            "--config",
            str(resolved_config),
        ]
        if action == "probe":
            if out_dir is None:
                raise PrepError("missing_probe_out", "probe requires --out.")
            if out_dir.exists():
                if not out_dir.is_dir():
                    raise PrepError("probe_output_not_directory", f"Probe output path is not a directory: {out_dir}")
                if any(out_dir.iterdir()):
                    raise PrepError("probe_output_not_empty", f"Probe output directory is not empty: {out_dir}")
            command.extend(["--out", str(out_dir)])
        command.append("--json")
        return subprocess.run(command, cwd=ROOT, env=datalox_env(), check=False).returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare and run Freshdesk authenticated provider probes without persisting credentials."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    render = subcommands.add_parser("render", help="Render a concrete tenant probe config.")
    render.add_argument("--out", type=Path, required=True)
    render.add_argument("--seed-manifest", type=Path)

    validate = subcommands.add_parser("validate", help="Validate a config or rendered template.")
    validate.add_argument("--config", type=Path)
    validate.add_argument("--seed-manifest", type=Path)

    seed = subcommands.add_parser(
        "seed",
        help="Explicitly create linked provider state outside Datalox and render its probe config.",
    )
    seed.add_argument("--fixture-id")
    seed.add_argument("--out-dir", type=Path)

    preflight = subcommands.add_parser(
        "auth-preflight",
        help="Render if needed and run the Datalox auth preflight.",
    )
    preflight.add_argument("--config", type=Path)
    preflight.add_argument("--seed-manifest", type=Path)

    probe = subcommands.add_parser("probe", help="Run the GET-only Datalox provider probe.")
    probe.add_argument("--config", type=Path)
    probe.add_argument("--seed-manifest", type=Path)
    probe.add_argument("--out", type=Path, required=True)
    return parser


def reject_ambiguous_inputs(config: Path | None, seed_manifest: Path | None) -> None:
    if config is not None and seed_manifest is not None:
        raise PrepError(
            "ambiguous_probe_input",
            "Use either --config or --seed-manifest, not both.",
        )


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "render":
            request_count = render_probe(args.out, args.seed_manifest)
            print(
                json.dumps(
                    {
                        "kind": "freshdesk_probe_render_v0",
                        "path": str(args.out),
                        "probe_request_count": request_count,
                        "status": "completed",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "validate":
            reject_ambiguous_inputs(args.config, args.seed_manifest)
            temporary: tempfile.TemporaryDirectory[str] | None = None
            try:
                path, temporary = validated_config_path(temporary, args.config, args.seed_manifest)
                config = validate_probe(path)
                print(
                    json.dumps(
                        {
                            "auth_schema": config.auth_schema,
                            "kind": "freshdesk_probe_validation_v0",
                            "probe_request_count": len(config.probe_requests),
                            "status": "completed",
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
                return 0
            finally:
                if temporary is not None:
                    temporary.cleanup()
        if args.command == "seed":
            print(json.dumps(seed_fixture(args.out_dir, args.fixture_id), indent=2, sort_keys=True))
            return 0
        if args.command == "auth-preflight":
            reject_ambiguous_inputs(args.config, args.seed_manifest)
            return run_datalox("auth-preflight", args.config, args.seed_manifest, None)
        if args.command == "probe":
            reject_ambiguous_inputs(args.config, args.seed_manifest)
            return run_datalox("probe", args.config, args.seed_manifest, args.out)
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
