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
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "jira_cloud.json"
SRC = ROOT / "src"
DEFAULT_WORK_DIR = ROOT / ".tmp" / "jira-cloud-sandbox"
DEFAULT_MANIFEST = DEFAULT_WORK_DIR / "ids.json"
DEFAULT_CONFIG = DEFAULT_WORK_DIR / "jira-cloud.probe.rendered.json"
DEFAULT_PROBE_OUT = DEFAULT_WORK_DIR / "probe-run"
BASE_REQUEST_COUNT = 12
FIXTURE_REQUEST_COUNT = 35
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
SITE_HOST_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.atlassian\.net")
ISSUE_SUMMARY = "Datalox Jira Cloud Probe Issue v1"
REQUEST_SUMMARY = "Datalox Jira Service Management Probe Request v1"
JIRA_COMMENT = "Datalox Jira Cloud Probe Comment v1"
REQUEST_COMMENT = "Datalox Jira Service Management Probe Comment v1"
SEED_KEYS = frozenset(
    {
        "account_id",
        "approval_id",
        "group_id",
        "issue_key",
        "issue_type_id",
        "jira_comment_id",
        "project_id",
        "project_key",
        "queue_id",
        "request_comment_id",
        "request_key",
        "request_type_id",
        "service_desk_id",
        "sla_metric_id",
        "status_id",
        "workflow_scheme_id",
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


def configured_site_url() -> str:
    value = require_env("JIRA_CLOUD_SITE_URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PrepError("invalid_jira_cloud_site_url", "JIRA_CLOUD_SITE_URL is not a valid URL.") from exc
    host = (parsed.hostname or "").lower()
    if (
        parsed.scheme.lower() != "https"
        or not SITE_HOST_RE.fullmatch(host)
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise PrepError(
            "unsupported_jira_cloud_site_url",
            "JIRA_CLOUD_SITE_URL must be an HTTPS *.atlassian.net origin with no port, query, fragment, or userinfo.",
        )
    return f"https://{host}"


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrepError("invalid_json_file", f"Could not read valid JSON from {path}.") from exc


def write_json(path: Path, payload: Any) -> None:
    temporary_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="utf-8", delete=False) as handle:
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
    except (ImportError, OSError, TypeError, ValueError) as exc:
        raise PrepError("invalid_probe_config", f"Probe config failed runtime validation: {path}") from exc
    finally:
        if sys.path and sys.path[0] == str(SRC):
            sys.path.pop(0)


def request_sections(payload: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    base = payload.get("probe_requests")
    fixture_section = payload.get("fixture_expansions")
    fixture = fixture_section.get("probe_requests") if isinstance(fixture_section, dict) else None
    if not isinstance(base, list) or not isinstance(fixture, list):
        raise PrepError(
            "invalid_probe_template",
            "probe_requests and fixture_expansions.probe_requests must be lists.",
        )
    return base, fixture


def validate_requests(requests: Any, expected_count: int, *, concrete: bool) -> None:
    if not isinstance(requests, list) or len(requests) != expected_count:
        raise PrepError("invalid_probe_request_count", f"Expected exactly {expected_count} requests.")
    for request in requests:
        if not isinstance(request, dict) or request.get("method") != "GET":
            raise PrepError("non_get_probe_request", "Every Jira Cloud probe request must use GET.")
        if not isinstance(request.get("path"), str) or not isinstance(request.get("query"), dict):
            raise PrepError("invalid_probe_request", "Every request needs a string path and object query.")
    if concrete and PLACEHOLDER_RE.search(json.dumps(requests, sort_keys=True)):
        raise PrepError("unresolved_probe_placeholder", "Rendered requests contain a placeholder.")


def load_seed_context(path: Path) -> dict[str, str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict) or manifest.get("kind") != "jira_cloud_probe_seed_v0":
        raise PrepError("invalid_seed_manifest", "Seed manifest kind must be jira_cloud_probe_seed_v0.")
    ids = manifest.get("ids")
    if not isinstance(ids, dict) or not set(ids).issubset(SEED_KEYS):
        raise PrepError("invalid_seed_manifest", "Seed manifest ids contain an unknown Jira fixture key.")
    context: dict[str, str] = {}
    for key, value in ids.items():
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise PrepError("invalid_seed_manifest", "Seed manifest IDs must be non-empty strings or null.")
        context[key] = value
    return context


def substitute(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        return value.format_map(context)
    if isinstance(value, list):
        return [substitute(item, context) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, context) for key, item in value.items()}
    return value


def resolvable(value: Any, context: dict[str, str]) -> bool:
    return set(PLACEHOLDER_RE.findall(json.dumps(value, sort_keys=True))).issubset(context)


def render_probe(out_path: Path, seed_manifest: Path | None) -> int:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError("invalid_probe_template", "Tracked Jira Cloud probe must be an object.")
    base, fixture = request_sections(payload)
    validate_requests(base, BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture, FIXTURE_REQUEST_COUNT, concrete=False)
    context = load_seed_context(seed_manifest) if seed_manifest is not None else {}
    payload.pop("fixture_expansions")
    payload["base_url"] = configured_site_url()
    payload["probe_requests"] = [*base, *[substitute(item, context) for item in fixture if resolvable(item, context)]]
    payload["rate_budget"]["max_requests"] = len(payload["probe_requests"])
    validate_requests(payload["probe_requests"], len(payload["probe_requests"]), concrete=True)
    write_json(out_path, payload)
    validate_runtime_schema(out_path)
    return len(payload["probe_requests"])


def validate_template() -> dict[str, int]:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict) or payload.get("base_url") != "https://{jira_site}.atlassian.net":
        raise PrepError("invalid_probe_template", "Tracked Jira Cloud base_url is not the expected template.")
    base, fixture = request_sections(payload)
    validate_requests(base, BASE_REQUEST_COUNT, concrete=False)
    validate_requests(fixture, FIXTURE_REQUEST_COUNT, concrete=False)
    if payload.get("rate_budget", {}).get("max_requests") != BASE_REQUEST_COUNT:
        raise PrepError("invalid_probe_budget", "Tracked max_requests must equal the base request count.")
    validate_runtime_schema(TEMPLATE)
    return {"base": len(base), "fixture": len(fixture)}


class JiraClient:
    def __init__(self) -> None:
        self.site_url = configured_site_url()
        email = require_env("JIRA_CLOUD_EMAIL")
        token = require_env("JIRA_CLOUD_API_TOKEN")
        credential = base64.b64encode(f"{email}:{token}".encode()).decode("ascii")
        self.authorization = f"Basic {credential}"

    def get(self, path: str, query: dict[str, Any] | None = None, *, optional: bool = False) -> Any | None:
        query_string = urlencode(query or {}, doseq=True)
        url = f"{self.site_url}{path}" + (f"?{query_string}" if query_string else "")
        request = Request(url, method="GET", headers={"Accept": "application/json", "Authorization": self.authorization})
        try:
            with urlopen(request, timeout=30) as response:
                body = response.read()
                status = response.status
        except HTTPError as exc:
            body = exc.read()
            status = exc.code
        except URLError as exc:
            raise PrepError("jira_cloud_transport_error", f"GET {path} failed before an HTTP response.") from exc
        try:
            payload = json.loads(body) if body else None
        except json.JSONDecodeError as exc:
            if status == 200:
                raise PrepError("invalid_provider_json", f"GET {path} returned non-JSON content.") from exc
            payload = None
        if status == 200:
            return payload
        if optional and status in {403, 404}:
            return None
        message = provider_message(payload)
        suffix = f": {message}" if message else "."
        raise PrepError("jira_cloud_api_error", f"GET {path} returned HTTP {status}{suffix}")


def provider_message(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    if isinstance(payload.get("errorMessage"), str):
        return payload["errorMessage"]
    if isinstance(payload.get("message"), str):
        return payload["message"]
    errors = payload.get("errorMessages")
    if isinstance(errors, list) and errors and isinstance(errors[0], str):
        return errors[0]
    return ""


def jsm_values(client: JiraClient, path: str, query: dict[str, Any] | None = None) -> list[Any]:
    start = 0
    values: list[Any] = []
    for _ in range(100):
        page_query = {**(query or {}), "start": start, "limit": 50}
        page = client.get(path, page_query, optional=True)
        if page is None:
            return values
        page_values = page.get("values") if isinstance(page, dict) else None
        if not isinstance(page_values, list):
            raise PrepError("invalid_provider_json", f"GET {path} did not return a JSM values page.")
        values.extend(page_values)
        if page.get("isLastPage") is True or not page_values:
            return values
        start += len(page_values)
    raise PrepError("pagination_limit_exceeded", f"GET {path} exceeded 100 JSM pages.")


def jira_comments(client: JiraClient, issue_key: str) -> list[Any]:
    start = 0
    comments: list[Any] = []
    for _ in range(100):
        page = client.get(
            f"/rest/api/3/issue/{quote(issue_key, safe='')}/comment",
            {"startAt": start, "maxResults": 100, "orderBy": "created"},
        )
        page_values = page.get("comments") if isinstance(page, dict) else None
        if not isinstance(page_values, list):
            raise PrepError("invalid_provider_json", "Jira comments did not return a comments page.")
        comments.extend(page_values)
        total = page.get("total")
        start += len(page_values)
        if not page_values or (isinstance(total, int) and start >= total):
            return comments
    raise PrepError("pagination_limit_exceeded", "Jira comments exceeded 100 pages.")


def adf_text(value: Any) -> str:
    if isinstance(value, dict):
        return "".join(adf_text(item) for item in value.values())
    if isinstance(value, list):
        return "".join(adf_text(item) for item in value)
    return value if isinstance(value, str) else ""


def exact_issue(client: JiraClient, project_key: str, summary: str) -> dict[str, Any] | None:
    token: str | None = None
    for _ in range(100):
        query: dict[str, Any] = {
            "jql": f'project = "{project_key}" AND summary ~ "\\\"{summary}\\\"" ORDER BY key ASC',
            "maxResults": 50,
            "fields": ["summary", "status", "issuetype"],
        }
        if token:
            query["nextPageToken"] = token
        page = client.get("/rest/api/3/search/jql", query)
        issues = page.get("issues") if isinstance(page, dict) else None
        if not isinstance(issues, list):
            raise PrepError("invalid_provider_json", "Enhanced JQL search did not return issues.")
        matches = [item for item in issues if item.get("fields", {}).get("summary") == summary]
        if matches:
            return sorted(matches, key=lambda item: str(item.get("key", "")))[0]
        token = page.get("nextPageToken") if isinstance(page.get("nextPageToken"), str) else None
        if page.get("isLast") is True or not token:
            return None
    raise PrepError("pagination_limit_exceeded", "Enhanced JQL search exceeded 100 pages.")


def discover_seed() -> dict[str, Any]:
    client = JiraClient()
    project_key = require_env("JIRA_CLOUD_PROJECT_KEY")
    project = client.get(f"/rest/api/3/project/{quote(project_key, safe='')}")
    myself = client.get("/rest/api/3/myself")
    if not isinstance(project.get("key"), str) or not isinstance(project.get("id"), str):
        raise PrepError("invalid_provider_json", "Jira project detail omitted its key or ID.")
    project_key = project["key"]
    ids: dict[str, str | None] = {key: None for key in sorted(SEED_KEYS)}
    ids.update(
        account_id=str(myself.get("accountId")) if myself.get("accountId") else None,
        project_id=str(project.get("id")) if project.get("id") else None,
        project_key=str(project.get("key")) if project.get("key") else project_key,
    )

    issue = exact_issue(client, project_key, ISSUE_SUMMARY)
    request_issue = exact_issue(client, project_key, REQUEST_SUMMARY)
    if issue:
        fields = issue.get("fields", {})
        ids["issue_key"] = str(issue.get("key"))
        ids["issue_type_id"] = str(fields.get("issuetype", {}).get("id")) if fields.get("issuetype", {}).get("id") else None
        ids["status_id"] = str(fields.get("status", {}).get("id")) if fields.get("status", {}).get("id") else None
        comments = jira_comments(client, ids["issue_key"])
        match = next((item for item in comments if JIRA_COMMENT in adf_text(item.get("body"))), None)
        ids["jira_comment_id"] = str(match.get("id")) if match and match.get("id") else None
    else:
        ids["issue_type_id"] = os.environ.get("JIRA_CLOUD_ISSUE_TYPE_ID")

    groups = client.get("/rest/api/3/group/bulk", {"startAt": 0, "maxResults": 50}, optional=True)
    group_values = groups.get("values", []) if isinstance(groups, dict) else []
    selected_group = sorted(group_values, key=lambda item: str(item.get("groupId", "")))[0] if group_values else None
    ids["group_id"] = os.environ.get("JIRA_CLOUD_GROUP_ID") or (
        str(selected_group.get("groupId")) if selected_group and selected_group.get("groupId") else None
    )

    associations = client.get(
        "/rest/api/3/workflowscheme/project",
        {"projectId": [ids["project_id"]]},
        optional=True,
    )
    association_values = associations.get("values", []) if isinstance(associations, dict) else []
    scheme = association_values[0].get("workflowScheme", {}) if association_values else {}
    ids["workflow_scheme_id"] = str(scheme.get("id")) if scheme.get("id") else None

    service_desks = jsm_values(client, "/rest/servicedeskapi/servicedesk")
    service_desk_id = os.environ.get("JIRA_CLOUD_SERVICE_DESK_ID")
    if not service_desk_id:
        matches = [item for item in service_desks if item.get("projectKey") == project_key]
        service_desk_id = str(matches[0].get("id")) if matches else None
    ids["service_desk_id"] = service_desk_id

    if request_issue:
        ids["request_key"] = str(request_issue.get("key"))
        detail = client.get(
            f"/rest/servicedeskapi/request/{quote(ids['request_key'], safe='')}",
            optional=True,
        )
        if isinstance(detail, dict):
            ids["request_type_id"] = str(detail.get("requestTypeId")) if detail.get("requestTypeId") else None
            ids["service_desk_id"] = str(detail.get("serviceDeskId")) if detail.get("serviceDeskId") else ids["service_desk_id"]
    ids["request_type_id"] = os.environ.get("JIRA_CLOUD_REQUEST_TYPE_ID") or ids["request_type_id"]

    if ids["service_desk_id"]:
        queue_path = f"/rest/servicedeskapi/servicedesk/{quote(ids['service_desk_id'], safe='')}/queue"
        queues = jsm_values(client, queue_path, {"includeCount": "true"})
        selected_queue = sorted(queues, key=lambda item: int(item.get("id", 0)))[0] if queues else None
        ids["queue_id"] = os.environ.get("JIRA_CLOUD_QUEUE_ID") or (
            str(selected_queue.get("id")) if selected_queue and selected_queue.get("id") else None
        )

    if ids["request_key"]:
        key = quote(ids["request_key"], safe="")
        comments = jsm_values(client, f"/rest/servicedeskapi/request/{key}/comment")
        match = next((item for item in comments if item.get("body") == REQUEST_COMMENT), None)
        ids["request_comment_id"] = str(match.get("id")) if match and match.get("id") else None
        approvals = jsm_values(client, f"/rest/servicedeskapi/request/{key}/approval")
        if approvals and approvals[0].get("id"):
            ids["approval_id"] = str(sorted(approvals, key=lambda item: int(item.get("id", 0)))[0]["id"])
        slas = jsm_values(client, f"/rest/servicedeskapi/request/{key}/sla")
        sla_ids = []
        for sla in slas:
            self_link = sla.get("_links", {}).get("self")
            if isinstance(self_link, str) and self_link.rstrip("/").rsplit("/", 1)[-1].isdigit():
                sla_ids.append(self_link.rstrip("/").rsplit("/", 1)[-1])
        ids["sla_metric_id"] = sorted(sla_ids, key=int)[0] if sla_ids else None

    return {
        "kind": "jira_cloud_probe_seed_v0",
        "markers": {
            "issue_summary": ISSUE_SUMMARY,
            "jira_comment": JIRA_COMMENT,
            "request_summary": REQUEST_SUMMARY,
            "request_comment": REQUEST_COMMENT,
        },
        "ids": ids,
    }


def auth_env() -> dict[str, str]:
    email = require_env("JIRA_CLOUD_EMAIL")
    token = require_env("JIRA_CLOUD_API_TOKEN")
    encoded = base64.b64encode(f"{email}:{token}".encode()).decode("ascii")
    child = os.environ.copy()
    child.pop("JIRA_CLOUD_EMAIL", None)
    child.pop("JIRA_CLOUD_API_TOKEN", None)
    child["JIRA_CLOUD_BASIC_AUTH_B64"] = encoded
    prior = child.get("PYTHONPATH")
    child["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    return child


def validate_rendered(path: Path) -> None:
    payload = load_json(path)
    requests = payload.get("probe_requests") if isinstance(payload, dict) else None
    if not isinstance(requests, list) or not requests:
        raise PrepError("invalid_probe_config", "Rendered config has no probe requests.")
    validate_requests(requests, len(requests), concrete=True)
    if payload.get("base_url") != configured_site_url():
        raise PrepError("probe_site_url_mismatch", "Rendered config base_url does not match JIRA_CLOUD_SITE_URL.")
    if payload.get("rate_budget", {}).get("max_requests") != len(requests):
        raise PrepError("invalid_probe_budget", "Rendered request count does not match max_requests.")
    if "fixture_expansions" in payload:
        raise PrepError("unresolved_fixture_expansions", "Rendered config contains fixture_expansions.")
    validate_runtime_schema(path)


def run_datalox(action: str, config: Path, out: Path | None) -> int:
    validate_rendered(config)
    command = [
        sys.executable,
        "-m",
        "datalox_gated_runtime.cli",
        "provider",
        action,
        "--config",
        str(config),
        "--json",
    ]
    if out is not None:
        if out.exists():
            raise PrepError("probe_output_exists", "Choose a new --out path; the current path exists.")
        command.extend(["--out", str(out)])
    return subprocess.run(command, cwd=ROOT, env=auth_env(), check=False).returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare a GET-only Jira Cloud/JSM Datalox probe.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="Validate the tracked template locally.")

    render = subparsers.add_parser("render", help="Render a concrete GET-only probe config.")
    render.add_argument("--out", type=Path, default=DEFAULT_CONFIG)
    render.add_argument("--seed-manifest", type=Path)

    discover = subparsers.add_parser("discover", help="Discover exact existing fixture IDs with GETs only.")
    discover.add_argument("--out-manifest", type=Path, default=DEFAULT_MANIFEST)
    discover.add_argument("--out-config", type=Path, default=DEFAULT_CONFIG)

    preflight = subparsers.add_parser("auth-preflight", help="Run Datalox auth preflight.")
    preflight.add_argument("--config", type=Path, default=DEFAULT_CONFIG)

    probe = subparsers.add_parser("probe", help="Run Datalox GET-only live capture.")
    probe.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    probe.add_argument("--out", type=Path, default=DEFAULT_PROBE_OUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "validate":
        counts = validate_template()
        print(json.dumps({"status": "completed", "kind": "jira_cloud_probe_validation_v0", "get_only": True, "request_counts": counts}, sort_keys=True))
        return 0
    if args.command == "render":
        count = render_probe(args.out, args.seed_manifest)
        print(json.dumps({"status": "completed", "kind": "jira_cloud_probe_render_v0", "config": str(args.out), "probe_request_count": count, "get_only": True}, sort_keys=True))
        return 0
    if args.command == "discover":
        manifest = discover_seed()
        write_json(args.out_manifest, manifest)
        count = render_probe(args.out_config, args.out_manifest)
        print(json.dumps({"status": "completed", "kind": "jira_cloud_probe_discovery_v0", "manifest": str(args.out_manifest), "config": str(args.out_config), "probe_request_count": count, "provider_writes": 0}, sort_keys=True))
        return 0
    if args.command in {"auth-preflight", "probe"}:
        return run_datalox(args.command, args.config, args.out if args.command == "probe" else None)
    raise AssertionError(args.command)


try:
    raise SystemExit(main())
except PrepError as exc:
    print(json.dumps({"status": "blocked", "blocker": {"code": exc.code, "message": exc.message}}, sort_keys=True), file=sys.stderr)
    raise SystemExit(1)
PY
