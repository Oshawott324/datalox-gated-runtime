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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(sys.argv[1]).resolve()
sys.argv = [sys.argv[0], *sys.argv[2:]]
TEMPLATE = ROOT / "probes" / "trigger_dev.json"
SRC = ROOT / "src"
CANONICAL_API_URL = "https://api.trigger.dev"
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]*)\}")
FIXTURE_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?")
DOCUMENTED_ROUTES = (
    re.compile(r"/api/v1/runs"),
    re.compile(r"/api/v3/runs/[^/]+"),
    re.compile(r"/api/v1/runs/[^/]+/(?:events|result|trace)"),
    re.compile(r"/api/v1/batches/[^/]+"),
    re.compile(r"/api/v1/batches/[^/]+/results"),
    re.compile(r"/api/v1/deployments"),
    re.compile(r"/api/v1/deployments/latest"),
    re.compile(r"/api/v1/deployments/[^/]+"),
    re.compile(r"/api/v1/errors"),
    re.compile(r"/api/v1/errors/[^/]+"),
    re.compile(r"/api/v1/query/(?:dashboards|schema)"),
    re.compile(r"/api/v1/queues"),
    re.compile(r"/api/v1/queues/[^/]+"),
    re.compile(r"/api/v1/schedules"),
    re.compile(r"/api/v1/schedules/[^/]+"),
    re.compile(r"/api/v1/sessions"),
    re.compile(r"/api/v1/sessions/[^/]+"),
    re.compile(r"/api/v1/timezones"),
    re.compile(r"/api/v1/waitpoints/tokens"),
    re.compile(r"/api/v1/waitpoints/tokens/[^/]+"),
    re.compile(r"/api/v1/projects/[^/]+/envvars/dev"),
    re.compile(r"/api/v1/projects/[^/]+/envvars/dev/[^/]+"),
)
SEED_ID_KEYS = (
    "run_id",
    "batch_id",
    "deployment_id",
    "error_id",
    "queue_param",
    "schedule_id",
    "session_id",
    "waitpoint_id",
    "envvar_name",
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


def require_token(auth_kind: str) -> str:
    if auth_kind == "pat":
        name, prefix = "TRIGGER_ACCESS_TOKEN", "tr_pat_"
    else:
        name, prefix = "TRIGGER_SECRET_KEY", "tr_dev_"
    token = require_env(name)
    if not token.startswith(prefix) or len(token) == len(prefix):
        raise PrepError("invalid_token_prefix", f"{name} must use the {prefix} prefix.")
    return token


def configured_api_url() -> str:
    value = os.environ.get("TRIGGER_API_URL", CANONICAL_API_URL)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise PrepError("invalid_trigger_api_url", "TRIGGER_API_URL is not a valid URL.") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.trigger.dev"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise PrepError(
            "unsupported_trigger_api_url",
            "This probe supports only https://api.trigger.dev; self-hosted Trigger.dev is outside this cloud provider implementation.",
        )
    return CANONICAL_API_URL


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrepError("invalid_json_file", f"Could not read valid JSON from {path}.") from exc


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="utf-8", delete=False) as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary_path = Path(handle.name)
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)


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
    finally:
        if sys.path and sys.path[0] == str(SRC):
            sys.path.pop(0)


def validate_documented_routes(payload: dict[str, Any], *, concrete: bool) -> None:
    requests = payload.get("probe_requests")
    if not isinstance(requests, list) or not requests:
        raise PrepError("invalid_probe_template", "probe_requests must be a non-empty list.")
    for request in requests:
        if not isinstance(request, dict) or request.get("method") != "GET":
            raise PrepError("non_get_probe_request", "Every Trigger.dev capture request must use GET.")
        path = request.get("path")
        query = request.get("query")
        if not isinstance(path, str) or not isinstance(query, dict):
            raise PrepError("invalid_probe_request", "Every probe request needs a string path and object query.")
        route_path = PLACEHOLDER_RE.sub("fixture", path)
        if not any(pattern.fullmatch(route_path) for pattern in DOCUMENTED_ROUTES):
            raise PrepError("undocumented_probe_route", f"Route is not in the offline Trigger.dev catalog: {path}")
        if concrete and (PLACEHOLDER_RE.search(path) or PLACEHOLDER_RE.search(json.dumps(query))):
            raise PrepError("unresolved_probe_placeholder", f"Rendered request still has a placeholder: {path}")


def load_seed_context(path: Path) -> dict[str, str]:
    manifest = load_json(path)
    if not isinstance(manifest, dict) or manifest.get("kind") != "trigger_dev_probe_seed_v0":
        raise PrepError("invalid_seed_manifest", "Seed manifest kind must be trigger_dev_probe_seed_v0.")
    if manifest.get("api_url") != configured_api_url():
        raise PrepError("seed_api_url_mismatch", "Seed manifest api_url does not match TRIGGER_API_URL.")
    if manifest.get("project_ref") != require_env("TRIGGER_PROJECT_REF"):
        raise PrepError("seed_project_mismatch", "Seed manifest project_ref does not match TRIGGER_PROJECT_REF.")
    ids = manifest.get("ids")
    if not isinstance(ids, dict):
        raise PrepError("invalid_seed_manifest", "Seed manifest ids must be an object.")
    if set(ids) != set(SEED_ID_KEYS):
        raise PrepError("invalid_seed_manifest", "Seed manifest must contain exactly the documented fixture IDs and names.")
    context: dict[str, str] = {"project_ref": manifest["project_ref"]}
    for key, value in ids.items():
        if not isinstance(key, str) or not isinstance(value, str) or not value:
            raise PrepError("invalid_seed_manifest", "Seed manifest IDs must be non-empty strings.")
        context[key] = value
    return context


def substitute(value: Any, context: dict[str, str]) -> Any:
    if isinstance(value, str):
        try:
            return value.format_map(context)
        except KeyError as exc:
            raise PrepError("invalid_seed_manifest", f"Seed manifest is missing fixture ID {exc.args[0]!r}.") from exc
    if isinstance(value, list):
        return [substitute(item, context) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, context) for key, item in value.items()}
    return value


def requests_resolved(requests: Any, context: dict[str, str]) -> list[dict[str, Any]]:
    if not isinstance(requests, list):
        raise PrepError("invalid_probe_template", "probe_requests must be a list.")
    rendered: list[dict[str, Any]] = []
    for request in requests:
        if not isinstance(request, dict):
            raise PrepError("invalid_probe_template", "Every probe request must be an object.")
        placeholders = set(PLACEHOLDER_RE.findall(json.dumps(request, sort_keys=True)))
        if placeholders - context.keys():
            continue
        rendered.append(substitute(request, context))
    return rendered


def render_probe(out_path: Path, auth_kind: str, seed_manifest: Path | None) -> int:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict):
        raise PrepError("invalid_probe_template", "Trigger.dev probe template must be an object.")
    payload["base_url"] = configured_api_url()
    fixture_section = payload.pop("fixture_expansions", {})
    pat_section = payload.pop("pat_capture", {})
    context = load_seed_context(seed_manifest) if seed_manifest is not None else {}

    if auth_kind == "pat":
        require_token("pat")
        context.setdefault("project_ref", require_env("TRIGGER_PROJECT_REF"))
        payload["auth_profile"] = "trigger_dev_pat"
        payload["probe_requests"] = requests_resolved(pat_section.get("probe_requests", []), context)
        payload["safe_read_prefixes"] = pat_section.get("safe_read_prefixes", [])
    else:
        require_token("environment")
        requests = list(payload.get("probe_requests", []))
        requests.extend(requests_resolved(fixture_section.get("probe_requests", []), context))
        payload["probe_requests"] = requests

    payload["rate_budget"]["max_requests"] = len(payload["probe_requests"])
    validate_documented_routes(payload, concrete=True)
    write_json(out_path, payload)
    validate_runtime_schema(out_path)
    return len(payload["probe_requests"])


def validate_template() -> dict[str, int]:
    payload = load_json(TEMPLATE)
    if not isinstance(payload, dict) or payload.get("base_url") != CANONICAL_API_URL:
        raise PrepError("invalid_probe_template", "Tracked Trigger.dev base_url must be https://api.trigger.dev.")
    counts: dict[str, int] = {}
    for name, section in (
        ("base", payload),
        ("fixture", payload.get("fixture_expansions", {})),
        ("pat", payload.get("pat_capture", {})),
    ):
        if not isinstance(section, dict):
            raise PrepError("invalid_probe_template", f"{name} request section must be an object.")
        validate_documented_routes({"probe_requests": section.get("probe_requests")}, concrete=False)
        counts[name] = len(section["probe_requests"])
    budget = payload.get("rate_budget", {}).get("max_requests")
    if budget != counts["base"]:
        raise PrepError("invalid_probe_budget", "Tracked max_requests must exactly equal the base request count.")
    validate_runtime_schema(TEMPLATE)
    return counts


SDK_SEED_PROGRAM = r'''
import { batch, configure, envvars, runs, schedules, sessions, tasks, wait } from "@trigger.dev/sdk";

const secretKey = process.env.TRIGGER_SECRET_KEY;
const apiUrl = process.env.TRIGGER_API_URL;
const projectRef = process.env.TRIGGER_PROJECT_REF;
const taskId = process.env.TRIGGER_PROBE_TASK_ID;
const fixtureId = process.env.TRIGGER_PROBE_FIXTURE_ID;
configure({ secretKey, baseURL: apiUrl });

const tags = ["datalox:trigger-dev-probe", `datalox:fixture:${fixtureId}`];
const failureTags = [...tags, "datalox:mode:fail"];
const externalId = `datalox-${fixtureId}`;
const run = await tasks.trigger(taskId, { fixtureId, mode: "complete" }, { tags });
const failingRun = await tasks.trigger(taskId, { fixtureId, mode: "fail" }, { tags: failureTags });
const batchHandle = await batch.triggerByTask(taskId, [
  { payload: { fixtureId, item: 1 }, options: { tags } },
  { payload: { fixtureId, item: 2 }, options: { tags } }
]);
const schedule = await schedules.create({
  task: taskId,
  cron: "0 0 1 1 *",
  externalId,
  deduplicationKey: externalId
});
const waitpoint = await wait.createToken({ timeout: "1h", tags });
const envvarName = `DATALOX_TRIGGER_DEV_PROBE_${fixtureId.replaceAll("-", "_").toUpperCase()}`;
await envvars.upload(projectRef, "dev", { [envvarName]: `fixture-${fixtureId}` });
const session = await sessions.start({
  type: "datalox.probe",
  externalId,
  taskIdentifier: taskId,
  triggerConfig: { basePayload: { fixtureId, mode: "session" }, tags },
  tags,
  metadata: { fixtureId }
});

const POLL_INTERVAL_MS = 1000;
const POLL_TIMEOUT_MS = 120000;
const TERMINAL_RUN_STATUSES = new Set([
  "COMPLETED",
  "FAILED",
  "CRASHED",
  "SYSTEM_FAILURE",
  "CANCELED",
  "INTERRUPTED",
  "TIMED_OUT",
  "EXPIRED"
]);
const FAILURE_RUN_STATUSES = new Set([
  "FAILED",
  "CRASHED",
  "SYSTEM_FAILURE",
  "INTERRUPTED",
  "TIMED_OUT"
]);

function seedFailure(code, message, details = {}) {
  const error = new Error(JSON.stringify({ code, message, details }));
  error.name = "TriggerDevSeedFailure";
  return error;
}

const sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function waitForFailingRun(runId) {
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  let lastStatus = null;
  while (Date.now() < deadline) {
    const currentRun = await runs.retrieve(runId);
    lastStatus = currentRun?.status ?? null;
    if (TERMINAL_RUN_STATUSES.has(lastStatus)) {
      if (!FAILURE_RUN_STATUSES.has(lastStatus)) {
        throw seedFailure(
          "failing_run_unexpected_terminal_status",
          "Trigger.dev failure seed reached a non-failing terminal status.",
          { runId, status: lastStatus }
        );
      }
      return currentRun;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw seedFailure(
    "failing_run_poll_timeout",
    "Trigger.dev failure seed did not reach a terminal status before the polling deadline.",
    { runId, lastStatus, timeoutMs: POLL_TIMEOUT_MS }
  );
}

async function fetchJson(path, label) {
  const response = await fetch(new URL(path, apiUrl), {
    method: "GET",
    headers: { Authorization: `Bearer ${secretKey}` }
  });
  if (!response.ok) {
    throw seedFailure(
      `${label}_read_failed`,
      `Trigger.dev ${label} read failed.`,
      { status: response.status }
    );
  }
  return response.json();
}

async function firstId(path, label) {
  const payload = await fetchJson(path, label);
  const id = payload?.data?.[0]?.id;
  if (typeof id !== "string" || id.length === 0) {
    throw seedFailure(
      `${label}_not_found`,
      `Trigger.dev ${label} discovery returned no ID.`,
      { path }
    );
  }
  return id;
}

function errorGroupReferencesRun(errorGroup, runIds) {
  const referencedIds = [
    errorGroup?.runId,
    errorGroup?.runFriendlyId,
    errorGroup?.latestRunId,
    errorGroup?.latestRunFriendlyId,
    errorGroup?.run?.id,
    errorGroup?.run?.friendlyId,
    errorGroup?.latestRun?.id,
    errorGroup?.latestRun?.friendlyId
  ];
  return referencedIds.some((value) => typeof value === "string" && runIds.has(value));
}

async function findErrorGroup(failedRun) {
  const runIds = new Set(
    [failingRun.id, failedRun?.id, failedRun?.friendlyId].filter(
      (value) => typeof value === "string" && value.length > 0
    )
  );
  const deadline = Date.now() + POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const payload = await fetchJson("/api/v1/errors?page=1&perPage=20", "error_group");
    const errorGroups = Array.isArray(payload?.data) ? payload.data : [];
    const errorGroup = errorGroups.find((item) => errorGroupReferencesRun(item, runIds));
    if (typeof errorGroup?.id === "string" && errorGroup.id.length > 0) {
      return errorGroup.id;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw seedFailure(
    "error_group_poll_timeout",
    "Trigger.dev did not expose an error group for the failing seed run before the polling deadline.",
    { runIds: [...runIds], timeoutMs: POLL_TIMEOUT_MS }
  );
}

const failedRun = await waitForFailingRun(failingRun.id);
const [deploymentId, errorId, queueParam] = await Promise.all([
  firstId("/api/v1/deployments?page=1&perPage=20", "deployment"),
  findErrorGroup(failedRun),
  firstId("/api/v1/queues?page=1&perPage=20", "queue")
]);
if (!run.id || !batchHandle.id || !schedule.id || !waitpoint.id || !session.id) {
  throw new Error("Trigger.dev SDK seed response omitted required IDs");
}
process.stdout.write(JSON.stringify({
  ids: {
    run_id: run.id,
    batch_id: batchHandle.id,
    deployment_id: deploymentId,
    error_id: errorId,
    queue_param: queueParam,
    schedule_id: schedule.id,
    session_id: session.id,
    waitpoint_id: waitpoint.id,
    envvar_name: envvarName
  }
}));
'''


def normalized_fixture_id(value: str | None) -> str:
    fixture_id = value or datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    if not FIXTURE_ID_RE.fullmatch(fixture_id):
        raise PrepError("invalid_fixture_id", "--fixture-id must be 1-32 lowercase letters, digits, or hyphens.")
    return fixture_id


def seed_fixture(out_dir: Path, fixture_id_value: str | None, task_id: str | None) -> dict[str, Any]:
    api_url = configured_api_url()
    require_token("environment")
    project_ref = require_env("TRIGGER_PROJECT_REF")
    task_identifier = task_id or os.environ.get("TRIGGER_PROBE_TASK_ID")
    if not task_identifier:
        raise PrepError("missing_seed_task", "Set TRIGGER_PROBE_TASK_ID or pass --task-id for a deployed seed task.")
    fixture_id = normalized_fixture_id(fixture_id_value)
    if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
        raise PrepError("seed_output_not_empty", f"Seed output directory must be absent or empty: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    child_env = os.environ.copy()
    child_env["TRIGGER_API_URL"] = api_url
    child_env["TRIGGER_PROJECT_REF"] = project_ref
    child_env["TRIGGER_PROBE_TASK_ID"] = task_identifier
    child_env["TRIGGER_PROBE_FIXTURE_ID"] = fixture_id
    try:
        result = subprocess.run(
            ["node", "--input-type=module", "-"],
            input=SDK_SEED_PROGRAM,
            text=True,
            capture_output=True,
            env=child_env,
            check=False,
        )
    except FileNotFoundError as exc:
        raise PrepError("node_unavailable", "node is required for the official @trigger.dev/sdk seed step.") from exc
    if result.returncode != 0:
        raise PrepError("trigger_seed_failed", f"Trigger.dev SDK seed failed: {result.stderr.strip()[:1000]}")
    try:
        sdk_payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise PrepError("trigger_seed_response_invalid", "Trigger.dev SDK seed did not return JSON IDs.") from exc
    ids = sdk_payload.get("ids") if isinstance(sdk_payload, dict) else None
    if not isinstance(ids, dict) or set(SEED_ID_KEYS) != set(ids) or not all(isinstance(v, str) and v for v in ids.values()):
        raise PrepError("trigger_seed_response_invalid", "Trigger.dev SDK seed omitted required string IDs.")
    manifest = {
        "api_url": api_url,
        "created_at": datetime.now(UTC).isoformat(),
        "fixture_id": fixture_id,
        "ids": ids,
        "kind": "trigger_dev_probe_seed_v0",
        "project_ref": project_ref,
        "task_id": task_identifier,
    }
    manifest_path = out_dir / "trigger-dev.seed.json"
    config_path = out_dir / "trigger-dev.probe.json"
    write_json(manifest_path, manifest)
    count = render_probe(config_path, "environment", manifest_path)
    return {
        "kind": "trigger_dev_seed_receipt_v0", "status": "completed",
        "fixture_id": fixture_id, "seed_manifest": str(manifest_path),
        "rendered_probe_config": str(config_path), "probe_request_count": count,
    }


def datalox_env(auth_kind: str) -> dict[str, str]:
    source_name = "TRIGGER_ACCESS_TOKEN" if auth_kind == "pat" else "TRIGGER_SECRET_KEY"
    token = require_token(auth_kind)
    child_env = os.environ.copy()
    child_env.pop("TRIGGER_ACCESS_TOKEN", None)
    child_env.pop("TRIGGER_SECRET_KEY", None)
    child_env[source_name] = token
    prior = child_env.get("PYTHONPATH")
    child_env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    return child_env


def run_datalox(action: str, args: argparse.Namespace) -> int:
    temporary: tempfile.TemporaryDirectory[str] | None = None
    try:
        config_path = args.config
        if config_path is None:
            temporary = tempfile.TemporaryDirectory(prefix="datalox_trigger_dev_config_")
            config_path = Path(temporary.name) / "trigger-dev.probe.json"
            render_probe(config_path, args.auth_kind, args.seed_manifest)
        else:
            validate_runtime_schema(config_path)
            validate_documented_routes(load_json(config_path), concrete=True)
        command = [sys.executable, "-m", "datalox_gated_runtime.cli", "provider", action, "--config", str(config_path)]
        if action == "probe":
            if args.out.exists() and (not args.out.is_dir() or any(args.out.iterdir())):
                raise PrepError("probe_output_not_empty", f"Probe output must be absent or empty: {args.out}")
            command.extend(["--out", str(args.out)])
        command.append("--json")
        return subprocess.run(command, cwd=ROOT, env=datalox_env(args.auth_kind), check=False).returncode
    finally:
        if temporary is not None:
            temporary.cleanup()


def promote(run_dir: Path, out_dir: Path) -> int:
    if not run_dir.is_dir():
        raise PrepError("missing_probe_run", f"Probe run directory does not exist: {run_dir}")
    if out_dir.exists():
        raise PrepError("promote_output_exists", f"Promotion output already exists: {out_dir}")
    env = os.environ.copy()
    env.pop("TRIGGER_ACCESS_TOKEN", None)
    env.pop("TRIGGER_SECRET_KEY", None)
    prior = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) + (os.pathsep + prior if prior else "")
    command = [sys.executable, "-m", "datalox_gated_runtime.cli", "session", "promote", "--run", str(run_dir), "--out", str(out_dir), "--json"]
    return subprocess.run(command, cwd=ROOT, env=env, check=False).returncode


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Prepare Trigger.dev cloud provider probes without persisting credentials.")
    commands = root.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render")
    render.add_argument("--out", type=Path, required=True)
    render.add_argument("--auth-kind", choices=("environment", "pat"), default="environment")
    render.add_argument("--seed-manifest", type=Path)
    commands.add_parser("validate")
    preflight = commands.add_parser("auth-preflight")
    probe = commands.add_parser("probe")
    for item in (preflight, probe):
        item.add_argument("--config", type=Path)
        item.add_argument("--auth-kind", choices=("environment", "pat"), default="environment")
        item.add_argument("--seed-manifest", type=Path)
    probe.add_argument("--out", type=Path, required=True)
    seed = commands.add_parser("seed")
    seed.add_argument("--out-dir", type=Path, required=True)
    seed.add_argument("--fixture-id")
    seed.add_argument("--task-id")
    promotion = commands.add_parser("promote")
    promotion.add_argument("--run", type=Path, required=True)
    promotion.add_argument("--out", type=Path, required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "validate":
            counts = validate_template()
            print(json.dumps({"kind": "trigger_dev_probe_validation_v0", "status": "completed", "request_counts": counts, "get_only": True}, indent=2, sort_keys=True))
            return 0
        if args.command == "render":
            count = render_probe(args.out, args.auth_kind, args.seed_manifest)
            print(json.dumps({"kind": "trigger_dev_probe_render_v0", "status": "completed", "auth_kind": args.auth_kind, "path": str(args.out), "probe_request_count": count}, indent=2, sort_keys=True))
            return 0
        if args.command == "seed":
            print(json.dumps(seed_fixture(args.out_dir, args.fixture_id, args.task_id), indent=2, sort_keys=True))
            return 0
        if args.command in {"auth-preflight", "probe"}:
            if args.config is not None and args.seed_manifest is not None:
                raise PrepError("ambiguous_probe_input", "Use either --config or --seed-manifest, not both.")
            return run_datalox(args.command, args)
        if args.command == "promote":
            return promote(args.run, args.out)
        raise PrepError("unknown_command", f"Unknown command: {args.command}")
    except PrepError as exc:
        print(json.dumps({"status": "blocked", "blocker": {"code": exc.code, "message": exc.message}}, indent=2, sort_keys=True), file=sys.stderr)
        return 1


raise SystemExit(main())
PY
