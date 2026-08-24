from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from tempfile import mkdtemp
from typing import Any
from urllib.parse import urlparse

from datalox_gated_runtime.audit import run_config_audit
from datalox_gated_runtime.auth import (
    AuthBrokerConfig,
    AuthBrokerError,
    AuthInjection,
    AuthProfile,
    parse_auth_broker_config,
    parse_auth_profile_ref,
    preflight_auth,
)
from datalox_gated_runtime.authoring_runtime import AuthoringGatedRuntime
from datalox_gated_runtime.capture import (
    CaptureStore,
    LiveCaptureClient,
    validate_live_capture_prefixes,
)
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.ledger import SessionLedger, load_events, shadow_state_from_events
from datalox_gated_runtime.models import CallRequest, RunExport, path_prefix_matches
from datalox_gated_runtime.policy import GatePolicy
from datalox_gated_runtime.query import QueryParams
from datalox_gated_runtime.session import create_session

ACCESS_CLASSES = frozenset({"approval_gated", "instant_sandbox", "self_hosted", "open_public"})
PAGINATION_KEYS = ("has_more", "next_cursor", "next_page", "offset")
COUNT_KEYS = ("attempted", "captured", "2xx", "4xx", "429", "5xx", "errors")
FORBIDDEN_STATIC_HEADER_NAMES = {"authorization", "cookie", "set-cookie"}
FORBIDDEN_STATIC_HEADER_SUBSTRINGS = ("secret", "token", "api-key", "apikey")


@dataclass(frozen=True)
class ProbeConfigError(ValueError):
    code: str
    message: str


@dataclass(frozen=True)
class ProbeAuthHeader:
    header: str
    env: str
    scheme: str = "Bearer"


@dataclass(frozen=True)
class ProbeRateBudget:
    max_requests: int
    min_interval_seconds: float


@dataclass(frozen=True)
class ProbeRequest:
    method: str
    path: str
    query: QueryParams = field(default_factory=dict)


@dataclass(frozen=True)
class ProbeConfig:
    provider_id: str
    base_url: str
    auth_env: str | None
    auth_header: str
    auth_scheme: str
    extra_auth: list[ProbeAuthHeader]
    auth_profile: str | None
    auth_broker: AuthBrokerConfig
    auth_schema: str
    static_headers: dict[str, str]
    access_class: str
    probe_status: str
    tos_note: str | None
    rate_budget: ProbeRateBudget
    safe_read_prefixes: list[str]
    probe_requests: list[ProbeRequest]


def load_probe_config(path: Path) -> ProbeConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProbeConfigError(
            "invalid_probe_config_json", "Probe config is not valid JSON."
        ) from exc
    if not isinstance(raw, dict):
        raise ProbeConfigError("invalid_probe_config", "Probe config must be an object.")
    return parse_probe_config(raw)


def parse_probe_config(raw: dict[str, Any]) -> ProbeConfig:
    provider_id = _required_str(raw, "provider_id")
    if "/" in provider_id or provider_id in {"", ".", ".."} or provider_id.strip() != provider_id:
        raise ProbeConfigError(
            "invalid_provider_id",
            "provider_id must be usable as a single path segment.",
        )

    base_url = _required_str(raw, "base_url")
    parsed_url = urlparse(base_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.netloc
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise ProbeConfigError("invalid_base_url", "base_url must be an http(s) URL.")

    auth_env = _optional_nullable_str(raw, "auth_env")
    auth_header = _optional_str(raw, "auth_header", default="Authorization")
    auth_scheme = _optional_auth_scheme(raw, "auth_scheme", default="Bearer")
    extra_auth = _parse_extra_auth(raw.get("extra_auth", []), default_scheme=auth_scheme)
    auth_broker = _parse_probe_auth_profiles(raw)
    auth_profile = _parse_probe_auth_profile(raw)
    if auth_profile is not None and _has_legacy_probe_auth(raw):
        raise ProbeConfigError(
            "auth_profile_legacy_mix",
            "auth_profile must not be mixed with legacy auth fields.",
        )
    if auth_profile is not None and auth_profile not in auth_broker.profiles:
        raise ProbeConfigError(
            "unknown_auth_profile",
            "auth_profile references an unknown auth_profiles entry.",
        )
    auth_schema = "none"
    if auth_profile is not None:
        auth_schema = "auth_broker_v0"
    elif auth_env is not None or extra_auth:
        auth_profile = "default"
        auth_broker = AuthBrokerConfig(
            profiles={
                auth_profile: _legacy_probe_auth_profile(
                    auth_env=auth_env,
                    auth_header=auth_header,
                    auth_scheme=auth_scheme,
                    extra_auth=extra_auth,
                )
            }
        )
        auth_schema = "legacy_normalized"
    static_headers = _parse_static_headers(raw.get("static_headers", {}))

    access_class = _required_str(raw, "access_class")
    if access_class not in ACCESS_CLASSES:
        raise ProbeConfigError(
            "invalid_access_class",
            "access_class must be one of approval_gated, instant_sandbox, self_hosted, open_public.",
        )

    probe_status = _required_str(raw, "probe_status")
    if probe_status != "allowed":
        raise ProbeConfigError(
            "probe_status_not_allowed",
            'probe_status must be "allowed" before provider probe can run.',
        )

    rate_budget = _parse_rate_budget(raw.get("rate_budget"))
    safe_read_prefixes = _parse_safe_read_prefixes(raw.get("safe_read_prefixes"))
    probe_requests = _parse_probe_requests(raw.get("probe_requests"))
    if len(probe_requests) > rate_budget.max_requests:
        raise ProbeConfigError(
            "probe_requests_exceed_rate_budget",
            "probe_requests length must not exceed rate_budget.max_requests.",
        )
    for request in probe_requests:
        if not any(path_prefix_matches(request.path, prefix) for prefix in safe_read_prefixes):
            raise ProbeConfigError(
                "probe_request_out_of_safe_prefix",
                f"Probe request {request.path} is outside safe_read_prefixes before session start.",
            )

    tos_note = _optional_nullable_str(raw, "tos_note")
    return ProbeConfig(
        provider_id=provider_id,
        base_url=base_url,
        auth_env=auth_env,
        auth_header=auth_header,
        auth_scheme=auth_scheme,
        extra_auth=extra_auth,
        auth_profile=auth_profile,
        auth_broker=auth_broker,
        auth_schema=auth_schema,
        static_headers=static_headers,
        access_class=access_class,
        probe_status=probe_status,
        tos_note=tos_note,
        rate_budget=rate_budget,
        safe_read_prefixes=safe_read_prefixes,
        probe_requests=probe_requests,
    )


def run_provider_auth_preflight(config_path: Path) -> tuple[int, dict[str, Any]]:
    try:
        config = load_probe_config(config_path)
    except ProbeConfigError as exc:
        return (
            1,
            _blocked_report(
                provider_id=None,
                access_class=None,
                code=exc.code,
                message=exc.message,
                missing_env=[],
            ),
        )

    auth_preflight = _auth_preflight(config)
    missing_env = auth_preflight.missing_env
    if missing_env:
        return (
            1,
            _blocked_report(
                provider_id=config.provider_id,
                access_class=config.access_class,
                code="missing_auth_env",
                message="Required auth environment variables are not set.",
                missing_env=missing_env,
                auth_schema=config.auth_schema,
                auth_preflight=auth_preflight.to_dict(),
            ),
        )

    return (
        0,
        {
            "provider_id": config.provider_id,
            "status": "completed",
            "access_class": config.access_class,
            "auth_schema": config.auth_schema,
            "auth_preflight": auth_preflight.to_dict(),
        },
    )


def run_provider_probe(config_path: Path, out_dir: Path) -> tuple[int, dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        config = load_probe_config(config_path)
    except ProbeConfigError as exc:
        payload = _blocked_report(
            provider_id=None,
            access_class=None,
            code=exc.code,
            message=exc.message,
            missing_env=[],
        )
        _write_report(out_dir, payload)
        return 1, payload

    auth_preflight = _auth_preflight(config)
    missing_env = auth_preflight.missing_env
    if missing_env:
        payload = _blocked_report(
            provider_id=config.provider_id,
            access_class=config.access_class,
            code="missing_auth_env",
            message="Required auth environment variables are not set.",
            missing_env=missing_env,
            auth_schema=config.auth_schema,
            auth_preflight=auth_preflight.to_dict(),
        )
        _write_report(out_dir, payload)
        return 1, payload

    examples_root = Path(mkdtemp(prefix="datalox_probe_example_"))
    prior_examples_dir = os.environ.get("DATALOX_GATE_EXAMPLES_DIR")
    try:
        _write_ephemeral_example(examples_root, config)
        manifest = create_session(
            example=config.provider_id,
            out_dir=out_dir,
            http_port=0,
        )
        gate_config = load_gate_config(Path(manifest.run_dir) / "gate_config.json")
        if gate_config.live is None:
            raise ValueError("provider probe authoring config requires live upstreams")
        validate_live_capture_prefixes(gate_config.policy, gate_config.live)
        capture_client = LiveCaptureClient(gate_config.live)
        runtime = AuthoringGatedRuntime(
            policy=GatePolicy.from_config(gate_config.policy, allow_live=True),
            response_cases=gate_config.response_cases,
            ledger=SessionLedger(path=out_dir / "ledger.jsonl"),
            capture_client=capture_client,
            capture_store=CaptureStore(out_dir / "captures.jsonl"),
        )
        try:
            requests = _drive_probe_requests(config, runtime)
        finally:
            capture_client.close()
        audit_payload = _finalize_run(out_dir)
    finally:
        if prior_examples_dir is None:
            os.environ.pop("DATALOX_GATE_EXAMPLES_DIR", None)
        else:
            os.environ["DATALOX_GATE_EXAMPLES_DIR"] = prior_examples_dir
        shutil.rmtree(examples_root, ignore_errors=True)

    counts = _counts(requests)
    blocker = _probe_blocker(counts)
    payload = {
        "provider_id": config.provider_id,
        "status": "blocked" if blocker is not None else "completed",
        "access_class": config.access_class,
        "auth_schema": config.auth_schema,
        "auth_preflight": auth_preflight.to_dict(),
        "base_url": config.base_url,
        "tos_note": config.tos_note,
        "authoring": {"mode": "direct", "provider_access": True},
        "requests": requests,
        "counts": counts,
        "pagination_signals": _pagination_signals(requests),
        "blocker": blocker,
        "hygiene": _hygiene(config, out_dir),
        "audit": audit_payload,
    }
    _write_report(out_dir, payload)
    return (0 if audit_payload.get("passed") and blocker is None else 1), payload


def rollup_probe_reports(runs_dir: Path) -> dict[str, Any]:
    reports = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(runs_dir.rglob("probe_report.json"))
    ]
    status_histogram = {key: 0 for key in ("2xx", "4xx", "429", "5xx", "errors")}
    blocked: list[dict[str, str]] = []
    pagination: dict[str, list[dict[str, Any]]] = {}
    promotable: list[str] = []
    promoted_envs: list[str] = []
    verify_green: list[str] = []
    access_breakdown: dict[str, int] = {}
    requests_attempted = 0
    responses_captured = 0

    for report in reports:
        provider_id = str(report.get("provider_id") or "")
        access_class = report.get("access_class")
        if isinstance(access_class, str) and access_class:
            access_breakdown[access_class] = access_breakdown.get(access_class, 0) + 1

        counts = report.get("counts", {})
        if isinstance(counts, dict):
            requests_attempted += _int_count(counts, "attempted")
            responses_captured += _int_count(counts, "captured")
            for key in status_histogram:
                status_histogram[key] += _int_count(counts, key)

        blocker = report.get("blocker")
        if isinstance(blocker, dict) and blocker.get("code"):
            blocked.append({"provider_id": provider_id, "reason": str(blocker["code"])})

        signals = report.get("pagination_signals")
        if provider_id and isinstance(signals, list) and signals:
            pagination[provider_id] = signals

        if report.get("status") == "completed" and _int_count(counts, "captured") > 0:
            promotable.append(provider_id)

        promoted_env = report.get("promoted_env")
        if isinstance(promoted_env, str) and promoted_env:
            promoted_envs.append(promoted_env)

        verify_replay = report.get("verify_replay")
        if isinstance(verify_replay, dict) and verify_replay.get("fidelity_passed") is True:
            verify_green.append(provider_id)

    return {
        "providers_probed": len(reports),
        "providers_blocked": blocked,
        "requests_attempted": requests_attempted,
        "responses_captured": responses_captured,
        "status_histogram": status_histogram,
        "pagination_signals_by_provider": pagination,
        "promotable_providers": sorted(provider for provider in promotable if provider),
        "promoted_envs": sorted(promoted_envs),
        "verify_replay_green": sorted(provider for provider in verify_green if provider),
        "access_class_breakdown": dict(sorted(access_breakdown.items())),
    }


def _required_str(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ProbeConfigError(f"invalid_{key}", f"{key} must be a non-empty string.")
    return value


def _optional_str(raw: dict[str, Any], key: str, *, default: str) -> str:
    if key not in raw or raw[key] is None:
        return default
    value = raw[key]
    if not isinstance(value, str) or not value.strip():
        raise ProbeConfigError(f"invalid_{key}", f"{key} must be a non-empty string.")
    return value


def _optional_nullable_str(raw: dict[str, Any], key: str) -> str | None:
    if key not in raw or raw[key] is None:
        return None
    value = raw[key]
    if not isinstance(value, str) or not value.strip():
        raise ProbeConfigError(f"invalid_{key}", f"{key} must be null or a non-empty string.")
    return value


def _optional_auth_scheme(raw: dict[str, Any], key: str, *, default: str) -> str:
    if key not in raw or raw[key] is None:
        return default
    value = raw[key]
    if not isinstance(value, str):
        raise ProbeConfigError(f"invalid_{key}", f"{key} must be a string.")
    return value


def _parse_extra_auth(raw: Any, *, default_scheme: str) -> list[ProbeAuthHeader]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ProbeConfigError("invalid_extra_auth", "extra_auth must be a list.")
    extra_auth: list[ProbeAuthHeader] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ProbeConfigError("invalid_extra_auth", f"extra_auth[{index}] must be an object.")
        header = _required_str(item, "header")
        env = _required_str(item, "env")
        scheme = _optional_auth_scheme(item, "scheme", default=default_scheme)
        extra_auth.append(ProbeAuthHeader(header=header, env=env, scheme=scheme))
    return extra_auth


def _parse_probe_auth_profiles(raw: dict[str, Any]) -> AuthBrokerConfig:
    try:
        return parse_auth_broker_config(raw)
    except AuthBrokerError as exc:
        raise ProbeConfigError(exc.code, exc.message) from exc


def _parse_probe_auth_profile(raw: dict[str, Any]) -> str | None:
    try:
        return parse_auth_profile_ref(raw)
    except AuthBrokerError as exc:
        raise ProbeConfigError(exc.code, exc.message) from exc


def _has_legacy_probe_auth(raw: dict[str, Any]) -> bool:
    return any(
        key in raw and raw[key] not in (None, [], "")
        for key in ("auth_env", "auth_header", "auth_scheme", "extra_auth")
    )


def _legacy_probe_auth_profile(
    *,
    auth_env: str | None,
    auth_header: str,
    auth_scheme: str,
    extra_auth: list[ProbeAuthHeader],
) -> AuthProfile:
    inject: list[AuthInjection] = []
    if auth_env is not None:
        inject.append(
            AuthInjection(
                target="header",
                name=auth_header,
                env=auth_env,
                scheme=auth_scheme,
            )
        )
    inject.extend(
        AuthInjection(target="header", name=auth.header, env=auth.env, scheme=auth.scheme)
        for auth in extra_auth
    )
    return AuthProfile(kind="env_static", inject=tuple(inject))


def _parse_static_headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProbeConfigError("invalid_static_headers", "static_headers must be an object.")
    parsed: dict[str, str] = {}
    for header, value in raw.items():
        if not isinstance(header, str) or not header.strip():
            raise ProbeConfigError(
                "invalid_static_headers",
                "static_headers keys must be non-empty strings.",
            )
        if not isinstance(value, str) or not value.strip():
            raise ProbeConfigError(
                "invalid_static_headers",
                f"static_headers.{header} must be a non-empty string.",
            )
        normalized = header.lower()
        if normalized in FORBIDDEN_STATIC_HEADER_NAMES or any(
            item in normalized for item in FORBIDDEN_STATIC_HEADER_SUBSTRINGS
        ):
            raise ProbeConfigError(
                "invalid_static_headers",
                f"static_headers.{header} must not contain static credentials.",
            )
        parsed[header] = value
    return parsed


def _parse_rate_budget(raw: Any) -> ProbeRateBudget:
    if not isinstance(raw, dict):
        raise ProbeConfigError("invalid_rate_budget", "rate_budget must be an object.")
    max_requests = raw.get("max_requests")
    min_interval_seconds = raw.get("min_interval_seconds")
    if type(max_requests) is not int or max_requests <= 0:
        raise ProbeConfigError("invalid_rate_budget", "rate_budget.max_requests must be positive.")
    if type(min_interval_seconds) not in {int, float} or min_interval_seconds <= 0:
        raise ProbeConfigError(
            "invalid_rate_budget",
            "rate_budget.min_interval_seconds must be positive.",
        )
    return ProbeRateBudget(
        max_requests=max_requests,
        min_interval_seconds=float(min_interval_seconds),
    )


def _parse_safe_read_prefixes(raw: Any) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise ProbeConfigError(
            "invalid_safe_read_prefixes", "safe_read_prefixes must be a non-empty list."
        )
    prefixes: list[str] = []
    for prefix in raw:
        if not isinstance(prefix, str) or not prefix.startswith("/"):
            raise ProbeConfigError(
                "invalid_safe_read_prefix",
                "safe_read_prefixes entries must start with /.",
            )
        if not prefix.strip("/").split("/", 1)[0]:
            raise ProbeConfigError(
                "invalid_safe_read_prefix",
                "safe_read_prefixes entries must have a non-empty first segment.",
            )
        prefixes.append(prefix)
    return prefixes


def _parse_probe_requests(raw: Any) -> list[ProbeRequest]:
    if not isinstance(raw, list) or not raw:
        raise ProbeConfigError("invalid_probe_requests", "probe_requests must be a non-empty list.")
    requests: list[ProbeRequest] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ProbeConfigError(
                "invalid_probe_request", f"probe_requests[{index}] must be an object."
            )
        method = _required_str(item, "method").upper()
        if method != "GET":
            raise ProbeConfigError(
                "probe_request_method_not_allowed", "Probe requests must be GET-only."
            )
        path = _required_str(item, "path")
        if not path.startswith("/"):
            raise ProbeConfigError(
                "invalid_probe_request_path", "probe_request.path must start with /."
            )
        query = _parse_query(item.get("query", {}), index)
        requests.append(ProbeRequest(method=method, path=path, query=query))
    return requests


def _parse_query(raw: Any, index: int) -> QueryParams:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ProbeConfigError(
            "invalid_probe_request_query", f"probe_requests[{index}].query must be an object."
        )
    parsed: QueryParams = {}
    for key, value in sorted(raw.items()):
        if not isinstance(key, str):
            raise ProbeConfigError("invalid_probe_request_query", "query keys must be strings.")
        if isinstance(value, str | int | float | bool):
            parsed[key] = str(value)
            continue
        if (
            isinstance(value, list)
            and value
            and all(isinstance(item, str | int | float | bool) for item in value)
        ):
            parsed[key] = tuple(str(item) for item in value)
            continue
        raise ProbeConfigError(
            "invalid_probe_request_query",
            f"query value for {key} must be scalar or a non-empty list of scalars.",
        )
    return parsed


def _auth_preflight(config: ProbeConfig) -> Any:
    if config.auth_profile is None:
        return preflight_auth(config.auth_broker, [])
    return preflight_auth(config.auth_broker, [config.auth_profile])


def _blocked_report(
    *,
    provider_id: str | None,
    access_class: str | None,
    code: str,
    message: str,
    missing_env: list[str],
    auth_schema: str | None = None,
    auth_preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "provider_id": provider_id,
        "status": "blocked",
        "access_class": access_class,
        "counts": {key: 0 for key in COUNT_KEYS},
        "requests": [],
        "pagination_signals": [],
        "blocker": {
            "code": code,
            "message": message,
            "missing_env": missing_env,
        },
        "hygiene": {"secret_scan_passed": True, "findings": []},
    }
    if auth_schema is not None:
        payload["auth_schema"] = auth_schema
    if auth_preflight is not None:
        payload["auth_preflight"] = auth_preflight
    return payload


def _write_ephemeral_example(examples_root: Path, config: ProbeConfig) -> None:
    example_dir = examples_root / config.provider_id
    example_dir.mkdir(parents=True)
    (example_dir / "task.json").write_text(
        json.dumps(
            {
                "task_id": f"probe_{config.provider_id}",
                "title": f"Probe {config.provider_id}",
                "instructions": "Drive configured safe GET probe requests through the Datalox gate.",
                "success_criteria": ["All configured probe requests are recorded by the gate."],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    live_upstream: dict[str, Any] = {"base_url": config.base_url}
    if config.auth_profile is not None:
        live_upstream["auth_profile"] = config.auth_profile
    if config.static_headers:
        live_upstream["static_headers"] = dict(config.static_headers)
    auth_profiles_payload = _auth_profiles_payload(config.auth_broker)
    gate_config: dict[str, Any] = {
        "config_id": f"probe_{config.provider_id}",
        "response_cases": [],
        "audit_rules": [],
        "metadata": {
            "provider_id": config.provider_id,
            "access_class": config.access_class,
            "probe_status": config.probe_status,
            "auth_schema": config.auth_schema,
        },
        "policy": {
            "deny": [],
            "shadow_write": [],
            "live_capture": [
                {
                    "exact": True,
                    "method": "GET",
                    "path_prefix": f"/{config.provider_id}{request.path}",
                }
                for request in config.probe_requests
            ],
        },
        "live": {"upstreams": {config.provider_id: live_upstream}},
    }
    if auth_profiles_payload:
        gate_config["auth_profiles"] = auth_profiles_payload
    (example_dir / "gate_config.json").write_text(
        json.dumps(gate_config, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    os.environ["DATALOX_GATE_EXAMPLES_DIR"] = str(examples_root)


def _drive_probe_requests(
    config: ProbeConfig, runtime: AuthoringGatedRuntime
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for index, request in enumerate(config.probe_requests[: config.rate_budget.max_requests]):
        if index > 0 and config.rate_budget.min_interval_seconds:
            time.sleep(config.rate_budget.min_interval_seconds)
        gate_path = f"/{config.provider_id}{request.path}"
        try:
            response = runtime.handle(
                CallRequest(method=request.method, path=gate_path, query=request.query)
            )
        except (OSError, ValueError) as exc:
            results.append(
                {
                    "path": request.path,
                    "upstream_path": request.path,
                    "gate_path": gate_path,
                    "query": request.query,
                    "upstream_status": None,
                    "decision": "error",
                    "case_id": None,
                    "error": {"code": "authoring_request_failed", "message": str(exc)},
                    "pagination_signals": [],
                }
            )
            continue
        results.append(
            {
                "path": request.path,
                "upstream_path": request.path,
                "gate_path": gate_path,
                "query": request.query,
                "upstream_status": response.status_code,
                "decision": response.decision.kind,
                "case_id": response.response_case_id,
                "pagination_signals": _pagination_keys(response.body),
            }
        )
    return results


def _finalize_run(run_dir: Path) -> dict[str, Any]:
    gate_config = load_gate_config(run_dir / "gate_config.json")
    events = load_events(run_dir / "ledger.jsonl")
    run_export = RunExport.from_parts(
        events=events,
        shadow_state=shadow_state_from_events(events),
    )
    (run_dir / "run_export.json").write_text(
        json.dumps(asdict(run_export), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    audit = run_config_audit(run_export, gate_config.audit_rules)
    payload = asdict(audit)
    (run_dir / "audit.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return payload


def _counts(requests: list[dict[str, Any]]) -> dict[str, int]:
    counts = {key: 0 for key in COUNT_KEYS}
    counts["attempted"] = len(requests)
    for request in requests:
        status = request.get("upstream_status")
        if request.get("case_id"):
            counts["captured"] += 1
        if not isinstance(status, int):
            counts["errors"] += 1
        elif 200 <= status <= 299:
            counts["2xx"] += 1
        elif status == 429:
            counts["429"] += 1
        elif 400 <= status <= 499:
            counts["4xx"] += 1
        elif 500 <= status <= 599:
            counts["5xx"] += 1
    return counts


def _probe_blocker(counts: dict[str, int]) -> dict[str, Any] | None:
    if counts["attempted"] != counts["captured"]:
        return {
            "code": "probe_capture_incomplete",
            "message": "One or more probe requests did not produce captured response cases.",
        }
    if counts["attempted"] > 0 and counts["2xx"] + counts["4xx"] + counts["429"] == 0:
        return {
            "code": "probe_no_usable_response",
            "message": "Probe captured only 5xx or transport-error responses.",
        }
    return None


def _pagination_signals(requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for request in requests:
        found = request.get("pagination_signals", [])
        if found:
            signals.append({"path": request["path"], "signals": found})
    return signals


def _pagination_keys(value: Any) -> list[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in PAGINATION_KEYS:
                found.add(key)
            if key == "links" and isinstance(item, dict) and "next" in item:
                found.add("links.next")
            found.update(_pagination_keys(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_pagination_keys(item))
    return sorted(found)


def _hygiene(config: ProbeConfig, out_dir: Path) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    secret_values = [
        os.environ[env]
        for env in _auth_env_names(config)
        if env is not None and os.environ.get(env)
    ]
    for path in out_dir.rglob("*"):
        if not path.is_file():
            continue
        data = path.read_bytes()
        for secret in secret_values:
            if secret.encode("utf-8") in data:
                findings.append({"path": str(path), "code": "secret_value_found"})
    return {"secret_scan_passed": not findings, "findings": findings}


def _auth_env_names(config: ProbeConfig) -> list[str]:
    if config.auth_profile is None:
        return []
    profile = config.auth_broker.require_profile(config.auth_profile)
    return [injection.env for injection in profile.inject]


def _auth_profiles_payload(config: AuthBrokerConfig) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for profile_id, profile in config.profiles.items():
        payload[profile_id] = {
            "kind": profile.kind,
            "inject": [_auth_injection_payload(injection) for injection in profile.inject],
        }
    return payload


def _auth_injection_payload(injection: AuthInjection) -> dict[str, str]:
    payload = {
        "env": injection.env,
        "in": injection.target,
        "name": injection.name,
    }
    if injection.scheme is not None:
        payload["scheme"] = injection.scheme
    return payload


def _write_report(out_dir: Path, payload: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "probe_report.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _int_count(counts: Any, key: str) -> int:
    if not isinstance(counts, dict):
        return 0
    value = counts.get(key, 0)
    return value if type(value) is int else 0
