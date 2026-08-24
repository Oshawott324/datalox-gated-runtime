from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx

from datalox_gated_runtime.auth import (
    AuthBrokerConfig,
    AuthBrokerError,
    apply_auth_profile,
    preflight_auth,
)
from datalox_gated_runtime.models import (
    CallRequest,
    LiveGateConfig,
    PolicyConfig,
    ResponseCase,
    _utc_now,
)
from datalox_gated_runtime.query import iter_query_items
from datalox_gated_runtime.serializer import dataclass_from_dict, dataclass_to_dict


@dataclass(frozen=True)
class LiveCaptureError(Exception):
    code: str
    message: str


class CaptureStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, response_case: ResponseCase) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = (json.dumps(dataclass_to_dict(response_case), ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)


def load_captures(path: Path) -> list[ResponseCase]:
    if not path.exists():
        return []

    captures: list[ResponseCase] = []
    with path.open("r", encoding="utf-8") as file_handle:
        for line_number, raw_line in enumerate(file_handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid captures jsonl at line {line_number}") from exc
            try:
                captures.append(dataclass_from_dict(ResponseCase, payload))
            except Exception as exc:  # noqa: BLE001
                raise ValueError(f"invalid captures jsonl at line {line_number}") from exc
    return captures


class LiveCaptureClient:
    def __init__(
        self,
        live: LiveGateConfig,
        *,
        auth_profiles: AuthBrokerConfig | None = None,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.live = live
        self.auth_profiles = auth_profiles or live.auth_profiles
        for upstream_name, upstream in live.upstreams.items():
            missing = []
            if upstream.auth_profile is not None:
                proof = preflight_auth(self.auth_profiles, [upstream.auth_profile])
                missing = proof.missing_env
            else:
                missing = [
                    env
                    for env in [upstream.auth_env, *(auth.env for auth in upstream.extra_auth)]
                    if env is not None and os.environ.get(env) is None
                ]
            if missing:
                raise ValueError(
                    f"live upstream {upstream_name} requires env var(s) {', '.join(missing)}"
                )
        self._client = httpx.Client(timeout=timeout, transport=transport)

    def fetch(self, request: CallRequest) -> ResponseCase:
        if request.normalized_method() != "GET":
            raise LiveCaptureError(
                "live_method_not_allowed",
                "Live capture only supports GET requests.",
            )

        upstream_name = first_path_segment(request.path)
        if upstream_name is None or upstream_name not in self.live.upstreams:
            raise LiveCaptureError(
                "live_upstream_not_configured",
                f"Live upstream is not configured for path segment: {upstream_name or ''}",
            )

        upstream = self.live.upstreams[upstream_name]
        upstream_path = upstream_relative_path(request.path)
        headers = {"accept": "application/json"}
        headers.update(upstream.static_headers)
        query = dict(request.query)
        if upstream.auth_profile is not None:
            try:
                headers, query = apply_auth_profile(
                    self.auth_profiles.require_profile(upstream.auth_profile),
                    headers=headers,
                    query=query,
                )
            except AuthBrokerError as exc:
                raise LiveCaptureError(exc.code, exc.message) from exc
        else:
            if upstream.auth_env is not None:
                token = os.environ[upstream.auth_env]
                headers[upstream.auth_header] = _auth_header_value(upstream.auth_scheme, token)
            for auth in upstream.extra_auth:
                headers[auth.header] = _auth_header_value(auth.scheme, os.environ[auth.env])

        try:
            response = self._client.get(
                f"{upstream.base_url.rstrip('/')}{upstream_path}",
                params=list(iter_query_items(query)),
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise LiveCaptureError("live_upstream_unreachable", str(exc)) from exc

        body = _response_body(response)
        return ResponseCase(
            case_id=f"cap_{uuid4().hex}",
            method="GET",
            path=request.path,
            query=dict(request.query),
            status_code=response.status_code,
            body=body,
            evidence_ref=f"live:{upstream_name}:{_utc_now()}",
        )

    def close(self) -> None:
        self._client.close()


def validate_live_capture_prefixes(policy: PolicyConfig | None, live: LiveGateConfig) -> None:
    if policy is None:
        return
    unmapped = sorted(
        {
            segment
            for rule in policy.live_capture
            if (segment := first_path_segment(rule.path_prefix)) not in live.upstreams
        }
    )
    if unmapped:
        raise ValueError("unmapped live_capture prefix upstream segment(s): " + ", ".join(unmapped))


def first_path_segment(path: str) -> str | None:
    stripped = path.strip("/")
    if not stripped:
        return None
    return stripped.split("/", 1)[0]


def upstream_relative_path(path: str) -> str:
    stripped = path.lstrip("/")
    _upstream_name, separator, upstream_path = stripped.partition("/")
    if not stripped or not separator:
        return "/"
    return f"/{upstream_path}"


def _auth_header_value(scheme: str, value: str) -> str:
    return f"{scheme} {value}" if scheme else value


def _response_body(response: httpx.Response) -> dict[str, Any] | list[Any] | str | None:
    content_type = response.headers.get("content-type", "")
    if "json" in content_type.lower():
        try:
            return response.json()
        except ValueError as exc:
            raise LiveCaptureError(
                "live_upstream_invalid_response",
                "Live upstream returned invalid JSON response.",
            ) from exc
    return response.text
