from __future__ import annotations

import json
import os
from copy import deepcopy
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from uuid import uuid4

from datalox_gated_runtime.models import (
    CallRequest,
    GateDecision,
    LedgerEvent,
    McpDecision,
    McpLedgerEvent,
    _utc_now,
)
from datalox_gated_runtime.query import QueryParams, normalize_query
from datalox_gated_runtime.serializer import dataclass_from_dict, dataclass_to_dict

REDACTED_HEADER_VALUE = "[REDACTED]"
SAFE_EVIDENCE_REQUEST_HEADERS = frozenset(
    {
        "accept",
        "content-type",
    },
)


@dataclass
class SessionLedger:
    events: list[LedgerEvent | McpLedgerEvent] = field(default_factory=list)
    shadow_state: dict[str, Any] = field(
        default_factory=lambda: {"writes": [], "mcp_tool_calls": []}
    )
    path: Path | None = None

    def __post_init__(self) -> None:
        if self.path is None or not self.path.exists():
            return
        loaded_events = load_events(self.path)
        self.events = loaded_events
        self.shadow_state = shadow_state_from_events(loaded_events)

    def record(
        self,
        *,
        request: CallRequest,
        decision: GateDecision,
        response_status_code: int,
        response_body: dict[str, Any] | list[Any] | str | None,
        response_case_id: str | None = None,
        shadow_mutation: dict[str, Any] | None = None,
    ) -> LedgerEvent:
        request = replace(
            request,
            query=deepcopy(request.query),
            body=deepcopy(request.body),
            headers=redact_request_headers(dict(request.headers)),
        )
        event = LedgerEvent(
            event_id=f"evt_{uuid4().hex}",
            created_at=_utc_now(),
            request=request,
            decision=decision,
            response_status_code=response_status_code,
            response_body=deepcopy(response_body),
            response_case_id=response_case_id,
            shadow_mutation=deepcopy(shadow_mutation),
        )
        self.events.append(event)
        if shadow_mutation is not None:
            self.shadow_state["writes"].append(deepcopy(shadow_mutation))
        self._append_to_file(event)
        return event

    def record_mcp(
        self,
        *,
        event_id: str | None = None,
        tool_name: str,
        upstream_name: str,
        upstream_tool_name: str,
        arguments: dict[str, Any],
        decision: McpDecision,
        result: dict[str, Any],
        response_case_id: str | None = None,
        shadow_mutation: dict[str, Any] | None = None,
    ) -> McpLedgerEvent:
        event = McpLedgerEvent(
            surface="mcp",
            event_id=event_id or f"evt_{uuid4().hex}",
            created_at=_utc_now(),
            tool_name=tool_name,
            upstream_name=upstream_name,
            upstream_tool_name=upstream_tool_name,
            arguments=deepcopy(arguments),
            decision=decision,
            result=deepcopy(result),
            response_case_id=response_case_id,
            shadow_mutation=deepcopy(shadow_mutation),
        )
        self.events.append(event)
        if shadow_mutation is not None:
            self.shadow_state["mcp_tool_calls"].append(deepcopy(shadow_mutation))
        self._append_to_file(event)
        return event

    def _append_to_file(self, event: LedgerEvent | McpLedgerEvent) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = (json.dumps(dataclass_to_dict(event), ensure_ascii=False) + "\n").encode(
            "utf-8",
        )
        fd = os.open(
            self.path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND,
            0o644,
        )
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def latest_shadow_write(self, path: str, query: QueryParams) -> dict[str, Any] | None:
        writes = self.shadow_state.get("writes") if isinstance(self.shadow_state, dict) else None
        if not isinstance(writes, list):
            raise ValueError("invalid shadow_state.writes: expected list")

        for shadow_write in reversed(writes):
            if not isinstance(shadow_write, dict):
                continue
            try:
                stored_query = normalize_query(shadow_write.get("query", {}))
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError("invalid shadow_state.writes entry: invalid query") from exc
            if shadow_write.get("path") == path and stored_query == query:
                if "body" not in shadow_write:
                    raise ValueError("invalid shadow_state.writes entry: missing body")
                return shadow_write
        return None


def redact_request_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: value if name.lower() in SAFE_EVIDENCE_REQUEST_HEADERS else REDACTED_HEADER_VALUE
        for name, value in headers.items()
    }


def load_events(path: Path) -> list[LedgerEvent | McpLedgerEvent]:
    """Load event ledger records from JSONL.

    Invalid lines are treated as verifier-blocking corruption evidence and must fail
    loudly; they are not skipped or tolerated.
    """
    if not path.exists():
        return []

    events: list[LedgerEvent | McpLedgerEvent] = []
    with path.open("r", encoding="utf-8") as file_handle:
        for line_number, raw_line in enumerate(file_handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid ledger jsonl at line {line_number}") from exc
            surface = payload.get("surface", "http") if isinstance(payload, dict) else None
            try:
                if surface == "http":
                    event = dataclass_from_dict(LedgerEvent, payload)
                elif surface == "mcp":
                    event = dataclass_from_dict(McpLedgerEvent, payload)
                else:
                    raise ValueError(f"unsupported event surface: {surface}")
            except Exception as exc:  # noqa: BLE001
                raise ValueError(f"invalid ledger jsonl at line {line_number}") from exc
            events.append(event)
    return events


def shadow_state_from_events(events: list[LedgerEvent | McpLedgerEvent]) -> dict[str, Any]:
    shadow_state: dict[str, Any] = {"writes": [], "mcp_tool_calls": []}
    for event in events:
        if event.shadow_mutation is None:
            continue
        if isinstance(event, McpLedgerEvent):
            shadow_state["mcp_tool_calls"].append(event.shadow_mutation)
        else:
            shadow_state["writes"].append(event.shadow_mutation)
    return shadow_state
