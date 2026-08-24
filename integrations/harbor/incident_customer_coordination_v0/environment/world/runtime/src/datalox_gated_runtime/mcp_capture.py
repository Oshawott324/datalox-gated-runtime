from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from datalox_gated_runtime.models import McpResponseCase
from datalox_gated_runtime.serializer import dataclass_from_dict, dataclass_to_dict


def canonical_arguments(arguments: dict[str, Any]) -> str:
    return json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class McpCaptureStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, response_case: McpResponseCase) -> None:
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


class McpReplayStore:
    def __init__(self, cases: list[McpResponseCase]) -> None:
        self._cases = {
            (case.tool_name, canonical_arguments(case.arguments)): case for case in cases
        }

    def find(self, tool_name: str, arguments: dict[str, Any]) -> McpResponseCase | None:
        return self._cases.get((tool_name, canonical_arguments(arguments)))


def load_mcp_captures(path: Path) -> list[McpResponseCase]:
    if not path.exists():
        return []

    captures: list[McpResponseCase] = []
    with path.open("r", encoding="utf-8") as file_handle:
        for line_number, raw_line in enumerate(file_handle, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid mcp captures jsonl at line {line_number}") from exc
            try:
                response_case = dataclass_from_dict(McpResponseCase, payload)
                _validate_response_case_shape(response_case)
            except Exception as exc:  # noqa: BLE001
                raise ValueError(f"invalid mcp captures jsonl at line {line_number}") from exc
            captures.append(response_case)
    return captures


def _validate_response_case_shape(response_case: McpResponseCase) -> None:
    if not _non_empty_string(response_case.case_id):
        raise TypeError("case_id must be a non-empty string")
    if not _non_empty_string(response_case.tool_name):
        raise TypeError("tool_name must be a non-empty string")
    if not isinstance(response_case.arguments, dict):
        raise TypeError("arguments must be an object")
    if not isinstance(response_case.result, dict):
        raise TypeError("result must be an object")
    if response_case.evidence_ref is not None and not isinstance(response_case.evidence_ref, str):
        raise TypeError("evidence_ref must be a string")
    if response_case.input_schema is not None and not isinstance(response_case.input_schema, dict):
        raise TypeError("input_schema must be an object")


def _non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())
