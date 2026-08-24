from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.models import ResponseCase

TARGET_ARTIFACT_NAMES = ("gate_config.json", "task.json", "replay_script.json")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def import_source_pack(*, source_dir: Path, out_dir: Path) -> dict[str, Any]:
    source_dir = source_dir.resolve()
    out_dir = out_dir.resolve()
    source_pack = _load_source_pack(source_dir / "source_pack.json")
    source_pack_id = _require_str(source_pack, "source_pack_id", "source_pack.source_pack_id")
    provider = _require_str(source_pack, "provider", "source_pack.provider")
    version = _require_str(source_pack, "version", "source_pack.version")
    records = source_pack.get("records")
    if not isinstance(records, dict):
        raise ValueError("source_pack.records must be an object")

    operations = _load_record_by_name(source_dir, records, "operations")
    response_cases = _load_record_by_name(source_dir, records, "response_cases")
    operations_by_id = {
        operation["id"]: operation
        for operation in operations
        if isinstance(operation.get("id"), str) and operation["id"]
    }

    emitted: list[ResponseCase] = []
    replay_script: list[dict[str, Any]] = []
    skips: dict[str, int] = {}
    seen_keys: set[tuple[str, str, tuple[tuple[str, str], ...]]] = set()

    for response_case in response_cases:
        operation_ref = response_case.get("operation_ref")
        if not isinstance(operation_ref, str) or not operation_ref:
            _record_skip(skips, "missing_operation")
            continue
        operation = operations_by_id.get(operation_ref)
        if operation is None:
            _record_skip(skips, "missing_operation")
            continue

        mapped = _map_response_case(
            source_pack_id=source_pack_id,
            provider=provider,
            version=version,
            operation=operation,
            response_case=response_case,
            skips=skips,
        )
        if mapped is None:
            continue

        replay_key = (
            mapped.method.upper(),
            mapped.path,
            tuple(sorted(mapped.query.items())),
        )
        if replay_key in seen_keys:
            _record_skip(skips, "duplicate_replay_key")
            continue
        seen_keys.add(replay_key)
        emitted.append(mapped)
        replay_script.append(
            {
                "surface": "http",
                "method": mapped.method.upper(),
                "path": mapped.path,
                "query": dict(mapped.query),
                "body": None,
            }
        )

    _refuse_existing_target_artifacts(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    config_id = f"imported_{_slug(provider)}_{_slug(version)}"
    gate_config_payload = {
        "config_id": config_id,
        "metadata": {
            "provenance": "imported_source_pack",
            "source_pack": {
                "source_pack_id": source_pack_id,
                "provider": provider,
                "version": version,
                "path": str(source_dir),
            },
            "skips": skips,
        },
        "response_cases": [asdict(response_case) for response_case in emitted],
        "audit_rules": [],
        "policy": _replay_only_policy(),
    }
    task_payload = {
        "task_id": config_id,
        "title": f"[DRAFT] Imported {provider} source pack",
        "instructions": (
            "Use the imported replay cases as source-grounded API context. "
            "This environment is replay-only and has no live provider access."
        ),
        "success_criteria": [
            "Session check passes.",
            "Replay calls are served from imported source-pack response cases.",
        ],
    }

    _write_json(out_dir / "gate_config.json", gate_config_payload)
    _write_json(out_dir / "task.json", task_payload)
    _write_json(out_dir / "replay_script.json", replay_script)
    load_gate_config(out_dir / "gate_config.json")

    return {
        "out_dir": str(out_dir),
        "source": str(source_dir),
        "config_id": config_id,
        "response_case_count": len(emitted),
        "replay_step_count": len(replay_script),
        "skipped_count": sum(skips.values()),
        "skips": dict(sorted(skips.items())),
    }


def _map_response_case(
    *,
    source_pack_id: str,
    provider: str,
    version: str,
    operation: dict[str, Any],
    response_case: dict[str, Any],
    skips: dict[str, int],
) -> ResponseCase | None:
    method = operation.get("method")
    if not isinstance(method, str) or not method.strip():
        _record_skip(skips, "invalid_operation")
        return None
    method = method.upper()
    if method != "GET":
        _record_skip(skips, "non_get_method")
        return None

    raw_path = operation.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        _record_skip(skips, "invalid_operation")
        return None
    path = _normalize_path(raw_path)
    if _has_template(path):
        _record_skip(skips, "templated_path")
        return None

    status = response_case.get("status")
    if type(status) is not int:
        _record_skip(skips, "non_int_status")
        return None

    body = _select_body(response_case, skips)
    if body is _SKIP:
        return None

    case_id = response_case.get("id")
    if not isinstance(case_id, str) or not case_id.strip():
        _record_skip(skips, "invalid_response_case")
        return None

    return ResponseCase(
        case_id=case_id,
        method=method,
        path=path,
        query={},
        status_code=status,
        body=body,
        evidence_ref=_evidence_ref(
            source_pack_id=source_pack_id,
            provider=provider,
            version=version,
            operation=operation,
            response_case=response_case,
            operation_path_original=raw_path,
        ),
    )


class _Skip:
    pass


_SKIP = _Skip()


def _select_body(response_case: dict[str, Any], skips: dict[str, int]) -> Any:
    response_mode = response_case.get("response_mode")
    if response_mode == "body":
        return response_case.get("body")
    if response_mode == "body_excerpt":
        return _wrap_response_payload(response_case, "body_excerpt")
    if response_mode == "body_shape":
        return _wrap_response_payload(response_case, "body_shape")
    if response_mode == "error_shape":
        return _wrap_response_payload(response_case, "error_shape")
    if response_mode == "no_body":
        return None
    _record_skip(skips, "unsupported_response_mode")
    return _SKIP


def _wrap_response_payload(response_case: dict[str, Any], key: str) -> dict[str, Any]:
    body = {key: response_case.get(key)}
    if "headers" in response_case:
        body["headers"] = response_case["headers"]
    return body


def _evidence_ref(
    *,
    source_pack_id: str,
    provider: str,
    version: str,
    operation: dict[str, Any],
    response_case: dict[str, Any],
    operation_path_original: str,
) -> str:
    evidence = {
        "source_pack_id": source_pack_id,
        "provider": provider,
        "version": version,
        "operation_ref": response_case.get("operation_ref"),
        "operation_id": operation.get("operation_id"),
        "response_case_id": response_case.get("id"),
        "case": response_case.get("case"),
        "response_mode": response_case.get("response_mode"),
        "operation_source_refs": operation.get("source_refs", []),
        "response_source_refs": response_case.get("source_refs", []),
        "operation_path_original": operation_path_original,
    }
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"))


def _load_source_pack(path: Path) -> dict[str, Any]:
    payload = _load_json(path, "invalid source_pack json")
    if not isinstance(payload, dict):
        raise ValueError("source_pack.json must contain an object")
    return payload


def _load_record_by_name(
    source_dir: Path,
    records: dict[str, Any],
    record_name: str,
) -> list[dict[str, Any]]:
    rel_path = records.get(record_name)
    if not isinstance(rel_path, str) or not rel_path:
        raise ValueError(f"source_pack.records.{record_name} must be a non-empty string")
    record_path = _resolve_child(source_dir, rel_path)
    return _load_jsonl_objects(record_path)


def _load_json(path: Path, message: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{message}: {path}: line {exc.lineno}") from exc


def _load_jsonl_objects(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError as exc:
        raise ValueError(f"record file not found: {path}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid jsonl record: {path}: line {line_number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"jsonl record must be an object: {path}: line {line_number}")
        rows.append(row)
    return rows


def _resolve_child(root: Path, rel_path: str) -> Path:
    candidate = (root / rel_path).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"record path escapes source pack: {rel_path}") from exc
    return candidate


def _require_str(raw: dict[str, Any], key: str, path: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _normalize_path(path: str) -> str:
    parsed = urlparse(path)
    if parsed.scheme and parsed.netloc:
        return parsed.path or "/"
    if path.startswith("/"):
        return path
    return f"/{path}"


def _has_template(path: str) -> bool:
    return "{" in path or "}" in path


def _record_skip(skips: dict[str, int], reason: str) -> None:
    skips[reason] = skips.get(reason, 0) + 1


def _refuse_existing_target_artifacts(out_dir: Path) -> None:
    if out_dir.exists() and not out_dir.is_dir():
        raise ValueError(f"target path is not a directory: {out_dir}")
    for artifact_name in TARGET_ARTIFACT_NAMES:
        artifact_path = out_dir / artifact_name
        if artifact_path.exists():
            raise ValueError(f"target directory already contains {artifact_name}: {out_dir}")


def _replay_only_policy() -> dict[str, Any]:
    return {
        "deny": [
            {
                "method": method,
                "path_prefix": "/",
                "reason_code": "imported_source_pack_write_denied",
                "message": "Imported source-pack environments are replay-only.",
            }
            for method in WRITE_METHODS
        ],
        "shadow_write": [],
        "live_capture": [],
    }


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower()
