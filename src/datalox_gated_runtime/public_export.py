from __future__ import annotations

import json
import math
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PUBLIC_EXPORT_SCHEMA = "datalox_public_run_export_v1"
_HTTP_EVENT_FIELDS = frozenset(
    {
        "event_id",
        "created_at",
        "request",
        "decision",
        "response_status_code",
        "response_body",
        "surface",
        "response_case_id",
        "shadow_mutation",
    }
)
_MCP_EVENT_FIELDS = frozenset(
    {
        "surface",
        "event_id",
        "created_at",
        "tool_name",
        "upstream_name",
        "upstream_tool_name",
        "arguments",
        "decision",
        "result",
        "response_case_id",
        "shadow_mutation",
    }
)
_WORLD_FIELDS = frozenset(
    {
        "schema_version",
        "world_id",
        "bundle",
        "episode_id",
        "simulation_time",
        "state",
        "events",
        "scheduled_events",
        "artifacts",
        "conversations",
        "handoffs",
        "verification",
        "verifier_events",
    }
)
_MACHINE_PATH = re.compile(
    r"(?:^|[\s\"'=(])(?:file://|[A-Za-z]:[\\/]|/(?:Users|home|private|tmp|root|var/folders)/)"
)


def build_public_run_export(
    run_dir: Path,
    example: str,
    audit: dict[str, Any],
) -> dict[str, Any]:
    """Build a fail-closed projection from typed agent-visible run records."""

    run_dir = Path(run_dir).resolve()
    raw_export = _load_json_object(run_dir / "run_export.json")
    _exact_fields(
        raw_export,
        required={"run_id", "created_at", "events", "shadow_state"},
        optional={"world"},
        path="run_export",
    )
    task = _public_task(_load_json_object(run_dir / "task.json"))
    payload: dict[str, Any] = {
        "schema_version": PUBLIC_EXPORT_SCHEMA,
        "run_id": _string(raw_export["run_id"], "run_export.run_id"),
        "created_at": _string(raw_export["created_at"], "run_export.created_at"),
        "published_at": datetime.now(UTC).isoformat(),
        "example": _string(example, "example"),
        "task": task,
        "events": _public_events(raw_export["events"]),
        "verification": _public_verification(audit),
    }
    if "world" in raw_export:
        payload["world"] = _public_world(raw_export["world"])

    _validate_public_json(payload, path="public_export")
    _reject_machine_paths(payload, run_dir=run_dir, path="public_export")
    (run_dir / "public_run_export.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, allow_nan=False),
        encoding="utf-8",
    )
    return payload


def _public_task(raw: Any) -> dict[str, Any]:
    task = _object(raw, "task")
    _exact_fields(
        task,
        required={"task_id", "title", "instructions", "success_criteria"},
        path="task",
    )
    return {
        "task_id": _string(task["task_id"], "task.task_id"),
        "title": _string(task["title"], "task.title"),
        "instructions": _string(task["instructions"], "task.instructions"),
        "success_criteria": _string_list(
            task["success_criteria"],
            "task.success_criteria",
        ),
    }


def _public_events(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("run_export.events must be a list")
    return [_public_event(event, index) for index, event in enumerate(raw)]


def _public_event(raw: Any, index: int) -> dict[str, Any]:
    path = f"run_export.events[{index}]"
    event = _object(raw, path)
    surface = event.get("surface", "http")
    if surface == "http":
        _exact_fields(event, required=_HTTP_EVENT_FIELDS, path=path)
        request = _object(event["request"], f"{path}.request")
        _exact_fields(
            request,
            required={"method", "path", "query", "body", "headers", "operation_id"},
            # Wire metadata remains in the controller-only provider run export. The
            # public projection omits authorities just as it omits request headers,
            # because both can identify a private tenant or internal deployment.
            optional={"scheme", "authority", "raw_body_sha256"},
            path=f"{path}.request",
        )
        decision = _public_decision(
            event["decision"],
            path=f"{path}.decision",
            include_rule_id=True,
        )
        return {
            "surface": "http",
            "event_id": _string(event["event_id"], f"{path}.event_id"),
            "created_at": _string(event["created_at"], f"{path}.created_at"),
            "request": {
                "method": _string(request["method"], f"{path}.request.method"),
                "path": _string(request["path"], f"{path}.request.path"),
                "query": _string_map(request["query"], f"{path}.request.query"),
                "body": _validate_public_json(request["body"], path=f"{path}.request.body"),
                "operation_id": _optional_string(
                    request["operation_id"],
                    f"{path}.request.operation_id",
                ),
            },
            "decision": decision,
            "response_status_code": _integer(
                event["response_status_code"],
                f"{path}.response_status_code",
            ),
            "response_body": _validate_public_json(
                event["response_body"],
                path=f"{path}.response_body",
            ),
            "response_case_id": _optional_string(
                event["response_case_id"],
                f"{path}.response_case_id",
            ),
        }
    if surface == "mcp":
        _exact_fields(event, required=_MCP_EVENT_FIELDS, path=path)
        return {
            "surface": "mcp",
            "event_id": _string(event["event_id"], f"{path}.event_id"),
            "created_at": _string(event["created_at"], f"{path}.created_at"),
            "tool_name": _string(event["tool_name"], f"{path}.tool_name"),
            "upstream_name": _string(event["upstream_name"], f"{path}.upstream_name"),
            "upstream_tool_name": _string(
                event["upstream_tool_name"],
                f"{path}.upstream_tool_name",
            ),
            "arguments": _validate_public_json(
                event["arguments"],
                path=f"{path}.arguments",
            ),
            "decision": _public_decision(
                event["decision"],
                path=f"{path}.decision",
                include_rule_id=False,
            ),
            "result": _validate_public_json(event["result"], path=f"{path}.result"),
            "response_case_id": _optional_string(
                event["response_case_id"],
                f"{path}.response_case_id",
            ),
        }
    raise ValueError(f"{path}.surface is unsupported")


def _public_decision(
    raw: Any,
    *,
    path: str,
    include_rule_id: bool,
) -> dict[str, Any]:
    decision = _object(raw, path)
    required = {"kind", "reason_code", "message"}
    if include_rule_id:
        required.add("rule_id")
    _exact_fields(decision, required=required, path=path)
    result = {
        "kind": _string(decision["kind"], f"{path}.kind"),
        "reason_code": _string(decision["reason_code"], f"{path}.reason_code"),
        "message": _string(decision["message"], f"{path}.message"),
    }
    if include_rule_id:
        result["rule_id"] = _optional_string(decision["rule_id"], f"{path}.rule_id")
    return result


def _public_world(raw: Any) -> dict[str, Any]:
    world = _object(raw, "run_export.world")
    unknown = set(world) - _WORLD_FIELDS
    if unknown:
        raise ValueError(
            "run_export.world contains unsupported fields: " + ", ".join(sorted(unknown))
        )
    required = {"schema_version", "world_id", "episode_id", "bundle"}
    missing = required - set(world)
    if missing:
        raise ValueError(
            "run_export.world is missing required fields: " + ", ".join(sorted(missing))
        )
    bundle = _object(world["bundle"], "run_export.world.bundle")
    _exact_fields(
        bundle,
        required={
            "schema_version",
            "world_id",
            "bundle_version",
            "episode_id",
            "manifest_digest",
        },
        path="run_export.world.bundle",
    )
    return {
        "schema_version": _string(
            world["schema_version"],
            "run_export.world.schema_version",
        ),
        "world_id": _string(world["world_id"], "run_export.world.world_id"),
        "episode_id": _string(world["episode_id"], "run_export.world.episode_id"),
        "bundle": {
            key: _string(value, f"run_export.world.bundle.{key}") for key, value in bundle.items()
        },
    }


def _public_verification(raw: Any) -> dict[str, Any]:
    audit = _object(raw, "audit")
    _exact_fields(
        audit,
        required={"passed", "verifier_type", "checks", "failure_codes"},
        optional={"verifiers"},
        path="audit",
    )
    result: dict[str, Any] = {
        "passed": _boolean(audit["passed"], "audit.passed"),
        "verifier_type": _string(audit["verifier_type"], "audit.verifier_type"),
        "checks": _boolean_map(audit["checks"], "audit.checks"),
        "failure_codes": _string_list(audit["failure_codes"], "audit.failure_codes"),
    }
    if "verifiers" in audit:
        verifiers = _object(audit["verifiers"], "audit.verifiers")
        _exact_fields(
            verifiers,
            required={"config", "world"},
            path="audit.verifiers",
        )
        result["verifiers"] = {
            "config": _public_config_verifier(verifiers["config"]),
            "world": _public_world_verifier(verifiers["world"]),
        }
    return result


def _public_config_verifier(raw: Any) -> dict[str, Any]:
    verifier = _object(raw, "audit.verifiers.config")
    _exact_fields(
        verifier,
        required={"passed", "verifier_type", "checks", "failure_codes"},
        path="audit.verifiers.config",
    )
    return {
        "passed": _boolean(verifier["passed"], "audit.verifiers.config.passed"),
        "verifier_type": _string(
            verifier["verifier_type"],
            "audit.verifiers.config.verifier_type",
        ),
        "checks": _boolean_map(
            verifier["checks"],
            "audit.verifiers.config.checks",
        ),
        "failure_codes": _string_list(
            verifier["failure_codes"],
            "audit.verifiers.config.failure_codes",
        ),
    }


def _public_world_verifier(raw: Any) -> dict[str, Any]:
    verifier = _object(raw, "audit.verifiers.world")
    _exact_fields(
        verifier,
        required={"passed", "verifier_type", "checks", "failure_codes"},
        optional={"scenario", "public_evidence", "reward", "reward_atoms"},
        path="audit.verifiers.world",
    )
    checks = _public_world_checks(verifier["checks"])
    result: dict[str, Any] = {
        "passed": _boolean(verifier["passed"], "audit.verifiers.world.passed"),
        "verifier_type": _string(
            verifier["verifier_type"],
            "audit.verifiers.world.verifier_type",
        ),
        "checks": checks,
        "failure_codes": _string_list(
            verifier["failure_codes"],
            "audit.verifiers.world.failure_codes",
        ),
    }
    if "scenario" in verifier:
        result["scenario"] = _string(
            verifier["scenario"],
            "audit.verifiers.world.scenario",
        )
    if "public_evidence" in verifier:
        evidence = _object(
            _validate_public_json(
                verifier["public_evidence"],
                path="audit.verifiers.world.public_evidence",
            ),
            "audit.verifiers.world.public_evidence",
        )
        result["public_evidence"] = evidence
    else:
        evidence = None
    if "reward" in verifier:
        result["reward"] = _number(
            verifier["reward"],
            "audit.verifiers.world.reward",
        )
    if "reward_atoms" in verifier:
        atoms = verifier["reward_atoms"]
        if not isinstance(atoms, list):
            raise ValueError("audit.verifiers.world.reward_atoms must be a list")
        result["reward_atoms"] = [
            _object(
                _validate_public_json(
                    atom,
                    path=f"audit.verifiers.world.reward_atoms[{index}]",
                ),
                f"audit.verifiers.world.reward_atoms[{index}]",
            )
            for index, atom in enumerate(atoms)
        ]
    _validate_evidence_refs(checks, evidence)
    return result


def _public_world_checks(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError("audit.verifiers.world.checks must be a list")
    result = []
    for index, value in enumerate(raw):
        path = f"audit.verifiers.world.checks[{index}]"
        check = _object(value, path)
        if set(check) == {"name", "ok", "message"}:
            result.append(
                {
                    "name": _string(check["name"], f"{path}.name"),
                    "ok": _boolean(check["ok"], f"{path}.ok"),
                    "message": _string(check["message"], f"{path}.message"),
                }
            )
            continue
        if set(check) == {"code", "passed", "evidence_refs"}:
            result.append(
                {
                    "code": _string(check["code"], f"{path}.code"),
                    "passed": _boolean(check["passed"], f"{path}.passed"),
                    "evidence_refs": _string_list(
                        check["evidence_refs"],
                        f"{path}.evidence_refs",
                    ),
                }
            )
            continue
        raise ValueError(f"{path} does not match a public verifier-check contract")
    return result


def _validate_evidence_refs(
    checks: list[dict[str, Any]],
    evidence: dict[str, Any] | None,
) -> None:
    for check in checks:
        refs = check.get("evidence_refs", [])
        for ref in refs:
            prefix = "public_evidence:#"
            if not ref.startswith(prefix):
                raise ValueError(f"world verifier evidence reference is not public: {ref}")
            if evidence is None:
                raise ValueError("world verifier evidence reference has no public evidence capsule")
            _resolve_json_pointer(evidence, ref[len(prefix) :])


def _resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError(f"invalid public evidence JSON pointer: {pointer}")
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
            continue
        if isinstance(current, list) and token.isdigit() and int(token) < len(current):
            current = current[int(token)]
            continue
        raise ValueError(f"public evidence JSON pointer does not resolve: {pointer}")
    return current


def _validate_public_json(value: Any, *, path: str) -> Any:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return value
    if isinstance(value, list):
        return [
            _validate_public_json(item, path=f"{path}[{index}]") for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string object key")
            result[key] = _validate_public_json(item, path=f"{path}.{key}")
        return result
    raise ValueError(f"{path} contains a non-JSON value")


def _reject_machine_paths(value: Any, *, run_dir: Path, path: str) -> None:
    if isinstance(value, str):
        if str(run_dir) in value or _MACHINE_PATH.search(value):
            raise ValueError(f"{path} contains a machine-local path")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _reject_machine_paths(item, run_dir=run_dir, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_machine_paths(item, run_dir=run_dir, path=f"{path}.{key}")


def _exact_fields(
    value: dict[str, Any],
    *,
    required: set[str] | frozenset[str],
    path: str,
    optional: set[str] | frozenset[str] = frozenset(),
) -> None:
    missing = set(required) - set(value)
    unknown = set(value) - set(required) - set(optional)
    if missing:
        raise ValueError(f"{path} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{path} contains unsupported fields: {', '.join(sorted(unknown))}")


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path} must be a non-empty string")
    return value


def _optional_string(value: Any, path: str) -> str | None:
    if value is None:
        return None
    return _string(value, path)


def _string_list(value: Any, path: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    return [_string(item, f"{path}[{index}]") for index, item in enumerate(value)]


def _string_map(value: Any, path: str) -> dict[str, str]:
    mapping = _object(value, path)
    return {
        _string(key, f"{path}.key"): _string(item, f"{path}.{key}") for key, item in mapping.items()
    }


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{path} must be a boolean")
    return value


def _boolean_map(value: Any, path: str) -> dict[str, bool]:
    mapping = _object(value, path)
    return {
        _string(key, f"{path}.key"): _boolean(item, f"{path}.{key}")
        for key, item in mapping.items()
    }


def _integer(value: Any, path: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{path} must be an integer")
    return value


def _number(value: Any, path: str) -> int | float:
    if type(value) is int:
        return value
    if type(value) is not float or not math.isfinite(value):
        raise ValueError(f"{path} must be a finite number")
    return value


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path.name}")
    return payload
