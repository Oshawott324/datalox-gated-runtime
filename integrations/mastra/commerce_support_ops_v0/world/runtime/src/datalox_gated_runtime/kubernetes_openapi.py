from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import urlopen

from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.models import ResponseCase

TARGET_ARTIFACT_NAMES = ("gate_config.json", "task.json", "replay_script.json")
WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
GROUNDING_LEVEL = "G1_OPENAPI_SCHEMA"
DEFAULT_KUBERNETES_OPENAPI_URL = (
    "https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.2/api/openapi-spec/swagger.json"
)
SYNTHETIC_PATH_PARAMS = {
    "name": "datalox-example",
    "namespace": "default",
    "path": "datalox-proxy-path",
}
COMMON_GET_QUERY_VALUES = {
    "limit": "1",
    "pretty": "true",
    "resourceVersion": "0",
    "watch": "false",
}
HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def compile_kubernetes_openapi_env(
    *,
    openapi_source: str = DEFAULT_KUBERNETES_OPENAPI_URL,
    out_dir: Path,
    source_url: str | None = None,
    kubernetes_version: str | None = None,
) -> dict[str, Any]:
    source_bytes, resolved_source_url = _read_source(openapi_source, source_url=source_url)
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    spec = _load_openapi(source_bytes)
    version = kubernetes_version or _spec_version(spec)
    definitions = _definitions(spec)
    parameters = _parameters(spec)

    response_cases: list[ResponseCase] = []
    replay_script: list[dict[str, Any]] = []
    operation_schema_catalog: list[dict[str, Any]] = []
    skips: dict[str, int] = {}
    stats = {
        "total_paths": 0,
        "total_operations": 0,
        "operation_schema_count": 0,
        "total_get_operations": 0,
        "selected_get_operation_schema_count": 0,
        "selected_get_replay_cases": 0,
        "non_get_operation_schema_count": 0,
        "query_variant_replay_cases": 0,
        "templated_get_paths_selected": 0,
        "templated_get_paths_skipped": 0,
    }

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("openapi.paths must be an object")
    stats["total_paths"] = len(paths)

    for path, path_item in sorted(paths.items()):
        if not isinstance(path, str) or not path.startswith("/"):
            _record_skip(skips, "invalid_path")
            continue
        if not isinstance(path_item, dict):
            _record_skip(skips, "invalid_path_item")
            continue

        for method in HTTP_METHODS:
            operation = path_item.get(method)
            if operation is None:
                continue
            stats["total_operations"] += 1
            if method == "get":
                stats["total_get_operations"] += 1
            if not isinstance(operation, dict):
                _record_skip(skips, f"invalid_{method}_operation")
                continue

            response = _select_success_response(operation)
            if response is None:
                _record_skip(skips, "missing_success_response")
                continue
            status_code, response_payload = response
            schema = response_payload.get("schema")
            if not isinstance(schema, dict):
                _record_skip(skips, "missing_response_schema")
                continue

            operation_id = _operation_id(operation, path)
            stats["operation_schema_count"] += 1
            if method != "get":
                operation_schema_catalog.append(
                    _operation_schema_record(
                        method=method.upper(),
                        source_url=resolved_source_url,
                        source_sha256=source_sha256,
                        kubernetes_version=version,
                        path=path,
                        operation=operation,
                        operation_id=operation_id,
                        response_status=status_code,
                        schema=schema,
                        definitions=definitions,
                    )
                )
                continue

            replay_path, synthetic_path_params = _replay_path_for_openapi_path(path)
            if replay_path is None:
                _record_skip(skips, "unsupported_templated_path")
                stats["templated_get_paths_skipped"] += 1
                continue
            if synthetic_path_params:
                stats["templated_get_paths_selected"] += 1
            stats["selected_get_operation_schema_count"] += 1

            for query in _query_variants(operation, parameters):
                if query:
                    stats["query_variant_replay_cases"] += 1
                response_case = ResponseCase(
                    case_id=f"kubernetes_openapi:{operation_id}:schema{_query_case_suffix(query)}",
                    method="GET",
                    path=replay_path,
                    status_code=status_code,
                    query=query,
                    body=_response_body(
                        operation_id=operation_id,
                        schema=schema,
                        definitions=definitions,
                        status_code=status_code,
                        synthetic_path_params=synthetic_path_params,
                        query=query,
                    ),
                    evidence_ref=_evidence_ref(
                        method="GET",
                        source_url=resolved_source_url,
                        source_sha256=source_sha256,
                        kubernetes_version=version,
                        path=path,
                        replay_path=replay_path,
                        replay_query=query,
                        operation=operation,
                        operation_id=operation_id,
                        response_status=status_code,
                        response_schema=schema,
                        synthetic_path_params=synthetic_path_params,
                    ),
                )
                response_cases.append(response_case)
                replay_script.append(
                    {
                        "surface": "http",
                        "method": "GET",
                        "path": replay_path,
                        "query": query,
                        "body": None,
                    }
                )

    stats["selected_get_replay_cases"] = len(response_cases)
    stats["non_get_operation_schema_count"] = len(operation_schema_catalog)
    _refuse_existing_target_artifacts(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    config_id = f"kubernetes_openapi_g1_{_slug(version)}"
    gate_config_payload = {
        "config_id": config_id,
        "metadata": {
            "provenance": "kubernetes_openapi",
            "provider": "kubernetes",
            "source": {
                "kind": "openapi_v2",
                "url": resolved_source_url,
                "sha256": source_sha256,
                "kubernetes_version": version,
            },
            "grounding": {
                "level": GROUNDING_LEVEL,
                "live_probe_level": None,
                "not_g2_reason": (
                    "Generated from official Kubernetes OpenAPI response schemas; no live "
                    "provider responses were captured."
                ),
                "prior_probe_artifact": "probes/kubernetes_local.json",
            },
            "coverage": stats,
            "operation_schema_catalog": operation_schema_catalog,
            "skips": dict(sorted(skips.items())),
        },
        "response_cases": [asdict(response_case) for response_case in response_cases],
        "audit_rules": [],
        "policy": _replay_only_policy(),
    }
    task_payload = {
        "task_id": config_id,
        "title": "[DRAFT] Kubernetes OpenAPI G1 schema replay",
        "instructions": (
            "Use this replay-only Kubernetes API environment as G1 OpenAPI-grounded "
            "schema context. Responses include OpenAPI-derived response_body_shape "
            "artifacts, not live cluster state. Treat this as doc/OpenAPI coverage; "
            "live-probed G2 coverage requires captured successful GET responses from "
            "a Kubernetes API server."
        ),
        "success_criteria": [
            "Session check passes.",
            "Replay calls are served from Kubernetes OpenAPI-grounded response cases.",
            "Do not treat G1 schema cases as live-observed Kubernetes state.",
        ],
    }

    _write_json(out_dir / "gate_config.json", gate_config_payload)
    _write_json(out_dir / "task.json", task_payload)
    _write_json(out_dir / "replay_script.json", replay_script)
    load_gate_config(out_dir / "gate_config.json")

    return {
        "out_dir": str(out_dir.resolve()),
        "source": openapi_source,
        "source_url": resolved_source_url,
        "source_sha256": source_sha256,
        "config_id": config_id,
        "kubernetes_version": version,
        "operation_schema_count": stats["operation_schema_count"],
        "response_case_count": len(response_cases),
        "replay_step_count": len(replay_script),
        "skipped_count": sum(skips.values()),
        "skips": dict(sorted(skips.items())),
        "coverage": stats,
    }


def _read_source(openapi_source: str, *, source_url: str | None) -> tuple[bytes, str]:
    parsed = urlparse(openapi_source)
    if parsed.scheme in {"http", "https"}:
        try:
            with urlopen(openapi_source, timeout=60) as response:
                return response.read(), source_url or openapi_source
        except (OSError, TimeoutError, URLError) as exc:
            raise ValueError(f"failed to fetch openapi source: {openapi_source}: {exc}") from exc

    path = Path(openapi_source)
    try:
        source_bytes = path.read_bytes()
    except FileNotFoundError as exc:
        raise ValueError(f"openapi source not found: {path}") from exc
    resolved = path.resolve()
    return source_bytes, source_url or resolved.as_uri()


def _load_openapi(source_bytes: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(source_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("openapi source must be utf-8 json") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid openapi json: line {exc.lineno}") from exc
    if not isinstance(payload, dict):
        raise ValueError("openapi source must contain an object")
    return payload


def _spec_version(spec: dict[str, Any]) -> str:
    info = spec.get("info", {})
    if isinstance(info, dict):
        version = info.get("version")
        if isinstance(version, str) and version.strip():
            return version
    return "unknown"


def _select_success_response(operation: dict[str, Any]) -> tuple[int, dict[str, Any]] | None:
    responses = operation.get("responses")
    if not isinstance(responses, dict):
        return None
    for status_text in sorted(responses):
        if not isinstance(status_text, str) or not status_text.isdigit():
            continue
        status_code = int(status_text)
        if status_code < 200 or status_code >= 300:
            continue
        response = responses[status_text]
        if not isinstance(response, dict):
            continue
        return status_code, response
    return None


def _operation_id(operation: dict[str, Any], path: str) -> str:
    operation_id = operation.get("operationId")
    if isinstance(operation_id, str) and operation_id.strip():
        return operation_id
    return f"get_{_slug(path)}"


def _evidence_ref(
    *,
    method: str,
    source_url: str,
    source_sha256: str,
    kubernetes_version: str,
    path: str,
    replay_path: str | None,
    replay_query: dict[str, str],
    operation: dict[str, Any],
    operation_id: str,
    response_status: int,
    response_schema: dict[str, Any],
    synthetic_path_params: dict[str, str],
) -> str:
    evidence = {
        "provider": "kubernetes",
        "grounding_level": GROUNDING_LEVEL,
        "source_kind": "official_kubernetes_openapi",
        "source_url": source_url,
        "source_sha256": source_sha256,
        "kubernetes_version": kubernetes_version,
        "openapi_path": path,
        "replay_path": replay_path,
        "replay_query": replay_query,
        "method": method,
        "operation_id": operation_id,
        "tags": operation.get("tags", []),
        "response_status": response_status,
        "response_schema": response_schema,
        "live_probe_level": None,
    }
    if synthetic_path_params:
        evidence["synthetic_path_params"] = synthetic_path_params
    return json.dumps(evidence, sort_keys=True, separators=(",", ":"))


def _response_body(
    *,
    operation_id: str,
    schema: dict[str, Any],
    definitions: dict[str, Any],
    status_code: int,
    synthetic_path_params: dict[str, str],
    query: dict[str, str] | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "datalox_grounding_level": GROUNDING_LEVEL,
        "operation_id": operation_id,
        "response_body_shape": _schema_shape(schema, definitions=definitions),
        "response_schema": schema,
        "status_code": status_code,
    }
    if query:
        body["replay_query"] = query
    if synthetic_path_params:
        body["synthetic_path_params"] = synthetic_path_params
        body["synthetic_path_note"] = (
            "Path parameters are deterministic placeholders used to make the "
            "OpenAPI schema replayable. They are not live Kubernetes object identities."
        )
    return body


def _definitions(spec: dict[str, Any]) -> dict[str, Any]:
    definitions = spec.get("definitions", {})
    if not isinstance(definitions, dict):
        return {}
    return definitions


def _parameters(spec: dict[str, Any]) -> dict[str, Any]:
    parameters = spec.get("parameters", {})
    if not isinstance(parameters, dict):
        return {}
    return parameters


def _operation_schema_record(
    *,
    method: str,
    source_url: str,
    source_sha256: str,
    kubernetes_version: str,
    path: str,
    operation: dict[str, Any],
    operation_id: str,
    response_status: int,
    schema: dict[str, Any],
    definitions: dict[str, Any],
) -> dict[str, Any]:
    replay_path, synthetic_path_params = _replay_path_for_openapi_path(path)
    return {
        "method": method,
        "operation_id": operation_id,
        "openapi_path": path,
        "replay_executable": False,
        "replay_path": replay_path,
        "response_body_shape": _schema_shape(schema, definitions=definitions),
        "response_schema": schema,
        "response_status": response_status,
        "synthetic_path_params": synthetic_path_params,
        "evidence_ref": _evidence_ref(
            method=method,
            source_url=source_url,
            source_sha256=source_sha256,
            kubernetes_version=kubernetes_version,
            path=path,
            replay_path=replay_path,
            replay_query={},
            operation=operation,
            operation_id=operation_id,
            response_status=response_status,
            response_schema=schema,
            synthetic_path_params=synthetic_path_params,
        ),
    }


def _schema_shape(
    schema: dict[str, Any],
    *,
    definitions: dict[str, Any],
    depth: int = 4,
    seen_refs: frozenset[str] = frozenset(),
) -> Any:
    if depth <= 0:
        return _terminal_shape(schema)

    ref = schema.get("$ref")
    if isinstance(ref, str):
        if ref in seen_refs:
            return {"$ref": ref}
        resolved = _resolve_ref(ref, definitions)
        if resolved is None:
            return {"$ref": ref}
        return _schema_shape(
            resolved,
            definitions=definitions,
            depth=depth,
            seen_refs=seen_refs | {ref},
        )

    if isinstance(schema.get("allOf"), list):
        merged: dict[str, Any] = {}
        for item in schema["allOf"]:
            if not isinstance(item, dict):
                continue
            shape = _schema_shape(
                item,
                definitions=definitions,
                depth=depth - 1,
                seen_refs=seen_refs,
            )
            if isinstance(shape, dict):
                merged.update(shape)
        return merged or "object"

    schema_type = schema.get("type")
    if schema_type == "array":
        items = schema.get("items", {})
        if not isinstance(items, dict):
            return []
        return [
            _schema_shape(
                items,
                definitions=definitions,
                depth=depth - 1,
                seen_refs=seen_refs,
            )
        ]

    if schema_type == "object" or "properties" in schema:
        properties = schema.get("properties")
        if isinstance(properties, dict) and properties:
            shaped: dict[str, Any] = {}
            for name, property_schema in sorted(properties.items()):
                if not isinstance(name, str) or not isinstance(property_schema, dict):
                    continue
                shaped[name] = _schema_shape(
                    property_schema,
                    definitions=definitions,
                    depth=depth - 1,
                    seen_refs=seen_refs,
                )
            return shaped
        additional = schema.get("additionalProperties")
        if isinstance(additional, dict):
            return {
                "<key>": _schema_shape(
                    additional,
                    definitions=definitions,
                    depth=depth - 1,
                    seen_refs=seen_refs,
                )
            }
        return "object"

    return _terminal_shape(schema)


def _terminal_shape(schema: dict[str, Any]) -> str | dict[str, str]:
    schema_type = schema.get("type")
    if isinstance(schema_type, str) and schema_type:
        return schema_type
    ref = schema.get("$ref")
    if isinstance(ref, str):
        return {"$ref": ref}
    return "any"


def _resolve_ref(ref: str, definitions: dict[str, Any]) -> dict[str, Any] | None:
    prefix = "#/definitions/"
    if not ref.startswith(prefix):
        return None
    resolved = definitions.get(ref[len(prefix) :])
    if not isinstance(resolved, dict):
        return None
    return resolved


def _replay_path_for_openapi_path(path: str) -> tuple[str | None, dict[str, str]]:
    if "{" not in path and "}" not in path:
        return path, {}

    synthetic_path_params: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = SYNTHETIC_PATH_PARAMS.get(name)
        if value is None:
            synthetic_path_params[name] = ""
            return match.group(0)
        synthetic_path_params[name] = value
        return value

    replay_path = re.sub(r"\{([^}]+)\}", replace, path)
    if any(value == "" for value in synthetic_path_params.values()):
        return None, {}
    return replay_path, dict(sorted(synthetic_path_params.items()))


def _query_variants(
    operation: dict[str, Any],
    parameters: dict[str, Any],
) -> list[dict[str, str]]:
    query_names = _query_parameter_names(operation, parameters)
    variants: list[dict[str, str]] = [
        {},
        {"pretty": COMMON_GET_QUERY_VALUES["pretty"]},
    ]
    for name in ("limit", "resourceVersion", "watch"):
        if name in query_names:
            variants.append({name: COMMON_GET_QUERY_VALUES[name]})
    return _dedupe_queries(variants)


def _query_parameter_names(
    operation: dict[str, Any],
    parameters: dict[str, Any],
) -> set[str]:
    names: set[str] = set()
    raw_parameters = operation.get("parameters", [])
    if not isinstance(raw_parameters, list):
        return names
    for raw_parameter in raw_parameters:
        if not isinstance(raw_parameter, dict):
            continue
        parameter = raw_parameter
        ref = raw_parameter.get("$ref")
        if isinstance(ref, str):
            resolved = _resolve_parameter_ref(ref, parameters)
            if resolved is None:
                continue
            parameter = resolved
        if parameter.get("in") != "query":
            continue
        name = parameter.get("name")
        if isinstance(name, str) and name:
            names.add(name)
    return names


def _resolve_parameter_ref(ref: str, parameters: dict[str, Any]) -> dict[str, Any] | None:
    prefix = "#/parameters/"
    if not ref.startswith(prefix):
        return None
    parameter = parameters.get(ref[len(prefix) :])
    if not isinstance(parameter, dict):
        return None
    return parameter


def _dedupe_queries(queries: list[dict[str, str]]) -> list[dict[str, str]]:
    unique: list[dict[str, str]] = []
    seen: set[tuple[tuple[str, str], ...]] = set()
    for query in queries:
        key = tuple(sorted(query.items()))
        if key in seen:
            continue
        seen.add(key)
        unique.append(query)
    return unique


def _query_case_suffix(query: dict[str, str]) -> str:
    if not query:
        return ""
    suffix = "_".join(f"{_slug(key)}_{_slug(value)}" for key, value in sorted(query.items()))
    return f":query_{suffix}"


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
                "reason_code": "kubernetes_openapi_write_denied",
                "message": "Kubernetes OpenAPI G1 environments are replay-only.",
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
    return re.sub(r"[^a-zA-Z0-9]+", "_", value).strip("_").lower() or "unknown"
