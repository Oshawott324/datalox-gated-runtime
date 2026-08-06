from __future__ import annotations

from dataclasses import asdict, fields, is_dataclass
from types import UnionType
from typing import Any, TypeVar, get_args, get_origin, get_type_hints
from typing import Union as TypingUnion

from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import GateResponse

T = TypeVar("T")


def dataclass_to_dict(value: Any) -> dict[str, Any]:
    if not is_dataclass(value):
        raise TypeError(f"Expected dataclass instance, got {type(value).__name__}")
    return asdict(value)


def gate_response_envelope(response: GateResponse) -> dict[str, Any]:
    envelope = asdict(response)
    envelope["body_sha256"] = canonical_json_sha256(envelope["body"])
    return envelope


def dataclass_from_dict(cls: type[T], data: dict[str, Any]) -> T:
    if not is_dataclass(cls):
        raise TypeError(f"Expected dataclass type, got {cls!r}")
    if not isinstance(data, dict):
        raise TypeError(f"Expected dict data, got {type(data).__name__}")

    resolved_fields = get_type_hints(cls)
    unknown_keys = [key for key in data if key not in resolved_fields]
    if unknown_keys:
        raise ValueError(f"Unexpected keys for {cls.__name__}: {', '.join(unknown_keys)}")

    kwargs: dict[str, Any] = {}
    for field in fields(cls):
        key = field.name
        if key not in data:
            continue
        expected_type = resolved_fields[key]
        kwargs[key] = _decode_value(expected_type, data[key])
    return cls(**kwargs)  # type: ignore[misc]


def _decode_value(expected_type: Any, value: Any) -> Any:
    if value is None:
        return None

    if is_dataclass(expected_type) and isinstance(value, dict):
        return dataclass_from_dict(expected_type, value)

    origin = get_origin(expected_type)
    if origin is list and isinstance(value, list):
        (item_type,) = get_args(expected_type)
        return [_decode_value(item_type, item) for item in value]

    if _is_union_type(origin):
        return _decode_union(expected_type, value)

    return value


def _is_union_type(origin: Any) -> bool:
    return origin is TypingUnion or origin is UnionType


def _decode_union(expected_type: Any, value: Any) -> Any:
    from datalox_gated_runtime.models import LedgerEvent, McpLedgerEvent

    event_union = frozenset({LedgerEvent, McpLedgerEvent})
    if frozenset(get_args(expected_type)) != event_union:
        return value
    if not isinstance(value, dict):
        return value

    surface = value.get("surface", "http")
    if surface == "http":
        return dataclass_from_dict(LedgerEvent, value)
    if surface == "mcp":
        return dataclass_from_dict(McpLedgerEvent, value)
    raise ValueError(f"unsupported event surface: {surface}")
