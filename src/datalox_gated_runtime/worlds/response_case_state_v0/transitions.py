from __future__ import annotations

from copy import deepcopy
from typing import Any

from datalox_gated_runtime.worlds.response_case_state_v0.contracts import Effect, WorldContractError


def decode_pointer(pointer: str) -> list[str]:
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise WorldContractError(
            "invalid_json_pointer", "JSON pointers must be empty or start with '/'."
        )
    tokens: list[str] = []
    for raw_token in pointer[1:].split("/"):
        token = ""
        index = 0
        while index < len(raw_token):
            character = raw_token[index]
            if character != "~":
                token += character
                index += 1
                continue
            if index + 1 >= len(raw_token) or raw_token[index + 1] not in {"0", "1"}:
                raise WorldContractError(
                    "invalid_json_pointer", "JSON pointer contains an invalid escape."
                )
            token += "~" if raw_token[index + 1] == "0" else "/"
            index += 2
        if token == "-":
            raise WorldContractError("invalid_array_index", "The '-' array index is not supported.")
        tokens.append(token)
    return tokens


def resolve_pointer(
    document: Any, pointer: str, *, missing_code: str = "state_value_missing"
) -> Any:
    current = document
    for token in decode_pointer(pointer):
        if isinstance(current, dict):
            if token not in current:
                raise WorldContractError(
                    missing_code, f"JSON pointer value is missing at {pointer}."
                )
            current = current[token]
            continue
        if isinstance(current, list):
            index = _array_index(token, len(current), pointer)
            current = current[index]
            continue
        raise WorldContractError(
            "state_parent_missing", f"JSON pointer parent is not a container at {pointer}."
        )
    return current


def apply_effects(
    state: dict[str, Any],
    request_body: Any,
    effects: list[Effect],
) -> dict[str, Any]:
    updated = deepcopy(state)
    for effect in effects:
        if effect.state_key not in updated:
            raise WorldContractError(
                "state_key_missing", f"State key is not declared: {effect.state_key}."
            )
        if effect.operator == "set_literal":
            value = deepcopy(effect.value)
            _set_existing(updated[effect.state_key], effect.target, value)
        elif effect.operator == "set_from_request":
            value = deepcopy(
                resolve_pointer(
                    request_body, effect.request_pointer or "", missing_code="request_value_missing"
                )
            )
            _set_existing(updated[effect.state_key], effect.target, value)
        elif effect.operator == "append_from_request":
            value = deepcopy(
                resolve_pointer(
                    request_body, effect.request_pointer or "", missing_code="request_value_missing"
                )
            )
            target = resolve_pointer(updated[effect.state_key], effect.target)
            if not isinstance(target, list):
                raise WorldContractError(
                    "state_type_mismatch", "append_from_request target must be an array."
                )
            if target and any(json_type(item) != json_type(value) for item in target):
                raise WorldContractError(
                    "state_type_mismatch",
                    "append_from_request value does not match the target array item type.",
                )
            target.append(value)
        elif effect.operator == "set_from_state_lookup":
            request_value = resolve_pointer(
                request_body,
                effect.request_pointer or "",
                missing_code="request_value_missing",
            )
            if effect.source_state_key not in updated:
                raise WorldContractError(
                    "state_key_missing",
                    f"Source state key is not declared: {effect.source_state_key}.",
                )
            source = resolve_pointer(
                updated[effect.source_state_key],
                effect.source_pointer or "",
                missing_code="state_lookup_source_missing",
            )
            if not isinstance(source, list):
                raise WorldContractError(
                    "state_lookup_source_not_array", "State lookup source must be an array."
                )
            if not source:
                raise WorldContractError(
                    "state_lookup_source_empty", "State lookup source must not be empty."
                )
            matches = []
            for item in source:
                match_value = resolve_pointer(
                    item,
                    effect.match_pointer or "",
                    missing_code="state_lookup_match_missing",
                )
                if json_type(match_value) != json_type(request_value):
                    raise WorldContractError(
                        "state_lookup_match_type_mismatch",
                        "State lookup match type is incompatible with the request value.",
                    )
                if match_value == request_value:
                    matches.append(item)
            if not matches:
                raise WorldContractError(
                    "state_lookup_not_found",
                    "State lookup found no item matching the request value.",
                )
            if len(matches) > 1:
                raise WorldContractError(
                    "state_lookup_ambiguous",
                    "State lookup found more than one item matching the request value.",
                )
            value = deepcopy(
                resolve_pointer(
                    matches[0],
                    effect.value_pointer or "",
                    missing_code="state_lookup_value_missing",
                )
            )
            target_value = resolve_pointer(updated[effect.state_key], effect.target)
            if json_type(value) != json_type(target_value):
                raise WorldContractError(
                    "state_lookup_value_type_mismatch",
                    "State lookup value type is incompatible with its target.",
                )
            _set_existing(updated[effect.state_key], effect.target, value)
        elif effect.operator == "copy_state":
            if effect.source_state_key not in updated:
                raise WorldContractError(
                    "state_key_missing",
                    f"Source state key is not declared: {effect.source_state_key}.",
                )
            value = deepcopy(
                resolve_pointer(updated[effect.source_state_key], effect.source_pointer or "")
            )
            _set_existing(updated[effect.state_key], effect.target, value)
        else:
            raise WorldContractError(
                "unknown_transition_operator", f"Unsupported operator: {effect.operator}."
            )
    return updated


def _set_existing(document: Any, pointer: str, value: Any) -> None:
    tokens = decode_pointer(pointer)
    if not tokens:
        raise WorldContractError(
            "state_parent_missing", "Replacing a state view root is not supported."
        )
    parent_pointer = (
        "/" + "/".join(_encode_token(token) for token in tokens[:-1]) if len(tokens) > 1 else ""
    )
    parent = resolve_pointer(document, parent_pointer)
    target = tokens[-1]
    if isinstance(parent, dict):
        if target not in parent:
            raise WorldContractError(
                "state_value_missing", f"Transition target does not exist: {pointer}."
            )
        _require_same_json_type(parent[target], value, pointer)
        parent[target] = value
        return
    if isinstance(parent, list):
        index = _array_index(target, len(parent), pointer)
        _require_same_json_type(parent[index], value, pointer)
        parent[index] = value
        return
    raise WorldContractError(
        "state_parent_missing", f"Transition target parent is not a container: {pointer}."
    )


def _array_index(token: str, length: int, pointer: str) -> int:
    if not token.isascii() or not token.isdigit() or (len(token) > 1 and token.startswith("0")):
        raise WorldContractError(
            "invalid_array_index", f"Invalid array index in JSON pointer: {pointer}."
        )
    index = int(token)
    if index >= length:
        raise WorldContractError("invalid_array_index", f"Array index is out of range: {pointer}.")
    return index


def _require_same_json_type(current: Any, value: Any, pointer: str) -> None:
    if json_type(current) != json_type(value):
        raise WorldContractError(
            "state_type_mismatch", f"Transition value type does not match target: {pointer}."
        )


def json_type(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise WorldContractError(
        "invalid_json_value", f"Unsupported JSON value type: {type(value).__name__}."
    )


def _encode_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")
