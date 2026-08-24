from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from datalox_gated_runtime.reference.contracts import JsonValue


@dataclass(frozen=True)
class JsonDifference:
    kind: str
    path: str
    expected: JsonValue
    actual: JsonValue


def compare_json(expected: JsonValue, actual: JsonValue) -> tuple[JsonDifference, ...]:
    differences: list[JsonDifference] = []
    _compare(expected, actual, path="", differences=differences)
    return tuple(differences)


def _compare(
    expected: JsonValue,
    actual: JsonValue,
    *,
    path: str,
    differences: list[JsonDifference],
) -> None:
    expected_is_mapping = isinstance(expected, Mapping)
    actual_is_mapping = isinstance(actual, Mapping)
    if expected_is_mapping or actual_is_mapping:
        if not expected_is_mapping or not actual_is_mapping:
            differences.append(JsonDifference("type_mismatch", path, expected, actual))
            return
        expected_keys = set(expected)
        actual_keys = set(actual)
        for key in sorted(expected_keys - actual_keys):
            differences.append(
                JsonDifference(
                    "missing_key",
                    _join_pointer(path, key),
                    expected[key],
                    None,
                )
            )
        for key in sorted(actual_keys - expected_keys):
            differences.append(
                JsonDifference(
                    "unexpected_key",
                    _join_pointer(path, key),
                    None,
                    actual[key],
                )
            )
        for key in sorted(expected_keys & actual_keys):
            _compare(
                expected[key],
                actual[key],
                path=_join_pointer(path, key),
                differences=differences,
            )
        return

    expected_is_array = isinstance(expected, tuple)
    actual_is_array = isinstance(actual, tuple)
    if expected_is_array or actual_is_array:
        if not expected_is_array or not actual_is_array:
            differences.append(JsonDifference("type_mismatch", path, expected, actual))
            return
        common_length = min(len(expected), len(actual))
        for index in range(common_length):
            _compare(
                expected[index],
                actual[index],
                path=_join_pointer(path, str(index)),
                differences=differences,
            )
        for index in range(common_length, len(expected)):
            differences.append(
                JsonDifference(
                    "missing_index",
                    _join_pointer(path, str(index)),
                    expected[index],
                    None,
                )
            )
        for index in range(common_length, len(actual)):
            differences.append(
                JsonDifference(
                    "unexpected_index",
                    _join_pointer(path, str(index)),
                    None,
                    actual[index],
                )
            )
        return

    if type(expected) is not type(actual):
        differences.append(JsonDifference("type_mismatch", path, expected, actual))
    elif expected != actual:
        differences.append(JsonDifference("value_mismatch", path, expected, actual))


def _join_pointer(path: str, component: str) -> str:
    escaped = component.replace("~", "~0").replace("/", "~1")
    return f"{path}/{escaped}"
