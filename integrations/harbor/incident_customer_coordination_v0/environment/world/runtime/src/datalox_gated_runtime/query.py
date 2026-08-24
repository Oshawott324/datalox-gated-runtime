from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import TypeAlias

QueryScalar: TypeAlias = str | int | float | bool
QueryValue: TypeAlias = QueryScalar | tuple[str, ...]
QueryParams: TypeAlias = dict[str, QueryValue]
QueryInputValue: TypeAlias = QueryScalar | Sequence[str]


def normalize_query(
    query: Mapping[str, QueryInputValue] | None = None,
) -> QueryParams:
    """Return the canonical repeated-value query representation.

    Scalar values remain unchanged for backwards compatibility with direct
    world callers. A one-item sequence becomes its equivalent scalar wire
    value; sequences with two or more values become ordered string tuples, so
    true multiplicity and same-key value order survive every runtime boundary
    without delimiters or synthetic keys. Query key order and cross-key
    interleaving are intentionally non-semantic. HTTP adapters stringify scalar
    values only when rendering the wire request.
    """

    normalized: QueryParams = {}
    for key, value in (query or {}).items():
        if not isinstance(key, str):
            raise TypeError("query parameter names must be strings")
        if isinstance(value, str):
            normalized[key] = value
            continue
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            if not value:
                raise ValueError(f"query parameter {key!r} must contain at least one value")
            if any(not isinstance(item, str) for item in value):
                raise TypeError(f"query parameter {key!r} repeated values must be strings")
            normalized[key] = value[0] if len(value) == 1 else tuple(value)
            continue
        if isinstance(value, (int, float, bool)):
            normalized[key] = value
            continue
        raise TypeError(f"query parameter {key!r} must be a scalar or sequence of strings")
    return normalized


def query_from_items(items: Iterable[tuple[str, str]]) -> QueryParams:
    """Aggregate HTTP pairs while retaining multiplicity and same-key order."""

    query: QueryParams = {}
    for key, value in items:
        current = query.get(key)
        if current is None:
            query[key] = value
        elif isinstance(current, str):
            query[key] = (current, value)
        else:
            query[key] = (*current, value)
    return query


def iter_query_items(query: Mapping[str, QueryValue]) -> Iterable[tuple[str, str]]:
    """Expand canonical query values to ordered HTTP key/value pairs."""

    for key, value in query.items():
        if isinstance(value, tuple):
            yield from ((key, item) for item in value)
        elif isinstance(value, bool):
            yield key, str(value).lower()
        else:
            yield key, str(value)
