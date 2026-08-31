from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, TypeAlias

REFERENCE_TRACE_SCHEMA_ID = "datalox_reference_trace_v2"
CONFORMANCE_REPORT_SCHEMA_ID = "datalox_conformance_report_v1"

JsonValue: TypeAlias = (
    Mapping[str, "JsonValue"] | tuple["JsonValue", ...] | str | int | float | bool | None
)

_HTTP_METHODS = frozenset({"DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"})
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SENSITIVE_HEADER_NAMES = frozenset(
    {
        "api-key",
        "apikey",
        "authorization",
        "cookie",
        "proxy-authorization",
        "set-cookie",
        "x-access-token",
        "x-api-key",
        "x-auth-token",
    }
)


class ReferenceContractError(ValueError):
    """A durable reference artifact violates its fail-closed contract."""


def freeze_json(value: Any, *, path: str = "$") -> JsonValue:
    value_type = type(value)
    if value is None or value_type in {str, bool, int}:
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise ReferenceContractError(f"{path} must not contain a non-finite number")
        return value
    if value_type in {list, tuple}:
        return tuple(freeze_json(item, path=f"{path}[{index}]") for index, item in enumerate(value))
    if isinstance(value, Mapping):
        frozen: dict[str, JsonValue] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ReferenceContractError(f"{path} contains a non-string object key")
            frozen[key] = freeze_json(item, path=f"{path}.{key}")
        return MappingProxyType(frozen)
    raise ReferenceContractError(f"{path} contains non-JSON value of type {value_type.__name__}")


def thaw_json(value: JsonValue) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def _require_object(value: Any, *, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ReferenceContractError(f"{path} must be an object")
    return value


def _require_shape(
    raw: dict[str, Any],
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    path: str,
) -> None:
    missing = sorted(required - raw.keys())
    unknown = sorted(raw.keys() - required - optional)
    if missing:
        raise ReferenceContractError(f"{path} is missing fields: {', '.join(missing)}")
    if unknown:
        raise ReferenceContractError(f"{path} has unknown fields: {', '.join(unknown)}")


def _require_string(value: Any, *, path: str, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ReferenceContractError(f"{path} must be {qualifier}")
    return value


def _require_identifier(value: Any, *, path: str) -> str:
    identifier = _require_string(value, path=path)
    if _IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        raise ReferenceContractError(f"{path} is not a stable identifier")
    return identifier


def _require_int(value: Any, *, path: str) -> int:
    if type(value) is not int:
        raise ReferenceContractError(f"{path} must be an integer")
    return value


def _freeze_json_object(value: Any, *, path: str) -> Mapping[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise ReferenceContractError(f"{path} must be an object")
    frozen = freeze_json(value, path=path)
    if not isinstance(frozen, Mapping):
        raise ReferenceContractError(f"{path} must be an object")
    return frozen


def _is_sensitive_header(name: str) -> bool:
    compact_name = name.replace("-", "").replace("_", "")
    return (
        name in _SENSITIVE_HEADER_NAMES
        or "authorization" in compact_name
        or "cookie" in compact_name
        or "apikey" in compact_name
        or "authtoken" in compact_name
        or "accesstoken" in compact_name
        or "secretkey" in compact_name
    )


def _freeze_headers(value: Any, *, path: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise ReferenceContractError(f"{path} must be an object")
    headers: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        if type(raw_name) is not str or _HEADER_NAME_PATTERN.fullmatch(raw_name) is None:
            raise ReferenceContractError(f"{path} contains an invalid header name")
        name = raw_name.lower()
        if name in headers:
            raise ReferenceContractError(f"{path} contains duplicate header {name!r}")
        if _is_sensitive_header(name):
            raise ReferenceContractError(f"{path} contains sensitive header {name!r}")
        if type(raw_value) is not str:
            raise ReferenceContractError(f"{path}.{name} must be a string")
        if "\r" in raw_value or "\n" in raw_value:
            raise ReferenceContractError(f"{path}.{name} contains a line break")
        headers[name] = raw_value
    return MappingProxyType(headers)


def _string_tuple(value: Any, *, path: str) -> tuple[str, ...]:
    if type(value) is not list and type(value) is not tuple:
        raise ReferenceContractError(f"{path} must be an array")
    result = tuple(
        _require_string(item, path=f"{path}[{index}]") for index, item in enumerate(value)
    )
    if len(result) != len(set(result)):
        raise ReferenceContractError(f"{path} contains duplicate values")
    return result


@dataclass(frozen=True)
class ReferenceCall:
    method: str
    path: str
    operation_id: str
    query: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))
    body: JsonValue = None
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        method = _require_string(self.method, path="call.method").upper()
        if method not in _HTTP_METHODS:
            raise ReferenceContractError(f"call.method is unsupported: {method}")
        path = _require_string(self.path, path="call.path")
        invalid_character = any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in path
        )
        if not path.startswith("/") or "?" in path or "#" in path or invalid_character:
            raise ReferenceContractError(
                "call.path must be an absolute path without query or fragment"
            )
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "query", _freeze_json_object(self.query, path="call.query"))
        object.__setattr__(self, "body", freeze_json(self.body, path="call.body"))
        object.__setattr__(self, "headers", _freeze_headers(self.headers, path="call.headers"))
        object.__setattr__(
            self,
            "operation_id",
            _require_identifier(self.operation_id, path="call.operation_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "query": thaw_json(self.query),
            "body": thaw_json(self.body),
            "headers": dict(self.headers),
            "operation_id": self.operation_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ReferenceCall:
        raw = _require_object(value, path="call")
        _require_shape(
            raw,
            required=frozenset({"method", "path", "query", "body", "headers", "operation_id"}),
            path="call",
        )
        return cls(
            method=raw["method"],
            path=raw["path"],
            query=raw["query"],
            body=raw["body"],
            headers=raw["headers"],
            operation_id=raw["operation_id"],
        )


@dataclass(frozen=True)
class ObservedResponse:
    status_code: int
    body: JsonValue = None
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        status_code = _require_int(self.status_code, path="response.status_code")
        if not 100 <= status_code <= 599:
            raise ReferenceContractError("response.status_code must be between 100 and 599")
        object.__setattr__(self, "body", freeze_json(self.body, path="response.body"))
        object.__setattr__(
            self,
            "headers",
            _freeze_headers(self.headers, path="response.headers"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "body": thaw_json(self.body),
            "headers": dict(self.headers),
        }

    @classmethod
    def from_dict(cls, value: Any) -> ObservedResponse:
        raw = _require_object(value, path="response")
        _require_shape(
            raw,
            required=frozenset({"status_code", "body", "headers"}),
            path="response",
        )
        return cls(
            status_code=raw["status_code"],
            body=raw["body"],
            headers=raw["headers"],
        )


@dataclass(frozen=True)
class ObservationRequest:
    observation_id: str
    query: JsonValue

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "observation_id",
            _require_identifier(self.observation_id, path="observation.observation_id"),
        )
        object.__setattr__(
            self,
            "query",
            freeze_json(self.query, path="observation.query"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "query": thaw_json(self.query),
        }

    @classmethod
    def from_dict(cls, value: Any) -> ObservationRequest:
        raw = _require_object(value, path="observation")
        _require_shape(
            raw,
            required=frozenset({"observation_id", "query"}),
            path="observation",
        )
        return cls(observation_id=raw["observation_id"], query=raw["query"])


@dataclass(frozen=True)
class ExpectedObservation:
    request: ObservationRequest
    expected: JsonValue

    def __post_init__(self) -> None:
        if not isinstance(self.request, ObservationRequest):
            raise ReferenceContractError("expected_observation.request is invalid")
        object.__setattr__(
            self,
            "expected",
            freeze_json(self.expected, path="expected_observation.expected"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request.to_dict(),
            "expected": thaw_json(self.expected),
        }

    @classmethod
    def from_dict(cls, value: Any) -> ExpectedObservation:
        raw = _require_object(value, path="expected_observation")
        _require_shape(
            raw,
            required=frozenset({"request", "expected"}),
            path="expected_observation",
        )
        return cls(
            request=ObservationRequest.from_dict(raw["request"]),
            expected=raw["expected"],
        )


@dataclass(frozen=True)
class ReferenceStep:
    step_id: str
    principal_context_id: str
    call: ReferenceCall
    expected_response: ObservedResponse
    post_observations: tuple[ExpectedObservation, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "step_id",
            _require_identifier(self.step_id, path="step.step_id"),
        )
        object.__setattr__(
            self,
            "principal_context_id",
            _require_identifier(
                self.principal_context_id,
                path="step.principal_context_id",
            ),
        )
        if not isinstance(self.call, ReferenceCall):
            raise ReferenceContractError("step.call is invalid")
        if not isinstance(self.expected_response, ObservedResponse):
            raise ReferenceContractError("step.expected_response is invalid")
        observations = tuple(self.post_observations)
        if not all(isinstance(item, ExpectedObservation) for item in observations):
            raise ReferenceContractError("step.post_observations contains an invalid item")
        identifiers = [item.request.observation_id for item in observations]
        if len(identifiers) != len(set(identifiers)):
            raise ReferenceContractError(
                "step.post_observations contains duplicate observation ids"
            )
        object.__setattr__(self, "post_observations", observations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "principal_context_id": self.principal_context_id,
            "call": self.call.to_dict(),
            "expected_response": self.expected_response.to_dict(),
            "post_observations": [item.to_dict() for item in self.post_observations],
        }

    @classmethod
    def from_dict(cls, value: Any) -> ReferenceStep:
        raw = _require_object(value, path="step")
        _require_shape(
            raw,
            required=frozenset(
                {
                    "step_id",
                    "principal_context_id",
                    "call",
                    "expected_response",
                    "post_observations",
                }
            ),
            path="step",
        )
        observations = raw["post_observations"]
        if type(observations) is not list:
            raise ReferenceContractError("step.post_observations must be an array")
        return cls(
            step_id=raw["step_id"],
            principal_context_id=raw["principal_context_id"],
            call=ReferenceCall.from_dict(raw["call"]),
            expected_response=ObservedResponse.from_dict(raw["expected_response"]),
            post_observations=tuple(ExpectedObservation.from_dict(item) for item in observations),
        )


@dataclass(frozen=True)
class ReferenceTrace:
    provider_id: str
    provider_version: str
    seed: int
    initial_observations: tuple[ExpectedObservation, ...]
    steps: tuple[ReferenceStep, ...]
    evidence_refs: tuple[str, ...] = ()
    metadata: Mapping[str, JsonValue] = field(default_factory=lambda: MappingProxyType({}))
    schema_id: str = REFERENCE_TRACE_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != REFERENCE_TRACE_SCHEMA_ID:
            raise ReferenceContractError(f"unsupported trace schema: {self.schema_id}")
        object.__setattr__(
            self,
            "provider_id",
            _require_identifier(self.provider_id, path="trace.provider_id"),
        )
        object.__setattr__(
            self,
            "provider_version",
            _require_string(self.provider_version, path="trace.provider_version"),
        )
        object.__setattr__(self, "seed", _require_int(self.seed, path="trace.seed"))
        initial_observations = tuple(self.initial_observations)
        steps = tuple(self.steps)
        if not all(isinstance(item, ExpectedObservation) for item in initial_observations):
            raise ReferenceContractError("trace.initial_observations contains an invalid item")
        if not all(isinstance(item, ReferenceStep) for item in steps):
            raise ReferenceContractError("trace.steps contains an invalid item")
        step_ids = [step.step_id for step in steps]
        if len(step_ids) != len(set(step_ids)):
            raise ReferenceContractError("trace.steps contains duplicate step ids")
        observation_ids = [item.request.observation_id for item in initial_observations]
        observation_ids.extend(
            item.request.observation_id for step in steps for item in step.post_observations
        )
        if len(observation_ids) != len(set(observation_ids)):
            raise ReferenceContractError("trace contains duplicate observation ids")
        object.__setattr__(self, "initial_observations", initial_observations)
        object.__setattr__(self, "steps", steps)
        object.__setattr__(
            self,
            "evidence_refs",
            _string_tuple(self.evidence_refs, path="trace.evidence_refs"),
        )
        object.__setattr__(
            self,
            "metadata",
            _freeze_json_object(self.metadata, path="trace.metadata"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "seed": self.seed,
            "initial_observations": [item.to_dict() for item in self.initial_observations],
            "steps": [step.to_dict() for step in self.steps],
            "evidence_refs": list(self.evidence_refs),
            "metadata": thaw_json(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Any) -> ReferenceTrace:
        raw = _require_object(value, path="trace")
        _require_shape(
            raw,
            required=frozenset(
                {
                    "schema_id",
                    "provider_id",
                    "provider_version",
                    "seed",
                    "initial_observations",
                    "steps",
                    "evidence_refs",
                    "metadata",
                }
            ),
            path="trace",
        )
        initial_observations = raw["initial_observations"]
        steps = raw["steps"]
        if type(initial_observations) is not list:
            raise ReferenceContractError("trace.initial_observations must be an array")
        if type(steps) is not list:
            raise ReferenceContractError("trace.steps must be an array")
        return cls(
            schema_id=raw["schema_id"],
            provider_id=raw["provider_id"],
            provider_version=raw["provider_version"],
            seed=raw["seed"],
            initial_observations=tuple(
                ExpectedObservation.from_dict(item) for item in initial_observations
            ),
            steps=tuple(ReferenceStep.from_dict(item) for item in steps),
            evidence_refs=_string_tuple(
                raw["evidence_refs"],
                path="trace.evidence_refs",
            ),
            metadata=raw["metadata"],
        )


def compute_reference_trace_digest(trace: ReferenceTrace) -> str:
    if not isinstance(trace, ReferenceTrace):
        raise ReferenceContractError("trace digest input must be a ReferenceTrace")
    canonical_json = json.dumps(
        trace.to_dict(),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical_json).hexdigest()}"


@dataclass(frozen=True)
class ConformanceMismatch:
    code: str
    path: str
    expected: JsonValue
    actual: JsonValue
    step_id: str | None = None
    observation_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "code",
            _require_identifier(self.code, path="mismatch.code"),
        )
        path = _require_string(self.path, path="mismatch.path", allow_empty=True)
        if path and not path.startswith("/"):
            raise ReferenceContractError("mismatch.path must be a JSON pointer")
        object.__setattr__(self, "expected", freeze_json(self.expected, path="mismatch.expected"))
        object.__setattr__(self, "actual", freeze_json(self.actual, path="mismatch.actual"))
        if self.step_id is not None:
            object.__setattr__(
                self,
                "step_id",
                _require_identifier(self.step_id, path="mismatch.step_id"),
            )
        if self.observation_id is not None:
            object.__setattr__(
                self,
                "observation_id",
                _require_identifier(
                    self.observation_id,
                    path="mismatch.observation_id",
                ),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "path": self.path,
            "expected": thaw_json(self.expected),
            "actual": thaw_json(self.actual),
            "step_id": self.step_id,
            "observation_id": self.observation_id,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ConformanceMismatch:
        raw = _require_object(value, path="mismatch")
        _require_shape(
            raw,
            required=frozenset(
                {
                    "code",
                    "path",
                    "expected",
                    "actual",
                    "step_id",
                    "observation_id",
                }
            ),
            path="mismatch",
        )
        return cls(
            code=raw["code"],
            path=raw["path"],
            expected=raw["expected"],
            actual=raw["actual"],
            step_id=raw["step_id"],
            observation_id=raw["observation_id"],
        )


@dataclass(frozen=True)
class ConformanceReport:
    trace_schema_id: str
    trace_digest: str
    provider_id: str
    provider_version: str
    target_id: str
    target_version: str
    profile_id: str
    seed: int
    mismatches: tuple[ConformanceMismatch, ...] = ()
    schema_id: str = CONFORMANCE_REPORT_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != CONFORMANCE_REPORT_SCHEMA_ID:
            raise ReferenceContractError(f"unsupported report schema: {self.schema_id}")
        if self.trace_schema_id != REFERENCE_TRACE_SCHEMA_ID:
            raise ReferenceContractError(f"unsupported report trace schema: {self.trace_schema_id}")
        trace_digest = _require_string(self.trace_digest, path="report.trace_digest")
        if _SHA256_DIGEST_PATTERN.fullmatch(trace_digest) is None:
            raise ReferenceContractError(
                "report.trace_digest must use sha256:<64 lowercase hexadecimal characters>"
            )
        object.__setattr__(
            self,
            "provider_id",
            _require_identifier(self.provider_id, path="report.provider_id"),
        )
        object.__setattr__(
            self,
            "provider_version",
            _require_string(self.provider_version, path="report.provider_version"),
        )
        object.__setattr__(
            self,
            "target_id",
            _require_identifier(self.target_id, path="report.target_id"),
        )
        object.__setattr__(
            self,
            "target_version",
            _require_string(self.target_version, path="report.target_version"),
        )
        object.__setattr__(
            self,
            "profile_id",
            _require_identifier(self.profile_id, path="report.profile_id"),
        )
        object.__setattr__(self, "seed", _require_int(self.seed, path="report.seed"))
        mismatches = tuple(self.mismatches)
        if not all(isinstance(item, ConformanceMismatch) for item in mismatches):
            raise ReferenceContractError("report.mismatches contains an invalid item")
        object.__setattr__(self, "mismatches", mismatches)

    @property
    def passed(self) -> bool:
        return not self.mismatches

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "trace_schema_id": self.trace_schema_id,
            "trace_digest": self.trace_digest,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "target_id": self.target_id,
            "target_version": self.target_version,
            "profile_id": self.profile_id,
            "seed": self.seed,
            "passed": self.passed,
            "mismatches": [item.to_dict() for item in self.mismatches],
        }

    @classmethod
    def from_dict(cls, value: Any) -> ConformanceReport:
        raw = _require_object(value, path="report")
        _require_shape(
            raw,
            required=frozenset(
                {
                    "schema_id",
                    "trace_schema_id",
                    "trace_digest",
                    "provider_id",
                    "provider_version",
                    "target_id",
                    "target_version",
                    "profile_id",
                    "seed",
                    "passed",
                    "mismatches",
                }
            ),
            path="report",
        )
        mismatches = raw["mismatches"]
        if type(mismatches) is not list:
            raise ReferenceContractError("report.mismatches must be an array")
        report = cls(
            schema_id=raw["schema_id"],
            trace_schema_id=raw["trace_schema_id"],
            trace_digest=raw["trace_digest"],
            provider_id=raw["provider_id"],
            provider_version=raw["provider_version"],
            target_id=raw["target_id"],
            target_version=raw["target_version"],
            profile_id=raw["profile_id"],
            seed=raw["seed"],
            mismatches=tuple(ConformanceMismatch.from_dict(item) for item in mismatches),
        )
        if type(raw["passed"]) is not bool or raw["passed"] is not report.passed:
            raise ReferenceContractError("report.passed is inconsistent with report.mismatches")
        return report
