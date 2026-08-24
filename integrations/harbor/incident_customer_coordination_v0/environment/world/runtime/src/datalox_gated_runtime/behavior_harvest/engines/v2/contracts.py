from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Literal, TypeAlias
from urllib.parse import quote_plus, urlencode, urlsplit

BEHAVIOR_CONNECTOR_SCHEMA_ID = "datalox_behavior_connector_v1"
BEHAVIOR_RECIPE_SCHEMA_ID = "datalox_behavior_recipe_v1"
BEHAVIOR_CAPTURE_SCHEMA_ID = "datalox_behavior_capture_v1"
AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER = "opaque_authorization_header"

JsonValue: TypeAlias = (
    Mapping[str, "JsonValue"] | tuple["JsonValue", ...] | str | int | float | bool | None
)
DriverKind: TypeAlias = Literal["http"]
StepKind: TypeAlias = Literal["read", "mutation"]
StepRole: TypeAlias = Literal[
    "before", "duplicate", "native_failure", "resulting_state", "success", "supporting"
]
BindingType: TypeAlias = Literal[
    "array", "boolean", "integer", "null", "number", "object", "string"
]

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HTTP_METHODS = frozenset({"DELETE", "GET", "HEAD", "PATCH", "POST", "PUT"})
_READ_METHODS = frozenset({"GET", "HEAD"})
_MUTATION_METHODS = frozenset({"DELETE", "PATCH", "POST", "PUT"})
_COMPLETED_MUTATION_STATUSES = frozenset({200, 201, 204, 205})
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_PATH_BINDING_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~:-]{0,255}$")
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
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "expect",
        "host",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_SENSITIVE_JSON_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "authorization",
        "client_secret",
        "cookie",
        "password",
        "refresh_token",
        "secret",
        "secret_key",
        "token",
    }
)


class BehaviorContractError(ValueError):
    """A behavior-harvest input or artifact violates its fail-closed contract."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "behavior_contract_invalid",
    ) -> None:
        super().__init__(message)
        self.code = _identifier(code, path="error.code")


class BehaviorHarvestError(RuntimeError):
    """A behavior-harvest execution failed with an agent-readable stable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = _identifier(code, path="error.code")


def _identifier(value: Any, *, path: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise BehaviorContractError(f"{path} must be a stable identifier")
    return value


def validate_run_id(value: Any) -> str:
    return _identifier(value, path="run_id")


def _string(value: Any, *, path: str) -> str:
    if type(value) is not str or not value:
        raise BehaviorContractError(f"{path} must be a non-empty string")
    return value


def _positive_int(value: Any, *, path: str, allow_zero: bool = False) -> int:
    if type(value) is not int or value < (0 if allow_zero else 1):
        qualifier = "non-negative" if allow_zero else "positive"
        raise BehaviorContractError(f"{path} must be a {qualifier} integer")
    return value


def freeze_json(value: Any, *, path: str = "$") -> JsonValue:
    value_type = type(value)
    if value is None or value_type in {str, bool, int}:
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise BehaviorContractError(f"{path} contains a non-finite number")
        return value
    if value_type in {list, tuple}:
        return tuple(freeze_json(item, path=f"{path}[{index}]") for index, item in enumerate(value))
    if isinstance(value, Mapping):
        frozen: dict[str, JsonValue] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise BehaviorContractError(f"{path} contains a non-string object key")
            frozen[key] = freeze_json(item, path=f"{path}.{key}")
        return MappingProxyType(frozen)
    raise BehaviorContractError(f"{path} contains non-JSON value {value_type.__name__}")


def thaw_json(value: JsonValue) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def _json_object(value: Any, *, path: str) -> Mapping[str, JsonValue]:
    frozen = freeze_json(value, path=path)
    if not isinstance(frozen, Mapping):
        raise BehaviorContractError(f"{path} must be an object")
    return frozen


def _shape(
    value: Any,
    *,
    path: str,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if type(value) is not dict:
        raise BehaviorContractError(f"{path} must be an object")
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - optional)
    if missing:
        raise BehaviorContractError(f"{path} is missing fields: {', '.join(missing)}")
    if unknown:
        raise BehaviorContractError(f"{path} has unknown fields: {', '.join(unknown)}")
    return value


def _is_sensitive_header(name: str) -> bool:
    compact = name.replace("-", "").replace("_", "")
    return (
        name in _SENSITIVE_HEADER_NAMES
        or "authorization" in compact
        or "cookie" in compact
        or "apikey" in compact
        or "authtoken" in compact
        or "accesstoken" in compact
        or "secretkey" in compact
    )


def safe_headers(value: Any, *, path: str) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        raise BehaviorContractError(f"{path} must be an object")
    result: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        if type(raw_name) is not str or _HEADER_NAME.fullmatch(raw_name) is None:
            raise BehaviorContractError(f"{path} contains an invalid header name")
        name = raw_name.lower()
        if name in result:
            raise BehaviorContractError(f"{path} contains duplicate header {name!r}")
        if _is_sensitive_header(name):
            raise BehaviorContractError(f"{path} contains sensitive header {name!r}")
        if type(raw_value) is not str or "\r" in raw_value or "\n" in raw_value:
            raise BehaviorContractError(f"{path}.{name} must be a single-line string")
        result[name] = raw_value
    return MappingProxyType(result)


def reject_sensitive_json(value: JsonValue, *, path: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key.lower().replace("-", "_") in _SENSITIVE_JSON_KEYS:
                raise BehaviorContractError(f"{path} contains sensitive field {key!r}")
            reject_sensitive_json(item, path=f"{path}.{key}")
    elif isinstance(value, tuple):
        for index, item in enumerate(value):
            reject_sensitive_json(item, path=f"{path}[{index}]")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def canonical_contract_digest(value: Any) -> str:
    if not hasattr(value, "to_dict"):
        raise BehaviorContractError("contract digest input must provide to_dict()")
    return sha256_digest(canonical_json_bytes(value.to_dict()))


def _sha256(value: Any, *, path: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise BehaviorContractError(f"{path} must be an exact sha256 digest")
    return value


def _string_tuple(value: Any, *, path: str, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) not in {list, tuple}:
        raise BehaviorContractError(f"{path} must be an array")
    result = tuple(_string(item, path=f"{path}[{index}]") for index, item in enumerate(value))
    if not allow_empty and not result:
        raise BehaviorContractError(f"{path} must not be empty")
    if len(result) != len(set(result)):
        raise BehaviorContractError(f"{path} contains duplicate values")
    return result


def parse_json_bytes(value: bytes, *, path: str) -> JsonValue:
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BehaviorContractError(f"{path} must be UTF-8 JSON") from error

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise BehaviorContractError(f"{path} contains duplicate JSON key {key!r}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise BehaviorContractError(f"{path} contains non-finite JSON number {constant}")

    try:
        parsed = json.loads(
            decoded,
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except BehaviorContractError:
        raise
    except (json.JSONDecodeError, TypeError) as error:
        raise BehaviorContractError(f"{path} must be exactly one JSON value") from error
    return freeze_json(parsed, path=path)


@dataclass(frozen=True)
class HarvestBounds:
    max_requests: int
    max_request_bytes: int
    max_response_bytes: int
    max_total_response_bytes: int
    max_polls: int
    request_timeout_ms: int
    min_request_interval_ms: int = 0

    def __post_init__(self) -> None:
        for name in (
            "max_requests",
            "max_request_bytes",
            "max_response_bytes",
            "max_total_response_bytes",
            "request_timeout_ms",
        ):
            object.__setattr__(
                self, name, _positive_int(getattr(self, name), path=f"bounds.{name}")
            )
        object.__setattr__(
            self,
            "max_polls",
            _positive_int(self.max_polls, path="bounds.max_polls", allow_zero=True),
        )
        if self.max_polls != 0:
            raise BehaviorContractError(
                "behavior-harvest v1 does not implement polling; bounds.max_polls must be zero"
            )
        object.__setattr__(
            self,
            "min_request_interval_ms",
            _positive_int(
                self.min_request_interval_ms,
                path="bounds.min_request_interval_ms",
                allow_zero=True,
            ),
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "max_requests": self.max_requests,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "max_total_response_bytes": self.max_total_response_bytes,
            "max_polls": self.max_polls,
            "request_timeout_ms": self.request_timeout_ms,
            "min_request_interval_ms": self.min_request_interval_ms,
        }

    @classmethod
    def from_dict(cls, value: Any) -> HarvestBounds:
        raw = _shape(
            value,
            path="bounds",
            required=frozenset(
                {
                    "max_requests",
                    "max_request_bytes",
                    "max_response_bytes",
                    "max_total_response_bytes",
                    "max_polls",
                    "request_timeout_ms",
                    "min_request_interval_ms",
                }
            ),
        )
        return cls(**raw)


@dataclass(frozen=True)
class BoundarySpec:
    kind: Literal["developer_tenant", "managed_sandbox", "self_hosted_reference", "test_mode"]
    production_equivalence: Literal["documented_equivalent", "limited", "not_claimed"]
    statement: str

    def __post_init__(self) -> None:
        if self.kind not in {
            "developer_tenant",
            "managed_sandbox",
            "self_hosted_reference",
            "test_mode",
        }:
            raise BehaviorContractError("boundary.kind is unsupported")
        if self.production_equivalence not in {
            "documented_equivalent",
            "limited",
            "not_claimed",
        }:
            raise BehaviorContractError("boundary.production_equivalence is unsupported")
        object.__setattr__(self, "statement", _string(self.statement, path="boundary.statement"))

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "production_equivalence": self.production_equivalence,
            "statement": self.statement,
        }

    @classmethod
    def from_dict(cls, value: Any) -> BoundarySpec:
        return cls(
            **_shape(
                value,
                path="boundary",
                required=frozenset({"kind", "production_equivalence", "statement"}),
            )
        )


@dataclass(frozen=True)
class SecretSource:
    name: str
    kind: Literal["environment", "file_descriptor", "keychain"]
    scan_variants: tuple[Literal["base64", "basic", "bearer", "raw", "urlencoded"], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", _identifier(self.name, path="secret_source.name"))
        if self.kind not in {"environment", "file_descriptor", "keychain"}:
            raise BehaviorContractError("secret_source.kind is unsupported")
        variants = tuple(self.scan_variants)
        if not variants or any(
            item not in {"base64", "basic", "bearer", "raw", "urlencoded"} for item in variants
        ):
            raise BehaviorContractError(
                "secret_source.scan_variants must declare supported exact variants"
            )
        if len(variants) != len(set(variants)):
            raise BehaviorContractError("secret_source.scan_variants contains duplicates")
        object.__setattr__(self, "scan_variants", variants)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "scan_variants": list(self.scan_variants),
        }

    @classmethod
    def from_dict(cls, value: Any) -> SecretSource:
        return cls(
            **_shape(
                value,
                path="secret_source",
                required=frozenset({"name", "kind", "scan_variants"}),
            )
        )


@dataclass(frozen=True)
class AuthResponseFieldSpec:
    pointer: str
    expected: JsonValue

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "pointer",
            _validate_json_pointer(
                self.pointer,
                path="auth_response_field.pointer",
                allow_root=True,
            ),
        )
        expected = freeze_json(
            self.expected,
            path="auth_response_field.expected",
        )
        if isinstance(expected, (Mapping, tuple)):
            raise BehaviorContractError("auth response field expected value must be a safe scalar")
        reject_sensitive_json(expected, path="auth_response_field.expected")
        object.__setattr__(self, "expected", expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pointer": self.pointer,
            "expected": thaw_json(self.expected),
        }

    @classmethod
    def from_dict(cls, value: Any) -> AuthResponseFieldSpec:
        return cls(
            **_shape(
                value,
                path="auth_response_field",
                required=frozenset({"pointer", "expected"}),
            )
        )


@dataclass(frozen=True)
class ClientBasicAuthSpec:
    client_id: str
    client_secret_source: str

    def __post_init__(self) -> None:
        client_id = _string(self.client_id, path="client_basic_auth.client_id")
        if (
            ":" in client_id
            or "\r" in client_id
            or "\n" in client_id
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in client_id)
        ):
            raise BehaviorContractError("client_basic_auth.client_id must be a safe Basic username")
        object.__setattr__(self, "client_id", client_id)
        object.__setattr__(
            self,
            "client_secret_source",
            _identifier(
                self.client_secret_source,
                path="client_basic_auth.client_secret_source",
            ),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "client_id": self.client_id,
            "client_secret_source": self.client_secret_source,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ClientBasicAuthSpec:
        return cls(
            **_shape(
                value,
                path="client_basic_auth",
                required=frozenset({"client_id", "client_secret_source"}),
            )
        )


@dataclass(frozen=True)
class AuthGrantSpec:
    path: str
    form_fields: Mapping[str, str]
    form_secret_fields: Mapping[str, str]
    token_pointer: str
    response_fields: Mapping[str, AuthResponseFieldSpec]
    client_basic_auth: ClientBasicAuthSpec | None = None

    def __post_init__(self) -> None:
        path = _string(self.path, path="auth_grant.path")
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or any(character.isspace() for character in path)
        ):
            raise BehaviorContractError("auth_grant.path must be an absolute HTTP path")
        object.__setattr__(self, "path", path)
        if not isinstance(self.form_fields, Mapping):
            raise BehaviorContractError("auth_grant.form_fields must be an object")
        public_fields: dict[str, str] = {}
        for raw_field, raw_value in self.form_fields.items():
            field_name = _identifier(raw_field, path="auth_grant.form_fields key")
            if field_name.lower().replace("-", "_") in _SENSITIVE_JSON_KEYS:
                raise BehaviorContractError(
                    "auth grant sensitive form fields must reference secret sources"
                )
            public_fields[field_name] = _string(
                raw_value,
                path=f"auth_grant.form_fields.{field_name}",
            )
        object.__setattr__(self, "form_fields", MappingProxyType(public_fields))
        if not isinstance(self.form_secret_fields, Mapping):
            raise BehaviorContractError("auth_grant.form_secret_fields must be an object")
        fields: dict[str, str] = {}
        for raw_field, raw_source in self.form_secret_fields.items():
            field_name = _identifier(raw_field, path="auth_grant.form_secret_fields key")
            if field_name in fields:
                raise BehaviorContractError(
                    "auth_grant.form_secret_fields contains duplicate fields"
                )
            fields[field_name] = _identifier(
                raw_source,
                path=f"auth_grant.form_secret_fields.{field_name}",
            )
        if not fields:
            raise BehaviorContractError(
                "auth_grant.form_secret_fields must declare exact secret inputs"
            )
        object.__setattr__(self, "form_secret_fields", MappingProxyType(fields))
        if set(public_fields) & set(fields):
            raise BehaviorContractError("auth grant public and secret form fields must not overlap")
        if self.client_basic_auth is not None:
            if not isinstance(self.client_basic_auth, ClientBasicAuthSpec):
                raise BehaviorContractError("auth_grant.client_basic_auth is invalid")
            if self.client_basic_auth.client_secret_source in fields.values() or any(
                field_name.lower().replace("-", "_") == "client_secret" for field_name in fields
            ):
                raise BehaviorContractError(
                    "Basic client secret must not also appear in grant form fields"
                )
        if not isinstance(self.response_fields, Mapping):
            raise BehaviorContractError("auth_grant.response_fields must be an object")
        response_fields: dict[str, AuthResponseFieldSpec] = {}
        for raw_name, raw_spec in self.response_fields.items():
            name = _identifier(raw_name, path="auth_grant.response_fields key")
            if name.lower().replace("-", "_") in _SENSITIVE_JSON_KEYS:
                raise BehaviorContractError(
                    "auth grant response fields must contain only safe observations"
                )
            if not isinstance(raw_spec, AuthResponseFieldSpec):
                raise BehaviorContractError("auth_grant.response_fields contains an invalid field")
            response_fields[name] = raw_spec
        if "username" not in response_fields:
            raise BehaviorContractError("auth_grant.response_fields must declare username identity")
        object.__setattr__(
            self,
            "response_fields",
            MappingProxyType(response_fields),
        )
        object.__setattr__(
            self,
            "token_pointer",
            _validate_json_pointer(
                self.token_pointer,
                path="auth_grant.token_pointer",
                allow_root=False,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "form_fields": dict(self.form_fields),
            "form_secret_fields": dict(self.form_secret_fields),
            "token_pointer": self.token_pointer,
            "response_fields": {
                name: spec.to_dict() for name, spec in self.response_fields.items()
            },
            "client_basic_auth": (
                None if self.client_basic_auth is None else self.client_basic_auth.to_dict()
            ),
        }

    @classmethod
    def from_dict(cls, value: Any) -> AuthGrantSpec:
        raw = _shape(
            value,
            path="auth_grant",
            required=frozenset(
                {
                    "path",
                    "form_fields",
                    "form_secret_fields",
                    "token_pointer",
                    "response_fields",
                    "client_basic_auth",
                }
            ),
        )
        if type(raw["response_fields"]) is not dict:
            raise BehaviorContractError("auth_grant.response_fields must be an object")
        return cls(
            path=raw["path"],
            form_fields=raw["form_fields"],
            form_secret_fields=raw["form_secret_fields"],
            token_pointer=raw["token_pointer"],
            response_fields={
                name: AuthResponseFieldSpec.from_dict(spec)
                for name, spec in raw["response_fields"].items()
            },
            client_basic_auth=(
                None
                if raw["client_basic_auth"] is None
                else ClientBasicAuthSpec.from_dict(raw["client_basic_auth"])
            ),
        )


@dataclass(frozen=True)
class AuthContext:
    context_id: str
    strategy_id: str
    secret_source_names: tuple[str, ...]
    actor_alias: str
    grant_required: bool
    grant: AuthGrantSpec | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "context_id",
            _identifier(self.context_id, path="auth_context.context_id"),
        )
        object.__setattr__(
            self,
            "strategy_id",
            _identifier(self.strategy_id, path="auth_context.strategy_id"),
        )
        object.__setattr__(
            self,
            "secret_source_names",
            _string_tuple(
                self.secret_source_names,
                path="auth_context.secret_source_names",
            ),
        )
        object.__setattr__(
            self,
            "actor_alias",
            _identifier(self.actor_alias, path="auth_context.actor_alias"),
        )
        if type(self.grant_required) is not bool:
            raise BehaviorContractError("auth_context.grant_required must be a boolean")
        if self.grant_required != (self.grant is not None):
            raise BehaviorContractError(
                "auth_context.grant_required must exactly match grant presence"
            )
        if self.grant is not None:
            if not isinstance(self.grant, AuthGrantSpec):
                raise BehaviorContractError("auth_context.grant is invalid")
            if self.strategy_id != "oauth_password_grant":
                raise BehaviorContractError(
                    "auth grants require strategy_id oauth_password_grant",
                    code="auth_strategy_invalid",
                )
            grant_sources = set(self.grant.form_secret_fields.values())
            if self.grant.client_basic_auth is not None:
                grant_sources.add(self.grant.client_basic_auth.client_secret_source)
            if grant_sources != set(self.secret_source_names):
                raise BehaviorContractError(
                    "auth grant form and Basic sources must exactly cover context secret sources"
                )
            if self.grant.response_fields["username"].expected != self.actor_alias:
                raise BehaviorContractError(
                    "auth grant expected username must equal context actor_alias"
                )
        elif self.strategy_id not in {
            "none",
            "bearer",
            AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER,
        }:
            raise BehaviorContractError(
                "auth_context.strategy_id is unsupported by behavior-harvest engine v2",
                code="auth_strategy_invalid",
            )
        if self.strategy_id == "none" and self.secret_source_names:
            raise BehaviorContractError(
                "none auth strategy cannot reference secret sources",
                code="auth_strategy_invalid",
            )
        if self.strategy_id == "bearer" and len(self.secret_source_names) != 1:
            raise BehaviorContractError(
                "bearer auth strategy requires exactly one secret source",
                code="auth_strategy_invalid",
            )
        if (
            self.strategy_id == AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER
            and len(self.secret_source_names) != 1
        ):
            raise BehaviorContractError(
                "opaque Authorization header strategy requires exactly one secret source",
                code="auth_strategy_invalid",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "strategy_id": self.strategy_id,
            "secret_source_names": list(self.secret_source_names),
            "actor_alias": self.actor_alias,
            "grant_required": self.grant_required,
            "grant": None if self.grant is None else self.grant.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> AuthContext:
        raw = _shape(
            value,
            path="auth_context",
            required=frozenset(
                {
                    "context_id",
                    "strategy_id",
                    "secret_source_names",
                    "actor_alias",
                    "grant_required",
                    "grant",
                }
            ),
        )
        return cls(
            context_id=raw["context_id"],
            strategy_id=raw["strategy_id"],
            secret_source_names=_string_tuple(
                raw["secret_source_names"],
                path="auth_context.secret_source_names",
            ),
            actor_alias=raw["actor_alias"],
            grant_required=raw["grant_required"],
            grant=(None if raw["grant"] is None else AuthGrantSpec.from_dict(raw["grant"])),
        )


@dataclass(frozen=True)
class AuthProfile:
    profile_id: str
    kind: Literal["none", "secret"]
    secret_sources: tuple[SecretSource, ...]
    contexts: tuple[AuthContext, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "profile_id",
            _identifier(self.profile_id, path="auth.profile_id"),
        )
        if self.kind not in {"none", "secret"}:
            raise BehaviorContractError("auth.kind is unsupported")
        sources = tuple(self.secret_sources)
        if not all(isinstance(item, SecretSource) for item in sources):
            raise BehaviorContractError("auth.secret_sources contains an invalid declaration")
        if self.kind == "none" and sources:
            raise BehaviorContractError("auth kind 'none' must not declare secret sources")
        if self.kind == "secret" and not sources:
            raise BehaviorContractError("auth kind 'secret' requires secret sources")
        names = [item.name for item in sources]
        if len(names) != len(set(names)):
            raise BehaviorContractError("auth.secret_sources contains duplicate names")
        object.__setattr__(self, "secret_sources", sources)
        contexts = tuple(self.contexts)
        if not contexts or not all(isinstance(item, AuthContext) for item in contexts):
            raise BehaviorContractError("auth.contexts must contain explicit auth contexts")
        context_ids = [item.context_id for item in contexts]
        if len(context_ids) != len(set(context_ids)):
            raise BehaviorContractError("auth.contexts contains duplicate context ids")
        declared_names = set(names)
        referenced_names: set[str] = set()
        source_by_name = {item.name: item for item in sources}
        for context in contexts:
            unknown = set(context.secret_source_names) - declared_names
            if unknown:
                raise BehaviorContractError(
                    f"auth context {context.context_id!r} references undeclared secret sources"
                )
            if self.kind == "none" and context.secret_source_names:
                raise BehaviorContractError(
                    "auth kind 'none' contexts cannot reference secret sources"
                )
            if self.kind == "none" and context.grant_required:
                raise BehaviorContractError("auth kind 'none' contexts cannot require a grant")
            if self.kind == "none" and context.strategy_id != "none":
                raise BehaviorContractError("auth kind 'none' requires the none context strategy")
            referenced_names.update(context.secret_source_names)
            required_by_source: dict[str, set[str]] = {
                source_name: {"raw", "urlencoded", "base64"}
                for source_name in context.secret_source_names
            }
            if context.strategy_id == "bearer":
                required_by_source[context.secret_source_names[0]].add("bearer")
            elif context.grant is not None:
                if context.grant.client_basic_auth is not None:
                    required_by_source[context.grant.client_basic_auth.client_secret_source].add(
                        "basic"
                    )
            for source_name, required_variants in required_by_source.items():
                if not required_variants <= set(source_by_name[source_name].scan_variants):
                    raise BehaviorContractError(
                        f"secret source {source_name!r} omits variants required "
                        f"by auth strategy {context.strategy_id!r}"
                    )
        if referenced_names != declared_names:
            raise BehaviorContractError(
                "auth secret sources must be exactly referenced by auth contexts"
            )
        if self.kind == "none" and len(contexts) != 1:
            raise BehaviorContractError("auth kind 'none' requires exactly one explicit context")
        object.__setattr__(self, "contexts", contexts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "kind": self.kind,
            "secret_sources": [item.to_dict() for item in self.secret_sources],
            "contexts": [item.to_dict() for item in self.contexts],
        }

    @classmethod
    def from_dict(cls, value: Any) -> AuthProfile:
        raw = _shape(
            value,
            path="auth",
            required=frozenset({"profile_id", "kind", "secret_sources", "contexts"}),
        )
        for array_name in ("secret_sources", "contexts"):
            if type(raw[array_name]) is not list:
                raise BehaviorContractError(f"auth.{array_name} must be an array")
        return cls(
            profile_id=raw["profile_id"],
            kind=raw["kind"],
            secret_sources=tuple(SecretSource.from_dict(item) for item in raw["secret_sources"]),
            contexts=tuple(AuthContext.from_dict(item) for item in raw["contexts"]),
        )


@dataclass(frozen=True)
class EvidenceCallSpec:
    call_id: str
    strategy_id: str
    auth_context_id: str
    request: RequestTemplate
    assertions: tuple[AssertionSpec, ...]

    def __post_init__(self) -> None:
        for name in ("call_id", "strategy_id", "auth_context_id"):
            object.__setattr__(
                self,
                name,
                _identifier(getattr(self, name), path=f"evidence_call.{name}"),
            )
        if not isinstance(self.request, RequestTemplate):
            raise BehaviorContractError("evidence_call.request is invalid")
        if self.request.method not in _READ_METHODS:
            raise BehaviorContractError("evidence calls must use GET or HEAD")
        assertions = tuple(self.assertions)
        if not assertions or not all(isinstance(item, AssertionSpec) for item in assertions):
            raise BehaviorContractError("evidence_call.assertions must contain assertions")
        ids = [item.assertion_id for item in assertions]
        if len(ids) != len(set(ids)):
            raise BehaviorContractError("evidence_call.assertions contains duplicate assertion ids")
        if not any(item.kind in {"status_equals", "status_in"} for item in assertions):
            raise BehaviorContractError("evidence_call requires a status assertion")
        statuses: list[int] = []
        for assertion in assertions:
            if assertion.kind == "status_equals":
                assert type(assertion.expected) is int
                statuses.append(assertion.expected)
            elif assertion.kind == "status_in":
                assert type(assertion.expected) is tuple
                statuses.extend(assertion.expected)
        if any(not 200 <= status <= 299 for status in statuses):
            raise BehaviorContractError("evidence_call status assertions must contain only 2xx")
        for assertion in assertions:
            if assertion.prior_step_id is not None:
                raise BehaviorContractError(
                    "evidence_call assertions cannot reference program steps"
                )
        object.__setattr__(self, "assertions", assertions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "strategy_id": self.strategy_id,
            "auth_context_id": self.auth_context_id,
            "request": self.request.to_dict(),
            "assertions": [item.to_dict() for item in self.assertions],
        }

    @classmethod
    def from_dict(cls, value: Any) -> EvidenceCallSpec:
        raw = _shape(
            value,
            path="evidence_call",
            required=frozenset(
                {
                    "call_id",
                    "strategy_id",
                    "auth_context_id",
                    "request",
                    "assertions",
                }
            ),
        )
        if type(raw["assertions"]) is not list:
            raise BehaviorContractError("evidence_call.assertions must be an array")
        return cls(
            call_id=raw["call_id"],
            strategy_id=raw["strategy_id"],
            auth_context_id=raw["auth_context_id"],
            request=RequestTemplate.from_dict(raw["request"]),
            assertions=tuple(AssertionSpec.from_dict(item) for item in raw["assertions"]),
        )


@dataclass(frozen=True)
class StaticIdentityProjection:
    output_key: str
    input_id: str
    pointer: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "output_key",
            _identifier(self.output_key, path="static_projection.output_key"),
        )
        object.__setattr__(
            self,
            "input_id",
            _identifier(self.input_id, path="static_projection.input_id"),
        )
        object.__setattr__(
            self,
            "pointer",
            _validate_json_pointer(
                self.pointer,
                path="static_projection.pointer",
                allow_root=True,
            ),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "output_key": self.output_key,
            "input_id": self.input_id,
            "pointer": self.pointer,
        }

    @classmethod
    def from_dict(cls, value: Any) -> StaticIdentityProjection:
        return cls(
            **_shape(
                value,
                path="static_projection",
                required=frozenset({"output_key", "input_id", "pointer"}),
            )
        )


@dataclass(frozen=True)
class IdentityPreflight:
    strategy_id: str
    expected_identity: Mapping[str, JsonValue]
    calls: tuple[EvidenceCallSpec, ...]
    identity_call_id: str | None
    identity_pointer: str | None
    authenticated_context_ids: tuple[str, ...]
    static_projections: tuple[StaticIdentityProjection, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "strategy_id",
            _identifier(self.strategy_id, path="identity_preflight.strategy_id"),
        )
        expected = _json_object(
            self.expected_identity,
            path="identity_preflight.expected_identity",
        )
        if not expected:
            raise BehaviorContractError("identity_preflight.expected_identity must not be empty")
        reject_sensitive_json(expected, path="identity_preflight.expected_identity")
        object.__setattr__(self, "expected_identity", expected)
        calls = tuple(self.calls)
        if not all(isinstance(item, EvidenceCallSpec) for item in calls):
            raise BehaviorContractError("identity_preflight.calls contains an invalid call")
        call_ids = [item.call_id for item in calls]
        if len(call_ids) != len(set(call_ids)):
            raise BehaviorContractError("identity_preflight.calls contains duplicate call ids")
        if any(item.strategy_id != self.strategy_id for item in calls):
            raise BehaviorContractError(
                "identity_preflight call strategy must match preflight strategy"
            )
        object.__setattr__(self, "calls", calls)
        if (self.identity_call_id is None) != (self.identity_pointer is None):
            raise BehaviorContractError("identity call id and pointer must be declared together")
        if self.identity_call_id is not None:
            identity_call_id = _identifier(
                self.identity_call_id,
                path="identity_preflight.identity_call_id",
            )
            if identity_call_id not in call_ids:
                raise BehaviorContractError("identity_preflight.identity_call_id is not declared")
            object.__setattr__(self, "identity_call_id", identity_call_id)
            object.__setattr__(
                self,
                "identity_pointer",
                _validate_json_pointer(
                    self.identity_pointer,
                    path="identity_preflight.identity_pointer",
                    allow_root=True,
                ),
            )
        contexts = tuple(self.authenticated_context_ids)
        if len(contexts) != len(set(contexts)):
            raise BehaviorContractError(
                "identity_preflight.authenticated_context_ids contains duplicates"
            )
        for index, context_id in enumerate(contexts):
            _identifier(
                context_id,
                path=f"identity_preflight.authenticated_context_ids[{index}]",
            )
        object.__setattr__(
            self,
            "authenticated_context_ids",
            contexts,
        )
        projections = tuple(self.static_projections)
        if not all(isinstance(item, StaticIdentityProjection) for item in projections):
            raise BehaviorContractError(
                "identity_preflight.static_projections contains an invalid projection"
            )
        output_keys = [item.output_key for item in projections]
        if len(output_keys) != len(set(output_keys)):
            raise BehaviorContractError(
                "identity_preflight.static_projections contains duplicate output keys"
            )
        object.__setattr__(self, "static_projections", projections)
        if self.identity_call_id is None and not contexts and not projections:
            raise BehaviorContractError(
                "identity preflight requires provider, auth, or static evidence"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "expected_identity": thaw_json(self.expected_identity),
            "calls": [item.to_dict() for item in self.calls],
            "identity_call_id": self.identity_call_id,
            "identity_pointer": self.identity_pointer,
            "authenticated_context_ids": list(self.authenticated_context_ids),
            "static_projections": [item.to_dict() for item in self.static_projections],
        }

    @classmethod
    def from_dict(cls, value: Any) -> IdentityPreflight:
        raw = _shape(
            value,
            path="identity_preflight",
            required=frozenset(
                {
                    "strategy_id",
                    "expected_identity",
                    "calls",
                    "identity_call_id",
                    "identity_pointer",
                    "authenticated_context_ids",
                    "static_projections",
                }
            ),
        )
        if type(raw["calls"]) is not list:
            raise BehaviorContractError("identity_preflight.calls must be an array")
        if type(raw["static_projections"]) is not list:
            raise BehaviorContractError("identity_preflight.static_projections must be an array")
        return cls(
            strategy_id=raw["strategy_id"],
            expected_identity=raw["expected_identity"],
            calls=tuple(EvidenceCallSpec.from_dict(item) for item in raw["calls"]),
            identity_call_id=raw["identity_call_id"],
            identity_pointer=raw["identity_pointer"],
            authenticated_context_ids=_string_tuple(
                raw["authenticated_context_ids"],
                path="identity_preflight.authenticated_context_ids",
            ),
            static_projections=tuple(
                StaticIdentityProjection.from_dict(item) for item in raw["static_projections"]
            ),
        )


@dataclass(frozen=True)
class IsolationResetSpec:
    isolation_kind: Literal["namespace", "run_scoped_resources", "tenant"]
    cleanup_kind: Literal["delete_run_resources", "namespace_recreate", "none"]
    cleanup_strategy_id: str
    reset_kind: Literal["none", "snapshot_restore", "tenant_recreate"]
    reset_strategy_id: str | None
    reset_equivalence_claimed: bool

    def __post_init__(self) -> None:
        if self.isolation_kind not in {"namespace", "run_scoped_resources", "tenant"}:
            raise BehaviorContractError("isolation.isolation_kind is unsupported")
        if self.cleanup_kind not in {"delete_run_resources", "namespace_recreate", "none"}:
            raise BehaviorContractError("isolation.cleanup_kind is unsupported")
        if self.reset_kind not in {"none", "snapshot_restore", "tenant_recreate"}:
            raise BehaviorContractError("isolation.reset_kind is unsupported")
        object.__setattr__(
            self,
            "cleanup_strategy_id",
            _identifier(
                self.cleanup_strategy_id,
                path="isolation.cleanup_strategy_id",
            ),
        )
        if self.reset_kind == "none":
            if self.reset_strategy_id is not None or self.reset_equivalence_claimed is not False:
                raise BehaviorContractError(
                    "reset_kind 'none' requires no strategy and no equivalence claim"
                )
        else:
            if self.reset_strategy_id is None:
                raise BehaviorContractError("true reset requires reset_strategy_id")
            object.__setattr__(
                self,
                "reset_strategy_id",
                _identifier(
                    self.reset_strategy_id,
                    path="isolation.reset_strategy_id",
                ),
            )
            if type(self.reset_equivalence_claimed) is not bool:
                raise BehaviorContractError("isolation.reset_equivalence_claimed must be a boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "isolation_kind": self.isolation_kind,
            "cleanup_kind": self.cleanup_kind,
            "cleanup_strategy_id": self.cleanup_strategy_id,
            "reset_kind": self.reset_kind,
            "reset_strategy_id": self.reset_strategy_id,
            "reset_equivalence_claimed": self.reset_equivalence_claimed,
        }

    @classmethod
    def from_dict(cls, value: Any) -> IsolationResetSpec:
        return cls(
            **_shape(
                value,
                path="isolation",
                required=frozenset(
                    {
                        "isolation_kind",
                        "cleanup_kind",
                        "cleanup_strategy_id",
                        "reset_kind",
                        "reset_strategy_id",
                        "reset_equivalence_claimed",
                    }
                ),
            )
        )


@dataclass(frozen=True)
class AuthoringPolicy:
    concurrency: int = 1
    write_retries: int = 0

    def __post_init__(self) -> None:
        if self.concurrency != 1:
            raise BehaviorContractError("authoring_policy.concurrency must equal 1")
        if self.write_retries != 0:
            raise BehaviorContractError("authoring_policy.write_retries must equal 0")

    def to_dict(self) -> dict[str, int]:
        return {"concurrency": self.concurrency, "write_retries": self.write_retries}

    @classmethod
    def from_dict(cls, value: Any) -> AuthoringPolicy:
        return cls(
            **_shape(
                value,
                path="authoring_policy",
                required=frozenset({"concurrency", "write_retries"}),
            )
        )


@dataclass(frozen=True)
class StaticJsonInputSpec:
    input_id: str
    schema_id: str
    max_bytes: int
    expected_json: JsonValue

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "input_id",
            _identifier(self.input_id, path="static_input.input_id"),
        )
        object.__setattr__(
            self,
            "schema_id",
            _identifier(self.schema_id, path="static_input.schema_id"),
        )
        max_bytes = _positive_int(
            self.max_bytes,
            path="static_input.max_bytes",
        )
        if max_bytes > 16 << 20:
            raise BehaviorContractError("static_input.max_bytes exceeds the closed v1 limit")
        object.__setattr__(self, "max_bytes", max_bytes)
        expected = freeze_json(
            self.expected_json,
            path="static_input.expected_json",
        )
        reject_sensitive_json(expected, path="static_input.expected_json")
        object.__setattr__(self, "expected_json", expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_id": self.input_id,
            "schema_id": self.schema_id,
            "max_bytes": self.max_bytes,
            "expected_json": thaw_json(self.expected_json),
        }

    @classmethod
    def from_dict(cls, value: Any) -> StaticJsonInputSpec:
        return cls(
            **_shape(
                value,
                path="static_input",
                required=frozenset({"input_id", "schema_id", "max_bytes", "expected_json"}),
            )
        )


@dataclass(frozen=True)
class SourcePin:
    pin_id: str
    source_ref: str
    version: str
    sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "pin_id", _identifier(self.pin_id, path="source_pin.pin_id"))
        object.__setattr__(
            self,
            "source_ref",
            _string(self.source_ref, path="source_pin.source_ref"),
        )
        object.__setattr__(self, "version", _string(self.version, path="source_pin.version"))
        object.__setattr__(self, "sha256", _sha256(self.sha256, path="source_pin.sha256"))

    def to_dict(self) -> dict[str, str]:
        return {
            "pin_id": self.pin_id,
            "source_ref": self.source_ref,
            "version": self.version,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> SourcePin:
        return cls(
            **_shape(
                value,
                path="source_pin",
                required=frozenset({"pin_id", "source_ref", "version", "sha256"}),
            )
        )


@dataclass(frozen=True)
class CollectorSpec:
    collector_id: str
    kind: Literal["event", "job", "request_log", "webhook"]
    required: bool
    call: EvidenceCallSpec

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "collector_id",
            _identifier(self.collector_id, path="collector.collector_id"),
        )
        if self.kind not in {"event", "job", "request_log", "webhook"}:
            raise BehaviorContractError("collector.kind is unsupported")
        if type(self.required) is not bool:
            raise BehaviorContractError("collector.required must be a boolean")
        if not isinstance(self.call, EvidenceCallSpec):
            raise BehaviorContractError("collector.call is invalid")
        if self.call.call_id != self.collector_id:
            raise BehaviorContractError("collector.call.call_id must equal collector_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "collector_id": self.collector_id,
            "kind": self.kind,
            "required": self.required,
            "call": self.call.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> CollectorSpec:
        raw = _shape(
            value,
            path="collector",
            required=frozenset({"collector_id", "kind", "required", "call"}),
        )
        return cls(
            collector_id=raw["collector_id"],
            kind=raw["kind"],
            required=raw["required"],
            call=EvidenceCallSpec.from_dict(raw["call"]),
        )


@dataclass(frozen=True)
class EngineIdentity:
    engine_id: str
    engine_version: str
    source_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "engine_id",
            _identifier(self.engine_id, path="engine.engine_id"),
        )
        object.__setattr__(
            self,
            "engine_version",
            _string(self.engine_version, path="engine.engine_version"),
        )
        object.__setattr__(
            self,
            "source_sha256",
            _sha256(self.source_sha256, path="engine.source_sha256"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "engine_id": self.engine_id,
            "engine_version": self.engine_version,
            "source_sha256": self.source_sha256,
        }

    @classmethod
    def from_dict(cls, value: Any) -> EngineIdentity:
        return cls(
            **_shape(
                value,
                path="engine",
                required=frozenset({"engine_id", "engine_version", "source_sha256"}),
            )
        )


@dataclass(frozen=True)
class ConnectorSpec:
    connector_id: str
    provider_id: str
    provider_version: str
    origin: str
    driver_kind: DriverKind
    driver_id: str
    driver_version: str
    driver_source_sha256: str
    request_encoding: Literal["canonical_json"]
    allowed_request_headers: tuple[str, ...]
    boundary: BoundarySpec
    auth: AuthProfile
    identity_preflight: IdentityPreflight
    isolation: IsolationResetSpec
    authoring_policy: AuthoringPolicy
    static_json_inputs: tuple[StaticJsonInputSpec, ...]
    source_pins: tuple[SourcePin, ...]
    collectors: tuple[CollectorSpec, ...]
    known_limitations: tuple[str, ...]
    bounds: HarvestBounds
    schema_id: str = BEHAVIOR_CONNECTOR_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != BEHAVIOR_CONNECTOR_SCHEMA_ID:
            raise BehaviorContractError(f"unsupported connector schema: {self.schema_id}")
        for name in ("connector_id", "provider_id", "driver_id"):
            object.__setattr__(
                self, name, _identifier(getattr(self, name), path=f"connector.{name}")
            )
        object.__setattr__(
            self,
            "driver_version",
            _string(self.driver_version, path="connector.driver_version"),
        )
        object.__setattr__(
            self,
            "driver_source_sha256",
            _sha256(
                self.driver_source_sha256,
                path="connector.driver_source_sha256",
            ),
        )
        if self.request_encoding != "canonical_json":
            raise BehaviorContractError(
                "connector.request_encoding must equal 'canonical_json' in v1"
            )
        allowed_headers = _string_tuple(
            self.allowed_request_headers,
            path="connector.allowed_request_headers",
        )
        for header in allowed_headers:
            if (
                header != header.lower()
                or _HEADER_NAME.fullmatch(header) is None
                or _is_sensitive_header(header)
                or header in _FORBIDDEN_REQUEST_HEADERS
            ):
                raise BehaviorContractError(
                    "connector.allowed_request_headers must contain safe lowercase names"
                )
        object.__setattr__(self, "allowed_request_headers", allowed_headers)
        object.__setattr__(
            self,
            "provider_version",
            _string(self.provider_version, path="connector.provider_version"),
        )
        original_origin = _string(self.origin, path="connector.origin")
        origin = original_origin.rstrip("/")
        split = urlsplit(origin)
        original_split = urlsplit(original_origin)
        try:
            split.port
        except ValueError as error:
            raise BehaviorContractError("connector.origin contains an invalid port") from error
        if (
            split.scheme not in {"http", "https"}
            or not split.hostname
            or split.username is not None
            or split.password is not None
            or split.query
            or split.fragment
            or split.path not in {"", "/"}
        ):
            raise BehaviorContractError("connector.origin must be a credential-free HTTP(S) origin")
        if (
            isinstance(self.boundary, BoundarySpec)
            and self.boundary.kind == "self_hosted_reference"
            and (
                original_split.scheme != "http"
                or original_split.hostname != "127.0.0.1"
                or original_split.port is None
                or original_split.netloc != f"127.0.0.1:{original_split.port}"
                or original_split.path
                or original_split.query
                or original_split.fragment
            )
        ):
            raise BehaviorContractError(
                "self_hosted_reference origin must be exact http://127.0.0.1:<port>"
            )
        object.__setattr__(self, "origin", origin)
        if self.driver_kind != "http":
            raise BehaviorContractError("connector.driver_kind must equal 'http'")
        for name, expected_type in (
            ("boundary", BoundarySpec),
            ("auth", AuthProfile),
            ("identity_preflight", IdentityPreflight),
            ("isolation", IsolationResetSpec),
            ("authoring_policy", AuthoringPolicy),
        ):
            if not isinstance(getattr(self, name), expected_type):
                raise BehaviorContractError(f"connector.{name} is invalid")
        if (
            self.boundary.kind
            in {
                "developer_tenant",
                "managed_sandbox",
                "test_mode",
            }
            and split.scheme != "https"
        ):
            raise BehaviorContractError("remote writable boundary requires an exact HTTPS origin")
        static_inputs = tuple(self.static_json_inputs)
        if not all(isinstance(item, StaticJsonInputSpec) for item in static_inputs):
            raise BehaviorContractError("connector.static_json_inputs contains an invalid input")
        static_input_ids = [item.input_id for item in static_inputs]
        if len(static_input_ids) != len(set(static_input_ids)):
            raise BehaviorContractError("connector.static_json_inputs contains duplicate input ids")
        projected_input_ids = {item.input_id for item in self.identity_preflight.static_projections}
        if projected_input_ids != set(static_input_ids):
            raise BehaviorContractError(
                "every declared static input must be referenced by identity projection"
            )
        object.__setattr__(self, "static_json_inputs", static_inputs)
        pins = tuple(self.source_pins)
        if not pins or not all(isinstance(item, SourcePin) for item in pins):
            raise BehaviorContractError("connector.source_pins must contain exact source pins")
        pin_ids = [item.pin_id for item in pins]
        if len(pin_ids) != len(set(pin_ids)):
            raise BehaviorContractError("connector.source_pins contains duplicate pin ids")
        object.__setattr__(self, "source_pins", pins)
        collectors = tuple(self.collectors)
        if not all(isinstance(item, CollectorSpec) for item in collectors):
            raise BehaviorContractError("connector.collectors contains an invalid collector")
        collector_ids = [item.collector_id for item in collectors]
        if len(collector_ids) != len(set(collector_ids)):
            raise BehaviorContractError("connector.collectors contains duplicate collector ids")
        object.__setattr__(self, "collectors", collectors)
        object.__setattr__(
            self,
            "known_limitations",
            _string_tuple(
                self.known_limitations,
                path="connector.known_limitations",
                allow_empty=True,
            ),
        )
        if not isinstance(self.bounds, HarvestBounds):
            raise BehaviorContractError("connector.bounds is invalid")
        declared_contexts = {item.context_id for item in self.auth.contexts}
        referenced_contexts = {
            *[item.auth_context_id for item in self.identity_preflight.calls],
            *[item.call.auth_context_id for item in self.collectors],
            *self.identity_preflight.authenticated_context_ids,
        }
        if not referenced_contexts <= declared_contexts:
            raise BehaviorContractError("connector evidence references undeclared auth contexts")
        if not set(self.identity_preflight.authenticated_context_ids) <= {
            item.context_id for item in self.auth.contexts if item.grant_required
        }:
            raise BehaviorContractError(
                "identity authenticated contexts must require observed grants"
            )
        if self.boundary.kind in {
            "developer_tenant",
            "managed_sandbox",
            "test_mode",
        }:
            identity_call_id = self.identity_preflight.identity_call_id
            if identity_call_id is None:
                raise BehaviorContractError(
                    "remote writable boundary requires a provider identity call"
                )
            identity_call = next(
                item for item in self.identity_preflight.calls if item.call_id == identity_call_id
            )
            identity_context = next(
                item
                for item in self.auth.contexts
                if item.context_id == identity_call.auth_context_id
            )
            if identity_context.strategy_id == "none":
                raise BehaviorContractError(
                    "remote writable boundary identity call requires non-none auth"
                )
        elif self.boundary.kind == "self_hosted_reference":
            if not self.static_json_inputs:
                raise BehaviorContractError(
                    "self_hosted_reference requires static deployment evidence"
                )
            if (
                not self.identity_preflight.authenticated_context_ids
                and self.identity_preflight.identity_call_id is None
            ):
                raise BehaviorContractError(
                    "self_hosted_reference requires verified auth or provider identity evidence"
                )
        for call in (
            *self.identity_preflight.calls,
            *[item.call for item in self.collectors],
        ):
            validate_request_header_allowlist(self, call.request)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "connector_id": self.connector_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "origin": self.origin,
            "driver_kind": self.driver_kind,
            "driver_id": self.driver_id,
            "driver_version": self.driver_version,
            "driver_source_sha256": self.driver_source_sha256,
            "request_encoding": self.request_encoding,
            "allowed_request_headers": list(self.allowed_request_headers),
            "boundary": self.boundary.to_dict(),
            "auth": self.auth.to_dict(),
            "identity_preflight": self.identity_preflight.to_dict(),
            "isolation": self.isolation.to_dict(),
            "authoring_policy": self.authoring_policy.to_dict(),
            "static_json_inputs": [item.to_dict() for item in self.static_json_inputs],
            "source_pins": [item.to_dict() for item in self.source_pins],
            "collectors": [item.to_dict() for item in self.collectors],
            "known_limitations": list(self.known_limitations),
            "bounds": self.bounds.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any) -> ConnectorSpec:
        raw = _shape(
            value,
            path="connector",
            required=frozenset(
                {
                    "schema_id",
                    "connector_id",
                    "provider_id",
                    "provider_version",
                    "origin",
                    "driver_kind",
                    "driver_id",
                    "driver_version",
                    "driver_source_sha256",
                    "request_encoding",
                    "allowed_request_headers",
                    "boundary",
                    "auth",
                    "identity_preflight",
                    "isolation",
                    "authoring_policy",
                    "static_json_inputs",
                    "source_pins",
                    "collectors",
                    "known_limitations",
                    "bounds",
                }
            ),
        )
        for array_name in (
            "allowed_request_headers",
            "static_json_inputs",
            "source_pins",
            "collectors",
            "known_limitations",
        ):
            if type(raw[array_name]) is not list:
                raise BehaviorContractError(f"connector.{array_name} must be an array")
        return cls(
            schema_id=raw["schema_id"],
            connector_id=raw["connector_id"],
            provider_id=raw["provider_id"],
            provider_version=raw["provider_version"],
            origin=raw["origin"],
            driver_kind=raw["driver_kind"],
            driver_id=raw["driver_id"],
            driver_version=raw["driver_version"],
            driver_source_sha256=raw["driver_source_sha256"],
            request_encoding=raw["request_encoding"],
            allowed_request_headers=_string_tuple(
                raw["allowed_request_headers"],
                path="connector.allowed_request_headers",
            ),
            boundary=BoundarySpec.from_dict(raw["boundary"]),
            auth=AuthProfile.from_dict(raw["auth"]),
            identity_preflight=IdentityPreflight.from_dict(raw["identity_preflight"]),
            isolation=IsolationResetSpec.from_dict(raw["isolation"]),
            authoring_policy=AuthoringPolicy.from_dict(raw["authoring_policy"]),
            static_json_inputs=tuple(
                StaticJsonInputSpec.from_dict(item) for item in raw["static_json_inputs"]
            ),
            source_pins=tuple(SourcePin.from_dict(item) for item in raw["source_pins"]),
            collectors=tuple(CollectorSpec.from_dict(item) for item in raw["collectors"]),
            known_limitations=_string_tuple(
                raw["known_limitations"],
                path="connector.known_limitations",
            ),
            bounds=HarvestBounds.from_dict(raw["bounds"]),
        )


@dataclass(frozen=True)
class ResponseBindingOccurrence:
    step_id: str
    pointer: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "step_id",
            _identifier(self.step_id, path="binding.response_occurrence.step_id"),
        )
        _validate_json_pointer(
            self.pointer,
            path="binding.response_occurrence.pointer",
            allow_root=False,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "step_id": self.step_id,
            "pointer": self.pointer,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ResponseBindingOccurrence:
        return cls(
            **_shape(
                value,
                path="binding.response_occurrence",
                required=frozenset({"step_id", "pointer"}),
            )
        )


@dataclass(frozen=True)
class BindingSpec:
    binding_id: str
    pointer: str
    value_type: BindingType
    response_occurrences: tuple[ResponseBindingOccurrence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "binding_id",
            _identifier(self.binding_id, path="binding.binding_id"),
        )
        _validate_json_pointer(self.pointer, path="binding.pointer", allow_root=False)
        if self.value_type not in {"string", "integer"}:
            raise BehaviorContractError(
                "behavior-harvest v2 generated bindings must be strings or integers",
                code="binding_coercion_invalid",
            )
        occurrences = tuple(self.response_occurrences)
        if not all(isinstance(item, ResponseBindingOccurrence) for item in occurrences):
            raise BehaviorContractError(
                "binding.response_occurrences contains an invalid item",
                code="binding_occurrence_invalid",
            )
        locations = [(item.step_id, item.pointer) for item in occurrences]
        if len(locations) != len(set(locations)):
            raise BehaviorContractError(
                "binding.response_occurrences contains duplicate locations",
                code="binding_occurrence_invalid",
            )
        if self.value_type == "integer" and not occurrences:
            raise BehaviorContractError(
                "integer bindings require explicit response occurrences",
                code="binding_occurrence_invalid",
            )
        object.__setattr__(self, "response_occurrences", occurrences)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "binding_id": self.binding_id,
            "pointer": self.pointer,
            "value_type": self.value_type,
        }
        if self.response_occurrences:
            result["response_occurrences"] = [item.to_dict() for item in self.response_occurrences]
        return result

    @classmethod
    def from_dict(cls, value: Any) -> BindingSpec:
        raw = _shape(
            value,
            path="binding",
            required=frozenset({"binding_id", "pointer", "value_type"}),
            optional=frozenset({"response_occurrences"}),
        )
        raw_occurrences = raw.get("response_occurrences", [])
        if type(raw_occurrences) is not list:
            raise BehaviorContractError("binding.response_occurrences must be an array")
        return cls(
            binding_id=raw["binding_id"],
            pointer=raw["pointer"],
            value_type=raw["value_type"],
            response_occurrences=tuple(
                ResponseBindingOccurrence.from_dict(item) for item in raw_occurrences
            ),
        )


@dataclass(frozen=True)
class RequestTemplate:
    method: str
    path: JsonValue
    query: JsonValue = field(default_factory=lambda: MappingProxyType({}))
    body: JsonValue = None
    headers: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        method = _string(self.method, path="request.method").upper()
        if method not in _HTTP_METHODS:
            raise BehaviorContractError(f"request.method is unsupported: {method}")
        object.__setattr__(self, "method", method)
        path = freeze_json(self.path, path="request.path")
        if type(path) is str:
            pass
        elif type(path) is tuple:
            if not path:
                raise BehaviorContractError("request.path template must not be empty")
            saw_binding = False
            for index, segment in enumerate(path):
                if type(segment) is str:
                    if not segment:
                        raise BehaviorContractError(
                            f"request.path[{index}] literal must not be empty"
                        )
                elif isinstance(segment, Mapping) and set(segment.keys()) == {"$binding"}:
                    _identifier(segment["$binding"], path=f"request.path[{index}].$binding")
                    saw_binding = True
                else:
                    raise BehaviorContractError(
                        "request.path template segments must be literals or whole binding refs"
                    )
            for index, segment in enumerate(path):
                if not (isinstance(segment, Mapping) and set(segment.keys()) == {"$binding"}):
                    continue
                before = path[index - 1] if index > 0 else None
                after = path[index + 1] if index + 1 < len(path) else None
                if (
                    type(before) is not str
                    or not before.endswith("/")
                    or (after is not None and (type(after) is not str or not after.startswith("/")))
                ):
                    raise BehaviorContractError(
                        "request.path bindings must occupy one whole path segment",
                        code="binding_coercion_invalid",
                    )
            if not saw_binding:
                raise BehaviorContractError(
                    "request.path arrays are reserved for binding templates"
                )
        else:
            raise BehaviorContractError("request.path must be a string or path-segment array")
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "query", freeze_json(self.query, path="request.query"))
        object.__setattr__(self, "body", freeze_json(self.body, path="request.body"))
        object.__setattr__(self, "headers", safe_headers(self.headers, path="request.headers"))
        if set(self.headers) & _FORBIDDEN_REQUEST_HEADERS:
            raise BehaviorContractError(
                "request headers cannot control origin, framing, or connection behavior"
            )
        reject_sensitive_json(self.query, path="request.query")
        reject_sensitive_json(self.body, path="request.body")

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": thaw_json(self.path),
            "query": thaw_json(self.query),
            "body": thaw_json(self.body),
            "headers": dict(self.headers),
        }

    @classmethod
    def from_dict(cls, value: Any) -> RequestTemplate:
        raw = _shape(
            value,
            path="request",
            required=frozenset({"method", "path", "query", "body", "headers"}),
        )
        return cls(**raw)


@dataclass(frozen=True)
class AssertionSpec:
    assertion_id: str
    kind: Literal[
        "json_pointer_equals",
        "json_pointer_pattern",
        "json_pointer_type",
        "request_equals_step",
        "response_equals_step",
        "state_observe_step",
        "state_changes_from_step",
        "state_equals_step",
        "status_equals",
        "status_in",
    ]
    pointer: str | None = None
    expected: JsonValue = None
    value_type: BindingType | None = None
    pattern: str | None = None
    prior_step_id: str | None = None
    prior_pointer: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "assertion_id",
            _identifier(self.assertion_id, path="assertion.assertion_id"),
        )
        valid_kinds = {
            "json_pointer_equals",
            "json_pointer_pattern",
            "json_pointer_type",
            "request_equals_step",
            "response_equals_step",
            "state_observe_step",
            "state_changes_from_step",
            "state_equals_step",
            "status_equals",
            "status_in",
        }
        if self.kind not in valid_kinds:
            raise BehaviorContractError("assertion.kind is unsupported")
        expected = freeze_json(self.expected, path="assertion.expected")
        reject_sensitive_json(expected, path="assertion.expected")
        object.__setattr__(self, "expected", expected)
        pointer_kinds = {
            "json_pointer_equals",
            "json_pointer_pattern",
            "json_pointer_type",
            "state_changes_from_step",
            "state_equals_step",
            "state_observe_step",
        }
        if self.kind in pointer_kinds:
            _validate_json_pointer(self.pointer, path="assertion.pointer", allow_root=True)
        elif self.pointer is not None:
            raise BehaviorContractError(f"{self.kind} assertion does not accept pointer")
        if self.kind in {
            "request_equals_step",
            "response_equals_step",
            "state_changes_from_step",
            "state_equals_step",
            "state_observe_step",
        }:
            if self.prior_step_id is None:
                raise BehaviorContractError(f"{self.kind} assertion requires prior_step_id")
            object.__setattr__(
                self,
                "prior_step_id",
                _identifier(self.prior_step_id, path="assertion.prior_step_id"),
            )
        elif self.prior_step_id is not None:
            raise BehaviorContractError(f"{self.kind} assertion does not accept prior_step_id")
        if self.kind in {
            "state_changes_from_step",
            "state_equals_step",
            "state_observe_step",
        }:
            _validate_json_pointer(
                self.prior_pointer,
                path="assertion.prior_pointer",
                allow_root=True,
            )
        elif self.prior_pointer is not None:
            raise BehaviorContractError(f"{self.kind} assertion does not accept prior_pointer")
        if self.kind == "json_pointer_type":
            if self.value_type not in {
                "array",
                "boolean",
                "integer",
                "null",
                "number",
                "object",
                "string",
            }:
                raise BehaviorContractError("json_pointer_type requires value_type")
        elif self.value_type is not None:
            raise BehaviorContractError(f"{self.kind} assertion does not accept value_type")
        if self.kind == "json_pointer_pattern":
            if type(self.pattern) is not str or not self.pattern:
                raise BehaviorContractError("json_pointer_pattern requires pattern")
            try:
                re.compile(self.pattern)
            except re.error as error:
                raise BehaviorContractError("assertion.pattern is invalid") from error
        elif self.pattern is not None:
            raise BehaviorContractError(f"{self.kind} assertion does not accept pattern")
        if self.kind == "status_equals":
            if type(self.expected) is not int or not 100 <= self.expected <= 599:
                raise BehaviorContractError("status_equals expected must be one HTTP status")
        if self.kind == "status_in":
            if type(self.expected) is not tuple or not self.expected:
                raise BehaviorContractError("status_in expected must be a non-empty array")
            if any(type(item) is not int or not 100 <= item <= 599 for item in self.expected):
                raise BehaviorContractError("status_in expected contains an invalid HTTP status")

    def to_dict(self) -> dict[str, Any]:
        return {
            "assertion_id": self.assertion_id,
            "kind": self.kind,
            "pointer": self.pointer,
            "expected": thaw_json(self.expected),
            "value_type": self.value_type,
            "pattern": self.pattern,
            "prior_step_id": self.prior_step_id,
            "prior_pointer": self.prior_pointer,
        }

    @classmethod
    def from_dict(cls, value: Any) -> AssertionSpec:
        return cls(
            **_shape(
                value,
                path="assertion",
                required=frozenset(
                    {
                        "assertion_id",
                        "kind",
                        "pointer",
                        "expected",
                        "value_type",
                        "pattern",
                        "prior_step_id",
                        "prior_pointer",
                    }
                ),
            )
        )


@dataclass(frozen=True)
class ProgramRequirements:
    success: bool
    duplicate: bool
    native_failure: bool
    resulting_state: bool

    def __post_init__(self) -> None:
        for name in ("success", "duplicate", "native_failure", "resulting_state"):
            if getattr(self, name) is not True:
                raise BehaviorContractError(f"requirements.{name} must be true")

    def to_dict(self) -> dict[str, bool]:
        return {
            "success": self.success,
            "duplicate": self.duplicate,
            "native_failure": self.native_failure,
            "resulting_state": self.resulting_state,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ProgramRequirements:
        return cls(
            **_shape(
                value,
                path="requirements",
                required=frozenset({"success", "duplicate", "native_failure", "resulting_state"}),
            )
        )


@dataclass(frozen=True)
class BehaviorStep:
    step_id: str
    operation_id: str
    kind: StepKind
    role: StepRole
    expected_outcome: Literal[
        "duplicate_failure",
        "idempotent_success",
        "mutation_success",
        "native_failure",
        "observe",
        "read_success",
    ]
    subject_id: str
    auth_context_id: str
    request: RequestTemplate
    bindings: tuple[BindingSpec, ...] = ()
    assertions: tuple[AssertionSpec, ...] = ()

    def __post_init__(self) -> None:
        for name in ("step_id", "operation_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), path=f"step.{name}"))
        if self.kind not in {"read", "mutation"}:
            raise BehaviorContractError("step.kind is unsupported")
        if self.role not in {
            "before",
            "duplicate",
            "native_failure",
            "resulting_state",
            "success",
            "supporting",
        }:
            raise BehaviorContractError("step.role is unsupported")
        expected_outcomes = {
            "before": {"read_success"},
            "success": {"mutation_success"},
            "duplicate": {"idempotent_success", "duplicate_failure", "observe"},
            "native_failure": {"native_failure"},
            "resulting_state": {"read_success", "observe"},
            "supporting": {"read_success", "mutation_success"},
        }
        if self.expected_outcome not in expected_outcomes[self.role]:
            raise BehaviorContractError(f"step.expected_outcome is invalid for role {self.role!r}")
        object.__setattr__(
            self,
            "subject_id",
            _identifier(self.subject_id, path="step.subject_id"),
        )
        object.__setattr__(
            self,
            "auth_context_id",
            _identifier(self.auth_context_id, path="step.auth_context_id"),
        )
        if not isinstance(self.request, RequestTemplate):
            raise BehaviorContractError("step.request is invalid")
        if self.kind == "read" and self.request.method not in _READ_METHODS:
            raise BehaviorContractError("read step must use GET or HEAD")
        if self.kind == "mutation" and self.request.method not in _MUTATION_METHODS:
            raise BehaviorContractError("mutation step must use POST, PUT, PATCH, or DELETE")
        if self.role in {"before", "resulting_state"} and self.kind != "read":
            raise BehaviorContractError(f"{self.role} role must be a read")
        if self.role in {"success", "duplicate", "native_failure"} and self.kind != "mutation":
            raise BehaviorContractError(f"{self.role} role must be a mutation")
        bindings = tuple(self.bindings)
        if not all(isinstance(item, BindingSpec) for item in bindings):
            raise BehaviorContractError("step.bindings contains an invalid item")
        ids = [item.binding_id for item in bindings]
        if len(ids) != len(set(ids)):
            raise BehaviorContractError("step.bindings contains duplicate binding ids")
        object.__setattr__(self, "bindings", bindings)
        assertions = tuple(self.assertions)
        if not assertions or not all(isinstance(item, AssertionSpec) for item in assertions):
            raise BehaviorContractError("step.assertions must contain assertions")
        assertion_ids = [item.assertion_id for item in assertions]
        if len(assertion_ids) != len(set(assertion_ids)):
            raise BehaviorContractError("step.assertions contains duplicate assertion ids")
        statuses = _asserted_statuses(assertions)
        if self.expected_outcome != "observe" and not statuses:
            raise BehaviorContractError("non-observational step must assert exact allowed statuses")
        if self.expected_outcome == "observe" and statuses:
            raise BehaviorContractError("observational step cannot predeclare statuses")
        if self.expected_outcome in {
            "idempotent_success",
            "mutation_success",
            "read_success",
        }:
            if self.kind == "mutation" and any(
                status not in _COMPLETED_MUTATION_STATUSES for status in statuses
            ):
                raise BehaviorContractError(
                    "completed mutation status assertions must contain only 200, 201, 204, or 205"
                )
            if self.kind == "read" and any(not 200 <= status <= 299 for status in statuses):
                raise BehaviorContractError("read success status assertions must contain only 2xx")
        if self.expected_outcome in {"duplicate_failure", "native_failure"} and any(
            not 400 <= status <= 499 for status in statuses
        ):
            raise BehaviorContractError("failure step status assertions must contain only 4xx")
        object.__setattr__(self, "assertions", assertions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "operation_id": self.operation_id,
            "kind": self.kind,
            "role": self.role,
            "expected_outcome": self.expected_outcome,
            "subject_id": self.subject_id,
            "auth_context_id": self.auth_context_id,
            "request": self.request.to_dict(),
            "bindings": [item.to_dict() for item in self.bindings],
            "assertions": [item.to_dict() for item in self.assertions],
        }

    @classmethod
    def from_dict(cls, value: Any) -> BehaviorStep:
        raw = _shape(
            value,
            path="step",
            required=frozenset(
                {
                    "step_id",
                    "operation_id",
                    "kind",
                    "role",
                    "expected_outcome",
                    "subject_id",
                    "auth_context_id",
                    "request",
                    "bindings",
                    "assertions",
                }
            ),
        )
        for array_name in ("bindings", "assertions"):
            if type(raw[array_name]) is not list:
                raise BehaviorContractError(f"step.{array_name} must be an array")
        return cls(
            step_id=raw["step_id"],
            operation_id=raw["operation_id"],
            kind=raw["kind"],
            role=raw["role"],
            expected_outcome=raw["expected_outcome"],
            subject_id=raw["subject_id"],
            auth_context_id=raw["auth_context_id"],
            request=RequestTemplate.from_dict(raw["request"]),
            bindings=tuple(BindingSpec.from_dict(item) for item in raw["bindings"]),
            assertions=tuple(AssertionSpec.from_dict(item) for item in raw["assertions"]),
        )


@dataclass(frozen=True)
class BehaviorRecipe:
    program_id: str
    seed: int
    requirements: ProgramRequirements
    steps: tuple[BehaviorStep, ...]
    schema_id: str = BEHAVIOR_RECIPE_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != BEHAVIOR_RECIPE_SCHEMA_ID:
            raise BehaviorContractError(f"unsupported recipe schema: {self.schema_id}")
        object.__setattr__(
            self,
            "program_id",
            _identifier(self.program_id, path="recipe.program_id"),
        )
        if type(self.seed) is not int:
            raise BehaviorContractError("recipe.seed must be an integer")
        if not isinstance(self.requirements, ProgramRequirements):
            raise BehaviorContractError("recipe.requirements is invalid")
        steps = tuple(self.steps)
        if not steps or not all(isinstance(item, BehaviorStep) for item in steps):
            raise BehaviorContractError("recipe.steps must contain behavior steps")
        step_ids = [item.step_id for item in steps]
        if len(step_ids) != len(set(step_ids)):
            raise BehaviorContractError("recipe.steps contains duplicate step ids")
        roles = {step.role for step in steps}
        missing_roles = {
            "before",
            "success",
            "duplicate",
            "native_failure",
            "resulting_state",
        } - roles
        if missing_roles:
            raise BehaviorContractError(
                f"recipe.steps is missing required roles: {', '.join(sorted(missing_roles))}"
            )
        by_role: dict[str, list[tuple[int, BehaviorStep]]] = {}
        for index, step in enumerate(steps):
            by_role.setdefault(step.role, []).append((index, step))
        for role in ("before", "success", "duplicate", "resulting_state"):
            if len(by_role[role]) != 1:
                raise BehaviorContractError(f"recipe requires exactly one {role!r} step")
        before_index = by_role["before"][0][0]
        success_index = by_role["success"][0][0]
        duplicate_index = by_role["duplicate"][0][0]
        resulting_index = by_role["resulting_state"][0][0]
        failure_indices = [item[0] for item in by_role["native_failure"]]
        if not before_index < success_index < duplicate_index < resulting_index:
            raise BehaviorContractError(
                "required behavior roles must follow before/success/duplicate/resulting_state order"
            )
        if any(
            not before_index < failure_index < resulting_index for failure_index in failure_indices
        ):
            raise BehaviorContractError(
                "native_failure roles must occur after before and before resulting_state"
            )
        required_steps = [
            by_role["before"][0][1],
            by_role["success"][0][1],
            by_role["duplicate"][0][1],
            *[item[1] for item in by_role["native_failure"]],
            by_role["resulting_state"][0][1],
        ]
        if len({step.subject_id for step in required_steps}) != 1:
            raise BehaviorContractError(
                "required behavior roles must operate on one declared subject"
            )
        success_step = by_role["success"][0][1]
        duplicate_step = by_role["duplicate"][0][1]
        duplicate_request_assertions = [
            assertion
            for assertion in duplicate_step.assertions
            if assertion.kind == "request_equals_step"
        ]
        if not any(
            assertion.prior_step_id == success_step.step_id
            for assertion in duplicate_request_assertions
        ):
            raise BehaviorContractError("duplicate role must exact-repeat the sole success step")
        if (
            duplicate_step.operation_id != success_step.operation_id
            or duplicate_step.auth_context_id != success_step.auth_context_id
            or duplicate_step.request != success_step.request
        ):
            raise BehaviorContractError(
                "duplicate operation, auth context, and request template must exactly match success"
            )
        for step in steps:
            statuses = _asserted_statuses(step.assertions)
            if step.expected_outcome != "observe" and not statuses:
                raise BehaviorContractError(
                    f"step {step.step_id!r} must assert exact allowed statuses"
                )
            if step.expected_outcome == "observe" and statuses:
                raise BehaviorContractError(
                    f"observational step {step.step_id!r} cannot predeclare statuses"
                )
            expects_success = step.expected_outcome in {
                "idempotent_success",
                "mutation_success",
                "read_success",
            }
            if expects_success:
                if step.kind == "mutation" and any(
                    status not in _COMPLETED_MUTATION_STATUSES for status in statuses
                ):
                    raise BehaviorContractError(
                        f"step {step.step_id!r} completed mutation outcome must "
                        "assert only 200, 201, 204, or 205"
                    )
                if step.kind == "read" and any(not 200 <= status <= 299 for status in statuses):
                    raise BehaviorContractError(
                        f"step {step.step_id!r} read success outcome must assert only 2xx"
                    )
            if step.expected_outcome in {"duplicate_failure", "native_failure"} and any(
                not 400 <= status <= 499 for status in statuses
            ):
                raise BehaviorContractError(
                    f"step {step.step_id!r} failure outcome must assert only 4xx"
                )
        defined: dict[str, BindingType] = {}
        prior_steps: set[str] = set()
        step_indexes = {step.step_id: index for index, step in enumerate(steps)}
        occurrence_owners: dict[tuple[str, str], str] = {}
        for step_index, step in enumerate(steps):
            references = binding_references(step.request.to_dict())
            missing = sorted(references - defined.keys())
            if missing:
                raise BehaviorContractError(
                    f"step {step.step_id!r} references undefined bindings: {', '.join(missing)}"
                )
            for binding in step.bindings:
                if binding.binding_id in defined:
                    raise BehaviorContractError(
                        f"binding {binding.binding_id!r} is defined more than once"
                    )
                if binding.response_occurrences:
                    defining_location = (step.step_id, binding.pointer)
                    locations = {
                        (occurrence.step_id, occurrence.pointer)
                        for occurrence in binding.response_occurrences
                    }
                    if defining_location not in locations:
                        raise BehaviorContractError(
                            f"binding {binding.binding_id!r} must declare its defining "
                            "response occurrence",
                            code="binding_occurrence_invalid",
                        )
                    for location in locations:
                        occurrence_step_id, _ = location
                        occurrence_index = step_indexes.get(occurrence_step_id)
                        if occurrence_index is None:
                            raise BehaviorContractError(
                                f"binding {binding.binding_id!r} references an unknown "
                                "response occurrence step",
                                code="binding_occurrence_invalid",
                            )
                        if occurrence_index < step_index:
                            raise BehaviorContractError(
                                f"binding {binding.binding_id!r} response occurrences "
                                "cannot precede its definition",
                                code="binding_occurrence_invalid",
                            )
                        owner = occurrence_owners.get(location)
                        if owner is not None:
                            raise BehaviorContractError(
                                f"response occurrence {occurrence_step_id!r} is assigned "
                                "to more than one binding",
                                code="binding_occurrence_invalid",
                            )
                        occurrence_owners[location] = binding.binding_id
                defined[binding.binding_id] = binding.value_type
            for path_binding in path_binding_references(step.request.path):
                if defined[path_binding] not in {"string", "integer"}:
                    raise BehaviorContractError(
                        f"path binding {path_binding!r} must be declared as string or integer",
                        code="binding_coercion_invalid",
                    )
            for assertion in step.assertions:
                if (
                    assertion.prior_step_id is not None
                    and assertion.prior_step_id not in prior_steps
                ):
                    raise BehaviorContractError(
                        f"assertion {assertion.assertion_id!r} must reference an earlier step"
                    )
            prior_steps.add(step.step_id)
        before_step = by_role["before"][0][1]
        resulting_step = by_role["resulting_state"][0][1]
        relation_prior_ids = {before_step.step_id, success_step.step_id}
        for step in steps:
            observation_assertions = [
                item for item in step.assertions if item.kind == "state_observe_step"
            ]
            if observation_assertions and (
                step is not resulting_step or step.expected_outcome != "observe"
            ):
                raise BehaviorContractError(
                    "state_observe_step is allowed only on an observational resulting_state"
                )
        result_relations = [
            item
            for item in resulting_step.assertions
            if item.kind
            in {
                "state_changes_from_step",
                "state_equals_step",
                "state_observe_step",
            }
        ]
        if not result_relations or any(
            item.prior_step_id not in relation_prior_ids for item in result_relations
        ):
            raise BehaviorContractError(
                "resulting_state must relate observed state to before or success"
            )
        if resulting_step.expected_outcome == "observe" and not any(
            item.kind == "state_observe_step" for item in result_relations
        ):
            raise BehaviorContractError("observational resulting_state requires state_observe_step")
        if resulting_step.expected_outcome == "observe" and any(
            item.kind in {"state_changes_from_step", "state_equals_step"}
            for item in result_relations
        ):
            raise BehaviorContractError(
                "observational resulting_state cannot predeclare its state relation"
            )
        if resulting_step.expected_outcome == "read_success" and any(
            item.kind == "state_observe_step" for item in result_relations
        ):
            raise BehaviorContractError("gating resulting_state cannot use state_observe_step")
        _validate_required_assertion_kinds(steps)
        object.__setattr__(self, "steps", steps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "program_id": self.program_id,
            "seed": self.seed,
            "requirements": self.requirements.to_dict(),
            "steps": [item.to_dict() for item in self.steps],
        }

    @classmethod
    def from_dict(cls, value: Any) -> BehaviorRecipe:
        raw = _shape(
            value,
            path="recipe",
            required=frozenset({"schema_id", "program_id", "seed", "requirements", "steps"}),
        )
        if type(raw["steps"]) is not list:
            raise BehaviorContractError("recipe.steps must be an array")
        return cls(
            schema_id=raw["schema_id"],
            program_id=raw["program_id"],
            seed=raw["seed"],
            requirements=ProgramRequirements.from_dict(raw["requirements"]),
            steps=tuple(BehaviorStep.from_dict(item) for item in raw["steps"]),
        )


def binding_references(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        if set(value.keys()) == {"$binding"}:
            return {_identifier(value["$binding"], path="binding reference")}
        if "$binding" in value:
            raise BehaviorContractError("a binding reference must be the entire object value")
        result: set[str] = set()
        for item in value.values():
            result.update(binding_references(item))
        return result
    if isinstance(value, (list, tuple)):
        result = set()
        for item in value:
            result.update(binding_references(item))
        return result
    return set()


def path_binding_references(value: JsonValue) -> set[str]:
    if type(value) is not tuple:
        return set()
    return {
        segment["$binding"]
        for segment in value
        if isinstance(segment, Mapping) and set(segment.keys()) == {"$binding"}
    }


def render_path_template(value: JsonValue, bindings: Mapping[str, JsonValue]) -> str:
    if type(value) is str:
        return value
    if type(value) is not tuple:
        raise BehaviorContractError("request path contract is invalid")
    result: list[str] = []
    for segment in value:
        if type(segment) is str:
            result.append(segment)
            continue
        assert isinstance(segment, Mapping)
        binding_id = segment["$binding"]
        try:
            bound = bindings[binding_id]
        except KeyError as error:
            raise BehaviorHarvestError(
                "binding_missing",
                f"path binding {binding_id!r} is unavailable",
            ) from error
        if type(bound) is str and _PATH_BINDING_VALUE.fullmatch(bound) is not None:
            rendered = bound
        elif type(bound) is int and bound >= 0:
            rendered = str(bound)
        else:
            raise BehaviorHarvestError(
                "binding_coercion_invalid",
                f"path binding {binding_id!r} must be a safe string or non-negative integer",
            )
        result.append(rendered)
    return "".join(result)


def validate_request_header_allowlist(
    connector: ConnectorSpec,
    request: RequestTemplate,
) -> None:
    undeclared = sorted(set(request.headers) - set(connector.allowed_request_headers))
    if undeclared:
        raise BehaviorContractError(
            "request headers are not allowed by connector: " + ", ".join(undeclared)
        )


def encode_request_target(path: str, query: Mapping[str, JsonValue]) -> str:
    pairs: list[tuple[str, str]] = []
    for key in sorted(query):
        value = query[key]
        values = value if type(value) is tuple else (value,)
        for item in values:
            item_type = type(item)
            if item is None:
                encoded = ""
            elif item_type is bool:
                encoded = "true" if item else "false"
            elif item_type in {str, int, float}:
                encoded = str(item)
            else:
                raise BehaviorContractError(
                    "request query values must be scalars or arrays of scalars"
                )
            pairs.append((key, encoded))
    return path if not pairs else f"{path}?{urlencode(pairs)}"


def binding_type_matches(value: JsonValue, expected: BindingType) -> bool:
    value_type = type(value)
    return {
        "array": value_type is tuple,
        "boolean": value_type is bool,
        "integer": value_type is int,
        "null": value is None,
        "number": value_type in {int, float},
        "object": isinstance(value, Mapping),
        "string": value_type is str,
    }[expected]


def generated_binding_value_matches(value: JsonValue, expected: BindingType) -> bool:
    if expected == "string":
        return type(value) is str
    if expected == "integer":
        return type(value) is int and value >= 0
    return False


def _validate_json_pointer(value: Any, *, path: str, allow_root: bool) -> str:
    if type(value) is not str:
        raise BehaviorContractError(f"{path} must be a JSON pointer")
    if value == "" and allow_root:
        return value
    if not value.startswith("/") or value.endswith("/"):
        raise BehaviorContractError(f"{path} must be a JSON pointer")
    for component in value.split("/")[1:]:
        index = 0
        while index < len(component):
            if component[index] == "~":
                if index + 1 >= len(component) or component[index + 1] not in {"0", "1"}:
                    raise BehaviorContractError(f"{path} contains an invalid escape")
                index += 2
            else:
                index += 1
    return value


def _validate_required_assertion_kinds(steps: tuple[BehaviorStep, ...]) -> None:
    by_role: dict[str, list[AssertionSpec]] = {}
    step_by_role: dict[str, list[BehaviorStep]] = {}
    for step in steps:
        by_role.setdefault(step.role, []).extend(step.assertions)
        step_by_role.setdefault(step.role, []).append(step)
    status_kinds = {"status_equals", "status_in"}
    for role in ("before", "success"):
        if not any(item.kind in status_kinds for item in by_role[role]):
            raise BehaviorContractError(f"{role} role requires a status assertion")
    duplicate_assertions = by_role["duplicate"]
    success_step = step_by_role["success"][0]
    if not any(
        item.kind == "request_equals_step" and item.prior_step_id == success_step.step_id
        for item in duplicate_assertions
    ):
        raise BehaviorContractError(
            "duplicate role requires exact request_equals_step against success"
        )
    duplicate_is_observation = step_by_role["duplicate"][0].expected_outcome == "observe"
    duplicate_exact_response = any(
        item.kind == "response_equals_step" for item in duplicate_assertions
    )
    duplicate_status = any(item.kind in status_kinds for item in duplicate_assertions)
    duplicate_body = any(
        item.kind.startswith("json_pointer_") or item.kind == "state_equals_step"
        for item in duplicate_assertions
    )
    if (
        not duplicate_is_observation
        and not duplicate_exact_response
        and not (duplicate_status and duplicate_body)
    ):
        raise BehaviorContractError(
            "duplicate role must assert either exact prior response or status plus body"
        )
    for failure_step in step_by_role["native_failure"]:
        if not any(item.kind in status_kinds for item in failure_step.assertions):
            raise BehaviorContractError(
                f"native_failure step {failure_step.step_id!r} requires a status assertion"
            )
        if not any(item.kind.startswith("json_pointer_") for item in failure_step.assertions):
            raise BehaviorContractError(
                f"native_failure step {failure_step.step_id!r} requires a JSON-body assertion"
            )
    if not any(
        item.kind in {"state_changes_from_step", "state_equals_step", "state_observe_step"}
        for item in by_role["resulting_state"]
    ):
        raise BehaviorContractError("resulting_state role requires a state relation assertion")


def _asserted_statuses(assertions: tuple[AssertionSpec, ...]) -> tuple[int, ...]:
    statuses: list[int] = []
    for assertion in assertions:
        if assertion.kind == "status_equals":
            assert type(assertion.expected) is int
            statuses.append(assertion.expected)
        elif assertion.kind == "status_in":
            assert type(assertion.expected) is tuple
            statuses.extend(assertion.expected)
    return tuple(statuses)


def _pointer_value(value: JsonValue, pointer: str) -> JsonValue:
    current = value
    if pointer == "":
        return current
    for raw_component in pointer.split("/")[1:]:
        component = raw_component.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if component not in current:
                raise BehaviorContractError(f"assertion pointer {pointer!r} does not exist")
            current = current[component]
        elif type(current) is tuple:
            if not component.isascii() or not component.isdigit():
                raise BehaviorContractError(
                    f"assertion pointer {pointer!r} has a non-index array component"
                )
            index = int(component)
            if index >= len(current):
                raise BehaviorContractError(f"assertion pointer {pointer!r} does not exist")
            current = current[index]
        else:
            raise BehaviorContractError(f"assertion pointer {pointer!r} traverses a scalar")
    return current


def validate_assertion_prefix(
    steps: tuple[BehaviorStep, ...],
    exchanges: tuple[CapturedExchange, ...],
) -> None:
    if len(steps) != len(exchanges):
        raise BehaviorContractError("assertion prefix steps and exchanges must have equal length")
    prior: dict[str, CapturedExchange] = {}
    for step, exchange in zip(steps, exchanges, strict=True):
        for assertion in step.assertions:
            passed = False
            if assertion.kind == "status_equals":
                passed = exchange.status_code == assertion.expected
            elif assertion.kind == "status_in":
                assert isinstance(assertion.expected, tuple)
                passed = exchange.status_code in assertion.expected
            elif assertion.kind == "json_pointer_equals":
                assert assertion.pointer is not None
                passed = _pointer_value(exchange.body, assertion.pointer) == assertion.expected
            elif assertion.kind == "json_pointer_type":
                assert assertion.pointer is not None and assertion.value_type is not None
                passed = binding_type_matches(
                    _pointer_value(exchange.body, assertion.pointer),
                    assertion.value_type,
                )
            elif assertion.kind == "json_pointer_pattern":
                assert assertion.pointer is not None and assertion.pattern is not None
                actual = _pointer_value(exchange.body, assertion.pointer)
                passed = type(actual) is str and re.fullmatch(assertion.pattern, actual) is not None
            elif assertion.kind == "request_equals_step":
                assert assertion.prior_step_id is not None
                prior_request = prior[assertion.prior_step_id].request.to_dict()
                current_request = exchange.request.to_dict()
                for request_value in (prior_request, current_request):
                    request_value.pop("step_id")
                    request_value.pop("operation_id")
                    request_value.pop("kind")
                passed = current_request == prior_request
            elif assertion.kind == "response_equals_step":
                assert assertion.prior_step_id is not None
                prior_exchange = prior[assertion.prior_step_id]
                passed = (
                    exchange.status_code == prior_exchange.status_code
                    and exchange.headers == prior_exchange.headers
                    and exchange.body_kind == prior_exchange.body_kind
                    and exchange.body_base64 == prior_exchange.body_base64
                )
            elif assertion.kind in {"state_changes_from_step", "state_equals_step"}:
                assert assertion.pointer is not None
                assert assertion.prior_pointer is not None
                assert assertion.prior_step_id is not None
                current_value = _pointer_value(exchange.body, assertion.pointer)
                prior_value = _pointer_value(
                    prior[assertion.prior_step_id].body,
                    assertion.prior_pointer,
                )
                passed = (
                    current_value == prior_value
                    if assertion.kind == "state_equals_step"
                    else current_value != prior_value
                )
            elif assertion.kind == "state_observe_step":
                # This assertion records an observed relation after the sequence;
                # it intentionally does not gate the provider capture.
                continue
            if not passed:
                raise BehaviorContractError(
                    f"capture assertion failed: {step.step_id}.{assertion.assertion_id}"
                )
        prior[step.step_id] = exchange


def compute_observed_relations(
    steps: tuple[BehaviorStep, ...],
    exchanges: tuple[CapturedExchange, ...],
) -> Mapping[str, Literal["changed", "equal"]]:
    if len(steps) != len(exchanges):
        raise BehaviorContractError("observed relation steps and exchanges must have equal length")
    exchange_by_id = {item.step_id: item for item in exchanges}
    relations: dict[str, Literal["changed", "equal"]] = {}
    for step, exchange in zip(steps, exchanges, strict=True):
        for assertion in step.assertions:
            if assertion.kind != "state_observe_step":
                continue
            assert assertion.pointer is not None
            assert assertion.prior_step_id is not None
            assert assertion.prior_pointer is not None
            current = _pointer_value(exchange.body, assertion.pointer)
            prior = _pointer_value(
                exchange_by_id[assertion.prior_step_id].body,
                assertion.prior_pointer,
            )
            relations[f"{step.step_id}.{assertion.assertion_id}"] = (
                "equal" if current == prior else "changed"
            )
    return MappingProxyType(relations)


@dataclass(frozen=True)
class DispatchRequest:
    step_id: str
    operation_id: str
    kind: StepKind
    auth_context_id: str
    method: str
    path: str
    query: Mapping[str, JsonValue]
    body: JsonValue
    headers: Mapping[str, str]
    timeout_ms: int
    target: str

    def __post_init__(self) -> None:
        for name in ("step_id", "operation_id"):
            object.__setattr__(
                self, name, _identifier(getattr(self, name), path=f"dispatch.{name}")
            )
        if self.kind not in {"read", "mutation"}:
            raise BehaviorContractError("dispatch.kind is unsupported")
        object.__setattr__(
            self,
            "auth_context_id",
            _identifier(self.auth_context_id, path="dispatch.auth_context_id"),
        )
        method = _string(self.method, path="dispatch.method").upper()
        if method not in _HTTP_METHODS:
            raise BehaviorContractError("dispatch.method is unsupported")
        object.__setattr__(self, "method", method)
        path = _string(self.path, path="dispatch.path")
        invalid = any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in path
        )
        if not path.startswith("/") or "?" in path or "#" in path or invalid:
            raise BehaviorContractError("dispatch.path is invalid")
        object.__setattr__(self, "query", _json_object(self.query, path="dispatch.query"))
        object.__setattr__(self, "body", freeze_json(self.body, path="dispatch.body"))
        object.__setattr__(self, "headers", safe_headers(self.headers, path="dispatch.headers"))
        reject_sensitive_json(self.query, path="dispatch.query")
        reject_sensitive_json(self.body, path="dispatch.body")
        object.__setattr__(
            self,
            "timeout_ms",
            _positive_int(self.timeout_ms, path="dispatch.timeout_ms"),
        )
        target = _string(self.target, path="dispatch.target")
        if target != encode_request_target(path, self.query):
            raise BehaviorContractError("dispatch.target is not derived from exact path and query")
        object.__setattr__(self, "target", target)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "operation_id": self.operation_id,
            "kind": self.kind,
            "auth_context_id": self.auth_context_id,
            "method": self.method,
            "path": self.path,
            "query": thaw_json(self.query),
            "body": thaw_json(self.body),
            "headers": dict(self.headers),
            "timeout_ms": self.timeout_ms,
            "target": self.target,
        }

    @classmethod
    def from_dict(cls, value: Any) -> DispatchRequest:
        raw = _shape(
            value,
            path="dispatch",
            required=frozenset(
                {
                    "step_id",
                    "operation_id",
                    "kind",
                    "auth_context_id",
                    "method",
                    "path",
                    "query",
                    "body",
                    "headers",
                    "timeout_ms",
                    "target",
                }
            ),
        )
        return cls(**raw)


@dataclass(frozen=True)
class RequestReceipt:
    method: str
    target: str
    headers: Mapping[str, str]
    body_base64: str
    body_bytes: int
    body_sha256: str

    def __post_init__(self) -> None:
        method = _string(self.method, path="request_receipt.method").upper()
        if method not in _HTTP_METHODS:
            raise BehaviorContractError("request_receipt.method is unsupported")
        object.__setattr__(self, "method", method)
        object.__setattr__(
            self,
            "target",
            _string(self.target, path="request_receipt.target"),
        )
        object.__setattr__(
            self,
            "headers",
            safe_headers(self.headers, path="request_receipt.headers"),
        )
        if type(self.body_base64) is not str:
            raise BehaviorContractError("request_receipt.body_base64 must be a string")
        try:
            raw = base64.b64decode(self.body_base64, validate=True)
        except ValueError as error:
            raise BehaviorContractError("request_receipt.body_base64 is invalid") from error
        if self.body_bytes != len(raw):
            raise BehaviorContractError("request_receipt.body_bytes does not match exact body")
        if self.body_sha256 != sha256_digest(raw):
            raise BehaviorContractError("request_receipt.body_sha256 does not match exact body")

    @property
    def raw_body(self) -> bytes:
        return base64.b64decode(self.body_base64, validate=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "target": self.target,
            "headers": dict(self.headers),
            "body_base64": self.body_base64,
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
        }

    @classmethod
    def from_body(
        cls,
        *,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body_bytes: bytes,
    ) -> RequestReceipt:
        return cls(
            method=method,
            target=target,
            headers=headers,
            body_base64=base64.b64encode(body_bytes).decode("ascii"),
            body_bytes=len(body_bytes),
            body_sha256=sha256_digest(body_bytes),
        )

    @classmethod
    def from_dict(cls, value: Any) -> RequestReceipt:
        return cls(
            **_shape(
                value,
                path="request_receipt",
                required=frozenset(
                    {
                        "method",
                        "target",
                        "headers",
                        "body_base64",
                        "body_bytes",
                        "body_sha256",
                    }
                ),
            )
        )


@dataclass(frozen=True)
class RawTransportResponse:
    status_code: int
    headers: Mapping[str, str]
    body_bytes: bytes
    body_kind: Literal["empty", "json"] = "json"

    def __post_init__(self) -> None:
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise BehaviorContractError("response.status_code must be between 100 and 599")
        object.__setattr__(self, "headers", safe_headers(self.headers, path="response.headers"))
        if type(self.body_bytes) is not bytes:
            raise BehaviorContractError("response.body_bytes must be bytes")
        if self.body_kind not in {"empty", "json"}:
            raise BehaviorContractError(
                "response body framing must be exactly 'empty' or 'json'",
                code="response_body_framing_invalid",
            )
        if self.status_code in {204, 205} and (self.body_kind != "empty" or self.body_bytes != b""):
            raise BehaviorContractError(
                "status 204/205 requires declared empty body and exactly zero bytes",
                code="response_body_framing_invalid",
            )
        if self.body_kind == "empty" and self.body_bytes != b"":
            raise BehaviorContractError(
                "empty response requires exactly zero body bytes",
                code="response_body_framing_invalid",
            )
        if self.body_kind == "json" and self.body_bytes == b"":
            raise BehaviorContractError(
                "zero-length response must use empty body framing",
                code="response_body_framing_invalid",
            )


@dataclass(frozen=True)
class CapturedExchange:
    phase: Literal["collector", "preflight", "program"]
    step_id: str
    operation_id: str
    kind: StepKind
    subject_id: str
    auth_context_id: str
    request: DispatchRequest
    request_receipt: RequestReceipt
    status_code: int
    headers: Mapping[str, str]
    body_kind: Literal["empty", "json"]
    body: JsonValue
    body_base64: str
    body_bytes: int
    body_sha256: str

    def __post_init__(self) -> None:
        for name in ("step_id", "operation_id"):
            object.__setattr__(
                self, name, _identifier(getattr(self, name), path=f"exchange.{name}")
            )
        if self.phase not in {"collector", "preflight", "program"}:
            raise BehaviorContractError("exchange.phase is unsupported")
        if self.kind not in {"read", "mutation"}:
            raise BehaviorContractError("exchange.kind is unsupported")
        object.__setattr__(
            self,
            "subject_id",
            _identifier(self.subject_id, path="exchange.subject_id"),
        )
        object.__setattr__(
            self,
            "auth_context_id",
            _identifier(self.auth_context_id, path="exchange.auth_context_id"),
        )
        if not isinstance(self.request, DispatchRequest):
            raise BehaviorContractError("exchange.request is invalid")
        if not isinstance(self.request_receipt, RequestReceipt):
            raise BehaviorContractError("exchange.request_receipt is invalid")
        expected_request_body = (
            b"" if self.request.body is None else canonical_json_bytes(thaw_json(self.request.body))
        )
        if (
            self.request_receipt.method != self.request.method
            or self.request_receipt.target != self.request.target
            or self.request_receipt.headers != self.request.headers
            or self.request_receipt.raw_body != expected_request_body
        ):
            raise BehaviorContractError("exchange request receipt does not match resolved request")
        if (
            self.request.step_id != self.step_id
            or self.request.operation_id != self.operation_id
            or self.request.kind != self.kind
            or self.request.auth_context_id != self.auth_context_id
        ):
            raise BehaviorContractError("exchange request identity does not match exchange")
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise BehaviorContractError("exchange.status_code must be between 100 and 599")
        object.__setattr__(self, "headers", safe_headers(self.headers, path="exchange.headers"))
        if self.body_kind not in {"empty", "json"}:
            raise BehaviorContractError(
                "exchange body framing must be exactly 'empty' or 'json'",
                code="response_body_framing_invalid",
            )
        body = freeze_json(self.body, path="exchange.body")
        reject_sensitive_json(body, path="exchange.body")
        object.__setattr__(self, "body", body)
        if type(self.body_base64) is not str:
            raise BehaviorContractError("exchange.body_base64 must be a string")
        encoded = self.body_base64
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise BehaviorContractError("exchange.body_base64 is invalid") from error
        if self.body_bytes != len(raw):
            raise BehaviorContractError("exchange.body_bytes does not match exact raw body")
        if self.body_sha256 != sha256_digest(raw):
            raise BehaviorContractError("exchange.body_sha256 does not match exact raw body")
        if self.status_code in {204, 205} and (
            self.body_kind != "empty" or raw != b"" or body is not None
        ):
            raise BehaviorContractError(
                "status 204/205 exchange must have exact empty representation",
                code="response_body_framing_invalid",
            )
        if self.body_kind == "empty":
            if raw != b"" or body is not None:
                raise BehaviorContractError(
                    "empty exchange requires zero bytes and null body",
                    code="response_body_framing_invalid",
                )
        elif raw == b"":
            raise BehaviorContractError(
                "zero-length exchange must use empty body framing",
                code="response_body_framing_invalid",
            )
        elif parse_json_bytes(raw, path="exchange.raw_body") != body:
            raise BehaviorContractError("exchange.body is not derived from exact raw body")

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "step_id": self.step_id,
            "operation_id": self.operation_id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "auth_context_id": self.auth_context_id,
            "request": self.request.to_dict(),
            "request_receipt": self.request_receipt.to_dict(),
            "response": {
                "status_code": self.status_code,
                "headers": dict(self.headers),
                "body_kind": self.body_kind,
                "body": thaw_json(self.body),
                "body_base64": self.body_base64,
                "body_bytes": self.body_bytes,
                "body_sha256": self.body_sha256,
            },
        }

    @classmethod
    def create(
        cls,
        *,
        phase: Literal["collector", "preflight", "program"],
        step_id: str,
        operation_id: str,
        kind: StepKind,
        subject_id: str,
        auth_context_id: str,
        request: DispatchRequest,
        request_receipt: RequestReceipt,
        response: RawTransportResponse,
        body: JsonValue,
    ) -> CapturedExchange:
        return cls(
            phase=phase,
            step_id=step_id,
            operation_id=operation_id,
            kind=kind,
            subject_id=subject_id,
            auth_context_id=auth_context_id,
            request=request,
            request_receipt=request_receipt,
            status_code=response.status_code,
            headers=response.headers,
            body_kind=response.body_kind,
            body=body,
            body_base64=base64.b64encode(response.body_bytes).decode("ascii"),
            body_bytes=len(response.body_bytes),
            body_sha256=sha256_digest(response.body_bytes),
        )

    @classmethod
    def from_dict(cls, value: Any) -> CapturedExchange:
        raw = _shape(
            value,
            path="exchange",
            required=frozenset(
                {
                    "phase",
                    "step_id",
                    "operation_id",
                    "kind",
                    "subject_id",
                    "auth_context_id",
                    "request",
                    "request_receipt",
                    "response",
                }
            ),
        )
        response = _shape(
            raw["response"],
            path="exchange.response",
            required=frozenset(
                {
                    "status_code",
                    "headers",
                    "body_kind",
                    "body",
                    "body_base64",
                    "body_bytes",
                    "body_sha256",
                }
            ),
        )
        return cls(
            phase=raw["phase"],
            step_id=raw["step_id"],
            operation_id=raw["operation_id"],
            kind=raw["kind"],
            subject_id=raw["subject_id"],
            auth_context_id=raw["auth_context_id"],
            request=DispatchRequest.from_dict(raw["request"]),
            request_receipt=RequestReceipt.from_dict(raw["request_receipt"]),
            status_code=response["status_code"],
            headers=response["headers"],
            body_kind=response["body_kind"],
            body=response["body"],
            body_base64=response["body_base64"],
            body_bytes=response["body_bytes"],
            body_sha256=response["body_sha256"],
        )


@dataclass(frozen=True)
class AuthReceipt:
    context_id: str
    strategy_id: str
    actor_alias: str
    response_status: int
    provider_request_id: str | None
    authorization_applied: bool
    client_id: str | None
    observed_fields: Mapping[str, JsonValue]
    completed: bool

    def __post_init__(self) -> None:
        for name in ("context_id", "strategy_id", "actor_alias"):
            object.__setattr__(
                self,
                name,
                _identifier(getattr(self, name), path=f"auth_receipt.{name}"),
            )
        if type(self.response_status) is not int or not 200 <= self.response_status <= 299:
            raise BehaviorContractError("auth_receipt.response_status must be 2xx")
        if self.provider_request_id is not None:
            object.__setattr__(
                self,
                "provider_request_id",
                _string(
                    self.provider_request_id,
                    path="auth_receipt.provider_request_id",
                ),
            )
        if type(self.authorization_applied) is not bool:
            raise BehaviorContractError("auth_receipt.authorization_applied must be boolean")
        if self.authorization_applied != (self.client_id is not None):
            raise BehaviorContractError(
                "auth receipt client_id must exactly match authorization_applied"
            )
        if self.client_id is not None:
            object.__setattr__(
                self,
                "client_id",
                _string(self.client_id, path="auth_receipt.client_id"),
            )
        observed = _json_object(
            self.observed_fields,
            path="auth_receipt.observed_fields",
        )
        if not observed or any(isinstance(value, (Mapping, tuple)) for value in observed.values()):
            raise BehaviorContractError("auth receipt observed fields must contain safe scalars")
        reject_sensitive_json(observed, path="auth_receipt.observed_fields")
        object.__setattr__(self, "observed_fields", observed)
        if self.completed is not True:
            raise BehaviorContractError("auth_receipt.completed must be true")

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "strategy_id": self.strategy_id,
            "actor_alias": self.actor_alias,
            "response_status": self.response_status,
            "provider_request_id": self.provider_request_id,
            "authorization_applied": self.authorization_applied,
            "client_id": self.client_id,
            "observed_fields": thaw_json(self.observed_fields),
            "completed": self.completed,
        }

    @classmethod
    def from_dict(cls, value: Any) -> AuthReceipt:
        return cls(
            **_shape(
                value,
                path="auth_receipt",
                required=frozenset(
                    {
                        "context_id",
                        "strategy_id",
                        "actor_alias",
                        "response_status",
                        "provider_request_id",
                        "authorization_applied",
                        "client_id",
                        "observed_fields",
                        "completed",
                    }
                ),
            )
        )


@dataclass(frozen=True)
class StaticJsonReceipt:
    input_id: str
    schema_id: str
    body: JsonValue
    body_base64: str
    body_bytes: int
    body_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "input_id",
            _identifier(self.input_id, path="static_receipt.input_id"),
        )
        object.__setattr__(
            self,
            "schema_id",
            _identifier(self.schema_id, path="static_receipt.schema_id"),
        )
        body = freeze_json(self.body, path="static_receipt.body")
        reject_sensitive_json(body, path="static_receipt.body")
        object.__setattr__(self, "body", body)
        if type(self.body_base64) is not str:
            raise BehaviorContractError("static_receipt.body_base64 must be a string")
        try:
            raw = base64.b64decode(self.body_base64, validate=True)
        except ValueError as error:
            raise BehaviorContractError("static_receipt.body_base64 is invalid") from error
        if self.body_bytes != len(raw):
            raise BehaviorContractError("static_receipt.body_bytes does not match exact raw body")
        if self.body_sha256 != sha256_digest(raw):
            raise BehaviorContractError("static_receipt.body_sha256 does not match exact raw body")
        if parse_json_bytes(raw, path="static_receipt.raw_body") != body:
            raise BehaviorContractError("static_receipt.body is not derived from exact raw body")

    @property
    def raw_body(self) -> bytes:
        return base64.b64decode(self.body_base64, validate=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_id": self.input_id,
            "schema_id": self.schema_id,
            "body": thaw_json(self.body),
            "body_base64": self.body_base64,
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
        }

    @classmethod
    def from_body(
        cls,
        *,
        spec: StaticJsonInputSpec,
        body_bytes: bytes,
    ) -> StaticJsonReceipt:
        body = parse_json_bytes(
            body_bytes,
            path=f"static_input.{spec.input_id}",
        )
        return cls(
            input_id=spec.input_id,
            schema_id=spec.schema_id,
            body=body,
            body_base64=base64.b64encode(body_bytes).decode("ascii"),
            body_bytes=len(body_bytes),
            body_sha256=sha256_digest(body_bytes),
        )

    @classmethod
    def from_dict(cls, value: Any) -> StaticJsonReceipt:
        return cls(
            **_shape(
                value,
                path="static_receipt",
                required=frozenset(
                    {
                        "input_id",
                        "schema_id",
                        "body",
                        "body_base64",
                        "body_bytes",
                        "body_sha256",
                    }
                ),
            )
        )


@dataclass(frozen=True)
class BehaviorCapture:
    run_id: str
    connector: ConnectorSpec
    connector_sha256: str
    connector_canonical_sha256: str
    recipe: BehaviorRecipe
    recipe_sha256: str
    recipe_canonical_sha256: str
    engine: EngineIdentity
    static_input_receipts: tuple[StaticJsonReceipt, ...]
    auth_receipts: tuple[AuthReceipt, ...]
    preflight_exchanges: tuple[CapturedExchange, ...]
    exchanges: tuple[CapturedExchange, ...]
    collector_exchanges: tuple[CapturedExchange, ...]
    bindings: Mapping[str, JsonValue]
    observed_relations: Mapping[str, Literal["changed", "equal"]]
    complete: bool = True
    schema_id: str = BEHAVIOR_CAPTURE_SCHEMA_ID

    def __post_init__(self) -> None:
        if self.schema_id != BEHAVIOR_CAPTURE_SCHEMA_ID:
            raise BehaviorContractError(f"unsupported capture schema: {self.schema_id}")
        object.__setattr__(self, "run_id", _identifier(self.run_id, path="capture.run_id"))
        if not isinstance(self.connector, ConnectorSpec):
            raise BehaviorContractError("capture.connector is invalid")
        object.__setattr__(
            self,
            "connector_sha256",
            _sha256(self.connector_sha256, path="capture.connector_sha256"),
        )
        object.__setattr__(
            self,
            "connector_canonical_sha256",
            _sha256(
                self.connector_canonical_sha256,
                path="capture.connector_canonical_sha256",
            ),
        )
        if self.connector_canonical_sha256 != canonical_contract_digest(self.connector):
            raise BehaviorContractError(
                "capture.connector_canonical_sha256 does not match embedded connector"
            )
        if not isinstance(self.recipe, BehaviorRecipe):
            raise BehaviorContractError("capture.recipe is invalid")
        object.__setattr__(
            self,
            "recipe_sha256",
            _sha256(self.recipe_sha256, path="capture.recipe_sha256"),
        )
        object.__setattr__(
            self,
            "recipe_canonical_sha256",
            _sha256(
                self.recipe_canonical_sha256,
                path="capture.recipe_canonical_sha256",
            ),
        )
        if self.recipe_canonical_sha256 != canonical_contract_digest(self.recipe):
            raise BehaviorContractError(
                "capture.recipe_canonical_sha256 does not match embedded recipe"
            )
        if not isinstance(self.engine, EngineIdentity):
            raise BehaviorContractError("capture.engine is invalid")
        static_receipts = tuple(self.static_input_receipts)
        if not all(isinstance(item, StaticJsonReceipt) for item in static_receipts):
            raise BehaviorContractError("capture.static_input_receipts contains an invalid receipt")
        object.__setattr__(
            self,
            "static_input_receipts",
            static_receipts,
        )
        auth_receipts = tuple(self.auth_receipts)
        if not all(isinstance(item, AuthReceipt) for item in auth_receipts):
            raise BehaviorContractError("capture.auth_receipts contains an invalid receipt")
        object.__setattr__(self, "auth_receipts", auth_receipts)
        for name in ("preflight_exchanges", "exchanges", "collector_exchanges"):
            exchanges = tuple(getattr(self, name))
            if not all(isinstance(item, CapturedExchange) for item in exchanges):
                raise BehaviorContractError(f"capture.{name} contains an invalid exchange")
            object.__setattr__(self, name, exchanges)
        bindings = _json_object(self.bindings, path="capture.bindings")
        reject_sensitive_json(bindings, path="capture.bindings")
        object.__setattr__(self, "bindings", bindings)
        if not isinstance(self.observed_relations, Mapping):
            raise BehaviorContractError("capture.observed_relations must be an object")
        relations: dict[str, Literal["changed", "equal"]] = {}
        for raw_name, raw_relation in self.observed_relations.items():
            name = _identifier(raw_name, path="capture.observed_relations key")
            if raw_relation not in {"changed", "equal"}:
                raise BehaviorContractError(
                    "capture.observed_relations values must be changed or equal"
                )
            relations[name] = raw_relation
        object.__setattr__(
            self,
            "observed_relations",
            MappingProxyType(relations),
        )
        if self.complete is not True:
            raise BehaviorContractError("only complete behavior captures are publishable")
        validate_behavior_capture_semantics(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "run_id": self.run_id,
            "connector": self.connector.to_dict(),
            "connector_sha256": self.connector_sha256,
            "connector_canonical_sha256": self.connector_canonical_sha256,
            "recipe": self.recipe.to_dict(),
            "recipe_sha256": self.recipe_sha256,
            "recipe_canonical_sha256": self.recipe_canonical_sha256,
            "engine": self.engine.to_dict(),
            "static_input_receipts": [item.to_dict() for item in self.static_input_receipts],
            "auth_receipts": [item.to_dict() for item in self.auth_receipts],
            "preflight_exchanges": [item.to_dict() for item in self.preflight_exchanges],
            "exchanges": [item.to_dict() for item in self.exchanges],
            "collector_exchanges": [item.to_dict() for item in self.collector_exchanges],
            "bindings": thaw_json(self.bindings),
            "observed_relations": dict(self.observed_relations),
            "complete": self.complete,
        }

    @classmethod
    def from_dict(cls, value: Any) -> BehaviorCapture:
        raw = _shape(
            value,
            path="capture",
            required=frozenset(
                {
                    "schema_id",
                    "run_id",
                    "connector",
                    "connector_sha256",
                    "connector_canonical_sha256",
                    "recipe",
                    "recipe_sha256",
                    "recipe_canonical_sha256",
                    "engine",
                    "static_input_receipts",
                    "auth_receipts",
                    "preflight_exchanges",
                    "exchanges",
                    "collector_exchanges",
                    "bindings",
                    "observed_relations",
                    "complete",
                }
            ),
        )
        for name in (
            "static_input_receipts",
            "auth_receipts",
            "preflight_exchanges",
            "exchanges",
            "collector_exchanges",
        ):
            if type(raw[name]) is not list:
                raise BehaviorContractError(f"capture.{name} must be an array")
        return cls(
            schema_id=raw["schema_id"],
            run_id=raw["run_id"],
            connector=ConnectorSpec.from_dict(raw["connector"]),
            connector_sha256=raw["connector_sha256"],
            connector_canonical_sha256=raw["connector_canonical_sha256"],
            recipe=BehaviorRecipe.from_dict(raw["recipe"]),
            recipe_sha256=raw["recipe_sha256"],
            recipe_canonical_sha256=raw["recipe_canonical_sha256"],
            engine=EngineIdentity.from_dict(raw["engine"]),
            static_input_receipts=tuple(
                StaticJsonReceipt.from_dict(item) for item in raw["static_input_receipts"]
            ),
            auth_receipts=tuple(AuthReceipt.from_dict(item) for item in raw["auth_receipts"]),
            preflight_exchanges=tuple(
                CapturedExchange.from_dict(item) for item in raw["preflight_exchanges"]
            ),
            exchanges=tuple(CapturedExchange.from_dict(item) for item in raw["exchanges"]),
            collector_exchanges=tuple(
                CapturedExchange.from_dict(item) for item in raw["collector_exchanges"]
            ),
            bindings=raw["bindings"],
            observed_relations=raw["observed_relations"],
            complete=raw["complete"],
        )


def validate_behavior_capture_semantics(capture: BehaviorCapture) -> None:
    connector = capture.connector
    recipe = capture.recipe
    for step in recipe.steps:
        validate_request_header_allowlist(connector, step.request)
    if (
        connector.driver_id != capture.engine.engine_id
        or connector.driver_version != capture.engine.engine_version
        or connector.driver_source_sha256 != capture.engine.source_sha256
    ):
        raise BehaviorContractError(
            "capture engine identity does not match pinned connector driver"
        )
    static_specs = connector.static_json_inputs
    if len(capture.static_input_receipts) != len(static_specs):
        raise BehaviorContractError("capture static receipts do not exactly cover declared inputs")
    static_receipts: dict[str, StaticJsonReceipt] = {}
    for spec, receipt in zip(
        static_specs,
        capture.static_input_receipts,
        strict=True,
    ):
        if (
            receipt.input_id != spec.input_id
            or receipt.schema_id != spec.schema_id
            or receipt.body != spec.expected_json
            or receipt.body_bytes > spec.max_bytes
        ):
            raise BehaviorContractError(
                "capture static receipt does not match its exact declaration"
            )
        static_receipts[receipt.input_id] = receipt
    declared_contexts = {item.context_id for item in connector.auth.contexts}
    required_grants = {item.context_id for item in connector.auth.contexts if item.grant_required}
    receipt_contexts = [item.context_id for item in capture.auth_receipts]
    if len(receipt_contexts) != len(set(receipt_contexts)):
        raise BehaviorContractError("capture.auth_receipts contains duplicate contexts")
    if set(receipt_contexts) != required_grants:
        raise BehaviorContractError(
            "capture.auth_receipts does not exactly cover grant-required contexts"
        )
    context_by_id = {item.context_id: item for item in connector.auth.contexts}
    for receipt in capture.auth_receipts:
        context = context_by_id[receipt.context_id]
        assert context.grant is not None
        basic = context.grant.client_basic_auth
        expected_fields = freeze_json(
            {name: spec.expected for name, spec in context.grant.response_fields.items()}
        )
        if receipt.strategy_id != context.strategy_id or receipt.actor_alias != context.actor_alias:
            raise BehaviorContractError(
                "capture auth receipt identity does not match connector context"
            )
        if (
            receipt.observed_fields != expected_fields
            or receipt.observed_fields["username"] != context.actor_alias
            or receipt.authorization_applied != (basic is not None)
            or receipt.client_id != (None if basic is None else basic.client_id)
        ):
            raise BehaviorContractError(
                "capture auth receipt safe observations do not match grant contract"
            )

    preflight_specs = connector.identity_preflight.calls
    if len(capture.preflight_exchanges) != len(preflight_specs):
        raise BehaviorContractError(
            "capture.preflight_exchanges does not exactly cover preflight calls"
        )
    for spec, exchange in zip(
        preflight_specs,
        capture.preflight_exchanges,
        strict=True,
    ):
        _validate_evidence_exchange(
            spec,
            exchange,
            phase="preflight",
            bindings={},
            connector=connector,
        )
    projected_identity: dict[str, JsonValue] = {}
    if connector.identity_preflight.identity_call_id is not None:
        identity_exchange = next(
            item
            for item in capture.preflight_exchanges
            if item.step_id == connector.identity_preflight.identity_call_id
        )
        provider_identity = _pointer_value(
            identity_exchange.body,
            connector.identity_preflight.identity_pointer,
        )
        if not isinstance(provider_identity, Mapping):
            raise BehaviorContractError("capture preflight identity projection must be an object")
        projected_identity.update(provider_identity)
    if connector.identity_preflight.authenticated_context_ids:
        receipts = {item.context_id: item for item in capture.auth_receipts}
        projected_identity["authenticated_contexts"] = freeze_json(
            [
                {
                    "context_id": context_id,
                    "strategy_id": receipts[context_id].strategy_id,
                    "actor_alias": receipts[context_id].actor_alias,
                }
                for context_id in connector.identity_preflight.authenticated_context_ids
            ]
        )
    for projection in connector.identity_preflight.static_projections:
        if projection.output_key in projected_identity:
            raise BehaviorContractError(
                "static identity projection collides with another evidence key"
            )
        projected_identity[projection.output_key] = _pointer_value(
            static_receipts[projection.input_id].body,
            projection.pointer,
        )
    if freeze_json(projected_identity) != connector.identity_preflight.expected_identity:
        raise BehaviorContractError(
            "capture preflight identity projection does not match connector"
        )

    if len(capture.exchanges) != len(recipe.steps):
        raise BehaviorContractError(
            "complete capture exchanges must exactly match recipe step count"
        )
    bindings: dict[str, JsonValue] = {}
    for step, exchange in zip(recipe.steps, capture.exchanges, strict=True):
        if exchange.phase != "program":
            raise BehaviorContractError("program exchange has the wrong phase")
        if (
            exchange.step_id != step.step_id
            or exchange.operation_id != step.operation_id
            or exchange.kind != step.kind
            or exchange.subject_id != step.subject_id
            or exchange.auth_context_id != step.auth_context_id
        ):
            raise BehaviorContractError("complete capture exchange identity does not match recipe")
        _validate_resolved_request(
            step.request,
            exchange.request,
            bindings=bindings,
            connector=connector,
            step_id=step.step_id,
            operation_id=step.operation_id,
            kind=step.kind,
            auth_context_id=step.auth_context_id,
        )
        _validate_outcome(step, exchange.status_code)
        for binding in step.bindings:
            value = _pointer_value(exchange.body, binding.pointer)
            if not generated_binding_value_matches(value, binding.value_type):
                raise BehaviorContractError(
                    f"capture binding {binding.binding_id!r} has an invalid generated ID value",
                    code="binding_coercion_invalid",
                )
            bindings[binding.binding_id] = value
    validate_assertion_prefix(recipe.steps, capture.exchanges)
    if freeze_json(bindings, path="recomputed_bindings") != capture.bindings:
        raise BehaviorContractError("capture.bindings does not match recomputed response bindings")
    if compute_observed_relations(recipe.steps, capture.exchanges) != capture.observed_relations:
        raise BehaviorContractError(
            "capture.observed_relations does not match recomputed state relations"
        )

    collector_specs = connector.collectors
    if len(capture.collector_exchanges) != len(collector_specs):
        raise BehaviorContractError("capture.collector_exchanges does not exactly cover collectors")
    for collector, exchange in zip(
        collector_specs,
        capture.collector_exchanges,
        strict=True,
    ):
        _validate_evidence_exchange(
            collector.call,
            exchange,
            phase="collector",
            bindings=bindings,
            connector=connector,
        )

    physical_exchanges = (
        len(capture.auth_receipts)
        + len(capture.preflight_exchanges)
        + len(capture.exchanges)
        + len(capture.collector_exchanges)
    )
    if physical_exchanges > connector.bounds.max_requests:
        raise BehaviorContractError("capture physical exchanges exceed connector max_requests")
    all_exchanges = capture.preflight_exchanges + capture.exchanges + capture.collector_exchanges
    for exchange in all_exchanges:
        if (
            len(canonical_json_bytes(exchange.request_receipt.to_dict()))
            > connector.bounds.max_request_bytes
        ):
            raise BehaviorContractError("capture request exceeds connector max_request_bytes")
        if exchange.body_bytes > connector.bounds.max_response_bytes:
            raise BehaviorContractError("capture response exceeds connector max_response_bytes")
    total_response_bytes = sum(item.body_bytes for item in all_exchanges)
    if total_response_bytes > connector.bounds.max_total_response_bytes:
        raise BehaviorContractError("capture responses exceed connector max_total_response_bytes")
    if (
        not {
            *[item.auth_context_id for item in capture.preflight_exchanges],
            *[item.auth_context_id for item in capture.exchanges],
            *[item.auth_context_id for item in capture.collector_exchanges],
        }
        <= declared_contexts
    ):
        raise BehaviorContractError("capture uses an undeclared auth context")


def _validate_evidence_exchange(
    spec: EvidenceCallSpec,
    exchange: CapturedExchange,
    *,
    phase: Literal["collector", "preflight"],
    bindings: Mapping[str, JsonValue],
    connector: ConnectorSpec,
) -> None:
    if (
        exchange.phase != phase
        or exchange.step_id != spec.call_id
        or exchange.operation_id != spec.strategy_id
        or exchange.kind != "read"
        or exchange.subject_id != spec.call_id
        or exchange.auth_context_id != spec.auth_context_id
    ):
        raise BehaviorContractError(f"{phase} exchange identity does not match declaration")
    _validate_resolved_request(
        spec.request,
        exchange.request,
        bindings=bindings,
        connector=connector,
        step_id=spec.call_id,
        operation_id=spec.strategy_id,
        kind="read",
        auth_context_id=spec.auth_context_id,
    )
    _validate_standalone_assertions(spec.assertions, exchange)
    if not 200 <= exchange.status_code <= 299:
        raise BehaviorContractError(f"{phase} exchange must complete with 2xx")


def _validate_standalone_assertions(
    assertions: tuple[AssertionSpec, ...],
    exchange: CapturedExchange,
) -> None:
    for assertion in assertions:
        if assertion.kind == "status_equals":
            passed = exchange.status_code == assertion.expected
        elif assertion.kind == "status_in":
            assert isinstance(assertion.expected, tuple)
            passed = exchange.status_code in assertion.expected
        elif assertion.kind == "json_pointer_equals":
            assert assertion.pointer is not None
            passed = _pointer_value(exchange.body, assertion.pointer) == assertion.expected
        elif assertion.kind == "json_pointer_type":
            assert assertion.pointer is not None and assertion.value_type is not None
            passed = binding_type_matches(
                _pointer_value(exchange.body, assertion.pointer),
                assertion.value_type,
            )
        elif assertion.kind == "json_pointer_pattern":
            assert assertion.pointer is not None and assertion.pattern is not None
            actual = _pointer_value(exchange.body, assertion.pointer)
            passed = type(actual) is str and re.fullmatch(assertion.pattern, actual) is not None
        else:
            raise BehaviorContractError("standalone evidence assertion kind is unsupported")
        if not passed:
            raise BehaviorContractError(
                f"capture evidence assertion failed: {assertion.assertion_id}"
            )


def _validate_outcome(step: BehaviorStep, status_code: int) -> None:
    if step.expected_outcome == "observe":
        if step.kind == "mutation":
            valid = status_code in _COMPLETED_MUTATION_STATUSES or 400 <= status_code <= 499
        else:
            valid = 200 <= status_code <= 299 or 400 <= status_code <= 499
        if not valid:
            raise BehaviorContractError(
                f"observational step {step.step_id!r} status is not a completed "
                "mutation, 2xx read, or 4xx failure"
            )
        return
    if step.expected_outcome in {
        "idempotent_success",
        "mutation_success",
        "read_success",
    }:
        if step.kind == "mutation":
            valid = status_code in _COMPLETED_MUTATION_STATUSES
        else:
            valid = 200 <= status_code <= 299
        if not valid:
            raise BehaviorContractError(
                f"step {step.step_id!r} success outcome did not observe completion"
            )
    elif not 400 <= status_code <= 499:
        raise BehaviorContractError(f"step {step.step_id!r} native failure observed non-4xx")


def _validate_resolved_request(
    template: RequestTemplate,
    request: DispatchRequest,
    *,
    bindings: Mapping[str, JsonValue],
    connector: ConnectorSpec,
    step_id: str,
    operation_id: str,
    kind: StepKind,
    auth_context_id: str,
) -> None:
    resolved = _resolve_json_bindings(template.to_dict(), bindings)
    path = render_path_template(template.path, bindings)
    query = freeze_json(resolved["query"], path="resolved.query")
    if not isinstance(query, Mapping):
        raise BehaviorContractError("resolved request query must be an object")
    body = freeze_json(resolved["body"], path="resolved.body")
    headers = safe_headers(resolved["headers"], path="resolved.headers")
    expected = DispatchRequest(
        step_id=step_id,
        operation_id=operation_id,
        kind=kind,
        auth_context_id=auth_context_id,
        method=template.method,
        path=path,
        query=query,
        body=body,
        headers=headers,
        timeout_ms=connector.bounds.request_timeout_ms,
        target=encode_request_target(path, query),
    )
    if request != expected:
        raise BehaviorContractError(
            f"captured request {step_id!r} is not the deterministic resolution"
        )


def _resolve_json_bindings(value: Any, bindings: Mapping[str, JsonValue]) -> Any:
    if isinstance(value, Mapping):
        if set(value.keys()) == {"$binding"}:
            binding_id = value["$binding"]
            if binding_id not in bindings:
                raise BehaviorContractError(
                    f"binding {binding_id!r} is unavailable during re-resolution"
                )
            return thaw_json(bindings[binding_id])
        return {key: _resolve_json_bindings(item, bindings) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_resolve_json_bindings(item, bindings) for item in value]
    return value


def derive_secret_variants(
    auth: AuthProfile,
    sensitive_values: Mapping[str, bytes],
) -> tuple[bytes, ...]:
    declared = {item.name: item for item in auth.secret_sources}
    if set(sensitive_values) != set(declared):
        raise BehaviorContractError("sensitive values must exactly cover declared secret sources")
    variants: set[bytes] = set()
    for name, source in declared.items():
        raw = sensitive_values[name]
        if type(raw) is not bytes or not raw:
            raise BehaviorContractError("sensitive values must be non-empty bytes")
        variants.add(raw)
        variants.add(base64.b64encode(raw))
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BehaviorContractError(
                f"secret source {name!r} must be UTF-8 for mandatory URL-encoded scanning"
            ) from error
        variants.add(quote_plus(decoded).encode("ascii"))
        for variant in source.scan_variants:
            if variant in {"raw", "base64", "urlencoded"}:
                continue
            if variant == "basic":
                # Basic is derived below from the exact client_id:secret pair.
                pass
            elif variant == "bearer":
                variants.add(b"Bearer " + raw)
    for context in auth.contexts:
        if context.grant is None or context.grant.client_basic_auth is None:
            continue
        basic = context.grant.client_basic_auth
        source = declared[basic.client_secret_source]
        if "basic" not in source.scan_variants:
            raise BehaviorContractError(
                f"secret source {source.name!r} must declare basic scan variant"
            )
        combined = basic.client_id.encode("utf-8") + b":" + sensitive_values[source.name]
        encoded_combined = base64.b64encode(combined)
        variants.add(encoded_combined)
        variants.add(b"Basic " + encoded_combined)
    return tuple(sorted(variants))


def scan_sensitive_bytes(
    value: bytes,
    sensitive_variants: tuple[bytes, ...],
    *,
    path: str,
) -> None:
    for sensitive in sensitive_variants:
        if sensitive and sensitive in value:
            raise BehaviorHarvestError(
                "sensitive_value_detected",
                f"{path} contains a declared secret representation",
            )


_LOAD_PROVENANCE = object()


@dataclass(frozen=True, init=False)
class LoadedConnector:
    value: ConnectorSpec
    exact_sha256: str

    def __init__(
        self,
        value: ConnectorSpec,
        exact_sha256: str,
        *,
        _provenance: object,
    ) -> None:
        if _provenance is not _LOAD_PROVENANCE:
            raise BehaviorContractError(
                "LoadedConnector can only be constructed by load_connector()"
            )
        if not isinstance(value, ConnectorSpec):
            raise BehaviorContractError("loaded connector value is invalid")
        object.__setattr__(self, "value", value)
        object.__setattr__(
            self, "exact_sha256", _sha256(exact_sha256, path="loaded_connector.exact_sha256")
        )


@dataclass(frozen=True, init=False)
class LoadedRecipe:
    value: BehaviorRecipe
    exact_sha256: str

    def __init__(
        self,
        value: BehaviorRecipe,
        exact_sha256: str,
        *,
        _provenance: object,
    ) -> None:
        if _provenance is not _LOAD_PROVENANCE:
            raise BehaviorContractError("LoadedRecipe can only be constructed by load_recipe()")
        if not isinstance(value, BehaviorRecipe):
            raise BehaviorContractError("loaded recipe value is invalid")
        object.__setattr__(self, "value", value)
        object.__setattr__(
            self,
            "exact_sha256",
            _sha256(exact_sha256, path="loaded_recipe.exact_sha256"),
        )


@dataclass(frozen=True, init=False)
class LoadedCapture:
    value: BehaviorCapture
    exact_sha256: str

    def __init__(
        self,
        value: BehaviorCapture,
        exact_sha256: str,
        *,
        _provenance: object,
    ) -> None:
        if _provenance is not _LOAD_PROVENANCE:
            raise BehaviorContractError("LoadedCapture can only be constructed by load_capture()")
        if not isinstance(value, BehaviorCapture):
            raise BehaviorContractError("loaded capture value is invalid")
        object.__setattr__(self, "value", value)
        object.__setattr__(
            self,
            "exact_sha256",
            _sha256(exact_sha256, path="loaded_capture.exact_sha256"),
        )


def load_connector(path: os.PathLike[str] | str, *, expected_sha256: str) -> LoadedConnector:
    raw, digest = _load_exact_json(path, expected_sha256=expected_sha256, max_bytes=4 << 20)
    return LoadedConnector(
        ConnectorSpec.from_dict(raw),
        digest,
        _provenance=_LOAD_PROVENANCE,
    )


def load_recipe(path: os.PathLike[str] | str, *, expected_sha256: str) -> LoadedRecipe:
    raw, digest = _load_exact_json(path, expected_sha256=expected_sha256, max_bytes=4 << 20)
    return LoadedRecipe(
        BehaviorRecipe.from_dict(raw),
        digest,
        _provenance=_LOAD_PROVENANCE,
    )


def load_static_json_receipts(
    connector: ConnectorSpec,
    *,
    input_paths: Mapping[str, os.PathLike[str] | str],
    expected_sha256: Mapping[str, str],
) -> tuple[StaticJsonReceipt, ...]:
    # Paths are deliberately operator-local locators, not semantic provenance.
    # Exact bytes, external digests, schema identity, and parsed value are bound
    # into the receipt, so identical content may be reloaded from another path.
    if not isinstance(connector, ConnectorSpec):
        raise BehaviorContractError("static inputs require a ConnectorSpec")
    declared_ids = {item.input_id for item in connector.static_json_inputs}
    if set(input_paths) != declared_ids or set(expected_sha256) != declared_ids:
        raise BehaviorContractError(
            "static input paths and digests must exactly cover connector declarations"
        )
    receipts: list[StaticJsonReceipt] = []
    for spec in connector.static_json_inputs:
        raw_bytes, _ = _load_exact_bytes(
            input_paths[spec.input_id],
            expected_sha256=expected_sha256[spec.input_id],
            max_bytes=spec.max_bytes,
        )
        receipt = StaticJsonReceipt.from_body(
            spec=spec,
            body_bytes=raw_bytes,
        )
        if receipt.body != spec.expected_json:
            raise BehaviorContractError(
                f"static input {spec.input_id!r} does not equal connector expected_json"
            )
        receipts.append(receipt)
    return tuple(receipts)


def load_capture(
    path: os.PathLike[str] | str,
    *,
    expected_sha256: str,
    connector_path: os.PathLike[str] | str,
    expected_connector_sha256: str,
    recipe_path: os.PathLike[str] | str,
    expected_recipe_sha256: str,
    expected_engine: EngineIdentity,
    sensitive_values: Mapping[str, bytes],
    static_input_paths: Mapping[str, os.PathLike[str] | str],
    expected_static_input_sha256: Mapping[str, str],
) -> LoadedCapture:
    raw, digest = _load_exact_json(path, expected_sha256=expected_sha256, max_bytes=128 << 20)
    connector = load_connector(
        connector_path,
        expected_sha256=expected_connector_sha256,
    )
    recipe = load_recipe(recipe_path, expected_sha256=expected_recipe_sha256)
    static_receipts = load_static_json_receipts(
        connector.value,
        input_paths=static_input_paths,
        expected_sha256=expected_static_input_sha256,
    )
    capture = BehaviorCapture.from_dict(raw)
    if (
        capture.connector != connector.value
        or capture.connector_sha256 != connector.exact_sha256
        or capture.recipe != recipe.value
        or capture.recipe_sha256 != recipe.exact_sha256
    ):
        raise BehaviorContractError("capture does not match externally loaded connector and recipe")
    if capture.static_input_receipts != static_receipts:
        raise BehaviorContractError(
            "capture static receipts do not match externally reloaded inputs"
        )
    if not isinstance(expected_engine, EngineIdentity) or capture.engine != expected_engine:
        raise BehaviorContractError(
            "capture engine does not match the externally expected identity"
        )
    from datalox_gated_runtime.behavior_harvest.engines.v2.runner import (
        current_engine_identity,
    )

    if expected_engine != current_engine_identity():
        raise BehaviorContractError("capture engine does not match the installed harvest engine")
    secret_variants = derive_secret_variants(
        connector.value.auth,
        sensitive_values,
    )
    scan_sensitive_bytes(
        canonical_json_bytes(raw),
        secret_variants,
        path="capture artifact",
    )
    for receipt in static_receipts:
        scan_sensitive_bytes(
            receipt.raw_body,
            secret_variants,
            path=f"static input {receipt.input_id}",
        )
    return LoadedCapture(capture, digest, _provenance=_LOAD_PROVENANCE)


def _load_exact_json(
    path: os.PathLike[str] | str,
    *,
    expected_sha256: str,
    max_bytes: int,
) -> tuple[dict[str, Any], str]:
    raw_bytes, digest = _load_exact_bytes(
        path,
        expected_sha256=expected_sha256,
        max_bytes=max_bytes,
    )
    parsed = parse_json_bytes(raw_bytes, path="contract_file")
    if not isinstance(parsed, Mapping):
        raise BehaviorContractError("contract file root must be an object")
    thawed = thaw_json(parsed)
    assert type(thawed) is dict
    return thawed, digest


def _load_exact_bytes(
    path: os.PathLike[str] | str,
    *,
    expected_sha256: str,
    max_bytes: int,
) -> tuple[bytes, str]:
    expected = _sha256(expected_sha256, path="expected_sha256")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BehaviorContractError("contract file cannot be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise BehaviorContractError("contract file must be a regular file")
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise BehaviorContractError("contract file size is outside the strict bound")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1 << 20))
            if not chunk:
                raise BehaviorContractError("contract file changed during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise BehaviorContractError("contract file grew during read")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise BehaviorContractError("contract file changed during read")
    finally:
        os.close(descriptor)
    raw_bytes = b"".join(chunks)
    digest = sha256_digest(raw_bytes)
    if digest != expected:
        raise BehaviorContractError("contract file does not match expected exact SHA-256")
    return raw_bytes, digest
