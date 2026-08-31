"""Provider-native simulated identity policies for transparent runtime requests."""

from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any, Literal

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.world_v1.contracts import ActorContext

IDENTITY_POLICY_SCHEMA_VERSION = "datalox_provider_identity_v1"
FIXED_PRINCIPAL_CONTEXT_ID = "fixed"
ANONYMOUS_PRINCIPAL_CONTEXT_ID = "anonymous"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_STANDARD_SECRET_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
    }
)
RESERVED_AGENT_HEADERS = frozenset(
    {
        "x-datalox-actor-id",
        "x-datalox-actor-role",
        "x-datalox-tool-name",
    }
)


@dataclass(frozen=True)
class IdentityErrorResponse:
    status_code: int
    body: Any
    headers: Mapping[str, str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "body": self.body,
            "headers": dict(self.headers),
        }


@dataclass(frozen=True)
class CredentialSelector:
    location: Literal["header", "query", "cookie"]
    name: str
    value_sha256: str

    def key(self) -> tuple[str, str, str]:
        return (self.location, self.name, self.value_sha256)

    def to_dict(self) -> dict[str, str]:
        return {
            "location": self.location,
            "name": self.name,
            "value_sha256": self.value_sha256,
        }


@dataclass(frozen=True)
class CredentialPrincipal:
    principal_context_id: str
    actor_id: str
    actor_role: str
    credentials: tuple[CredentialSelector, ...]

    @property
    def actor(self) -> ActorContext:
        return ActorContext(self.actor_id, self.actor_role)

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_context_id": self.principal_context_id,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "credentials": [item.to_dict() for item in self.credentials],
        }


@dataclass(frozen=True)
class FixedIdentityPolicy:
    actor_id: str
    actor_role: str
    mode: Literal["fixed"] = "fixed"
    schema_version: str = IDENTITY_POLICY_SCHEMA_VERSION

    @property
    def actor(self) -> ActorContext:
        return ActorContext(self.actor_id, self.actor_role)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
        }


@dataclass(frozen=True)
class CredentialMapIdentityPolicy:
    principals: tuple[CredentialPrincipal, ...]
    missing_identity: IdentityErrorResponse
    invalid_identity: IdentityErrorResponse
    mode: Literal["credential_map"] = "credential_map"
    schema_version: str = IDENTITY_POLICY_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "principals": [item.to_dict() for item in self.principals],
            "missing_identity": self.missing_identity.to_dict(),
            "invalid_identity": self.invalid_identity.to_dict(),
        }


IdentityPolicy = FixedIdentityPolicy | CredentialMapIdentityPolicy


@dataclass(frozen=True)
class IdentityResolution:
    actor: ActorContext
    request: CallRequest


@dataclass(frozen=True)
class IdentityResolutionError(Exception):
    code: str
    response: IdentityErrorResponse


def load_identity_policy(raw: Any, *, declared_roles: frozenset[str]) -> IdentityPolicy:
    if not isinstance(raw, dict):
        raise _invalid("identity policy must be an object")
    if raw.get("schema_version") != IDENTITY_POLICY_SCHEMA_VERSION:
        raise _invalid("identity policy schema is unsupported")
    mode = raw.get("mode")
    if mode == "fixed":
        _require_fields(raw, {"schema_version", "mode", "actor_id", "actor_role"})
        policy = FixedIdentityPolicy(
            actor_id=_identifier(raw["actor_id"], "actor_id"),
            actor_role=_role(raw["actor_role"], declared_roles),
        )
        return policy
    if mode != "credential_map":
        raise _invalid("identity policy mode is unsupported")
    _require_fields(
        raw,
        {
            "schema_version",
            "mode",
            "principals",
            "missing_identity",
            "invalid_identity",
        },
    )
    principals_raw = raw["principals"]
    if not isinstance(principals_raw, list) or not principals_raw:
        raise _invalid("identity policy principals must be a non-empty array")
    principals = tuple(_principal(item, declared_roles=declared_roles) for item in principals_raw)
    context_ids = [item.principal_context_id for item in principals]
    if len(context_ids) != len(set(context_ids)):
        raise _invalid("identity policy principal contexts must be unique")
    credential_sets = [
        frozenset(item.key() for item in principal.credentials) for principal in principals
    ]
    for index, first in enumerate(credential_sets):
        for second in credential_sets[index + 1 :]:
            if first <= second or second <= first:
                raise _invalid("identity policy credential sets must not overlap by subset")
    return CredentialMapIdentityPolicy(
        principals=principals,
        missing_identity=_error_response(raw["missing_identity"], "missing_identity"),
        invalid_identity=_error_response(raw["invalid_identity"], "invalid_identity"),
    )


def resolve_external_identity(policy: IdentityPolicy, request: CallRequest) -> IdentityResolution:
    _reject_reserved_headers(request)
    if isinstance(policy, FixedIdentityPolicy):
        return IdentityResolution(policy.actor, _sanitize_request(request, policy))

    extracted: dict[tuple[str, str], str | None] = {}
    selectors = {
        (selector.location, selector.name): selector
        for principal in policy.principals
        for selector in principal.credentials
    }
    for key, selector in selectors.items():
        extracted[key] = _extract(request, selector)
    if not any(value is not None for value in extracted.values()):
        raise IdentityResolutionError("provider_identity_missing", policy.missing_identity)

    matching: list[CredentialPrincipal] = []
    for principal in policy.principals:
        if all(
            (value := extracted[(selector.location, selector.name)]) is not None
            and secrets.compare_digest(_sha256(value), selector.value_sha256)
            for selector in principal.credentials
        ):
            matching.append(principal)
    if len(matching) != 1:
        raise IdentityResolutionError("provider_identity_invalid", policy.invalid_identity)
    return IdentityResolution(matching[0].actor, _sanitize_request(request, policy))


def sanitize_external_request(
    request: CallRequest,
    policy: IdentityPolicy | None = None,
) -> CallRequest:
    """Reject internal control headers and remove credentials from runtime evidence."""

    _reject_reserved_headers(request)
    return redact_external_request(request, policy)


def redact_external_request(
    request: CallRequest,
    policy: IdentityPolicy | None = None,
) -> CallRequest:
    """Remove credentials and internal control headers without resolving identity."""

    sanitized = _sanitize_request(request, policy)
    return replace(
        sanitized,
        headers={
            name: value
            for name, value in sanitized.headers.items()
            if not name.lower().startswith("x-datalox-")
        },
    )


def _reject_reserved_headers(request: CallRequest) -> None:
    names = {name.lower() for name in request.headers}
    forbidden = sorted(name for name in names if name.startswith("x-datalox-"))
    if forbidden:
        raise ProviderRuntimeError(
            "provider_runtime_reserved_header",
            "Agent requests must not contain Datalox internal identity headers.",
            {"headers": forbidden},
        )


def _sanitize_request(request: CallRequest, policy: IdentityPolicy | None) -> CallRequest:
    secret_headers = set(_STANDARD_SECRET_HEADERS)
    secret_query_names: set[str] = set()
    if isinstance(policy, CredentialMapIdentityPolicy):
        for principal in policy.principals:
            for selector in principal.credentials:
                if selector.location in {"header", "cookie"}:
                    secret_headers.add("cookie" if selector.location == "cookie" else selector.name)
                elif selector.location == "query":
                    secret_query_names.add(selector.name)
    headers = {
        name: value for name, value in request.headers.items() if name.lower() not in secret_headers
    }
    query = {name: value for name, value in request.query.items() if name not in secret_query_names}
    return replace(request, headers=headers, query=query)


def _extract(request: CallRequest, selector: CredentialSelector) -> str | None:
    if selector.location == "header":
        values = [value for name, value in request.headers.items() if name.lower() == selector.name]
        if len(values) > 1:
            return None
        return values[0] if values else None
    if selector.location == "query":
        value = request.query.get(selector.name)
        return value if isinstance(value, str) else None
    cookie_headers = [value for name, value in request.headers.items() if name.lower() == "cookie"]
    if len(cookie_headers) != 1:
        return None
    cookies = _cookies(cookie_headers[0])
    return cookies.get(selector.name)


def _cookies(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for component in raw.split(";"):
        name, separator, value = component.strip().partition("=")
        if not separator or not _HEADER_NAME.fullmatch(name) or name in result:
            return {}
        result[name] = value
    return result


def _principal(raw: Any, *, declared_roles: frozenset[str]) -> CredentialPrincipal:
    if not isinstance(raw, dict):
        raise _invalid("identity principal must be an object")
    _require_fields(
        raw,
        {"principal_context_id", "actor_id", "actor_role", "credentials"},
    )
    credentials_raw = raw["credentials"]
    if not isinstance(credentials_raw, list) or not credentials_raw:
        raise _invalid("identity principal credentials must be a non-empty array")
    credentials = tuple(_selector(item) for item in credentials_raw)
    locations = [(item.location, item.name) for item in credentials]
    if len(locations) != len(set(locations)):
        raise _invalid("identity principal credentials must use unique locations")
    return CredentialPrincipal(
        principal_context_id=_identifier(raw["principal_context_id"], "principal_context_id"),
        actor_id=_identifier(raw["actor_id"], "actor_id"),
        actor_role=_role(raw["actor_role"], declared_roles),
        credentials=credentials,
    )


def _selector(raw: Any) -> CredentialSelector:
    if not isinstance(raw, dict):
        raise _invalid("identity credential selector must be an object")
    _require_fields(raw, {"location", "name", "value_sha256"})
    location = raw["location"]
    if location not in {"header", "query", "cookie"}:
        raise _invalid("identity credential location is unsupported")
    name = raw["name"]
    if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
        raise _invalid("identity credential name is invalid")
    canonical_name = name.lower() if location == "header" else name
    digest = raw["value_sha256"]
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise _invalid("identity credential digest is invalid")
    return CredentialSelector(location, canonical_name, digest)


def _error_response(raw: Any, field: str) -> IdentityErrorResponse:
    if not isinstance(raw, dict):
        raise _invalid(f"{field} must be an object")
    _require_fields(raw, {"status_code", "body", "headers"})
    status = raw["status_code"]
    if type(status) is not int or not 400 <= status <= 499:
        raise _invalid(f"{field}.status_code must be a 4xx integer")
    headers = raw["headers"]
    if not isinstance(headers, dict) or any(
        not isinstance(name, str)
        or not _HEADER_NAME.fullmatch(name)
        or not isinstance(value, str)
        or name.lower() in _STANDARD_SECRET_HEADERS
        for name, value in headers.items()
    ):
        raise _invalid(f"{field}.headers is invalid")
    return IdentityErrorResponse(status, raw["body"], dict(headers))


def _role(value: Any, declared_roles: frozenset[str]) -> str:
    role = _identifier(value, "actor_role")
    if role not in declared_roles:
        raise _invalid(f"identity policy actor role is not declared: {role}")
    return role


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise _invalid(f"identity policy {field} is invalid")
    return value


def _require_fields(raw: dict[str, Any], required: set[str]) -> None:
    if set(raw) != required:
        raise _invalid(
            "identity policy fields do not match the contract: "
            f"missing={sorted(required - set(raw))} unknown={sorted(set(raw) - required)}"
        )


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _invalid(message: str) -> ProviderRuntimeError:
    return ProviderRuntimeError("provider_runtime_identity_invalid", message)
