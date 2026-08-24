from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Mapping

from datalox_gated_runtime.query import QueryInputValue, QueryParams, normalize_query

AuthTarget = Literal["header", "query"]


@dataclass(frozen=True)
class AuthBrokerError(Exception):
    code: str
    message: str
    missing_env: tuple[str, ...] = ()

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class AuthInjection:
    target: AuthTarget
    name: str
    env: str
    scheme: str | None = None


@dataclass(frozen=True)
class AuthProfile:
    kind: Literal["env_static"]
    inject: tuple[AuthInjection, ...]


@dataclass(frozen=True)
class AuthBrokerConfig:
    profiles: dict[str, AuthProfile] = field(default_factory=dict)

    def require_profile(self, profile_id: str) -> AuthProfile:
        try:
            return self.profiles[profile_id]
        except KeyError as exc:
            raise AuthBrokerError(
                "unknown_auth_profile",
                f"auth_profile {profile_id!r} is not defined.",
            ) from exc


@dataclass(frozen=True)
class AuthPreflightProof:
    profile_ids: tuple[str, ...]
    requirements: tuple[dict[str, Any], ...]
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def status(self) -> Literal["passed", "failed"]:
        return "failed" if self.missing_env else "passed"

    @property
    def missing_env(self) -> list[str]:
        return sorted(
            {
                str(requirement["env"])
                for requirement in self.requirements
                if requirement.get("present") is False
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked_at": self.checked_at,
            "kind": "auth_preflight_v0",
            "profile_ids": list(self.profile_ids),
            "requirements": list(self.requirements),
            "status": self.status,
        }


def parse_auth_broker_config(raw: Mapping[str, Any] | None) -> AuthBrokerConfig:
    if raw is None:
        return AuthBrokerConfig()
    auth_profiles = raw.get("auth_profiles", {})
    if auth_profiles is None:
        return AuthBrokerConfig()
    if not isinstance(auth_profiles, dict):
        raise AuthBrokerError("invalid_auth_profiles", "auth_profiles must be an object.")

    profiles: dict[str, AuthProfile] = {}
    for profile_id, profile_raw in auth_profiles.items():
        _validate_profile_id(profile_id)
        profiles[profile_id] = _parse_profile(profile_raw, profile_id)
    return AuthBrokerConfig(profiles=profiles)


def parse_auth_profile_ref(raw: Mapping[str, Any], *, path: str = "auth_profile") -> str | None:
    if "auth_profile" not in raw or raw["auth_profile"] is None:
        return None
    value = raw["auth_profile"]
    if not isinstance(value, str) or not value.strip():
        raise AuthBrokerError("invalid_auth_profile", f"{path} must be a non-empty string.")
    _validate_profile_id(value)
    return value


def preflight_auth(
    config: AuthBrokerConfig,
    profile_ids: list[str] | tuple[str, ...],
    *,
    environ: Mapping[str, str] | None = None,
) -> AuthPreflightProof:
    env = environ if environ is not None else os.environ
    ordered_profile_ids = tuple(dict.fromkeys(profile_ids))
    requirements: list[dict[str, Any]] = []
    for profile_id in ordered_profile_ids:
        profile = config.require_profile(profile_id)
        for injection in profile.inject:
            requirements.append(
                {
                    "env": injection.env,
                    "present": env.get(injection.env) is not None,
                    "profile_id": profile_id,
                    "target": {"in": injection.target, "name": injection.name},
                }
            )
    return AuthPreflightProof(
        profile_ids=ordered_profile_ids,
        requirements=tuple(requirements),
    )


def apply_auth_profile(
    profile: AuthProfile,
    *,
    headers: Mapping[str, str] | None = None,
    query: Mapping[str, QueryInputValue] | None = None,
    environ: Mapping[str, str] | None = None,
) -> tuple[dict[str, str], QueryParams]:
    env = environ if environ is not None else os.environ
    next_headers = dict(headers or {})
    next_query = normalize_query(query)
    missing = sorted(
        {injection.env for injection in profile.inject if env.get(injection.env) is None}
    )
    if missing:
        raise AuthBrokerError(
            "missing_auth_env",
            "Required auth environment variables are not set.",
            tuple(missing),
        )

    for injection in profile.inject:
        secret_value = env[injection.env]
        if injection.target == "header":
            next_headers[injection.name] = _auth_value(injection.scheme, secret_value)
            continue
        if injection.name in next_query:
            raise AuthBrokerError(
                "auth_query_collision",
                f"Request query already contains auth-owned key {injection.name!r}.",
            )
        next_query[injection.name] = secret_value
    return next_headers, next_query


def _parse_profile(raw: Any, profile_id: str) -> AuthProfile:
    if not isinstance(raw, dict):
        raise AuthBrokerError(
            "invalid_auth_profile", f"auth_profiles.{profile_id} must be an object."
        )
    kind = raw.get("kind")
    if kind != "env_static":
        raise AuthBrokerError(
            "invalid_auth_profile",
            f"auth_profiles.{profile_id}.kind must be env_static.",
        )
    inject_raw = raw.get("inject")
    if not isinstance(inject_raw, list) or not inject_raw:
        raise AuthBrokerError(
            "invalid_auth_profile",
            f"auth_profiles.{profile_id}.inject must be a non-empty list.",
        )
    inject = tuple(
        _parse_injection(item, profile_id=profile_id, index=index)
        for index, item in enumerate(inject_raw)
    )
    _validate_unique_targets(profile_id, inject)
    return AuthProfile(kind="env_static", inject=inject)


def _parse_injection(raw: Any, *, profile_id: str, index: int) -> AuthInjection:
    if not isinstance(raw, dict):
        raise AuthBrokerError(
            "invalid_auth_profile",
            f"auth_profiles.{profile_id}.inject[{index}] must be an object.",
        )
    target = raw.get("in")
    if target not in {"header", "query"}:
        raise AuthBrokerError(
            "invalid_auth_profile",
            f"auth_profiles.{profile_id}.inject[{index}].in must be header or query.",
        )
    name = _required_str(raw, "name", f"auth_profiles.{profile_id}.inject[{index}].name")
    env = _required_str(raw, "env", f"auth_profiles.{profile_id}.inject[{index}].env")
    scheme = raw.get("scheme")
    if target == "query":
        if "scheme" in raw:
            raise AuthBrokerError(
                "invalid_auth_profile",
                f"auth_profiles.{profile_id}.inject[{index}].scheme is not allowed for query injection.",
            )
        return AuthInjection(target="query", name=name, env=env, scheme=None)
    if scheme is None:
        scheme = "Bearer"
    if not isinstance(scheme, str):
        raise AuthBrokerError(
            "invalid_auth_profile",
            f"auth_profiles.{profile_id}.inject[{index}].scheme must be a string.",
        )
    return AuthInjection(target="header", name=name, env=env, scheme=scheme)


def _validate_profile_id(profile_id: Any) -> None:
    if (
        not isinstance(profile_id, str)
        or not profile_id.strip()
        or profile_id.strip() != profile_id
        or "/" in profile_id
        or "." in profile_id
    ):
        raise AuthBrokerError(
            "invalid_auth_profile",
            "auth profile ids must be non-empty names without / or ..",
        )


def _validate_unique_targets(profile_id: str, inject: tuple[AuthInjection, ...]) -> None:
    header_targets: set[str] = set()
    query_targets: set[str] = set()
    for injection in inject:
        if injection.target == "header":
            normalized = injection.name.lower()
            if normalized in header_targets:
                raise AuthBrokerError(
                    "invalid_auth_profile",
                    f"auth_profiles.{profile_id} has duplicate header target {injection.name!r}.",
                )
            header_targets.add(normalized)
            continue
        if injection.name in query_targets:
            raise AuthBrokerError(
                "invalid_auth_profile",
                f"auth_profiles.{profile_id} has duplicate query target {injection.name!r}.",
            )
        query_targets.add(injection.name)


def _required_str(raw: Mapping[str, Any], key: str, path: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuthBrokerError("invalid_auth_profile", f"{path} must be a non-empty string.")
    return value


def _auth_value(scheme: str | None, value: str) -> str:
    return f"{scheme} {value}" if scheme else value
