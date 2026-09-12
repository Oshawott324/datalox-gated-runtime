"""Controller-only contract for the bounded clean/hostile repeat experiment.

The manifest freezes a native Verifiers run; it supplies neither agent input nor
provider behavior. Its schema is generated from these models, and the runner
must validate the serialized manifest before making any model request.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from datalox_dirty_integration.audit import canonical_sha256


def _integer_literal(value: Any) -> Any:
    # Literal validation accepts 0 == False and 1 == True, even in strict mode.
    if type(value) is not int:
        raise ValueError("fixed integer controls require an integer")
    return value


def _boolean_literal(value: Any) -> Any:
    if type(value) is not bool:
        raise ValueError("fixed boolean controls require a boolean")
    return value


Sha256 = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
Seed = Annotated[str, StringConstraints(min_length=1, max_length=128)]
BindingName = Annotated[str, StringConstraints(min_length=1, max_length=256)]
Profile = Literal["clean", "hostile"]
ZeroRetries = Annotated[Literal[0], BeforeValidator(_integer_literal)]
OneConcurrent = Annotated[Literal[1], BeforeValidator(_integer_literal)]
NoParallelTools = Annotated[Literal[False], BeforeValidator(_boolean_literal)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        allow_inf_nan=False,
    )


class RolloutSlot(_StrictModel):
    slot_id: Annotated[str, StringConstraints(pattern=r"^r[0-9]+-s[0-9]+-(clean|hostile)$")]
    profile: Profile
    seed: Seed
    repetition: int = Field(ge=1)
    order: int = Field(ge=0)


class _ScheduleParameters(_StrictModel):
    seeds: tuple[Seed, ...] = Field(min_length=1)
    repetitions: int = Field(ge=1)

    @field_validator("seeds")
    @classmethod
    def unique_seeds(cls, seeds: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(seeds)) != len(seeds):
            raise ValueError("environment seed labels must be unique")
        return seeds


def build_schedule(
    seeds: tuple[str, ...] = ("1", "7", "23"), repetitions: int = 10
) -> list[RolloutSlot]:
    """Pair profiles within seed/repetition blocks, alternating the first arm.

    No random generator is involved. Each seed has equal clean-first and
    hostile-first blocks when the repetition count is even. Slot IDs are local
    to the experiment and retain the seed's declared position.
    """
    parameters = _ScheduleParameters(seeds=seeds, repetitions=repetitions)
    slots: list[RolloutSlot] = []
    for repetition_index in range(parameters.repetitions):
        for seed_index, seed in enumerate(parameters.seeds):
            profiles: tuple[Profile, Profile] = (
                ("clean", "hostile")
                if (repetition_index + seed_index) % 2 == 0
                else ("hostile", "clean")
            )
            for profile in profiles:
                slots.append(
                    RolloutSlot(
                        slot_id=f"r{repetition_index + 1:03d}-s{seed_index + 1:03d}-{profile}",
                        profile=profile,
                        seed=seed,
                        repetition=repetition_index + 1,
                        order=len(slots),
                    )
                )
    return slots


class ModelConfig(_StrictModel):
    model: Annotated[str, StringConstraints(pattern=r"^gpt-5\.6-[a-z0-9]+(?:-[a-z0-9]+)*$")] = (
        "gpt-5.6-sol"
    )
    endpoint: str = "https://api.openai.com/v1"
    api_key_env: Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")] = (
        "OPENAI_API_KEY"
    )
    reasoning_effort: Literal["none", "low", "medium", "high", "xhigh", "max"] = "medium"
    # None explicitly records omission; the preflight confirms supported settings.
    temperature: float | None = Field(default=None, ge=0, le=2)
    model_seed: None = None
    parallel_tool_calls: NoParallelTools = False
    max_completion_tokens: int = Field(gt=0)
    request_timeout_seconds: float = Field(gt=0)
    connect_timeout_seconds: float = Field(gt=0)

    @field_validator("endpoint")
    @classmethod
    def credential_free_endpoint(cls, endpoint: str) -> str:
        if any(character.isspace() or ord(character) < 32 for character in endpoint):
            raise ValueError("inference endpoint must contain no whitespace or controls")
        if any(character in endpoint for character in ("?", "#", "\\")):
            raise ValueError("inference endpoint must contain no query, fragment, or backslash")
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or (port is not None and port == 0)
            ):
                raise ValueError("inference endpoint must be HTTPS with no user information")
            # A URL authority is not a place to encode path delimiters or credentials.
            if "%" in parsed.netloc:
                raise ValueError("inference endpoint authority must contain no percent escapes")
        except ValueError as error:
            raise ValueError("invalid credential-free HTTPS inference endpoint") from error
        return endpoint

    @model_validator(mode="after")
    def timeout_order(self) -> Self:
        if self.connect_timeout_seconds > self.request_timeout_seconds:
            raise ValueError("connect timeout must be within the model request timeout")
        return self


class ExperimentConfig(_StrictModel):
    schema_version: Literal["datalox_repeat_experiment_v1"] = "datalox_repeat_experiment_v1"
    experiment_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]
    source_revision: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    bindings: dict[BindingName, Sha256] = Field(min_length=1)
    model: ModelConfig
    seeds: tuple[Seed, ...] = ("1", "7", "23")
    repetitions: int = Field(default=10, ge=1)
    max_turns: int = Field(default=30, gt=0)
    per_rollout_timeout_seconds: float = Field(gt=0)
    max_total_cost_usd: float = Field(gt=0)
    per_rollout_reservation_usd: float = Field(gt=0)
    concurrency: OneConcurrent = 1
    evaluator_retries: ZeroRetries = 0
    client_retries: ZeroRetries = 0
    schedule: list[RolloutSlot]

    @model_validator(mode="after")
    def fixed_experiment(self) -> Self:
        if self.per_rollout_reservation_usd > self.max_total_cost_usd:
            raise ValueError("per-rollout reservation must fit the total spending cap")
        if self.schedule != build_schedule(self.seeds, self.repetitions):
            raise ValueError("schedule must exactly match the declared seeds and repetitions")
        return self


def experiment_json_schema() -> dict[str, Any]:
    """Return the schema generated from the executable validation contract."""
    return ExperimentConfig.model_json_schema()


def write_json_exclusive(path: Path, value: Any) -> None:
    """Create one mode-0600 controller artifact, preserving any existing file."""
    payload = (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)


__all__ = [
    "ExperimentConfig",
    "ModelConfig",
    "RolloutSlot",
    "build_schedule",
    "canonical_sha256",
    "experiment_json_schema",
    "write_json_exclusive",
]
