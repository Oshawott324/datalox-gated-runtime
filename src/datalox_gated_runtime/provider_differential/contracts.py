"""Strict, content-addressable contracts for release differential evidence."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from datalox_gated_runtime.json_digest import canonical_json_bytes, canonical_json_sha256
from datalox_gated_runtime.provider_differential.errors import ProviderDifferentialError
from datalox_gated_runtime.reference import ConformanceReport, ObservedResponse, ReferenceCall
from datalox_gated_runtime.reference.contracts import freeze_json, thaw_json

GROUNDING_MEASUREMENT_SCHEMA_VERSION = "datalox_provider_grounding_measurement_v1"
DIFFERENTIAL_ATTESTATION_SCHEMA_VERSION = "datalox_provider_differential_attestation_v1"
DIFFERENTIAL_COMPARISON_PROFILE = "behavior_binding_exact_v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
_DISTRIBUTIONS = frozenset({"public", "restricted", "private"})
_COMPLETIONS = frozenset({"complete", "incomplete"})
_RUN_PHASES = frozenset(
    {"within_instance_initial", "within_instance_after_reset", "fresh_instance"}
)


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderDifferentialError(code, message, details)


def _string(value: Any, *, field_name: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        _fail(
            "provider_differential_string_invalid",
            f"{field_name} must be a non-empty canonical string.",
            field=field_name,
        )
    return value


def _identifier(value: Any, *, field_name: str) -> str:
    result = _string(value, field_name=field_name)
    if _IDENTIFIER.fullmatch(result) is None:
        _fail(
            "provider_differential_identifier_invalid",
            f"{field_name} must be a stable identifier.",
            field=field_name,
        )
    return result


def _digest(value: Any, *, field_name: str) -> str:
    result = _string(value, field_name=field_name)
    if _DIGEST.fullmatch(result) is None:
        _fail(
            "provider_differential_digest_invalid",
            f"{field_name} must use sha256:<64 lowercase hexadecimal characters>.",
            field=field_name,
        )
    return result


def _utc_timestamp(value: Any, *, field_name: str) -> str:
    result = _string(value, field_name=field_name)
    if _UTC_TIMESTAMP.fullmatch(result) is None:
        _fail(
            "provider_differential_timestamp_invalid",
            f"{field_name} must be an RFC 3339 UTC timestamp ending in Z.",
            field=field_name,
        )
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as error:
        raise ProviderDifferentialError(
            "provider_differential_timestamp_invalid",
            f"{field_name} is not a valid timestamp.",
            {"field": field_name},
        ) from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        _fail(
            "provider_differential_timestamp_invalid",
            f"{field_name} must be UTC.",
            field=field_name,
        )
    return result


def _strict_shape(
    value: Any,
    *,
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
    field_name: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(
            "provider_differential_shape_invalid",
            f"{field_name} must be an object.",
            field=field_name,
        )
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required - optional)
    if missing or unknown:
        _fail(
            "provider_differential_shape_invalid",
            f"{field_name} has an invalid field set.",
            field=field_name,
            missing=missing,
            unknown=unknown,
        )
    return value


@dataclass(frozen=True)
class GroundingMeasurement:
    measurement_id: str
    provider_id: str
    provider_version: str
    program_id: str
    observed_at: str
    capture_sha256: str
    connector_sha256: str
    recipe_sha256: str
    harvest_engine_sha256: str
    compiled_program_sha256: str | None
    completion: str
    rights_ref: str
    distribution: str
    source_reset_receipt_sha256: str | None = None
    schema_version: str = GROUNDING_MEASUREMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != GROUNDING_MEASUREMENT_SCHEMA_VERSION:
            _fail(
                "provider_grounding_measurement_schema_unsupported",
                "Unsupported provider grounding measurement schema.",
            )
        for name in ("measurement_id", "provider_id", "program_id", "rights_ref"):
            object.__setattr__(self, name, _identifier(getattr(self, name), field_name=name))
        object.__setattr__(
            self,
            "provider_version",
            _string(self.provider_version, field_name="provider_version"),
        )
        object.__setattr__(
            self,
            "observed_at",
            _utc_timestamp(self.observed_at, field_name="observed_at"),
        )
        for name in (
            "capture_sha256",
            "connector_sha256",
            "recipe_sha256",
            "harvest_engine_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), field_name=name))
        if self.source_reset_receipt_sha256 is not None:
            object.__setattr__(
                self,
                "source_reset_receipt_sha256",
                _digest(
                    self.source_reset_receipt_sha256,
                    field_name="source_reset_receipt_sha256",
                ),
            )
        if self.completion not in _COMPLETIONS:
            _fail(
                "provider_grounding_measurement_completion_invalid",
                "completion must be complete or incomplete.",
            )
        if self.completion == "complete":
            if self.compiled_program_sha256 is None:
                _fail(
                    "provider_grounding_measurement_compiled_program_binding_invalid",
                    "A complete measurement requires a compiled-program digest.",
                )
            object.__setattr__(
                self,
                "compiled_program_sha256",
                _digest(
                    self.compiled_program_sha256,
                    field_name="compiled_program_sha256",
                ),
            )
        elif self.compiled_program_sha256 is not None:
            _fail(
                "provider_grounding_measurement_compiled_program_binding_invalid",
                "An incomplete measurement cannot claim a compiled-program digest.",
            )
        if self.distribution not in _DISTRIBUTIONS:
            _fail(
                "provider_grounding_measurement_distribution_invalid",
                "distribution must be public, restricted, or private.",
            )

    @property
    def sha256(self) -> str:
        return canonical_json_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "measurement_id": self.measurement_id,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "program_id": self.program_id,
            "observed_at": self.observed_at,
            "capture_sha256": self.capture_sha256,
            "connector_sha256": self.connector_sha256,
            "recipe_sha256": self.recipe_sha256,
            "harvest_engine_sha256": self.harvest_engine_sha256,
            "compiled_program_sha256": self.compiled_program_sha256,
            "completion": self.completion,
            "rights_ref": self.rights_ref,
            "distribution": self.distribution,
        }
        if self.source_reset_receipt_sha256 is not None:
            payload["source_reset_receipt_sha256"] = self.source_reset_receipt_sha256
        return payload

    @classmethod
    def from_dict(cls, value: Any) -> GroundingMeasurement:
        raw = _strict_shape(
            value,
            required=frozenset(
                {
                    "schema_version",
                    "measurement_id",
                    "provider_id",
                    "provider_version",
                    "program_id",
                    "observed_at",
                    "capture_sha256",
                    "connector_sha256",
                    "recipe_sha256",
                    "harvest_engine_sha256",
                    "compiled_program_sha256",
                    "completion",
                    "rights_ref",
                    "distribution",
                }
            ),
            optional=frozenset({"source_reset_receipt_sha256"}),
            field_name="measurement",
        )
        return cls(**raw)


class DifferentialProgramTarget(Protocol):
    target_id: str
    target_version: str

    def reset(self, seed: int) -> None: ...

    def execute(
        self,
        call: ReferenceCall,
        *,
        principal_context_id: str,
    ) -> ObservedResponse: ...


ProgramRunner = Callable[[DifferentialProgramTarget], ConformanceReport]


@dataclass(frozen=True)
class DifferentialProgramBinding:
    """Immutable identity plus an injected binding-aware offline executor."""

    program_id: str
    provider_id: str
    provider_version: str
    trace_schema_id: str
    trace_digest: str
    connector_sha256: str
    recipe_sha256: str
    harvest_engine_sha256: str
    compiled_program_sha256: str
    seed: int
    profile_id: str
    runner: ProgramRunner = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        for name in ("program_id", "provider_id", "trace_schema_id", "profile_id"):
            object.__setattr__(self, name, _identifier(getattr(self, name), field_name=name))
        object.__setattr__(
            self,
            "provider_version",
            _string(self.provider_version, field_name="provider_version"),
        )
        object.__setattr__(
            self,
            "trace_digest",
            _digest(self.trace_digest, field_name="trace_digest"),
        )
        for name in (
            "connector_sha256",
            "recipe_sha256",
            "harvest_engine_sha256",
            "compiled_program_sha256",
        ):
            object.__setattr__(self, name, _digest(getattr(self, name), field_name=name))
        if type(self.seed) is not int:
            _fail(
                "provider_differential_seed_invalid",
                "seed must be an integer.",
            )
        if not callable(self.runner):
            _fail(
                "provider_differential_runner_invalid",
                "runner must be callable.",
            )


@dataclass(frozen=True)
class DifferentialRunEvidence:
    phase: str
    status: str
    passed: bool
    reset_generation: int
    initial_state_sha256: str | None
    final_state_sha256: str | None
    behavioral_fingerprint: str | None
    report: Mapping[str, Any] | None
    error: Mapping[str, Any] | None

    def __post_init__(self) -> None:
        if self.phase not in _RUN_PHASES:
            _fail("provider_differential_run_phase_invalid", "Run phase is invalid.")
        if self.status not in {"completed", "failed"}:
            _fail("provider_differential_run_status_invalid", "Run status is invalid.")
        if type(self.passed) is not bool:
            _fail("provider_differential_run_passed_invalid", "Run passed must be boolean.")
        if type(self.reset_generation) is not int or self.reset_generation < 0:
            _fail(
                "provider_differential_reset_generation_invalid",
                "reset_generation must be a non-negative integer.",
            )
        for name in (
            "initial_state_sha256",
            "final_state_sha256",
            "behavioral_fingerprint",
        ):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _digest(value, field_name=name))
        report = None
        if self.report is not None:
            try:
                parsed_report = ConformanceReport.from_dict(dict(self.report))
            except Exception as error:
                raise ProviderDifferentialError(
                    "provider_differential_report_invalid",
                    "run.report must be a strict ConformanceReport.",
                ) from error
            report = freeze_json(parsed_report.to_dict(), path="run.report")
        error = None if self.error is None else freeze_json(self.error, path="run.error")
        if report is not None and not isinstance(report, Mapping):
            _fail("provider_differential_shape_invalid", "run.report must be an object.")
        if error is not None and not isinstance(error, Mapping):
            _fail("provider_differential_shape_invalid", "run.error must be an object.")
        if self.status == "completed":
            if (
                report is None
                or error is not None
                or self.initial_state_sha256 is None
                or self.final_state_sha256 is None
                or self.behavioral_fingerprint is None
            ):
                _fail(
                    "provider_differential_run_evidence_invalid",
                    "A completed run requires state, fingerprint, and report evidence.",
                )
            if bool(report.get("passed")) is not self.passed:
                _fail(
                    "provider_differential_run_evidence_invalid",
                    "Run passed must equal report.passed.",
                )
        elif self.passed or report is not None or error is None:
            _fail(
                "provider_differential_run_evidence_invalid",
                "A failed run requires only structured error evidence.",
            )
        object.__setattr__(self, "report", report)
        object.__setattr__(self, "error", error)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase,
            "status": self.status,
            "passed": self.passed,
            "reset_generation": self.reset_generation,
            "initial_state_sha256": self.initial_state_sha256,
            "final_state_sha256": self.final_state_sha256,
            "behavioral_fingerprint": self.behavioral_fingerprint,
            "report": None if self.report is None else thaw_json(self.report),
            "error": None if self.error is None else thaw_json(self.error),
        }

    @classmethod
    def from_dict(cls, value: Any) -> DifferentialRunEvidence:
        raw = _strict_shape(
            value,
            required=frozenset(
                {
                    "phase",
                    "status",
                    "passed",
                    "reset_generation",
                    "initial_state_sha256",
                    "final_state_sha256",
                    "behavioral_fingerprint",
                    "report",
                    "error",
                }
            ),
            field_name="run",
        )
        return cls(**raw)


@dataclass(frozen=True)
class ProviderDifferentialAttestation:
    attestation_id: str
    observed_at: str
    provider_id: str
    provider_version: str
    program_id: str
    measurement_sha256: str
    source: Mapping[str, str]
    replica: Mapping[str, str]
    comparison_profile: str
    program: Mapping[str, Any]
    runs: Mapping[str, DifferentialRunEvidence]
    functional_reset: Mapping[str, bool]
    passed: bool
    schema_version: str = DIFFERENTIAL_ATTESTATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != DIFFERENTIAL_ATTESTATION_SCHEMA_VERSION:
            _fail(
                "provider_differential_attestation_schema_unsupported",
                "Unsupported provider differential attestation schema.",
            )
        for name in ("attestation_id", "provider_id", "program_id", "comparison_profile"):
            object.__setattr__(self, name, _identifier(getattr(self, name), field_name=name))
        object.__setattr__(
            self,
            "provider_version",
            _string(self.provider_version, field_name="provider_version"),
        )
        object.__setattr__(
            self,
            "observed_at",
            _utc_timestamp(self.observed_at, field_name="observed_at"),
        )
        object.__setattr__(
            self,
            "measurement_sha256",
            _digest(self.measurement_sha256, field_name="measurement_sha256"),
        )
        source = _strict_shape(
            dict(self.source),
            required=frozenset(
                {
                    "capture_sha256",
                    "connector_sha256",
                    "recipe_sha256",
                    "harvest_engine_sha256",
                    "compiled_program_sha256",
                }
            ),
            field_name="attestation.source",
        )
        for name, value in source.items():
            source[name] = _digest(value, field_name=f"source.{name}")
        replica = _strict_shape(
            dict(self.replica),
            required=frozenset(
                {
                    "release_reference",
                    "release_manifest_sha256",
                    "profile_id",
                    "provider_runtime_sha256",
                    "provider_admission_sha256",
                }
            ),
            field_name="attestation.replica",
        )
        replica["release_reference"] = _string(
            replica["release_reference"], field_name="replica.release_reference"
        )
        replica["profile_id"] = _identifier(replica["profile_id"], field_name="replica.profile_id")
        for name in (
            "release_manifest_sha256",
            "provider_runtime_sha256",
            "provider_admission_sha256",
        ):
            replica[name] = _digest(replica[name], field_name=f"replica.{name}")
        program = _strict_shape(
            dict(self.program),
            required=frozenset(
                {"trace_schema_id", "trace_digest", "compiled_program_sha256", "seed"}
            ),
            field_name="attestation.program",
        )
        program["trace_schema_id"] = _identifier(
            program["trace_schema_id"], field_name="program.trace_schema_id"
        )
        program["trace_digest"] = _digest(
            program["trace_digest"], field_name="program.trace_digest"
        )
        program["compiled_program_sha256"] = _digest(
            program["compiled_program_sha256"],
            field_name="program.compiled_program_sha256",
        )
        if type(program["seed"]) is not int:
            _fail("provider_differential_seed_invalid", "program.seed must be an integer.")
        runs = dict(self.runs)
        if set(runs) != _RUN_PHASES or not all(
            isinstance(value, DifferentialRunEvidence) for value in runs.values()
        ):
            _fail(
                "provider_differential_run_set_invalid",
                "Attestation runs must contain exactly the three differential phases.",
            )
        if any(key != value.phase for key, value in runs.items()):
            _fail(
                "provider_differential_run_set_invalid",
                "Attestation run keys must equal their phase.",
            )
        for run in runs.values():
            if run.status != "completed":
                continue
            if run.report is None:
                _fail(
                    "provider_differential_run_evidence_invalid",
                    "Completed run report is absent.",
                    phase=run.phase,
                )
            report = run.report
            report_expected = {
                "trace_schema_id": program["trace_schema_id"],
                "trace_digest": program["trace_digest"],
                "provider_id": self.provider_id,
                "provider_version": self.provider_version,
                "target_id": replica["release_manifest_sha256"],
                "target_version": replica["release_reference"],
                "profile_id": self.comparison_profile,
                "seed": program["seed"],
            }
            if any(report[name] != expected for name, expected in report_expected.items()):
                _fail(
                    "provider_differential_report_binding_mismatch",
                    "Run report does not bind the attestation inputs.",
                    phase=run.phase,
                )
        if program["trace_digest"] != source["capture_sha256"]:
            _fail(
                "provider_differential_input_binding_mismatch",
                "Program trace digest must equal the measured capture digest.",
            )
        if program["compiled_program_sha256"] != source["compiled_program_sha256"]:
            _fail(
                "provider_differential_input_binding_mismatch",
                "Program artifact digest must equal the measured compiled-program digest.",
            )
        if not replica["release_reference"].startswith(self.provider_id + "@"):
            _fail(
                "provider_differential_release_binding_mismatch",
                "Release reference provider does not match the attestation provider.",
            )
        functional_reset = _strict_shape(
            dict(self.functional_reset),
            required=frozenset(
                {"within_instance_equivalent", "fresh_instance_equivalent", "passed"}
            ),
            field_name="attestation.functional_reset",
        )
        if any(type(value) is not bool for value in functional_reset.values()):
            _fail(
                "provider_differential_functional_reset_invalid",
                "Functional reset fields must be boolean.",
            )
        expected_reset_passed = (
            functional_reset["within_instance_equivalent"]
            and functional_reset["fresh_instance_equivalent"]
        )
        if functional_reset["passed"] is not expected_reset_passed:
            _fail(
                "provider_differential_functional_reset_invalid",
                "Functional reset passed is inconsistent.",
            )
        expected_passed = functional_reset["passed"] and all(
            run.status == "completed" and run.passed for run in runs.values()
        )
        if type(self.passed) is not bool or self.passed is not expected_passed:
            _fail(
                "provider_differential_attestation_passed_invalid",
                "Attestation passed is inconsistent with its run evidence.",
            )
        object.__setattr__(self, "source", MappingProxyType(source))
        object.__setattr__(self, "replica", MappingProxyType(replica))
        object.__setattr__(self, "program", MappingProxyType(program))
        object.__setattr__(self, "runs", MappingProxyType(runs))
        object.__setattr__(self, "functional_reset", MappingProxyType(functional_reset))

    @property
    def sha256(self) -> str:
        return canonical_json_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attestation_id": self.attestation_id,
            "observed_at": self.observed_at,
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "program_id": self.program_id,
            "measurement_sha256": self.measurement_sha256,
            "source": dict(self.source),
            "replica": dict(self.replica),
            "comparison_profile": self.comparison_profile,
            "program": dict(self.program),
            "runs": {phase: self.runs[phase].to_dict() for phase in sorted(self.runs)},
            "functional_reset": dict(self.functional_reset),
            "passed": self.passed,
        }

    @classmethod
    def from_dict(cls, value: Any) -> ProviderDifferentialAttestation:
        raw = _strict_shape(
            value,
            required=frozenset(
                {
                    "schema_version",
                    "attestation_id",
                    "observed_at",
                    "provider_id",
                    "provider_version",
                    "program_id",
                    "measurement_sha256",
                    "source",
                    "replica",
                    "comparison_profile",
                    "program",
                    "runs",
                    "functional_reset",
                    "passed",
                }
            ),
            field_name="attestation",
        )
        runs = raw["runs"]
        if type(runs) is not dict:
            _fail("provider_differential_shape_invalid", "attestation.runs must be an object.")
        return cls(
            **{
                **raw,
                "runs": {
                    phase: DifferentialRunEvidence.from_dict(run) for phase, run in runs.items()
                },
            }
        )


def load_grounding_measurement(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> GroundingMeasurement:
    payload, digest = _load_json(path)
    if expected_sha256 is not None and digest != _digest(
        expected_sha256, field_name="expected_sha256"
    ):
        _fail(
            "provider_grounding_measurement_digest_mismatch",
            "Grounding measurement does not match its expected digest.",
            expected=expected_sha256,
            actual=digest,
        )
    return GroundingMeasurement.from_dict(payload)


def load_differential_attestation(
    path: Path,
    *,
    expected_sha256: str | None = None,
) -> ProviderDifferentialAttestation:
    payload, digest = _load_json(path)
    if expected_sha256 is not None and digest != _digest(
        expected_sha256, field_name="expected_sha256"
    ):
        _fail(
            "provider_differential_attestation_digest_mismatch",
            "Differential attestation does not match its expected digest.",
            expected=expected_sha256,
            actual=digest,
        )
    return ProviderDifferentialAttestation.from_dict(payload)


def write_differential_attestation(
    path: Path,
    attestation: ProviderDifferentialAttestation,
) -> str:
    """Atomically publish canonical evidence without replacing an existing path."""

    if not isinstance(attestation, ProviderDifferentialAttestation):
        _fail(
            "provider_differential_attestation_invalid",
            "attestation must be a ProviderDifferentialAttestation.",
        )
    if not path.parent.is_dir() or path.parent.is_symlink():
        _fail(
            "provider_differential_output_parent_invalid",
            "Attestation output parent must be an existing regular directory.",
            path=str(path.parent),
        )
    if path.exists() or path.is_symlink():
        _fail(
            "provider_differential_output_exists",
            "Attestation output already exists.",
            path=str(path),
        )
    parent = path.parent.resolve(strict=True)
    destination = parent / path.name
    payload = canonical_json_bytes(attestation.to_dict())
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".datalox-differential-attestation-",
        dir=parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        try:
            os.link(temporary, destination)
        except FileExistsError as error:
            raise ProviderDifferentialError(
                "provider_differential_output_exists",
                "Attestation output already exists.",
                {"path": str(destination)},
            ) from error
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        temporary.unlink(missing_ok=True)
    return attestation.sha256


def _load_json(path: Path) -> tuple[dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        _fail(
            "provider_differential_artifact_unreadable",
            "Differential artifact must be a regular file.",
            path=str(path),
        )
    body = path.read_bytes()
    if len(body) > 8 * 1024 * 1024:
        _fail(
            "provider_differential_artifact_too_large",
            "Differential artifact exceeds the 8 MiB limit.",
            path=str(path),
        )
    try:
        value = json.loads(body, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProviderDifferentialError(
            "provider_differential_json_invalid",
            "Differential artifact is not valid UTF-8 JSON.",
            {"path": str(path)},
        ) from error
    if type(value) is not dict:
        _fail(
            "provider_differential_shape_invalid",
            "Differential artifact must be an object.",
            path=str(path),
        )
    return value, canonical_json_sha256(value)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            _fail(
                "provider_differential_json_duplicate_key",
                "Differential artifact contains a duplicate JSON key.",
                key=key,
            )
        value[key] = item
    return value
