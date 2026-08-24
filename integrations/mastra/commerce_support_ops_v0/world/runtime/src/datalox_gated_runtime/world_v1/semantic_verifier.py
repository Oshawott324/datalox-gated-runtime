from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping, Protocol, Sequence

from datalox_gated_runtime.world_v1.verifier_assertions import (
    DeterministicVerificationResult,
    JsonValue,
)


SEMANTIC_FAILURE_CODES = {
    "semantic_verifier_unavailable",
    "semantic_verifier_error",
    "semantic_verifier_malformed",
    "semantic_verdict_missing",
    "semantic_verdict_uncited",
    "semantic_verdict_disallowed_evidence",
    "semantic_rubric_failed",
}


@dataclass(frozen=True)
class SemanticRubric:
    rubric_id: str
    instruction: str

    def __post_init__(self) -> None:
        if not self.rubric_id.strip() or not self.instruction.strip():
            raise ValueError("semantic rubric id and instruction must be non-empty")


@dataclass(frozen=True)
class SemanticVerifierInput:
    sanitized_workspace: JsonValue
    rubrics: tuple[SemanticRubric, ...]
    allowed_evidence: Mapping[str, JsonValue]


class SemanticVerifier(Protocol):
    def verify(self, verifier_input: SemanticVerifierInput) -> object: ...


@dataclass(frozen=True)
class SemanticVerdict:
    rubric_id: str
    passed: bool
    failure_code: str | None
    message: str
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rubric_id": self.rubric_id,
            "passed": self.passed,
            "failure_code": self.failure_code,
            "message": self.message,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class SemanticVerifierProvenance:
    implementation: str
    model: str
    prompt: str

    def to_dict(self) -> dict[str, str]:
        return {
            "implementation": self.implementation,
            "model": self.model,
            "prompt": self.prompt,
        }


@dataclass(frozen=True)
class SemanticVerificationResult:
    enabled: bool
    passed: bool
    verdicts: tuple[SemanticVerdict, ...]
    failure_codes: tuple[str, ...]
    provenance: SemanticVerifierProvenance | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "passed": self.passed,
            "verdicts": [verdict.to_dict() for verdict in self.verdicts],
            "failure_codes": list(self.failure_codes),
            "provenance": self.provenance.to_dict() if self.provenance is not None else None,
        }


@dataclass(frozen=True)
class CompositeVerificationResult:
    passed: bool
    deterministic: DeterministicVerificationResult
    semantic: SemanticVerificationResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "deterministic": self.deterministic.to_dict(),
            "semantic": self.semantic.to_dict(),
        }


def verify_composite(
    *,
    deterministic: DeterministicVerificationResult,
    rubrics: Sequence[SemanticRubric],
    sanitized_workspace: JsonValue,
    allowed_evidence: Mapping[str, JsonValue],
    semantic_verifier: SemanticVerifier | None,
) -> CompositeVerificationResult:
    """Run the optional semantic layer and combine it with deterministic checks.

    Empty rubrics return before touching ``semantic_verifier``.  For enabled
    semantic verification, input is copied through JSON to prevent the verifier
    from mutating authoritative runtime objects.
    """

    rubric_tuple = tuple(rubrics)
    if not rubric_tuple:
        semantic = SemanticVerificationResult(
            enabled=False,
            passed=True,
            verdicts=(),
            failure_codes=(),
            provenance=None,
        )
        return CompositeVerificationResult(
            passed=deterministic.passed,
            deterministic=deterministic,
            semantic=semantic,
        )

    _validate_unique_rubrics(rubric_tuple)
    if semantic_verifier is None:
        semantic = _fail_all(
            rubric_tuple, "semantic_verifier_unavailable", "No semantic verifier is configured."
        )
    else:
        try:
            verifier_input = SemanticVerifierInput(
                sanitized_workspace=_json_copy(sanitized_workspace),
                rubrics=rubric_tuple,
                allowed_evidence=_json_copy(dict(allowed_evidence)),
            )
            response = semantic_verifier.verify(verifier_input)
        except Exception as exc:
            semantic = _fail_all(
                rubric_tuple,
                "semantic_verifier_error",
                f"Semantic verifier failed closed: {type(exc).__name__}.",
            )
        else:
            semantic = _parse_response(response, rubric_tuple, set(allowed_evidence))

    return CompositeVerificationResult(
        passed=deterministic.passed and semantic.passed,
        deterministic=deterministic,
        semantic=semantic,
    )


def _parse_response(
    raw: object,
    rubrics: tuple[SemanticRubric, ...],
    allowed_refs: set[str],
) -> SemanticVerificationResult:
    if not isinstance(raw, Mapping) or set(raw) != {"verdicts", "provenance"}:
        return _fail_all(
            rubrics, "semantic_verifier_malformed", "Semantic response has an invalid root shape."
        )
    provenance = _parse_provenance(raw["provenance"])
    verdict_items = raw["verdicts"]
    if provenance is None or not isinstance(verdict_items, list):
        return _fail_all(
            rubrics,
            "semantic_verifier_malformed",
            "Semantic response has malformed verdicts or provenance.",
        )

    parsed: dict[str, Mapping[str, Any]] = {}
    malformed_ids: set[str] = set()
    for item in verdict_items:
        if not isinstance(item, Mapping) or set(item) != {
            "rubric_id",
            "passed",
            "message",
            "evidence_refs",
        }:
            return _fail_all(
                rubrics,
                "semantic_verifier_malformed",
                "A semantic verdict has an invalid shape.",
                provenance=provenance,
            )
        rubric_id = item["rubric_id"]
        if not isinstance(rubric_id, str) or not rubric_id or rubric_id in parsed:
            return _fail_all(
                rubrics,
                "semantic_verifier_malformed",
                "Semantic verdict ids must be non-empty and unique.",
                provenance=provenance,
            )
        if (
            type(item["passed"]) is not bool
            or not isinstance(item["message"], str)
            or not item["message"].strip()
        ):
            malformed_ids.add(rubric_id)
        refs = item["evidence_refs"]
        if not isinstance(refs, list) or any(not isinstance(ref, str) or not ref for ref in refs):
            malformed_ids.add(rubric_id)
        parsed[rubric_id] = item

    expected_ids = {rubric.rubric_id for rubric in rubrics}
    if set(parsed) - expected_ids:
        return _fail_all(
            rubrics,
            "semantic_verifier_malformed",
            "Semantic response contains an undeclared rubric id.",
            provenance=provenance,
        )

    verdicts: list[SemanticVerdict] = []
    for rubric in rubrics:
        item = parsed.get(rubric.rubric_id)
        if item is None:
            verdicts.append(
                _failed_verdict(
                    rubric.rubric_id, "semantic_verdict_missing", "Semantic verdict is missing."
                )
            )
            continue
        if rubric.rubric_id in malformed_ids:
            verdicts.append(
                _failed_verdict(
                    rubric.rubric_id,
                    "semantic_verifier_malformed",
                    "Semantic verdict is malformed.",
                )
            )
            continue
        refs = tuple(item["evidence_refs"])
        if not refs:
            verdicts.append(
                _failed_verdict(
                    rubric.rubric_id,
                    "semantic_verdict_uncited",
                    "Semantic verdict did not cite evidence.",
                )
            )
            continue
        if not set(refs).issubset(allowed_refs):
            verdicts.append(
                _failed_verdict(
                    rubric.rubric_id,
                    "semantic_verdict_disallowed_evidence",
                    "Semantic verdict cited evidence outside the allowed workspace.",
                    refs,
                )
            )
            continue
        passed = item["passed"]
        verdicts.append(
            SemanticVerdict(
                rubric_id=rubric.rubric_id,
                passed=passed,
                failure_code=None if passed else "semantic_rubric_failed",
                message=item["message"],
                evidence_refs=refs,
            )
        )

    failure_codes = tuple(
        verdict.failure_code for verdict in verdicts if verdict.failure_code is not None
    )
    return SemanticVerificationResult(
        enabled=True,
        passed=not failure_codes,
        verdicts=tuple(verdicts),
        failure_codes=failure_codes,
        provenance=provenance,
    )


def _parse_provenance(raw: object) -> SemanticVerifierProvenance | None:
    if not isinstance(raw, Mapping) or set(raw) != {"implementation", "model", "prompt"}:
        return None
    if any(not isinstance(raw[key], str) or not raw[key].strip() for key in raw):
        return None
    return SemanticVerifierProvenance(
        implementation=raw["implementation"],
        model=raw["model"],
        prompt=raw["prompt"],
    )


def _fail_all(
    rubrics: Sequence[SemanticRubric],
    failure_code: str,
    message: str,
    *,
    provenance: SemanticVerifierProvenance | None = None,
) -> SemanticVerificationResult:
    verdicts = tuple(_failed_verdict(rubric.rubric_id, failure_code, message) for rubric in rubrics)
    return SemanticVerificationResult(
        enabled=True,
        passed=False,
        verdicts=verdicts,
        failure_codes=tuple(verdict.failure_code for verdict in verdicts if verdict.failure_code),
        provenance=provenance,
    )


def _failed_verdict(
    rubric_id: str,
    failure_code: str,
    message: str,
    evidence_refs: Sequence[str] = (),
) -> SemanticVerdict:
    if failure_code not in SEMANTIC_FAILURE_CODES:
        raise ValueError(f"unsupported semantic failure code: {failure_code}")
    return SemanticVerdict(
        rubric_id=rubric_id,
        passed=False,
        failure_code=failure_code,
        message=message,
        evidence_refs=tuple(evidence_refs),
    )


def _validate_unique_rubrics(rubrics: Sequence[SemanticRubric]) -> None:
    ids = [rubric.rubric_id for rubric in rubrics]
    if len(ids) != len(set(ids)):
        raise ValueError("semantic rubric ids must be unique")


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
