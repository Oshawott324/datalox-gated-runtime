from __future__ import annotations

from dataclasses import dataclass

import pytest

from datalox_gated_runtime.world_v1.semantic_verifier import (
    SemanticRubric,
    SemanticVerifierInput,
    verify_composite,
)
from datalox_gated_runtime.world_v1.verifier_assertions import (
    AssertionResult,
    DeterministicVerificationResult,
)


PASSING_DETERMINISTIC = DeterministicVerificationResult(True, (), ())
FAILING_DETERMINISTIC = DeterministicVerificationResult(
    False,
    (
        AssertionResult(
            ok=False,
            failure_code="wrong_amount",
            message="Refund amount is wrong.",
            evidence_refs=("state:refund#/amount",),
        ),
    ),
    ("wrong_amount",),
)
RUBRICS = (SemanticRubric("clarity", "The customer update must be clear."),)
ALLOWED_EVIDENCE = {"artifact:draft-1": {"text": "Clear update"}}


@dataclass
class FakeSemanticVerifier:
    response: object
    calls: int = 0
    last_input: SemanticVerifierInput | None = None

    def verify(self, verifier_input: SemanticVerifierInput) -> object:
        self.calls += 1
        self.last_input = verifier_input
        return self.response


class ExplodingSemanticVerifier:
    def verify(self, verifier_input: SemanticVerifierInput) -> object:
        raise RuntimeError("provider unavailable")


def _response(*, passed: bool = True, refs=None, rubric_id: str = "clarity") -> dict:
    return {
        "verdicts": [
            {
                "rubric_id": rubric_id,
                "passed": passed,
                "message": "The artifact is clear." if passed else "The artifact is unclear.",
                "evidence_refs": ["artifact:draft-1"] if refs is None else refs,
            }
        ],
        "provenance": {
            "implementation": "semantic-reviewer-v1",
            "model": "cheap-test-model",
            "prompt": "sha256:prompt",
        },
    }


def test_no_rubrics_skip_semantic_verifier_entirely() -> None:
    verifier = FakeSemanticVerifier(_response())

    result = verify_composite(
        deterministic=PASSING_DETERMINISTIC,
        rubrics=(),
        sanitized_workspace={},
        allowed_evidence={},
        semantic_verifier=verifier,
    )

    assert verifier.calls == 0
    assert result.passed is True
    assert result.semantic.enabled is False
    assert result.semantic.provenance is None


def test_semantic_pass_records_provenance_and_allowed_evidence() -> None:
    verifier = FakeSemanticVerifier(_response())

    result = verify_composite(
        deterministic=PASSING_DETERMINISTIC,
        rubrics=RUBRICS,
        sanitized_workspace={"artifact": "sanitized text"},
        allowed_evidence=ALLOWED_EVIDENCE,
        semantic_verifier=verifier,
    )

    assert result.passed is True
    assert verifier.calls == 1
    assert verifier.last_input is not None
    assert verifier.last_input.allowed_evidence == ALLOWED_EVIDENCE
    assert result.semantic.provenance is not None
    assert result.semantic.provenance.model == "cheap-test-model"
    assert result.to_dict() == {
        "passed": True,
        "deterministic": {
            "passed": True,
            "assertions": [],
            "failure_codes": [],
        },
        "semantic": {
            "enabled": True,
            "passed": True,
            "verdicts": [
                {
                    "rubric_id": "clarity",
                    "passed": True,
                    "failure_code": None,
                    "message": "The artifact is clear.",
                    "evidence_refs": ["artifact:draft-1"],
                }
            ],
            "failure_codes": [],
            "provenance": {
                "implementation": "semantic-reviewer-v1",
                "model": "cheap-test-model",
                "prompt": "sha256:prompt",
            },
        },
    }


def test_semantic_failure_cannot_hide_deterministic_failure() -> None:
    verifier = FakeSemanticVerifier(_response(passed=False))

    result = verify_composite(
        deterministic=FAILING_DETERMINISTIC,
        rubrics=RUBRICS,
        sanitized_workspace={},
        allowed_evidence=ALLOWED_EVIDENCE,
        semantic_verifier=verifier,
    )

    assert result.passed is False
    assert result.deterministic.failure_codes == ("wrong_amount",)
    assert result.semantic.failure_codes == ("semantic_rubric_failed",)


def test_semantic_pass_cannot_override_deterministic_failure() -> None:
    result = verify_composite(
        deterministic=FAILING_DETERMINISTIC,
        rubrics=RUBRICS,
        sanitized_workspace={},
        allowed_evidence=ALLOWED_EVIDENCE,
        semantic_verifier=FakeSemanticVerifier(_response()),
    )

    assert result.passed is False
    assert result.deterministic.to_dict() == FAILING_DETERMINISTIC.to_dict()
    assert result.semantic.passed is True


@pytest.mark.parametrize(
    ("response", "failure_code"),
    [
        ({}, "semantic_verifier_malformed"),
        ({"verdicts": [], "provenance": {}}, "semantic_verifier_malformed"),
        (
            {
                "verdicts": [],
                "provenance": {
                    "implementation": "v1",
                    "model": "model",
                    "prompt": "prompt",
                },
            },
            "semantic_verdict_missing",
        ),
        (_response(refs=[]), "semantic_verdict_uncited"),
        (_response(refs=["artifact:secret"]), "semantic_verdict_disallowed_evidence"),
        (_response(rubric_id="undeclared"), "semantic_verifier_malformed"),
    ],
)
def test_missing_malformed_and_uncited_verdicts_fail_closed(
    response: object, failure_code: str
) -> None:
    result = verify_composite(
        deterministic=PASSING_DETERMINISTIC,
        rubrics=RUBRICS,
        sanitized_workspace={},
        allowed_evidence=ALLOWED_EVIDENCE,
        semantic_verifier=FakeSemanticVerifier(response),
    )

    assert result.passed is False
    assert failure_code in result.semantic.failure_codes


def test_missing_or_crashing_verifier_fails_closed() -> None:
    unavailable = verify_composite(
        deterministic=PASSING_DETERMINISTIC,
        rubrics=RUBRICS,
        sanitized_workspace={},
        allowed_evidence=ALLOWED_EVIDENCE,
        semantic_verifier=None,
    )
    crashed = verify_composite(
        deterministic=PASSING_DETERMINISTIC,
        rubrics=RUBRICS,
        sanitized_workspace={},
        allowed_evidence=ALLOWED_EVIDENCE,
        semantic_verifier=ExplodingSemanticVerifier(),
    )

    assert unavailable.semantic.failure_codes == ("semantic_verifier_unavailable",)
    assert crashed.semantic.failure_codes == ("semantic_verifier_error",)


def test_duplicate_rubric_ids_are_rejected_before_verifier_call() -> None:
    verifier = FakeSemanticVerifier(_response())

    with pytest.raises(ValueError, match="unique"):
        verify_composite(
            deterministic=PASSING_DETERMINISTIC,
            rubrics=(SemanticRubric("same", "One"), SemanticRubric("same", "Two")),
            sanitized_workspace={},
            allowed_evidence=ALLOWED_EVIDENCE,
            semantic_verifier=verifier,
        )

    assert verifier.calls == 0


def test_verifier_receives_json_copy_not_authoritative_workspace() -> None:
    workspace = {"artifact": {"text": "original"}}

    class MutatingVerifier:
        def verify(self, verifier_input: SemanticVerifierInput) -> object:
            assert isinstance(verifier_input.sanitized_workspace, dict)
            verifier_input.sanitized_workspace["artifact"]["text"] = "mutated"
            return _response()

    result = verify_composite(
        deterministic=PASSING_DETERMINISTIC,
        rubrics=RUBRICS,
        sanitized_workspace=workspace,
        allowed_evidence=ALLOWED_EVIDENCE,
        semantic_verifier=MutatingVerifier(),
    )

    assert result.passed is True
    assert workspace == {"artifact": {"text": "original"}}
