from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from datalox_gated_runtime.engineering_proof.contracts import (
    DifferentialProgramSpec,
    EngineeringProofContractError,
)
from datalox_gated_runtime.reference import (
    ConformanceProfile,
    ConformanceReport,
    ReferenceTrace,
    SequenceTarget,
    compute_reference_trace_digest,
    run_conformance,
)

DifferentialExecutor = Callable[[SequenceTarget], ConformanceReport]


@dataclass(frozen=True)
class CompiledDifferentialProgram:
    """A validated descriptor plus an in-memory executor.

    Only ``spec`` is serializable. The executor is deliberately absent from
    persisted proof and target specifications.
    """

    spec: DifferentialProgramSpec
    executor: DifferentialExecutor = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.spec, DifferentialProgramSpec):
            raise EngineeringProofContractError("compiled program spec is invalid")
        if not callable(self.executor):
            raise EngineeringProofContractError("compiled program executor is not callable")

    def run(self, target: SequenceTarget) -> ConformanceReport:
        report = self.executor(target)
        if not isinstance(report, ConformanceReport):
            raise EngineeringProofContractError(
                "compiled program executor must return ConformanceReport"
            )
        expected = {
            "trace_schema_id": self.spec.trace_schema_id,
            "trace_digest": self.spec.trace_digest,
            "provider_id": self.spec.provider_id,
            "provider_version": self.spec.provider_version,
            "target_id": target.target_id,
            "target_version": target.target_version,
            "seed": self.spec.seed,
        }
        actual = {field_name: getattr(report, field_name) for field_name in expected}
        mismatched = [
            field_name
            for field_name, expected_value in expected.items()
            if actual[field_name] != expected_value
        ]
        if mismatched:
            raise EngineeringProofContractError(
                "compiled program report identity differs: " + ", ".join(sorted(mismatched))
            )
        return report


def reference_trace_program(
    *,
    program_id: str,
    program_version: str,
    trace: ReferenceTrace,
    profile: ConformanceProfile | None = None,
) -> CompiledDifferentialProgram:
    """Adapt an existing exact reference trace to the neutral proof runner."""

    if not isinstance(trace, ReferenceTrace):
        raise EngineeringProofContractError("reference trace program requires ReferenceTrace")
    spec = DifferentialProgramSpec(
        program_id=program_id,
        program_version=program_version,
        provider_id=trace.provider_id,
        provider_version=trace.provider_version,
        trace_schema_id=trace.schema_id,
        trace_digest=compute_reference_trace_digest(trace),
        seed=trace.seed,
    )
    return CompiledDifferentialProgram(
        spec=spec,
        executor=lambda target: run_conformance(trace, target, profile=profile),
    )
