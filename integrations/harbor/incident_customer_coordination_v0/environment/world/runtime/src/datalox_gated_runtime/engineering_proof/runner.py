from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from datalox_gated_runtime.engineering_proof.contracts import (
    ENGINEERING_PROOF_SCHEMA,
    DifferentialProgram,
    EngineeringProofContractError,
    WorldTargetSpec,
)
from datalox_gated_runtime.engineering_proof.world_target import WorldBundleTraceTarget
from datalox_gated_runtime.reference.contracts import freeze_json, thaw_json
from datalox_gated_runtime.world_v1.admission import (
    AdmissionCallbacks,
    AdmissionReport,
    admit_world,
)
from datalox_gated_runtime.world_v1.admission_runtime import runtime_admission_callbacks

OutputCallback = Callable[[Path], Mapping[str, Any] | None]


@dataclass(frozen=True)
class ProofOutputBuilder:
    output_id: str
    callback: OutputCallback = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self.output_id) is not str
            or not self.output_id
            or not self.output_id[0].isalnum()
            or not all(
                character.isascii() and (character.isalnum() or character in {"-", "_"})
                for character in self.output_id
            )
        ):
            raise EngineeringProofContractError(
                "proof output id must contain only letters, numbers, hyphens, or underscores"
            )
        if not callable(self.callback):
            raise EngineeringProofContractError("proof output callback is not callable")


def run_engineering_proof(
    *,
    program: DifferentialProgram,
    target_spec: WorldTargetSpec,
    env_dir: Path,
    out_dir: Path,
    reference_bindings: Mapping[str, str] | None = None,
    exporters: Sequence[ProofOutputBuilder] = (),
    packagers: Sequence[ProofOutputBuilder] = (),
    admission_callbacks: AdmissionCallbacks | None = None,
) -> dict[str, Any]:
    """Run one compiled program through differential, reset, admission, and outputs."""

    if not isinstance(target_spec, WorldTargetSpec):
        raise EngineeringProofContractError("target_spec must be WorldTargetSpec")
    if not hasattr(program, "spec") or not callable(getattr(program, "run", None)):
        raise EngineeringProofContractError("program does not implement DifferentialProgram")
    _validate_builders(exporters, kind="export")
    _validate_builders(packagers, kind="package")
    destination = out_dir.resolve()
    if destination.exists():
        raise EngineeringProofContractError(f"output directory already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=str(destination.parent)))
    try:
        target = WorldBundleTraceTarget(
            env_dir=env_dir,
            spec=target_spec,
            reference_bindings=reference_bindings,
        )
        try:
            first = _run_differential(program, target)
            first_fingerprint = target.behavioral_fingerprint()
            second = _run_differential(program, target)
            second_fingerprint = target.behavioral_fingerprint()
        finally:
            target.close()
        reset_passed = (
            first["status"] == "completed"
            and second["status"] == "completed"
            and first_fingerprint == second_fingerprint
        )
        admission = _run_admission(
            env_dir,
            callbacks=admission_callbacks or runtime_admission_callbacks(),
        )
        prerequisite_passed = (
            first["passed"] and second["passed"] and reset_passed and admission["passed"]
        )
        package_reports = _run_builders(
            stage=stage,
            category="packages",
            builders=packagers,
            enabled=prerequisite_passed,
        )
        export_reports = _run_builders(
            stage=stage,
            category="exports",
            builders=exporters,
            enabled=prerequisite_passed,
        )
        output_reports = {
            "packages": package_reports,
            "exports": export_reports,
        }
        outputs_passed = all(
            report["passed"] for category in output_reports.values() for report in category.values()
        )
        passed = prerequisite_passed and outputs_passed
        payload = {
            "schema_version": ENGINEERING_PROOF_SCHEMA,
            "passed": passed,
            "program": program.spec.to_dict(),
            "target": target_spec.to_dict(),
            "differential": {
                "passed": first["passed"] and second["passed"],
                "first": first,
                "after_reset": second,
            },
            "functional_reset": {
                "passed": reset_passed,
                "first_behavioral_fingerprint": first_fingerprint,
                "second_behavioral_fingerprint": second_fingerprint,
            },
            "world_admission": admission,
            "outputs": output_reports,
        }
        (stage / "proof.json").write_text(
            json.dumps(payload, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        os.replace(stage, destination)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return {**payload, "out_dir": str(destination)}


def _validate_builders(builders: Sequence[ProofOutputBuilder], *, kind: str) -> None:
    if not all(isinstance(item, ProofOutputBuilder) for item in builders):
        raise EngineeringProofContractError(f"{kind} builders contain an invalid item")
    identifiers = [item.output_id for item in builders]
    if len(identifiers) != len(set(identifiers)):
        raise EngineeringProofContractError(f"{kind} builders contain duplicate output ids")


def _run_differential(
    program: DifferentialProgram,
    target: WorldBundleTraceTarget,
) -> dict[str, Any]:
    reset_generation = target.reset_generation
    try:
        report = program.run(target)
    except Exception as error:
        return {
            "passed": False,
            "status": "failed",
            "error": {"code": "differential_execution_failed", "type": type(error).__name__},
        }
    if target.reset_generation != reset_generation + 1:
        return {
            "passed": False,
            "status": "failed",
            "error": {
                "code": "differential_fresh_reset_required",
                "type": "EngineeringProofContractError",
            },
        }
    return {"status": "completed", **report.to_dict()}


def _run_admission(env_dir: Path, *, callbacks: AdmissionCallbacks) -> dict[str, Any]:
    try:
        report = admit_world(env_dir, callbacks=callbacks)
    except Exception as error:
        return {
            "passed": False,
            "status": "failed",
            "error": {"code": "world_admission_failed", "type": type(error).__name__},
        }
    return _portable_admission(report)


def _portable_admission(report: AdmissionReport) -> dict[str, Any]:
    return {
        "passed": report.admitted,
        "status": "completed",
        "world_id": report.world_id,
        "bundle_version": report.bundle_version,
        "artifact_hashes": dict(sorted(report.artifact_hashes.items())),
        "checks": report.checks,
        "findings": [finding.to_dict() for finding in report.findings],
    }


def _run_builders(
    *,
    stage: Path,
    category: str,
    builders: Sequence[ProofOutputBuilder],
    enabled: bool,
) -> dict[str, dict[str, Any]]:
    reports: dict[str, dict[str, Any]] = {}
    for builder in sorted(builders, key=lambda item: item.output_id):
        relative = Path("artifacts") / category / builder.output_id
        if not enabled:
            reports[builder.output_id] = {
                "passed": False,
                "status": "skipped",
                "reason_code": "proof_prerequisite_failed",
                "path": relative.as_posix(),
            }
            continue
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            metadata = builder.callback(destination)
            if not destination.is_dir() or not any(destination.iterdir()):
                raise EngineeringProofContractError(
                    "proof output callback must create a non-empty directory"
                )
            normalized_metadata = _normalize_metadata(metadata)
            reports[builder.output_id] = {
                "passed": True,
                "status": "completed",
                "path": relative.as_posix(),
                "content_digest": _tree_digest(destination),
                "metadata": normalized_metadata,
            }
        except Exception as error:
            shutil.rmtree(destination, ignore_errors=True)
            reports[builder.output_id] = {
                "passed": False,
                "status": "failed",
                "path": relative.as_posix(),
                "error": {"code": "proof_output_failed", "type": type(error).__name__},
            }
    return reports


def _normalize_metadata(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise EngineeringProofContractError("proof output metadata must be an object")
    frozen = freeze_json(value, path="proof.output.metadata")
    result = thaw_json(frozen)
    if not isinstance(result, dict):
        raise EngineeringProofContractError("proof output metadata must be an object")
    return result


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    entries = sorted(root.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise EngineeringProofContractError("proof output must not contain symbolic links")
    if any(not path.is_file() and not path.is_dir() for path in entries):
        raise EngineeringProofContractError("proof output contains a special filesystem entry")
    files = [path for path in entries if path.is_file()]
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        body = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(mode.to_bytes(2, "big"))
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return "sha256:" + digest.hexdigest()
