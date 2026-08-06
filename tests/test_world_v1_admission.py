from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from datalox_gated_runtime.world_v1.admission import (
    AdmissionCallbacks,
    ParityOutcome,
    TrajectoryOutcome,
    admit_world,
    write_admission_artifact,
)
from datalox_gated_runtime.world_v1.bundle import compute_bundle_hashes


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _bundle(tmp_path: Path) -> Path:
    root = tmp_path / "example_world"
    (root / "world").mkdir(parents=True)
    (root / "world" / "implementation.py").write_text(
        """from datalox_gated_runtime.world_v1.contracts import WorldImplementationV1


class ExampleWorld(WorldImplementationV1):
    def initialize_episode(self, *, session, episode):
        return None

    def handle(self, request, *, actor, session):
        return None

    def tool_schemas(self, *, actor):
        return {}

    def request_for_tool(self, tool_name, arguments, *, actor):
        raise KeyError(tool_name)

    def operation_for_tool(self, tool_name):
        return None

    def verify(self, *, session, episode):
        raise NotImplementedError

    def task(self, *, episode):
        return None


def create_world():
    return ExampleWorld()
""",
        encoding="utf-8",
    )
    (root / "world" / "episodes.jsonl").write_text(
        json.dumps(
            {
                "id": "episode-1",
                "task": {"instructions": "Review the selected case."},
                "agent_visible_state": {"case_id": "case-1"},
                "hidden": {"expected_values": ["private-outcome-17"]},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    _write_json(
        root / "world" / "roles.json",
        {"roles": [{"id": "reviewer", "description": "Reviews a case."}]},
    )
    _write_json(
        root / "world" / "tools.json",
        {
            "tools": [
                {
                    "id": "case.get",
                    "description": "Read one case.",
                    "list_roles": ["reviewer"],
                    "invoke_roles": ["reviewer"],
                    "input_schema": {"type": "object"},
                    "source_refs": ["source-1"],
                    "operation_family": "case_management",
                }
            ]
        },
    )
    _write_json(
        root / "world" / "sources.json",
        {
            "sources": [
                {
                    "id": "source-1",
                    "kind": "official_openapi",
                    "locator": "spec.json#sha256=abc",
                    "grounding_level": "G1",
                    "derivation": "Shape copied from the pinned schema.",
                    "supports": ["case.get.response_shape"],
                }
            ],
            "grounding_gaps": [
                {
                    "operation_family": "case_management",
                    "claim": "provider rate-limit timing",
                    "reason": "No sandbox or captured evidence.",
                }
            ],
        },
    )
    _write_json(
        root / "world" / "verifier.json",
        {"assertions": [], "hidden_expected_values": []},
    )
    _write_json(
        root / "tests" / "trajectories" / "admission.json",
        {
            "trajectories": [
                {
                    "id": "reference-1",
                    "kind": "reference",
                    "episode_id": "episode-1",
                    "steps": [],
                    "expected": {"passed": True, "failure_codes": []},
                },
                {
                    "id": "negative-1",
                    "kind": "negative",
                    "episode_id": "episode-1",
                    "steps": [],
                    "expected": {"passed": False, "failure_codes": ["required_read_missing"]},
                },
                {
                    "id": "parity-1",
                    "kind": "parity",
                    "episode_id": "episode-1",
                    "http_steps": [],
                    "mcp_steps": [],
                },
            ]
        },
    )
    manifest = {
        "schema_version": "datalox_world_bundle_v1",
        "world_id": "example_world",
        "bundle_version": "1.0.0",
        "implementation": "world/implementation.py:create_world",
        "episodes_path": "world/episodes.jsonl",
        "roles_path": "world/roles.json",
        "tools_path": "world/tools.json",
        "verifier_path": "world/verifier.json",
        "sources_path": "world/sources.json",
        "default_actor_role": "reviewer",
        "required_runtime_capabilities": ["actors"],
        "trajectory_paths": ["tests/trajectories/admission.json"],
        "content_hashes": compute_bundle_hashes(root),
    }
    _write_json(root / "world" / "manifest.json", manifest)
    return root


def _callbacks() -> AdmissionCallbacks:
    def run_trajectory(_root: Path, trajectory: dict[str, Any]) -> TrajectoryOutcome:
        if trajectory["kind"] == "reference":
            return TrajectoryOutcome(passed=True)
        return TrajectoryOutcome(passed=False, failure_codes=("required_read_missing",))

    return AdmissionCallbacks(
        reset_fingerprint=lambda _root, episode_id: f"reset:{episode_id}",
        run_trajectory=run_trajectory,
        run_parity=lambda _root, _case: ParityOutcome(
            matched=True,
            http_fingerprint="same",
            mcp_fingerprint="same",
        ),
        export_session=lambda _root: {"ok": True, "export_path": "run_export.json"},
    )


def test_admission_accepts_grounded_bundle_and_writes_derived_artifact(tmp_path: Path) -> None:
    root = _bundle(tmp_path)

    report = admit_world(
        root,
        callbacks=_callbacks(),
        admitted_at="2026-07-17T00:00:00+00:00",
    )

    assert report.admitted is True
    assert all(item["passed"] for item in report.checks.values())
    assert report.coverage == {
        "role_count": 1,
        "tool_count": 1,
        "episode_count": 1,
        "trajectory_count": 3,
        "reference_trajectory_count": 1,
        "negative_trajectory_count": 1,
        "parity_case_count": 1,
        "operation_families": ["case_management"],
    }
    assert report.provenance["grounding_gaps"] == [
        {
            "operation_family": "case_management",
            "claim": "provider rate-limit timing",
            "reason": "No sandbox or captured evidence.",
        }
    ]
    artifact = write_admission_artifact(report)
    payload = json.loads(artifact.read_text(encoding="utf-8"))
    assert payload["admitted"] is True
    assert payload["artifact_hashes"] == report.artifact_hashes


def test_broken_bundle_reports_independent_actionable_findings(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    roles = json.loads((root / "world" / "roles.json").read_text(encoding="utf-8"))
    roles["roles"][0]["id"] = "auditor"
    _write_json(root / "world" / "roles.json", roles)
    sources = json.loads((root / "world" / "sources.json").read_text(encoding="utf-8"))
    sources["sources"][0].update({"grounding_level": "G9", "api_key": "persisted-secret"})
    _write_json(root / "world" / "sources.json", sources)
    episode = {
        "id": "episode-1",
        "task": {"instructions": "Return private-outcome-17."},
        "agent_visible_state": {"case_id": "case-1"},
        "hidden": {"expected_values": ["private-outcome-17"]},
    }
    (root / "world" / "episodes.jsonl").write_text(json.dumps(episode) + "\n", encoding="utf-8")
    manifest_path = root / "world" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["content_hashes"] = compute_bundle_hashes(root)
    _write_json(manifest_path, manifest)

    report = admit_world(root)
    codes = {finding.code for finding in report.findings}

    assert report.admitted is False
    assert "world_admission_grounding_level_invalid" in codes
    assert "world_admission_default_role_unknown" in codes
    assert "world_admission_tool_role_unknown" in codes
    assert "world_admission_hidden_value_leaked" in codes
    assert "world_admission_credential_requirement" in codes
    assert "world_admission_execution_blocked" in codes


def test_negative_trajectory_must_fail_for_exact_declared_code(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    callbacks = _callbacks()
    callbacks = AdmissionCallbacks(
        reset_fingerprint=callbacks.reset_fingerprint,
        run_trajectory=lambda _root, trajectory: (
            TrajectoryOutcome(passed=True)
            if trajectory["kind"] == "reference"
            else TrajectoryOutcome(passed=False, failure_codes=("wrong_failure",))
        ),
        run_parity=callbacks.run_parity,
        export_session=callbacks.export_session,
    )

    report = admit_world(root, callbacks=callbacks)

    finding = next(
        item
        for item in report.findings
        if item.code == "world_admission_trajectory_outcome_mismatch"
    )
    assert finding.context["expected_failure_codes"] == ["required_read_missing"]
    assert finding.context["actual_failure_codes"] == ["wrong_failure"]


def test_admission_rejects_environment_credentials_and_live_write_code(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    implementation_path = root / "world" / "implementation.py"
    implementation_path.write_text(
        "import os\n"
        + implementation_path.read_text(encoding="utf-8").replace(
            "return ExampleWorld()",
            "mode = 'live_write'\n    os.getenv('PROVIDER_TOKEN')\n    return ExampleWorld()",
        ),
        encoding="utf-8",
    )
    manifest_path = root / "world" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["content_hashes"] = compute_bundle_hashes(root)
    _write_json(manifest_path, manifest)

    report = admit_world(root, callbacks=_callbacks())
    codes = {finding.code for finding in report.findings}

    assert "world_admission_credential_requirement" in codes
    assert "world_admission_live_write_expressible" in codes


def test_admission_scans_imported_python_modules_for_credential_and_live_write_code(
    tmp_path: Path,
) -> None:
    root = _bundle(tmp_path)
    (root / "world" / "support.py").write_text(
        "from os import getenv\nMODE = 'live_write'\nTOKEN = getenv('PROVIDER_TOKEN')\n",
        encoding="utf-8",
    )
    manifest_path = root / "world" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["content_hashes"] = compute_bundle_hashes(root)
    _write_json(manifest_path, manifest)

    report = admit_world(root, callbacks=_callbacks())
    findings = {(finding.code, finding.path) for finding in report.findings}

    assert (
        "world_admission_credential_requirement",
        "world/support.py",
    ) in findings
    assert (
        "world_admission_live_write_expressible",
        "world/support.py",
    ) in findings


def test_admission_rejects_factory_that_does_not_return_exact_protocol(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    (root / "world" / "implementation.py").write_text(
        "def create_world():\n    return object()\n", encoding="utf-8"
    )
    manifest_path = root / "world" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["content_hashes"] = compute_bundle_hashes(root)
    _write_json(manifest_path, manifest)

    report = admit_world(root, callbacks=_callbacks())
    codes = {finding.code for finding in report.findings}

    assert report.admitted is False
    assert "world_bundle_protocol_invalid" in codes
    assert "world_admission_execution_blocked" in codes
