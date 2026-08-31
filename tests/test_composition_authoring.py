from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

from test_composition_session import _pack, _release

from datalox_gated_runtime.composition.admission import (
    validate_composition_authoring_inputs,
)
from datalox_gated_runtime.composition.authoring import (
    DEFAULT_CANDIDATE_INITIAL_TIME,
    CandidateCompositionRunner,
    CompositionAuthoringError,
    admit_candidate_composition_pack,
)
from datalox_gated_runtime.cli import main

NOW = datetime(2026, 8, 25, tzinfo=UTC)


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _assertion(assertion_id: str, pointer: str, expected: object) -> dict[str, object]:
    return {
        "assertion_id": assertion_id,
        "source": "exported_evidence",
        "pointer": pointer,
        "operator": "equals",
        "expected_value": expected,
    }


def _cover(kind: str, subject_id: str, behavior: str) -> dict[str, str]:
    return {"subject_kind": kind, "subject_id": subject_id, "behavior": behavior}


def _request(*, event_id: str, stream: str) -> dict[str, object]:
    return {
        "scheme": "https",
        "authority": "api.provider.example",
        "method": "GET",
        "path": "/counter",
        "query": {},
        "headers": {"X-Event-Id": event_id, "X-Order-Key": stream},
        "body": None,
    }


def _claims(release, pack) -> dict[str, object]:
    profile = release.profiles[0]
    return {
        "schema_version": "datalox_composition_operation_claims_v1",
        "pack_id": pack.pack_id,
        "pack_version": pack.pack_version,
        "composition_pack_sha256": pack.canonical_sha256,
        "provider_profiles": [
            {
                "provider_id": release.provider_id,
                "profile_id": profile.profile_id,
                "release_manifest_sha256": release.manifest_descriptor["digest"],
                "provider_runtime_sha256": profile.provider_runtime_sha256,
                "provider_admission_sha256": profile.provider_admission_sha256,
                "operation_contract_sha256": release.config["operation_contract_sha256"],
            }
        ],
        "reset_probe": {
            "expected_result": {
                "composition_delivery_time": DEFAULT_CANDIDATE_INITIAL_TIME,
                "reset": True,
            },
            "assertions": [_assertion("reset_events_empty", "/events/source_events", [])],
        },
        "behavior_probes": [
            {
                "probe_id": "declared_delivery",
                "steps": [
                    {
                        "step_id": "source_read",
                        "action": "agent_http",
                        "provider_id": release.provider_id,
                        "operation_id": "counter.read",
                        "principal_context_id": "fixed",
                        "request": _request(event_id="event-1", stream="stream-1"),
                        "expected_result": {
                            "status_code": 200,
                            "decision_kind": "replay",
                            "headers": {},
                            "body": {"actor_role": "operator", "counter": 1},
                        },
                        "assertions": [
                            _assertion(
                                "source_event_recorded",
                                "/events/source_events/0/provider_event_id",
                                "event-1",
                            )
                        ],
                        "covers": [
                            _cover("source_contract", "counter_observed", "source_emission")
                        ],
                    },
                    {
                        "step_id": "delivery_drain",
                        "action": "controller_drain",
                        "expected_result": {
                            "deliveries": [
                                {
                                    "attempt_number": 1,
                                    "attempt_outcome": "delivered",
                                    "delivery_state": "delivered",
                                    "next_available_at": None,
                                }
                            ],
                            "drained": 1,
                        },
                        "assertions": [
                            _assertion(
                                "target_state_incremented",
                                "/providers/example_provider/provider_state/state/counter",
                                2,
                            )
                        ],
                        "covers": [
                            _cover("delivery_edge", "increment_after_read", behavior)
                            for behavior in (
                                "delivery_success",
                                "duplicate_idempotency",
                                "ordering",
                                "terminal_failure",
                            )
                        ],
                    },
                    {
                        "step_id": "read_after_write",
                        "action": "agent_http",
                        "provider_id": release.provider_id,
                        "operation_id": "counter.read",
                        "principal_context_id": "fixed",
                        "request": _request(event_id="event-2", stream="stream-2"),
                        "expected_result": {
                            "status_code": 200,
                            "decision_kind": "replay",
                            "headers": {},
                            "body": {"actor_role": "operator", "counter": 2},
                        },
                        "assertions": [
                            _assertion(
                                "readback_state_preserved",
                                "/providers/example_provider/provider_state/state/counter",
                                2,
                            )
                        ],
                        "covers": [
                            _cover(
                                "delivery_edge",
                                "increment_after_read",
                                "read_after_write",
                            )
                        ],
                    },
                ],
            }
        ],
    }


def _candidate_inputs(tmp_path: Path):
    release = _release(tmp_path / "provider")
    pack = _pack(tmp_path / "pack", release)
    claims = _write_json(tmp_path / "composition-claims.json", _claims(release, pack))
    validated = validate_composition_authoring_inputs(
        pack=pack,
        provider_releases={release.provider_id: release},
        claims_path=claims,
        admitted_at=NOW,
    )
    return release, pack, claims, validated


def test_candidate_runner_executes_exact_local_profiles_and_canonical_observations(
    tmp_path: Path,
) -> None:
    release, _, _, validated = _candidate_inputs(tmp_path)
    with CandidateCompositionRunner(
        validated=validated,
        provider_releases={release.provider_id: release},
        work_dir=tmp_path / "candidate-run",
    ) as runner:
        assert runner.reset() == {
            "composition_delivery_time": DEFAULT_CANDIDATE_INITIAL_TIME,
            "reset": True,
        }
        assert runner.agent_http(
            provider_id=release.provider_id,
            operation_id="counter.read",
            principal_context_id="fixed",
            request=_request(event_id="event-1", stream="stream-1"),
        ) == {
            "status_code": 200,
            "decision_kind": "replay",
            "headers": {},
            "body": {"actor_role": "operator", "counter": 1},
        }
        assert runner.drain()["drained"] == 1
        first = runner.export_evidence()
        assert first["pack"]["time_scope"] == "delivery_scheduler_only_v1"
        assert first["composition_delivery_time"] == DEFAULT_CANDIDATE_INITIAL_TIME
        runner.reset()
        runner.agent_http(
            provider_id=release.provider_id,
            operation_id="counter.read",
            principal_context_id="fixed",
            request=_request(event_id="event-1", stream="stream-1"),
        )
        runner.drain()
        assert runner.export_evidence() == first
        serialized = json.dumps(first, sort_keys=True)
        assert "response_event_id" not in serialized
        assert "created_at" not in serialized
        assert "run_id" not in serialized


def test_candidate_runner_admits_pack_end_to_end_without_runtime_bypass(tmp_path: Path) -> None:
    release, pack, claims, _ = _candidate_inputs(tmp_path)
    admitted = admit_candidate_composition_pack(
        pack=pack,
        provider_releases={release.provider_id: release},
        claims_path=claims,
        output_path=tmp_path / "composition-admission.json",
        work_dir=tmp_path / "candidate-run",
        admitted_at=NOW,
    )
    assert admitted.payload["admitted"] is True
    assert (
        admitted.payload["functional_reset"]["first_run_sha256"]
        == admitted.payload["functional_reset"]["second_run_sha256"]
    )


def test_candidate_runner_requires_fresh_private_work_directory(tmp_path: Path) -> None:
    release, _, _, validated = _candidate_inputs(tmp_path)
    work_dir = tmp_path / "existing"
    work_dir.mkdir()
    with pytest.raises(CompositionAuthoringError) as caught:
        CandidateCompositionRunner(
            validated=validated,
            provider_releases={release.provider_id: release},
            work_dir=work_dir,
        )
    assert caught.value.code == "composition_authoring_work_dir_exists"


def test_composition_cli_validates_then_admits_exact_candidate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    release, pack, claims, _ = _candidate_inputs(tmp_path)
    common = [
        "--pack",
        str(pack.root),
        "--claims",
        str(claims),
        "--provider",
        release.provider_id,
        str(release.root),
        "--admitted-at",
        "2026-08-25T00:00:00Z",
        "--json",
    ]
    with patch.object(sys, "argv", ["datalox-gate", "composition", "validate", *common]):
        assert main() == 0
    validated = json.loads(capsys.readouterr().out)
    assert validated["valid"] is True
    assert validated["time_scope"] == "delivery_scheduler_only_v1"
    assert validated["provider_profiles"] == [
        {"profile_id": "default", "provider_id": release.provider_id}
    ]

    output = tmp_path / "cli-composition-admission.json"
    with patch.object(
        sys,
        "argv",
        [
            "datalox-gate",
            "composition",
            "admit",
            *common[:-1],
            "--run",
            str(tmp_path / "cli-candidate-run"),
            "--out",
            str(output),
            "--json",
        ],
    ):
        assert main() == 0
    admitted = json.loads(capsys.readouterr().out)
    assert admitted["admission"] == str(output.resolve())
    assert admitted["pack_id"] == pack.pack_id
    assert admitted["time_scope"] == "delivery_scheduler_only_v1"
