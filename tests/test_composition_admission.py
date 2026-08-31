from __future__ import annotations

import json
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from test_composition_pack import _pack, _write_json
from test_provider_release_registry import _profile

from datalox_gated_runtime.composition.admission import (
    CompositionAdmissionError,
    admit_composition_pack,
    load_composition_admission,
)
from datalox_gated_runtime.composition.pack import load_composition_pack
from datalox_gated_runtime.provider_runtime.release import build_provider_release

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 25, tzinfo=UTC)


def _release(tmp_path: Path):
    profile = _profile(tmp_path / "profile", profile_id="default")
    return build_provider_release(
        profiles=(profile,), release_version="2026.08.25", output_dir=tmp_path / "release"
    )


def _loaded_pack(tmp_path: Path, *, retry: bool = False):
    release = _release(tmp_path)
    root, payload = _pack(tmp_path, release)
    if not retry:
        payload["delivery_edges"][0]["retry_delays_seconds"] = []
        payload["delivery_edges"][0]["retryable_statuses"] = []
        _write_json(root / "composition-pack.json", payload)
    pack = load_composition_pack(root, provider_releases={release.provider_id: release})
    return release, pack


def _assertion(assertion_id: str, phase: str) -> dict[str, object]:
    return {
        "assertion_id": assertion_id,
        "source": "exported_evidence",
        "pointer": "/phase",
        "operator": "equals",
        "expected_value": phase,
    }


def _cover(kind: str, subject_id: str, behavior: str) -> dict[str, str]:
    return {"subject_kind": kind, "subject_id": subject_id, "behavior": behavior}


def _request(method: str, *, body: object = None) -> dict[str, object]:
    return {
        "scheme": "https",
        "authority": "api.provider.example",
        "method": method,
        "path": "/counter",
        "query": {},
        "headers": {},
        "body": body,
    }


def _claims(release, pack, *, retry: bool = False) -> dict[str, object]:
    profile = release.profiles[0]
    edge_behaviors = ["delivery_success", "duplicate_idempotency"]
    terminal_behaviors = ["ordering", "terminal_failure"]
    if retry:
        terminal_behaviors.extend(["retryable_failure", "retry_exhaustion"])
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
            "expected_result": {"reset": True},
            "assertions": [_assertion("reset_is_empty", "reset")],
        },
        "behavior_probes": [
            {
                "probe_id": "delivery_program",
                "steps": [
                    {
                        "step_id": "emit_source",
                        "action": "agent_http",
                        "provider_id": release.provider_id,
                        "operation_id": "counter.increment",
                        "principal_context_id": "integration_service",
                        "request": _request("POST", body={"amount": 2, "order_id": "order_1"}),
                        "expected_result": {
                            "status_code": 200,
                            "decision_kind": "shadow_write",
                            "headers": {},
                            "body": {"event_id": "event_1"},
                        },
                        "assertions": [_assertion("source_recorded", "source")],
                        "covers": [
                            _cover("source_contract", "counter_incremented", "source_emission")
                        ],
                    },
                    {
                        "step_id": "advance_delivery",
                        "action": "controller_advance",
                        "seconds": 2,
                        "expected_result": {"composition_delivery_time": 2},
                        "assertions": [_assertion("time_advanced", "advanced")],
                        "covers": [],
                    },
                    {
                        "step_id": "deliver_success",
                        "action": "controller_drain",
                        "expected_result": {"drained": 1, "state": "delivered"},
                        "assertions": [_assertion("delivery_recorded", "delivered")],
                        "covers": [
                            *[
                                _cover("delivery_edge", "increment_replica", behavior)
                                for behavior in edge_behaviors
                            ]
                        ],
                    },
                    {
                        "step_id": "read_after_write",
                        "action": "agent_http",
                        "provider_id": release.provider_id,
                        "operation_id": "counter.read",
                        "principal_context_id": "integration_service",
                        "request": _request("GET"),
                        "expected_result": {
                            "status_code": 200,
                            "decision_kind": "replay",
                            "headers": {},
                            "body": {"counter": 3},
                        },
                        "assertions": [_assertion("readback_recorded", "readback")],
                        "covers": [
                            _cover("delivery_edge", "increment_replica", "read_after_write")
                        ],
                    },
                    {
                        "step_id": "emit_terminal_case",
                        "action": "agent_http",
                        "provider_id": release.provider_id,
                        "operation_id": "counter.increment",
                        "principal_context_id": "integration_service",
                        "request": _request("POST", body={"amount": 2, "order_id": "order_2"}),
                        "expected_result": {
                            "status_code": 200,
                            "decision_kind": "shadow_write",
                            "headers": {},
                            "body": {"event_id": "event_2"},
                        },
                        "assertions": [_assertion("terminal_source_recorded", "source_terminal")],
                        "covers": [],
                    },
                    {
                        "step_id": "deliver_terminal",
                        "action": "controller_drain",
                        "expected_result": {"drained": 1, "state": "terminal_failure"},
                        "assertions": [_assertion("terminal_recorded", "terminal")],
                        "covers": [
                            *[
                                _cover("delivery_edge", "increment_replica", behavior)
                                for behavior in terminal_behaviors
                            ]
                        ],
                    },
                ],
            }
        ],
    }


class _Runner:
    def __init__(self, *, diverge_second_reset: bool = False, fail: bool = False) -> None:
        self.resets = 0
        self.phase = "new"
        self.http_calls = 0
        self.drains = 0
        self.diverge_second_reset = diverge_second_reset
        self.fail = fail

    def reset(self) -> dict[str, object]:
        self.resets += 1
        self.phase = "reset"
        self.http_calls = 0
        self.drains = 0
        return {"reset": True}

    def agent_http(
        self,
        *,
        provider_id: str,
        operation_id: str,
        principal_context_id: str,
        request,
    ) -> dict[str, object]:
        del provider_id, principal_context_id, request
        if self.fail:
            raise RuntimeError("private credential and tenant details")
        self.http_calls += 1
        if operation_id == "counter.read":
            self.phase = "readback"
            return {
                "status_code": 200,
                "decision_kind": "replay",
                "headers": {},
                "body": {"counter": 3},
            }
        event_number = 1 if self.http_calls == 1 else 2
        self.phase = "source" if event_number == 1 else "source_terminal"
        return {
            "status_code": 200,
            "decision_kind": "shadow_write",
            "headers": {},
            "body": {"event_id": f"event_{event_number}"},
        }

    def advance_delivery_time(self, *, seconds: int) -> dict[str, object]:
        self.phase = "advanced"
        return {"composition_delivery_time": seconds}

    def drain(self) -> dict[str, object]:
        self.drains += 1
        if self.drains == 1:
            self.phase = "delivered"
            return {"drained": 1, "state": "delivered"}
        self.phase = "terminal"
        return {"drained": 1, "state": "terminal_failure"}

    def export_evidence(self) -> dict[str, object]:
        result: dict[str, object] = {"phase": self.phase}
        if self.diverge_second_reset and self.resets == 2 and self.phase == "terminal":
            result["unstable_generation"] = 2
        return result


def _write_claims(path: Path, payload: object) -> Path:
    _write_json(path, payload)
    return path


def test_admits_exact_bound_pack_with_functional_reset_and_schemas(tmp_path: Path) -> None:
    release, pack = _loaded_pack(tmp_path)
    claims_payload = _claims(release, pack)
    claims = _write_claims(tmp_path / "composition-claims.json", claims_payload)
    output = tmp_path / "composition-admission.json"

    admitted = admit_composition_pack(
        pack=pack,
        provider_releases={release.provider_id: release},
        claims_path=claims,
        runner=_Runner(),
        output_path=output,
        admitted_at=NOW,
    )

    assert admitted.pack_id == "counter_delivery"
    assert admitted.composition_pack_sha256 == pack.canonical_sha256
    assert (
        admitted.provider_profiles[0].provider_admission_sha256
        == release.profiles[0].provider_admission_sha256
    )
    assert admitted.payload["admitted"] is True
    assert admitted.time_scope == "delivery_scheduler_only_v1"
    assert admitted.payload["time_scope"] == admitted.time_scope
    assert (
        admitted.payload["functional_reset"]["first_run_sha256"]
        == admitted.payload["functional_reset"]["second_run_sha256"]
    )
    with pytest.raises(TypeError):
        admitted.payload["pack_id"] = "changed"  # type: ignore[index]
    assert (
        load_composition_admission(
            output, pack=pack, provider_releases={release.provider_id: release}
        ).canonical_sha256
        == admitted.canonical_sha256
    )

    for schema_name, payload in (
        ("composition-operation-claims-v1.schema.json", claims_payload),
        ("composition-admission-v1.schema.json", json.loads(output.read_text())),
    ):
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(payload)


def test_rejects_missing_extra_and_ambiguous_coverage(tmp_path: Path) -> None:
    release, pack = _loaded_pack(tmp_path)
    base = _claims(release, pack)

    missing = deepcopy(base)
    missing["behavior_probes"][0]["steps"][2]["covers"].pop()
    claims = _write_claims(tmp_path / "missing.json", missing)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "missing-admission.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_coverage_missing"

    ambiguous = deepcopy(base)
    atom = deepcopy(ambiguous["behavior_probes"][0]["steps"][2]["covers"][0])
    ambiguous["behavior_probes"][0]["steps"][5]["covers"].append(atom)
    claims = _write_claims(tmp_path / "ambiguous.json", ambiguous)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "ambiguous-admission.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_coverage_ambiguous"

    extra = deepcopy(base)
    extra["behavior_probes"][0]["steps"][2]["covers"].append(
        _cover("delivery_edge", "increment_replica", "invented")
    )
    claims = _write_claims(tmp_path / "extra.json", extra)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "extra-admission.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_coverage_extra"


def test_retry_declaration_requires_retryable_and_exhaustion_proofs(tmp_path: Path) -> None:
    release, pack = _loaded_pack(tmp_path, retry=True)
    claims_payload = _claims(release, pack, retry=False)
    claims = _write_claims(tmp_path / "claims.json", claims_payload)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "admission.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_coverage_missing"
    assert {item["behavior"] for item in caught.value.details["missing"]} == {
        "retryable_failure",
        "retry_exhaustion",
    }


def test_rejects_pack_profile_freshness_secret_and_reset_mismatch(tmp_path: Path) -> None:
    release, pack = _loaded_pack(tmp_path)
    base = _claims(release, pack)

    wrong = deepcopy(base)
    wrong["provider_profiles"][0]["provider_runtime_sha256"] = "sha256:" + "0" * 64
    claims = _write_claims(tmp_path / "wrong.json", wrong)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "wrong-out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_provider_profile_binding_invalid"

    secret = deepcopy(base)
    secret["behavior_probes"][0]["steps"][0]["request"]["headers"] = {
        "Authorization": "Bearer private"
    }
    claims = _write_claims(tmp_path / "secret.json", secret)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "secret-out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_probe_credentials_forbidden"

    secret_result = deepcopy(base)
    secret_result["behavior_probes"][0]["steps"][0]["expected_result"]["headers"] = {
        "Set-Cookie": "private=session"
    }
    claims = _write_claims(tmp_path / "secret-result.json", secret_result)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "secret-result-out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_probe_credentials_forbidden"

    claims = _write_claims(tmp_path / "diverge.json", base)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(diverge_second_reset=True),
            output_path=tmp_path / "diverge-out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_reset_not_equivalent"

    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "stale-out.json",
            admitted_at=datetime(2028, 1, 1, tzinfo=UTC),
        )
    assert caught.value.code == "composition_admission_evidence_not_current"


def test_runner_error_is_stable_and_does_not_copy_private_message(tmp_path: Path) -> None:
    release, pack = _loaded_pack(tmp_path)
    claims = _write_claims(tmp_path / "claims.json", _claims(release, pack))
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(fail=True),
            output_path=tmp_path / "out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_probe_runner_failed"
    assert "credential" not in str(caught.value)
    assert caught.value.details == {"action": "agent_http", "exception_type": "RuntimeError"}


def test_revalidates_pack_bytes_and_rejects_unaccepted_source_outcome(tmp_path: Path) -> None:
    release, pack = _loaded_pack(tmp_path)
    claims_payload = _claims(release, pack)
    claims = _write_claims(tmp_path / "claims.json", claims_payload)

    manifest_path = pack.root / "composition-pack.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["pack_version"] = "2026.08.26"
    _write_json(manifest_path, manifest)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "changed-out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_pack_changed"

    release, pack = _loaded_pack(tmp_path / "outcome")
    claims_payload = _claims(release, pack)
    claims_payload["behavior_probes"][0]["steps"][0]["expected_result"]["decision_kind"] = "deny"
    claims = _write_claims(tmp_path / "outcome" / "claims.json", claims_payload)
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "outcome" / "out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_coverage_action_invalid"


def test_rejects_duplicate_json_keys_before_execution(tmp_path: Path) -> None:
    release, pack = _loaded_pack(tmp_path)
    claims = _write_claims(tmp_path / "claims.json", _claims(release, pack))
    text = claims.read_text(encoding="utf-8")
    text = text.replace(
        '"pack_id": "counter_delivery",',
        '"pack_id": "counter_delivery",\n  "pack_id": "counter_delivery",',
        1,
    )
    claims.write_text(text, encoding="utf-8")
    with pytest.raises(CompositionAdmissionError) as caught:
        admit_composition_pack(
            pack=pack,
            provider_releases={release.provider_id: release},
            claims_path=claims,
            runner=_Runner(),
            output_path=tmp_path / "out.json",
            admitted_at=NOW,
        )
    assert caught.value.code == "composition_admission_json_duplicate_key"
