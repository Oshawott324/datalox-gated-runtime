from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MethodType

import pytest
from fastapi.testclient import TestClient

from test_composition_session import _edge, _named_release, _pack, _source
from test_composition_pack import _release

from datalox_gated_runtime.composition.admission import admit_composition_pack
from datalox_gated_runtime.composition.runtime_binding import load_runtime_composition
from datalox_gated_runtime.interception import composition_server
from datalox_gated_runtime.interception.composition_gateway import (
    CompositionInterceptionGateway,
)
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.rollout import (
    ProviderReleaseSelection,
    load_materialized_rollout_provider_set_v2,
    materialize_rollout_provider_set_v2,
    write_rollout_provider_set_v2,
)

NOW = datetime(2026, 8, 25, tzinfo=UTC)
INITIAL_TIME = "2030-01-01T00:00:00Z"


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _assertion(assertion_id: str, phase: str) -> dict[str, object]:
    return {
        "assertion_id": assertion_id,
        "source": "exported_evidence",
        "pointer": "/phase",
        "operator": "equals",
        "expected_value": phase,
    }


def _coverage(kind: str, subject_id: str, behavior: str) -> dict[str, str]:
    return {"subject_kind": kind, "subject_id": subject_id, "behavior": behavior}


class _CompositionAdmissionRunner:
    def __init__(self, *, source_provider_id: str, target_provider_id: str) -> None:
        self.source_provider_id = source_provider_id
        self.target_provider_id = target_provider_id
        self.phase = "new"
        self.drain_count = 0

    def reset(self) -> dict[str, object]:
        self.phase = "reset"
        self.drain_count = 0
        return {"reset": True}

    def agent_http(
        self,
        *,
        provider_id: str,
        operation_id: str,
        principal_context_id: str,
        request: object,
    ) -> dict[str, object]:
        del operation_id, principal_context_id, request
        if provider_id == self.source_provider_id:
            self.phase = "source"
            counter = 1
        elif provider_id == self.target_provider_id:
            self.phase = "readback"
            counter = 2
        else:
            raise AssertionError("unexpected provider")
        return {
            "status_code": 200,
            "decision_kind": "replay",
            "headers": {},
            "body": {"counter": counter},
        }

    def advance_delivery_time(self, *, seconds: int) -> dict[str, object]:
        self.phase = "advanced"
        return {"composition_delivery_time": seconds}

    def drain(self) -> dict[str, object]:
        phases = ("delivered", "duplicate", "ordered", "terminal")
        phase = phases[self.drain_count]
        self.drain_count += 1
        self.phase = phase
        return {"phase": phase}

    def export_evidence(self) -> dict[str, object]:
        return {"phase": self.phase}


@dataclass(frozen=True)
class _Artifacts:
    provider_set_root: Path
    pack_dir: Path
    admission_path: Path
    source_provider_id: str
    source_authority: str
    target_provider_id: str
    target_authority: str


def _artifacts(tmp_path: Path) -> _Artifacts:
    source = _release(tmp_path / "source")
    target = _named_release(
        tmp_path / "target",
        provider_id="target_provider",
        authority="api.target.example",
    )
    source_contract = _source(source.provider_id)
    source_contract["provider_event_id"] = {
        "kind": "select",
        "context": "request",
        "pointer": "/headers/x-event-id",
    }
    source_contract["payload"]["fields"]["event_id"] = {
        "kind": "select",
        "context": "request",
        "pointer": "/headers/x-event-id",
    }
    source_contract["correlations"] = {
        "stream": {
            "kind": "select",
            "context": "request",
            "pointer": "/headers/x-order-key",
        }
    }
    edge = _edge(target.provider_id)
    pack = _pack(
        tmp_path / "composition-pack",
        source,
        source=source_contract,
        edge=edge,
        additional_releases=(target,),
    )

    profiles = []
    for release in sorted((source, target), key=lambda item: item.provider_id):
        profile = release.profiles[0]
        profiles.append(
            {
                "provider_id": release.provider_id,
                "profile_id": profile.profile_id,
                "release_manifest_sha256": release.manifest_descriptor["digest"],
                "provider_runtime_sha256": profile.provider_runtime_sha256,
                "provider_admission_sha256": profile.provider_admission_sha256,
                "operation_contract_sha256": release.config["operation_contract_sha256"],
            }
        )
    read_request = {
        "scheme": "https",
        "method": "GET",
        "path": "/counter",
        "query": {},
        "headers": {"X-Event-Id": "event-1", "X-Order-Key": "stream-1"},
        "body": None,
    }
    steps = [
        {
            "step_id": "emit_source",
            "action": "agent_http",
            "provider_id": source.provider_id,
            "operation_id": "counter.read",
            "principal_context_id": "fixed",
            "request": {**read_request, "authority": source.config["authorities"][0]},
            "expected_result": {
                "status_code": 200,
                "decision_kind": "replay",
                "headers": {},
                "body": {"counter": 1},
            },
            "assertions": [_assertion("source_recorded", "source")],
            "covers": [
                _coverage(
                    "source_contract", source_contract["source_contract_id"], "source_emission"
                )
            ],
        },
        {
            "step_id": "deliver_success",
            "action": "controller_drain",
            "expected_result": {"phase": "delivered"},
            "assertions": [_assertion("delivered_recorded", "delivered")],
            "covers": [_coverage("delivery_edge", edge["edge_id"], "delivery_success")],
        },
        {
            "step_id": "read_after_write",
            "action": "agent_http",
            "provider_id": target.provider_id,
            "operation_id": "counter.read",
            "principal_context_id": "fixed",
            "request": {
                **read_request,
                "authority": target.config["authorities"][0],
                "headers": {},
            },
            "expected_result": {
                "status_code": 200,
                "decision_kind": "replay",
                "headers": {},
                "body": {"counter": 2},
            },
            "assertions": [_assertion("readback_recorded", "readback")],
            "covers": [_coverage("delivery_edge", edge["edge_id"], "read_after_write")],
        },
    ]
    for step_id, phase, behavior in (
        ("prove_duplicate", "duplicate", "duplicate_idempotency"),
        ("prove_ordering", "ordered", "ordering"),
        ("prove_terminal", "terminal", "terminal_failure"),
    ):
        steps.append(
            {
                "step_id": step_id,
                "action": "controller_drain",
                "expected_result": {"phase": phase},
                "assertions": [_assertion(f"{phase}_recorded", phase)],
                "covers": [_coverage("delivery_edge", edge["edge_id"], behavior)],
            }
        )
    claims = {
        "schema_version": "datalox_composition_operation_claims_v1",
        "pack_id": pack.pack_id,
        "pack_version": pack.pack_version,
        "composition_pack_sha256": pack.canonical_sha256,
        "provider_profiles": profiles,
        "reset_probe": {
            "expected_result": {"reset": True},
            "assertions": [_assertion("reset_recorded", "reset")],
        },
        "behavior_probes": [{"probe_id": "two_provider_delivery", "steps": steps}],
    }
    claims_path = tmp_path / "composition-claims.json"
    _write_json(claims_path, claims)
    admission_path = tmp_path / "composition-admission.json"
    admit_composition_pack(
        pack=pack,
        provider_releases={source.provider_id: source, target.provider_id: target},
        claims_path=claims_path,
        runner=_CompositionAdmissionRunner(
            source_provider_id=source.provider_id,
            target_provider_id=target.provider_id,
        ),
        output_path=admission_path,
        admitted_at=NOW,
    )

    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")
    references = {
        release.provider_id: registry.publish(release).reference for release in (source, target)
    }
    selected = write_rollout_provider_set_v2(
        selections=tuple(
            ProviderReleaseSelection(references[provider_id], "default")
            for provider_id in sorted(references)
        ),
        registry=registry,
        output_path=tmp_path / "provider-set-v2.json",
    )
    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=tmp_path / "materialized-provider-set",
    )
    return _Artifacts(
        provider_set_root=materialized.root,
        pack_dir=pack.root,
        admission_path=admission_path,
        source_provider_id=source.provider_id,
        source_authority=source.config["authorities"][0],
        target_provider_id=target.provider_id,
        target_authority=target.config["authorities"][0],
    )


def _gateway(tmp_path: Path, artifacts: _Artifacts) -> CompositionInterceptionGateway:
    provider_set = load_materialized_rollout_provider_set_v2(artifacts.provider_set_root)
    return CompositionInterceptionGateway.from_materialized_provider_set(
        provider_set=provider_set,
        composition_pack_dir=artifacts.pack_dir,
        composition_admission_path=artifacts.admission_path,
        session_root=tmp_path / "session",
        episode_seed="episode-1",
        initial_time=INITIAL_TIME,
        control_token="controller-secret",
    )


def test_runtime_binding_uses_selected_materialized_profiles_without_oci_store(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    provider_set = load_materialized_rollout_provider_set_v2(artifacts.provider_set_root)

    loaded = load_runtime_composition(
        provider_set=provider_set,
        pack_dir=artifacts.pack_dir,
        admission_path=artifacts.admission_path,
    )

    assert set(loaded.releases) == {artifacts.source_provider_id, artifacts.target_provider_id}
    assert loaded.admission.composition_pack_sha256 == loaded.pack.canonical_sha256
    assert all(release.profile_id == "default" for release in loaded.releases.values())
    assert not (provider_set.root / "blobs").exists()


def test_composition_gateway_never_silently_resumes_an_existing_session(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    gateway = _gateway(tmp_path, artifacts)
    gateway.close()

    with pytest.raises(ValueError, match="session directory must not already exist"):
        _gateway(tmp_path, artifacts)


def test_composed_gateway_preserves_provider_urls_and_owns_only_atomic_controls(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    gateway = _gateway(tmp_path, artifacts)
    control_headers = {"x-datalox-control-token": "controller-secret"}
    try:
        with TestClient(
            gateway.data_app,
            base_url=f"https://{artifacts.source_authority}",
        ) as source_agent:
            assert source_agent.post("/v1/composition/reset", json={}).status_code == 403
            assert source_agent.get("/_datalox/health").status_code == 403
            reserved = source_agent.get(
                "/counter",
                headers={
                    "X-Event-Id": "event-2",
                    "X-Order-Key": "stream-2",
                    "x-datalox-invented-control": "true",
                },
            )
            assert reserved.status_code == 400
            source = source_agent.get(
                "/counter",
                headers={"X-Event-Id": "event-1", "X-Order-Key": "stream-1"},
            )
            assert source.status_code == 200
            assert source.json()["counter"] == 1

        with TestClient(gateway.control_app) as controller:
            unauthorized = controller.get("/health")
            assert unauthorized.status_code == 401
            assert unauthorized.json() == {
                "error": {
                    "code": "composition_control_unauthorized",
                    "message": "The control token is invalid.",
                }
            }
            missing_content_type = controller.post(
                "/v1/composition/reset",
                headers=control_headers,
                content=b"{}",
            )
            assert missing_content_type.status_code == 415
            duplicate_field = controller.post(
                "/v1/composition/time/advance",
                headers={**control_headers, "content-type": "application/json"},
                content=b'{"to":"2030-01-01T00:00:01Z","to":"2030-01-01T00:00:02Z"}',
            )
            assert duplicate_field.status_code == 400
            non_finite = controller.post(
                "/v1/composition/deliveries/missing/resolve",
                headers={**control_headers, "content-type": "application/json"},
                content=b'{"outcome":"delivered","status_code":null,"receipt":{"n":1e999}}',
            )
            assert non_finite.status_code == 400
            before = controller.get("/v1/composition/export", headers=control_headers).json()
            assert len(before["events"]["source_events"]) == 1
            assert len(before["events"]["deliveries"]) == 1
            drained = controller.post(
                "/v1/composition/deliveries/drain",
                headers=control_headers,
                json={},
            )
            assert drained.status_code == 200
            assert [item["delivery_state"] for item in drained.json()["deliveries"]] == [
                "delivered"
            ]
            assert (
                controller.post(
                    f"/v1/providers/{artifacts.source_provider_id}/reset",
                    headers=control_headers,
                    json={},
                ).status_code
                == 404
            )

        with TestClient(
            gateway.data_app,
            base_url=f"https://{artifacts.target_authority}",
        ) as target_agent:
            assert target_agent.get("/counter").json()["counter"] == 2

        with TestClient(gateway.control_app) as controller:
            advanced = controller.post(
                "/v1/composition/time/advance",
                headers=control_headers,
                json={"to": "2030-01-01T00:00:01Z"},
            )
            assert advanced.status_code == 200
            assert advanced.json() == {"composition_delivery_time": "2030-01-01T00:00:01.000000Z"}
            reverse = controller.post(
                "/v1/composition/time/advance",
                headers=control_headers,
                json={"to": INITIAL_TIME},
            )
            assert reverse.status_code == 409
            reset = controller.post("/v1/composition/reset", headers=control_headers, json={})
            assert reset.status_code == 200
            assert reset.json()["events"]["deliveries"] == []
            finalized = controller.post(
                "/v1/composition/finalize", headers=control_headers, json={}
            )
            assert finalized.status_code == 200
            assert finalized.json()["finalized"] is True
            repeated = controller.post("/v1/composition/reset", headers=control_headers, json={})
            assert repeated.status_code == 409
    finally:
        gateway.close()


def test_unknown_delivery_requires_explicit_trusted_resolution(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    gateway = _gateway(tmp_path, artifacts)
    control_headers = {"x-datalox-control-token": "controller-secret"}
    target_runtime = gateway.session._providers[artifacts.target_provider_id].runtime

    def unknown(self, request, *, principal_context_id):
        del self, request, principal_context_id
        raise RuntimeError("credential must never enter evidence")

    target_runtime.handle_as_principal = MethodType(unknown, target_runtime)  # type: ignore[method-assign]
    try:
        with TestClient(
            gateway.data_app,
            base_url=f"https://{artifacts.source_authority}",
        ) as agent:
            assert (
                agent.get(
                    "/counter",
                    headers={"X-Event-Id": "event-1", "X-Order-Key": "stream-1"},
                ).status_code
                == 200
            )
        with TestClient(gateway.control_app) as controller:
            result = controller.post(
                "/v1/composition/deliveries/drain",
                headers=control_headers,
                json={},
            ).json()["deliveries"][0]
            assert result["delivery_state"] == "unknown_completion"
            delivery_id = result["delivery_id"]
            assert (
                controller.post(
                    "/v1/composition/deliveries/drain",
                    headers=control_headers,
                    json={},
                ).json()["deliveries"]
                == []
            )
            resolved = controller.post(
                f"/v1/composition/deliveries/{delivery_id}/resolve",
                headers=control_headers,
                json={
                    "outcome": "delivered",
                    "status_code": None,
                    "receipt": {"readback": "confirmed_applied"},
                },
            )
            assert resolved.status_code == 200
            assert resolved.json()["delivery_state"] == "delivered"
            exported = controller.get("/v1/composition/export", headers=control_headers).json()
            assert "credential must never enter evidence" not in json.dumps(exported)
    finally:
        gateway.close()


def test_prepared_composition_server_binds_every_artifact_and_rejects_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(tmp_path)
    provider_set = load_materialized_rollout_provider_set_v2(artifacts.provider_set_root)
    run_root = tmp_path / "run"
    prepared = composition_server.prepare_composition_interception_run(
        provider_set=provider_set,
        composition_pack_dir=artifacts.pack_dir,
        composition_admission_path=artifacts.admission_path,
        run_root=run_root,
        episode_seed="episode-1",
        initial_time=INITIAL_TIME,
        trust_dir=tmp_path / "trust",
    )
    payload = json.loads(prepared.read_text(encoding="utf-8"))
    assert payload["schema_version"] == composition_server.PREPARED_COMPOSITION_RUN_SCHEMA
    assert payload["authorities"] == [artifacts.source_authority, artifacts.target_authority]
    assert payload["composition"]["composition_admission_sha256"].startswith("sha256:")

    observed: dict[str, object] = {}

    def fake_serve(*, gateway, run_root: Path, host: str, port: int) -> None:
        observed.update({"gateway": gateway, "run_root": run_root, "host": host, "port": port})
        gateway.close()

    monkeypatch.setattr(composition_server, "_serve_gateway_process", fake_serve)
    composition_server.serve_composition_interception_gateway(
        provider_set=provider_set,
        composition_pack_dir=artifacts.pack_dir,
        composition_admission_path=artifacts.admission_path,
        run_root=run_root,
        episode_seed="episode-1",
        initial_time=INITIAL_TIME,
        host="127.0.0.1",
        port=8443,
        prepared=True,
    )
    assert observed["run_root"] == run_root

    tampered = json.loads(prepared.read_text(encoding="utf-8"))
    tampered["composition"]["composition_admission_sha256"] = "sha256:" + "0" * 64
    prepared.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match its admitted artifacts"):
        composition_server.serve_composition_interception_gateway(
            provider_set=provider_set,
            composition_pack_dir=artifacts.pack_dir,
            composition_admission_path=artifacts.admission_path,
            run_root=run_root,
            episode_seed="episode-1",
            initial_time=INITIAL_TIME,
            host="127.0.0.1",
            port=8443,
            prepared=True,
        )


def test_composition_prepare_cleans_partial_private_artifacts_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(tmp_path)
    provider_set = load_materialized_rollout_provider_set_v2(artifacts.provider_set_root)
    run_root = tmp_path / "failed-run"
    trust_dir = tmp_path / "failed-trust"

    def fail_certificates(*, output_dir: Path, authorities: tuple[str, ...]) -> None:
        del output_dir, authorities
        raise RuntimeError("certificate generation failed")

    monkeypatch.setattr(composition_server, "generate_run_certificates", fail_certificates)
    with pytest.raises(RuntimeError, match="certificate generation failed"):
        composition_server.prepare_composition_interception_run(
            provider_set=provider_set,
            composition_pack_dir=artifacts.pack_dir,
            composition_admission_path=artifacts.admission_path,
            run_root=run_root,
            episode_seed="episode-1",
            initial_time=INITIAL_TIME,
            trust_dir=trust_dir,
        )

    assert not run_root.exists()
    assert not trust_dir.exists()
