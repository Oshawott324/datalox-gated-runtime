from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType, MethodType

import pytest

from provider_runtime_helpers import PROVIDER_AUTHORITY
from test_composition_pack import _literal, _release, _rights, _select
from test_provider_admission import _claims
from world_v1_helpers import create_valid_bundle

from datalox_gated_runtime.composition.admission import (
    AdmissionProviderProfile,
    LoadedCompositionAdmission,
)
from datalox_gated_runtime.composition.events import DeliveryOutcome, SessionEventEngine
from datalox_gated_runtime.composition.pack import load_composition_pack
from datalox_gated_runtime.composition.session import (
    CompositionProviderSession,
    CompositionRuntimeRelease,
    CompositionSession,
    CompositionSessionError,
)
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse
from datalox_gated_runtime.provider_runtime.release import (
    LoadedProviderRelease,
    ProviderReleaseProfileInput,
    build_provider_release,
    materialize_provider_release_profile,
)
from datalox_gated_runtime.provider_runtime import (
    admit_provider_runtime,
    build_provider_runtime_from_world,
)
from datalox_gated_runtime.provider_runtime.runtime import ProviderRuntime


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _grounding() -> dict[str, object]:
    return {"level": "G2_OBSERVED", "evidence_refs": ["observed_delivery"]}


def _request_template(*, amount: int = 1, event_header: bool = False) -> dict[str, object]:
    headers: dict[str, object] = {}
    if event_header:
        headers["Integration-Event-Id"] = _select("source_event", "/provider_event_id")
    return {
        "path_params": {},
        "query": {},
        "headers": headers,
        "body": {
            "kind": "object",
            "fields": {"amount": _literal(amount)},
        },
    }


def _source(
    provider_id: str,
    *,
    source_id: str = "counter_observed",
    operation_id: str = "counter.read",
    event_header: str = "X-Event-Id",
    accepted_decision: str = "replay",
) -> dict[str, object]:
    return {
        "source_contract_id": source_id,
        "provider_id": provider_id,
        "source_operation_id": operation_id,
        "event_type": source_id,
        "accepted_outcomes": [
            {"status_code": 200, "decision_kind": accepted_decision},
        ],
        "match": [],
        "provider_event_id": _select("request", f"/headers/{event_header}"),
        "payload": {
            "kind": "object",
            "fields": {
                "amount": _literal(1),
                "event_id": _select("request", f"/headers/{event_header}"),
            },
        },
        "correlations": {"stream": _select("request", "/headers/X-Order-Key")},
        "grounding": _grounding(),
        "rights": _rights(),
    }


def _edge(
    provider_id: str,
    *,
    edge_id: str = "increment_after_read",
    source_id: str = "counter_observed",
    delay: int = 0,
    retry_delays: list[int] | None = None,
    principal: str = "fixed",
    compensation: dict[str, object] | None = None,
    event_header: bool = False,
) -> dict[str, object]:
    return {
        "edge_id": edge_id,
        "source_contract_id": source_id,
        "target_provider_id": provider_id,
        "target_operation_id": "counter.increment",
        "principal_context_id": principal,
        "request": _request_template(event_header=event_header),
        "logical_delay_seconds": delay,
        "retry_delays_seconds": retry_delays or [],
        "idempotency_key": _select("source_event", "/provider_event_id"),
        "ordering_key": _select("source_event", "/correlation_ids/stream"),
        "correlations": {"stream": _select("source_event", "/correlation_ids/stream")},
        "delivered_statuses": [200],
        "retryable_statuses": [503] if retry_delays is not None else [],
        "default_outcome": "terminal_failure",
        "compensation": compensation,
        "grounding": _grounding(),
        "rights": _rights(),
    }


def _compensation(provider_id: str) -> dict[str, object]:
    return {
        "compensation_id": "compensate_increment",
        "triggers": ["retry_exhausted", "terminal_failure"],
        "target_provider_id": provider_id,
        "target_operation_id": "counter.increment",
        "principal_context_id": "fixed",
        "request": {
            **_request_template(amount=5),
            "headers": {
                "Compensation-For": _select("delivery_outcome", "/delivery_id"),
            },
        },
        "logical_delay_seconds": 0,
        "idempotency_key": _select("source_event", "/provider_event_id"),
        "ordering_key": _select("source_event", "/correlation_ids/stream"),
        "correlations": {"stream": _select("source_event", "/correlation_ids/stream")},
        "delivered_statuses": [200],
        "default_outcome": "terminal_failure",
        "grounding": _grounding(),
        "rights": _rights(),
    }


def _pack(
    root: Path,
    release: LoadedProviderRelease,
    *,
    source: dict[str, object] | None = None,
    edge: dict[str, object] | None = None,
    additional_releases: tuple[LoadedProviderRelease, ...] = (),
    sources: tuple[dict[str, object], ...] | None = None,
    edges: tuple[dict[str, object], ...] | None = None,
):
    evidence = root / "evidence" / "delivery.json"
    _write_json(evidence, {"observation": "explicit source caused declared delivery"})
    digest = "sha256:" + hashlib.sha256(evidence.read_bytes()).hexdigest()
    payload = {
        "schema_version": "datalox_composition_pack_v1",
        "claim_status": "authored_not_admitted",
        "time_scope": "delivery_scheduler_only_v1",
        "pack_id": "counter_delivery",
        "pack_version": "2026.08.25",
        "distribution_label": "public",
        "providers": sorted(
            [
                {
                    "provider_id": item.provider_id,
                    "release_manifest_sha256": item.manifest_descriptor["digest"],
                    "operation_contract_sha256": item.config["operation_contract_sha256"],
                }
                for item in (release, *additional_releases)
            ],
            key=lambda item: item["provider_id"],
        ),
        "evidence_sources": [
            {
                "evidence_id": "observed_delivery",
                "artifact_path": "evidence/delivery.json",
                "artifact_sha256": digest,
                "grounding_level": "G2_OBSERVED",
                "observed_at": "2026-08-01T00:00:00Z",
                "valid_through": "2027-08-01T00:00:00Z",
                "distribution_label": "public",
                "rights_basis": "Self-authored test integration capture.",
            }
        ],
        "source_event_contracts": sorted(
            list(sources or (source or _source(release.provider_id),)),
            key=lambda item: item["source_contract_id"],
        ),
        "delivery_edges": sorted(
            list(edges or (edge or _edge(release.provider_id),)),
            key=lambda item: item["edge_id"],
        ),
    }
    _write_json(root / "composition-pack.json", payload)
    releases = {item.provider_id: item for item in (release, *additional_releases)}
    return load_composition_pack(root, provider_releases=releases)


def _admission(pack, *releases: LoadedProviderRelease) -> LoadedCompositionAdmission:
    provider_profiles = []
    for release in sorted(releases, key=lambda item: item.provider_id):
        profile = release.profiles[0]
        provider_profiles.append(
            AdmissionProviderProfile(
                provider_id=release.provider_id,
                profile_id=profile.profile_id,
                release_manifest_sha256=release.manifest_descriptor["digest"],
                provider_runtime_sha256=profile.provider_runtime_sha256,
                provider_admission_sha256=profile.provider_admission_sha256,
                operation_contract_sha256=release.config["operation_contract_sha256"],
            )
        )
    return LoadedCompositionAdmission(
        path=pack.root / "composition-admission.json",
        canonical_sha256="sha256:" + "a" * 64,
        pack_id=pack.pack_id,
        pack_version=pack.pack_version,
        composition_pack_sha256=pack.canonical_sha256,
        distribution_label=pack.distribution_label,
        time_scope=pack.time_scope,
        provider_profiles=tuple(provider_profiles),
        required_coverage=(),
        payload=MappingProxyType({"admitted": True}),
    )


def _named_release(root: Path, *, provider_id: str, authority: str) -> LoadedProviderRelease:
    source = create_valid_bundle(root / "source-world")
    bundle = root / "provider-bundle"
    build_provider_runtime_from_world(
        source_world_dir=source,
        output_dir=bundle,
        provider_id=provider_id,
        authorities=(authority,),
        episode_id="episode-1",
    )
    claims_root = root / "claims"
    claims_root.mkdir(parents=True)
    claims_path = _claims(claims_root)
    claims = json.loads(claims_path.read_text(encoding="utf-8"))
    claims["provider_id"] = provider_id
    for operation in claims["operations"]:
        operation["native_surface"]["authority"] = authority
    for probe in claims["behavior_probes"]:
        for step in probe["steps"]:
            step["request"]["authority"] = authority
    _write_json(claims_path, claims)
    admission = root / "provider-admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims_path,
        output_path=admission,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    return build_provider_release(
        profiles=(ProviderReleaseProfileInput("default", bundle, admission),),
        release_version="2026.08.25",
        output_dir=root / "release",
    )


def _session(
    tmp_path: Path,
    *,
    delay: int = 0,
    retry_delays: list[int] | None = None,
    principal: str = "fixed",
    compensation: dict[str, object] | None = None,
    event_header: bool = False,
    source_match: list[dict[str, object]] | None = None,
    source_payload: dict[str, object] | None = None,
):
    release = _release(tmp_path / "provider")
    edge = _edge(
        release.provider_id,
        delay=delay,
        retry_delays=retry_delays,
        principal=principal,
        compensation=compensation,
        event_header=event_header,
    )
    source = _source(release.provider_id)
    source["match"] = deepcopy(source_match or [])
    if source_payload is not None:
        source["payload"] = deepcopy(source_payload)
    pack = _pack(tmp_path / "pack", release, source=source, edge=edge)
    materialized = materialize_provider_release_profile(
        release=release,
        profile_id="default",
        output_dir=tmp_path / "materialized",
    )
    runtime = ProviderRuntime(
        bundle_dir=materialized.bundle_dir,
        admission_path=materialized.admission_path,
        run_dir=tmp_path / "run",
    )
    event_root = tmp_path / "events"
    event_root.mkdir(mode=0o700)
    engine = SessionEventEngine(
        event_root / "events.sqlite3",
        episode_seed="episode-1",
        initial_time="2030-01-01T00:00:00Z",
    )
    session = CompositionSession(
        pack=pack,
        admission=_admission(pack, release),
        providers={
            release.provider_id: CompositionProviderSession(
                CompositionRuntimeRelease.from_loaded_release(release, profile_id="default"),
                runtime,
            ),
        },
        event_engine=engine,
    )
    return session, runtime, release


def _compensation_session(
    tmp_path: Path,
    *,
    primary_principal: str,
    retry_delays: list[int] | None,
):
    primary = _release(tmp_path / "primary")
    compensator = _named_release(
        tmp_path / "compensator",
        provider_id="compensation_provider",
        authority="api.compensation.example",
    )
    compensation = _compensation(compensator.provider_id)
    edge = _edge(
        primary.provider_id,
        retry_delays=retry_delays,
        principal=primary_principal,
        compensation=compensation,
    )
    pack = _pack(
        tmp_path / "pack",
        primary,
        edge=edge,
        additional_releases=(compensator,),
    )
    bindings: dict[str, CompositionProviderSession] = {}
    runtimes: dict[str, ProviderRuntime] = {}
    for release in (primary, compensator):
        materialized = materialize_provider_release_profile(
            release=release,
            profile_id="default",
            output_dir=tmp_path / f"materialized-{release.provider_id}",
        )
        runtime = ProviderRuntime(
            bundle_dir=materialized.bundle_dir,
            admission_path=materialized.admission_path,
            run_dir=tmp_path / f"run-{release.provider_id}",
        )
        bindings[release.provider_id] = CompositionProviderSession(
            CompositionRuntimeRelease.from_loaded_release(release, profile_id="default"),
            runtime,
        )
        runtimes[release.provider_id] = runtime
    event_root = tmp_path / "events"
    event_root.mkdir(mode=0o700)
    engine = SessionEventEngine(
        event_root / "events.sqlite3",
        episode_seed="episode-1",
        initial_time="2030-01-01T00:00:00Z",
    )
    session = CompositionSession(
        pack=pack,
        admission=_admission(pack, primary, compensator),
        providers=bindings,
        event_engine=engine,
    )
    return session, runtimes, primary, compensator


def _read(*, event_id: str = "event-1", order_key: str = "stream-1") -> CallRequest:
    return CallRequest(
        scheme="https",
        authority=PROVIDER_AUTHORITY,
        method="GET",
        path="/counter",
        headers={"X-Event-Id": event_id, "X-Order-Key": order_key},
        operation_id="caller-controlled-value",
    )


def _write(amount: int = 1) -> CallRequest:
    return CallRequest(
        scheme="https",
        authority=PROVIDER_AUTHORITY,
        method="POST",
        path="/counter",
        body={"amount": amount},
        operation_id="counter.read",
    )


def _counter(session: CompositionSession) -> int:
    return session.export()["providers"]["example_provider"]["provider_state"]["state"]["counter"]


def test_agent_calls_remain_agent_mediated_and_caller_operation_id_is_ignored(
    tmp_path: Path,
) -> None:
    session, _, _ = _session(tmp_path)

    direct = session.handle_agent_request(_write(2))
    assert direct.status_code == 200
    assert _counter(session) == 3
    assert session.export()["events"]["source_events"] == []

    source = session.handle_agent_request(_read())
    assert source.status_code == 200
    assert _counter(session) == 3
    events = session.export()["events"]
    assert len(events["source_events"]) == 1
    assert events["deliveries"][0]["state"] == "queued"
    session.finalize()


def test_post_operation_provider_state_controls_source_emission_and_templates(
    tmp_path: Path,
) -> None:
    session, _, _ = _session(
        tmp_path,
        source_match=[
            {
                "context": "provider_state",
                "pointer": "/state/counter",
                "operator": "equals",
                "expected_value": 2,
            }
        ],
        source_payload={
            "kind": "object",
            "fields": {
                "counter": _select("provider_state", "/state/counter"),
                "event_id": _select("request", "/headers/X-Event-Id"),
            },
        },
    )

    assert session.handle_agent_request(_read(event_id="before-write")).status_code == 200
    assert session.export()["events"]["source_events"] == []

    assert session.handle_agent_request(_write(1)).status_code == 200
    assert session.handle_agent_request(_read(event_id="after-write")).status_code == 200
    events = session.export()["events"]
    assert len(events["source_events"]) == 1
    assert events["source_events"][0]["payload"] == {
        "counter": 2,
        "event_id": "after-write",
    }
    session.finalize()


def test_runtime_latches_if_multiple_source_contracts_match_despite_admission(
    tmp_path: Path,
) -> None:
    session, _, _ = _session(tmp_path)
    contract = session.pack.source_event_contracts[0]
    duplicate = replace(contract, source_contract_id="escaped_duplicate")
    session._source_contracts[(contract.provider_id, contract.source_operation_id)] = (
        contract,
        duplicate,
    )

    response = session.handle_agent_request(_read())
    assert response.status_code == 200
    exported = session.export()
    assert exported["status"] == "invalid"
    assert exported["failure"] == {
        "code": "composition_source_scheduling_failed",
        "cause_code": "composition_source_match_ambiguous",
    }
    assert exported["events"]["source_events"] == []
    denied = session.handle_agent_request(_read(event_id="after-latch"))
    assert denied.decision.reason_code == "composition_session_invalid"
    session.finalize()


def test_zero_delay_waits_for_next_boundary_and_delayed_edge_uses_delivery_time(
    tmp_path: Path,
) -> None:
    immediate, _, _ = _session(tmp_path / "immediate")
    immediate.handle_agent_request(_read())
    assert _counter(immediate) == 1
    second = immediate.handle_agent_request(
        replace(_read(event_id="event-2"), headers={"X-Event-Id": "event-2", "X-Order-Key": "s"})
    )
    assert second.status_code == 200
    assert _counter(immediate) == 2
    immediate.finalize()

    delayed, _, _ = _session(tmp_path / "delayed", delay=5)
    delayed.handle_agent_request(_read())
    assert delayed.drain_due() == ()
    delayed.advance_delivery_time_to("2030-01-01T00:00:04Z")
    assert delayed.drain_due() == ()
    delayed.advance_delivery_time_to("2030-01-01T00:00:05Z")
    results = delayed.drain_due()
    assert len(results) == 1
    assert results[0].delivery_state == "delivered"
    assert _counter(delayed) == 2
    delayed.finalize()


def test_composition_delivery_time_never_advances_provider_clocks(tmp_path: Path) -> None:
    session, _, _ = _session(tmp_path, delay=5)
    before = session.export()
    provider_time = before["providers"]["example_provider"]["provider_state"]["simulation_time"]

    advanced = session.advance_delivery_time_to("2030-01-01T00:00:05Z")
    after = session.export()

    assert advanced == "2030-01-01T00:00:05.000000Z"
    assert after["composition_delivery_time"] == advanced
    assert after["pack"]["time_scope"] == "delivery_scheduler_only_v1"
    assert (
        after["providers"]["example_provider"]["provider_state"]["simulation_time"] == provider_time
    )
    session.finalize()


def test_retry_schedule_idempotency_and_ordering_are_deterministic(tmp_path: Path) -> None:
    session, runtime, _ = _session(tmp_path, retry_delays=[2])
    original = runtime.handle_as_principal
    attempts: list[str] = []

    def flaky(self, request, *, principal_context_id):
        attempts.append(request.headers.get("X-Event", request.body.get("amount", "")))
        if len(attempts) == 1:
            return GateResponse(
                status_code=503,
                body={"error": "retry"},
                decision=GateDecision("deny", "temporary", "Temporary failure."),
                event_id="provider-event-retry",
            )
        return original(request, principal_context_id=principal_context_id)

    runtime.handle_as_principal = MethodType(flaky, runtime)  # type: ignore[method-assign]
    session.handle_agent_request(_read(event_id="event-1"))
    session.handle_agent_request(_read(event_id="event-1"))
    exported = session.export()["events"]
    assert len(exported["source_events"]) == 1
    assert len(exported["deliveries"]) == 1
    assert exported["deliveries"][0]["state"] == "retry_scheduled"
    session.advance_delivery_time_to("2030-01-01T00:00:02Z")
    results = session.drain_due()
    assert [item.delivery_state for item in results] == ["delivered"]
    assert len(attempts) == 2
    session.finalize()


def test_same_ordering_stream_delivers_in_source_sequence(tmp_path: Path) -> None:
    session, runtime, _ = _session(tmp_path, delay=5, event_header=True)
    original = runtime.handle_as_principal
    delivered: list[str] = []

    def recording(self, request, *, principal_context_id):
        delivered.append(request.headers["Integration-Event-Id"])
        return original(request, principal_context_id=principal_context_id)

    runtime.handle_as_principal = MethodType(recording, runtime)  # type: ignore[method-assign]
    session.handle_agent_request(_read(event_id="event-1", order_key="same-stream"))
    session.handle_agent_request(_read(event_id="event-2", order_key="same-stream"))
    assert delivered == []
    session.advance_delivery_time_to("2030-01-01T00:00:05Z")
    results = session.drain_due()
    assert [item.delivery_state for item in results] == ["delivered", "delivered"]
    assert delivered == ["event-1", "event-2"]
    session.finalize()


def test_one_source_fanout_is_committed_as_one_complete_batch(tmp_path: Path) -> None:
    release = _release(tmp_path / "provider")
    first_edge = _edge(release.provider_id, edge_id="fanout_first", delay=10)
    second_edge = _edge(release.provider_id, edge_id="fanout_second", delay=10)
    first_edge["idempotency_key"] = _select("source_event", "/source_event_id")
    second_edge["idempotency_key"] = _select("source_event", "/source_event_id")
    pack = _pack(
        tmp_path / "pack",
        release,
        edges=(first_edge, second_edge),
    )
    materialized = materialize_provider_release_profile(
        release=release,
        profile_id="default",
        output_dir=tmp_path / "materialized",
    )
    runtime = ProviderRuntime(
        bundle_dir=materialized.bundle_dir,
        admission_path=materialized.admission_path,
        run_dir=tmp_path / "run",
    )
    event_root = tmp_path / "events"
    event_root.mkdir(mode=0o700)
    session = CompositionSession(
        pack=pack,
        admission=_admission(pack, release),
        providers={
            release.provider_id: CompositionProviderSession(
                CompositionRuntimeRelease.from_loaded_release(release, profile_id="default"),
                runtime,
            )
        },
        event_engine=SessionEventEngine(
            event_root / "events.sqlite3",
            episode_seed="episode-1",
            initial_time="2030-01-01T00:00:00Z",
        ),
    )
    session.handle_agent_request(_read())
    events = session.export()["events"]
    assert len(events["source_events"]) == 1
    assert [item["edge_id"] for item in events["deliveries"]] == [
        "fanout_first",
        "fanout_second",
    ]
    session.finalize()


def test_unknown_completion_never_retries_or_compensates_until_trusted_resolution(
    tmp_path: Path,
) -> None:
    session, runtimes, primary, _ = _compensation_session(
        tmp_path,
        primary_principal="fixed",
        retry_delays=[1],
    )
    runtime = runtimes[primary.provider_id]

    def unknown(self, request, *, principal_context_id):
        raise RuntimeError("provider secret must not be persisted")

    runtime.handle_as_principal = MethodType(unknown, runtime)  # type: ignore[method-assign]
    session.handle_agent_request(_read())
    result = session.drain_due()[0]
    assert result.delivery_state == "unknown_completion"
    session.advance_delivery_time_to("2030-01-02T00:00:00Z")
    assert session.drain_due() == ()
    events = session.export()["events"]
    assert len(events["deliveries"]) == 1
    assert "provider secret" not in json.dumps(events)

    resolved = session.resolve_unknown(
        result.delivery_id,
        DeliveryOutcome(
            kind="terminal_failure",
            receipt={"resolution": "provider_readback_failed"},
            status_code=500,
            error_code="trusted_readback_failed",
            error_message="Trusted readback established terminal failure.",
        ),
    )
    assert resolved.delivery_state == "terminal_failure"
    assert len(session.export()["events"]["deliveries"]) == 2
    session.finalize()


def test_terminal_failure_schedules_explicit_compensation_exactly_once(tmp_path: Path) -> None:
    session, _, release, compensator = _compensation_session(
        tmp_path,
        primary_principal="missing-principal",
        retry_delays=[1],
    )
    assert release.provider_id == "example_provider"
    session.handle_agent_request(_read())
    first = session.drain_due()
    assert [item.delivery_state for item in first] == ["terminal_failure", "delivered"]
    assert _counter(session) == 1
    assert (
        session.export()["providers"][compensator.provider_id]["provider_state"]["state"]["counter"]
        == 6
    )
    assert session.drain_due() == ()
    edges = [item["edge_id"] for item in session.export()["events"]["deliveries"]]
    assert edges == ["increment_after_read", "compensate_increment"]
    effects = session.export()["events"]["post_outcome_effects"]
    assert len(effects) == 1
    assert effects[0]["effect_kind"] == "existing_source_delivery"
    assert effects[0]["state"] == "applied"
    session.finalize()


def test_retry_exhaustion_triggers_declared_compensation_once(tmp_path: Path) -> None:
    session, runtimes, primary, compensator = _compensation_session(
        tmp_path,
        primary_principal="fixed",
        retry_delays=[2],
    )
    runtime = runtimes[primary.provider_id]

    def retryable(self, request, *, principal_context_id):
        return GateResponse(
            status_code=503,
            body={"error": "retry"},
            decision=GateDecision("deny", "temporary", "Temporary failure."),
            event_id="provider-event-retry",
        )

    runtime.handle_as_principal = MethodType(retryable, runtime)  # type: ignore[method-assign]
    session.handle_agent_request(_read())
    first = session.drain_due()
    assert [item.delivery_state for item in first] == ["retry_scheduled"]
    assert len(session.export()["events"]["deliveries"]) == 1

    session.advance_delivery_time_to("2030-01-01T00:00:02Z")
    second = session.drain_due()
    assert [item.delivery_state for item in second] == ["terminal_failure", "delivered"]
    edges = [item["edge_id"] for item in session.export()["events"]["deliveries"]]
    assert edges == ["increment_after_read", "compensate_increment"]
    assert (
        session.export()["providers"][compensator.provider_id]["provider_state"]["state"]["counter"]
        == 6
    )
    session.finalize()


def test_delivered_target_may_emit_only_its_next_explicit_causal_edge(tmp_path: Path) -> None:
    first = _release(tmp_path / "first")
    second = _named_release(
        tmp_path / "second",
        provider_id="second_provider",
        authority="api.second.example",
    )
    third = _named_release(
        tmp_path / "third",
        provider_id="third_provider",
        authority="api.third.example",
    )
    source_first = _source(first.provider_id, source_id="first_observed")
    source_second = _source(
        second.provider_id,
        source_id="second_written",
        operation_id="counter.increment",
        event_header="Integration-Event-Id",
        accepted_decision="shadow_write",
    )
    source_second["correlations"] = {"stream": _select("request", "/headers/Integration-Event-Id")}
    edge_first = _edge(
        second.provider_id,
        edge_id="first_to_second",
        source_id="first_observed",
        event_header=True,
    )
    edge_second = _edge(
        third.provider_id,
        edge_id="second_to_third",
        source_id="second_written",
    )
    pack = _pack(
        tmp_path / "pack",
        first,
        additional_releases=(second, third),
        sources=(source_first, source_second),
        edges=(edge_first, edge_second),
    )
    bindings: dict[str, CompositionProviderSession] = {}
    for release in (first, second, third):
        materialized = materialize_provider_release_profile(
            release=release,
            profile_id="default",
            output_dir=tmp_path / f"materialized-{release.provider_id}",
        )
        runtime = ProviderRuntime(
            bundle_dir=materialized.bundle_dir,
            admission_path=materialized.admission_path,
            run_dir=tmp_path / f"run-{release.provider_id}",
        )
        bindings[release.provider_id] = CompositionProviderSession(
            CompositionRuntimeRelease.from_loaded_release(release, profile_id="default"),
            runtime,
        )
    event_root = tmp_path / "events"
    event_root.mkdir(mode=0o700)
    session = CompositionSession(
        pack=pack,
        admission=_admission(pack, first, second, third),
        providers=bindings,
        event_engine=SessionEventEngine(
            event_root / "events.sqlite3",
            episode_seed="episode-1",
            initial_time="2030-01-01T00:00:00Z",
        ),
    )

    session.handle_agent_request(_read(event_id="chain-1"))
    results = session.drain_due()
    assert [item.delivery_state for item in results] == ["delivered", "delivered"]
    exported = session.export()
    assert len(exported["events"]["source_events"]) == 2
    assert [item["edge_id"] for item in exported["events"]["deliveries"]] == [
        "first_to_second",
        "second_to_third",
    ]
    assert len(exported["events"]["post_outcome_effects"]) == 1
    assert exported["events"]["post_outcome_effects"][0]["effect_kind"] == "source_fanout"
    assert exported["events"]["post_outcome_effects"][0]["state"] == "applied"
    assert exported["providers"][first.provider_id]["provider_state"]["state"]["counter"] == 1
    assert exported["providers"][second.provider_id]["provider_state"]["state"]["counter"] == 2
    assert exported["providers"][third.provider_id]["provider_state"]["state"]["counter"] == 2
    session.finalize()


def test_secret_headers_are_absent_from_source_and_delivery_evidence(tmp_path: Path) -> None:
    session, runtime, _ = _session(tmp_path)
    original = runtime.handle_as_principal

    def response_with_secret(self, request, *, principal_context_id):
        response = original(request, principal_context_id=principal_context_id)
        return replace(
            response,
            headers={"Set-Cookie": "secret-cookie", "X-Request-Id": "safe-id"},
        )

    runtime.handle_as_principal = MethodType(response_with_secret, runtime)  # type: ignore[method-assign]
    request = replace(
        _read(),
        headers={
            "Authorization": "Bearer source-secret",
            "X-Event-Id": "event-1",
            "X-Order-Key": "stream-1",
        },
    )
    session.handle_agent_request(request)
    session.drain_due()
    serialized = json.dumps(session.export(), sort_keys=True)
    assert "source-secret" not in serialized
    assert "secret-cookie" not in serialized
    assert "safe-id" in serialized
    session.finalize()


def test_exact_admission_release_profile_binding_is_required(tmp_path: Path) -> None:
    release = _release(tmp_path / "provider")
    pack = _pack(tmp_path / "pack", release)
    admission = _admission(pack, release)
    bad_profile = replace(
        admission.provider_profiles[0],
        provider_runtime_sha256="sha256:" + "0" * 64,
    )
    bad_admission = replace(admission, provider_profiles=(bad_profile,))
    materialized = materialize_provider_release_profile(
        release=release, profile_id="default", output_dir=tmp_path / "materialized"
    )
    runtime = ProviderRuntime(
        bundle_dir=materialized.bundle_dir,
        admission_path=materialized.admission_path,
        run_dir=tmp_path / "run",
    )
    event_root = tmp_path / "events"
    event_root.mkdir(mode=0o700)
    engine = SessionEventEngine(
        event_root / "events.sqlite3",
        episode_seed="episode-1",
        initial_time="2030-01-01T00:00:00Z",
    )
    with pytest.raises(CompositionSessionError) as caught:
        CompositionSession(
            pack=pack,
            admission=bad_admission,
            providers={
                release.provider_id: CompositionProviderSession(
                    CompositionRuntimeRelease.from_loaded_release(release, profile_id="default"),
                    runtime,
                )
            },
            event_engine=engine,
        )
    assert caught.value.code == "composition_session_provider_binding_mismatch"
    runtime.close()
    engine.close()


def test_reset_restores_equivalent_provider_and_event_capabilities(tmp_path: Path) -> None:
    session, _, _ = _session(tmp_path)
    baseline = session.export()
    session.handle_agent_request(_write(9))
    session.handle_agent_request(_read())
    session.drain_due()
    assert _counter(session) == 11

    reset = session.reset()
    assert _counter(session) == 1
    assert reset["events"]["source_events"] == []
    assert reset["events"]["deliveries"] == []
    assert (
        reset["providers"]["example_provider"]["provider_state"]
        == baseline["providers"]["example_provider"]["provider_state"]
    )
    session.handle_agent_request(_read())
    session.drain_due()
    assert _counter(session) == 2
    session.finalize()


def test_partial_reset_failure_latches_every_agent_surface_until_full_reset(
    tmp_path: Path,
) -> None:
    session, runtime, _ = _session(tmp_path)
    original = runtime.reset

    def failed_reset():
        raise RuntimeError("private reset failure")

    runtime.reset = failed_reset  # type: ignore[method-assign]
    with pytest.raises(CompositionSessionError) as caught:
        session.reset()
    assert caught.value.code == "composition_session_reset_failed"
    denied = session.handle_agent_request(_read())
    assert denied.status_code == 500
    assert denied.decision.reason_code == "composition_session_invalid"
    assert "private reset failure" not in json.dumps(session.export())

    runtime.reset = original  # type: ignore[method-assign]
    reset = session.reset()
    assert reset["status"] == "valid"
    assert session.handle_agent_request(_read(event_id="after-reset")).status_code == 200
    session.finalize()
