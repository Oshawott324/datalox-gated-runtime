from __future__ import annotations

import json
import hashlib
import os
import stat
import threading
from pathlib import Path

import jsonschema
import pytest

from datalox_gated_runtime.composition.events import (
    DeliveryRequest,
    DeliveryOutcome,
    ExistingSourceDeliveryRequest,
    MAX_SESSION_EVENT_EXPORT_BYTES,
    MAX_SESSION_STORED_JSON_BYTES,
    SessionEventEngine,
    SessionEventError,
    SourceFanoutRequest,
)

START = "2026-08-25T00:00:00Z"


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _engine(tmp_path: Path, name: str = "events.sqlite3") -> SessionEventEngine:
    return SessionEventEngine(tmp_path / name, episode_seed="episode-0042", initial_time=START)


def _source(engine: SessionEventEngine, *, suffix: str = "1") -> str:
    return engine.record_source_event(
        source_provider_id="lims",
        provider_event_id=f"run.created.{suffix}",
        event_type="run.created",
        payload={"run_id": suffix, "ready": True},
        correlation_ids={"workflow": f"wf-{suffix}"},
        idempotency_key=f"source-{suffix}",
    )


def _delivery(
    engine: SessionEventEngine,
    source_event_id: str,
    *,
    suffix: str = "1",
    available_at: str = START,
    retry_delays_seconds: tuple[int, ...] = (5, 10),
    ordering_key: str | None = None,
) -> str:
    return engine.enqueue_delivery(
        edge_id="lims-to-venus",
        ordering_key=ordering_key or f"workflow-{suffix}",
        source_event_id=source_event_id,
        target_provider_id="venus",
        target_operation_id="initialize_run",
        target_principal_context_id="automation-service",
        request={"run_id": suffix},
        available_at=available_at,
        retry_delays_seconds=retry_delays_seconds,
        correlation_ids={"workflow": f"wf-{suffix}"},
        idempotency_key=f"delivery-{suffix}",
    )


def _delivered(receipt: str = "ok") -> DeliveryOutcome:
    return DeliveryOutcome(kind="delivered", receipt={"provider_receipt": receipt}, status_code=201)


def _retryable(code: str = "provider_busy") -> DeliveryOutcome:
    return DeliveryOutcome(
        kind="retryable_failure",
        receipt={"provider_receipt": "rejected"},
        status_code=503,
        error_code=code,
        error_message="Provider asked the caller to retry.",
    )


def test_reset_replay_is_deterministic_and_export_validates(tmp_path: Path) -> None:
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas" / "session-event-export-v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    with _engine(tmp_path) as engine:
        source = _source(engine)
        delivery = _delivery(engine, source)
        result = engine.run_due(lambda command: _delivered(command.delivery_id))
        assert result is not None and result.delivery_state == "delivered"
        first = engine.export()
        jsonschema.Draft202012Validator(schema).validate(first)

        engine.reset()
        source_again = _source(engine)
        delivery_again = _delivery(engine, source_again)
        engine.run_due(lambda command: _delivered(command.delivery_id))
        second = engine.export()

    assert source_again == source
    assert delivery_again == delivery
    assert second == first

    invalid = json.loads(json.dumps(first))
    invalid["deliveries"][0]["attempts"][0]["finished_at"] = None
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(schema).validate(invalid)


def test_due_order_is_available_time_then_enqueue_sequence(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        first_source = _source(engine, suffix="1")
        second_source = _source(engine, suffix="2")
        late = _delivery(
            engine,
            first_source,
            suffix="1",
            available_at="2026-08-25T00:00:10Z",
        )
        early = _delivery(engine, second_source, suffix="2")
        observed: list[str] = []
        engine.run_due(lambda command: observed.append(command.delivery_id) or _delivered())
        assert observed == [early]
        assert engine.run_due(lambda _: _delivered()) is None
        engine.advance_to("2026-08-25T00:00:10Z")
        engine.run_due(lambda command: observed.append(command.delivery_id) or _delivered())
        assert observed == [early, late]


def test_exact_duplicates_are_idempotent_and_changed_content_conflicts(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        source = _source(engine)
        assert _source(engine) == source
        with pytest.raises(SessionEventError, match="different content") as source_error:
            engine.record_source_event(
                source_provider_id="lims",
                provider_event_id="run.created.1",
                event_type="run.created",
                payload={"run_id": "changed"},
                correlation_ids={"workflow": "wf-1"},
                idempotency_key="source-1",
            )
        assert source_error.value.code == "session_event_idempotency_conflict"

        delivery = _delivery(engine, source)
        assert _delivery(engine, source) == delivery
        with pytest.raises(SessionEventError, match="different content") as delivery_error:
            engine.enqueue_delivery(
                edge_id="lims-to-venus",
                ordering_key="workflow-1",
                source_event_id=source,
                target_provider_id="venus",
                target_operation_id="initialize_run",
                target_principal_context_id="automation-service",
                request={"run_id": "changed"},
                available_at=START,
                retry_delays_seconds=(5, 10),
                correlation_ids={"workflow": "wf-1"},
                idempotency_key="delivery-1",
            )
        assert delivery_error.value.code == "session_event_idempotency_conflict"


def test_source_fanout_is_atomic_and_idempotent(tmp_path: Path) -> None:
    def request(suffix: str, *, idempotency_key: str) -> DeliveryRequest:
        return DeliveryRequest(
            edge_id=f"lims-to-target-{suffix}",
            ordering_key="workflow-atomic",
            target_provider_id=f"target-{suffix}",
            target_operation_id="create_run",
            target_principal_context_id="integration-service",
            request={"run_id": "atomic"},
            available_at=START,
            retry_delays_seconds=(5,),
            correlation_ids={"workflow": "wf-atomic"},
            idempotency_key=idempotency_key,
        )

    with _engine(tmp_path) as engine:
        arguments = {
            "source_provider_id": "lims",
            "provider_event_id": "run.created.atomic",
            "event_type": "run.created",
            "payload": {"run_id": "atomic"},
            "correlation_ids": {"workflow": "wf-atomic"},
            "idempotency_key": "source-atomic",
            "deliveries": (
                request("one", idempotency_key="fanout-one"),
                request("two", idempotency_key="fanout-two"),
            ),
        }
        first = engine.record_source_event_with_deliveries(**arguments)
        second = engine.record_source_event_with_deliveries(**arguments)
        assert second == first
        assert (
            engine.source_event_identity(
                source_provider_id="lims", provider_event_id="run.created.atomic"
            )
            == first[0]
        )
        exported = engine.export()
        assert len(exported["source_events"]) == 1
        assert len(exported["deliveries"]) == 2


def test_source_fanout_rolls_back_all_rows_on_delivery_conflict(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        prior_source = _source(engine, suffix="prior")
        engine.enqueue_delivery(
            edge_id="shared-edge",
            ordering_key="prior",
            source_event_id=prior_source,
            target_provider_id="target",
            target_operation_id="create_run",
            target_principal_context_id="integration-service",
            request={"run_id": "prior"},
            available_at=START,
            retry_delays_seconds=(),
            idempotency_key="already-used",
        )
        before = engine.export()
        with pytest.raises(SessionEventError) as conflict:
            engine.record_source_event_with_deliveries(
                source_provider_id="lims",
                provider_event_id="run.created.new",
                event_type="run.created",
                payload={"run_id": "new"},
                idempotency_key="source-new",
                deliveries=(
                    DeliveryRequest(
                        edge_id="free-edge",
                        ordering_key="new",
                        target_provider_id="target",
                        target_operation_id="create_run",
                        target_principal_context_id="integration-service",
                        request={"run_id": "new"},
                        available_at=START,
                        retry_delays_seconds=(),
                        idempotency_key="free",
                    ),
                    DeliveryRequest(
                        edge_id="shared-edge",
                        ordering_key="new",
                        target_provider_id="target",
                        target_operation_id="create_run",
                        target_principal_context_id="integration-service",
                        request={"run_id": "new"},
                        available_at=START,
                        retry_delays_seconds=(),
                        idempotency_key="already-used",
                    ),
                ),
            )
        assert conflict.value.code == "session_event_delivery_conflict"
        assert engine.export() == before


def test_outcome_and_durable_followup_commit_together_then_recover(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    parent = _delivery(engine, _source(engine))

    def effects(command, outcome, state):
        assert command.delivery_id == parent
        assert outcome.kind == "delivered"
        assert state == "delivered"
        return (
            SourceFanoutRequest(
                source_provider_id="venus",
                provider_event_id="run.initialized.1",
                event_type="run.initialized",
                payload={"run_id": "1"},
                correlation_ids={"workflow": "wf-1"},
                idempotency_key="venus-source-1",
                deliveries=(
                    DeliveryRequest(
                        edge_id="venus-to-robot",
                        ordering_key="workflow-1",
                        target_provider_id="robot",
                        target_operation_id="start_run",
                        target_principal_context_id="automation-service",
                        request={"path": "/runs/1/start"},
                        available_at=START,
                        retry_delays_seconds=(5,),
                        correlation_ids={"workflow": "wf-1"},
                        idempotency_key="robot-delivery-1",
                    ),
                ),
            ),
        )

    result = engine.run_due(lambda _: _delivered(), effect_factory=effects)
    assert result is not None and result.delivery_state == "delivered"
    before_recovery = engine.export()
    assert len(before_recovery["source_events"]) == 1
    assert len(before_recovery["deliveries"]) == 1
    assert before_recovery["post_outcome_effects"][0]["state"] == "pending"
    engine.close()

    with _engine(tmp_path) as recovered:
        applied = recovered.apply_pending_effects()
        assert len(applied) == 1
        exported = recovered.export()
        assert len(exported["source_events"]) == 2
        assert len(exported["deliveries"]) == 2
        assert exported["post_outcome_effects"][0]["state"] == "applied"
        assert recovered.apply_pending_effects() == ()


def test_terminal_outcome_persists_compensation_delivery_before_commit(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        source = _source(engine)
        parent = _delivery(engine, source, retry_delays_seconds=())

        def effects(command, _outcome, state):
            assert command.delivery_id == parent and state == "terminal_failure"
            return (
                ExistingSourceDeliveryRequest(
                    source_event_id=source,
                    delivery=DeliveryRequest(
                        edge_id="undo-lims-to-venus",
                        ordering_key="workflow-1",
                        target_provider_id="lims",
                        target_operation_id="mark_failed",
                        target_principal_context_id="automation-service",
                        request={"run_id": "1"},
                        available_at=START,
                        retry_delays_seconds=(),
                        idempotency_key="compensate-1",
                    ),
                ),
            )

        result = engine.run_due(
            lambda _: DeliveryOutcome(
                kind="terminal_failure",
                receipt={"rejected": True},
                error_code="invalid",
                error_message="Target rejected the delivery.",
            ),
            effect_factory=effects,
        )
        assert result is not None and result.delivery_state == "terminal_failure"
        assert engine.export()["post_outcome_effects"][0]["state"] == "pending"
        engine.apply_pending_effects()
        exported = engine.export()
        assert len(exported["deliveries"]) == 2
        assert exported["deliveries"][1]["edge_id"] == "undo-lims-to-venus"


def test_effect_factory_failure_leaves_claim_unknown_without_partial_effects(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path)
    _delivery(engine, _source(engine))

    def fail_effects(*_args):
        raise RuntimeError("must not escape into durable evidence")

    with pytest.raises(RuntimeError, match="must not escape"):
        engine.run_due(lambda _: _delivered(), effect_factory=fail_effects)
    assert engine.export()["post_outcome_effects"] == []
    engine.close()
    with _engine(tmp_path) as recovered:
        exported = recovered.export()
        assert exported["deliveries"][0]["state"] == "unknown_completion"
        assert exported["post_outcome_effects"] == []


def test_unknown_resolution_commits_confirmed_followup_to_durable_outbox(
    tmp_path: Path,
) -> None:
    with _engine(tmp_path) as engine:
        parent = _delivery(engine, _source(engine))
        engine.run_due(
            lambda _: DeliveryOutcome(
                kind="unknown_completion",
                receipt={"timeout": True},
                error_code="timeout_after_send",
                error_message="No response arrived after the request was sent.",
            )
        )

        def effects(_command, outcome, state):
            assert outcome.kind == "delivered" and state == "delivered"
            return (
                SourceFanoutRequest(
                    source_provider_id="venus",
                    provider_event_id="confirmed.run.1",
                    event_type="run.initialized",
                    payload={"run_id": "1"},
                    deliveries=(
                        DeliveryRequest(
                            edge_id="venus-to-robot",
                            ordering_key="workflow-1",
                            target_provider_id="robot",
                            target_operation_id="start_run",
                            target_principal_context_id="automation-service",
                            request={"run_id": "1"},
                            available_at=START,
                            retry_delays_seconds=(),
                            idempotency_key="confirmed-child-1",
                        ),
                    ),
                    idempotency_key="confirmed-source-1",
                ),
            )

        result = engine.resolve_unknown(parent, _delivered("confirmed"), effect_factory=effects)
        assert result.delivery_state == "delivered"
        pending = engine.export()["post_outcome_effects"][0]
        assert pending["origin_kind"] == "resolution"
        assert pending["state"] == "pending"
        engine.apply_pending_effects()
        assert len(engine.export()["deliveries"]) == 2


def test_retry_schedule_is_explicit_and_exhaustion_is_terminal(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        delivery = _delivery(engine, _source(engine), retry_delays_seconds=(5, 10))
        first = engine.run_due(lambda _: _retryable())
        assert first is not None
        assert first.delivery_state == "retry_scheduled"
        assert first.next_available_at == "2026-08-25T00:00:05.000000Z"
        assert engine.run_due(lambda _: _retryable()) is None

        engine.advance_to("2026-08-25T00:00:05Z")
        second = engine.run_due(lambda _: _retryable())
        assert second is not None
        assert second.next_available_at == "2026-08-25T00:00:15.000000Z"

        engine.advance_to("2026-08-25T00:00:15Z")
        third = engine.run_due(lambda _: _retryable())
        assert third is not None
        assert third.attempt_outcome == "retryable_failure"
        assert third.delivery_state == "terminal_failure"
        assert third.next_available_at is None
        record = engine.export()["deliveries"][0]
        assert record["delivery_id"] == delivery
        assert [attempt["outcome"] for attempt in record["attempts"]] == [
            "retryable_failure",
            "retryable_failure",
            "retryable_failure",
        ]
        assert [attempt["retry_delay_seconds"] for attempt in record["attempts"]] == [
            5,
            10,
            None,
        ]


def test_unknown_completion_never_retries_without_trusted_resolution(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        delivery = _delivery(engine, _source(engine))
        result = engine.run_due(
            lambda _: DeliveryOutcome(
                kind="unknown_completion",
                receipt={"timeout": True},
                error_code="timeout_after_send",
                error_message="No response arrived after the request was sent.",
            )
        )
        assert result is not None and result.delivery_state == "unknown_completion"
        engine.advance_to("2026-08-26T00:00:00Z")
        assert engine.run_due(lambda _: _delivered()) is None

        resolution = engine.resolve_unknown(delivery, _retryable("confirmed_not_applied"))
        assert resolution.delivery_state == "retry_scheduled"
        assert resolution.next_available_at == "2026-08-25T00:00:05.000000Z"
        retried = engine.run_due(
            lambda _: DeliveryOutcome(
                kind="unknown_completion",
                receipt={"timeout": "second-attempt"},
                error_code="second_timeout_after_send",
                error_message="The retried request also lost its response.",
            )
        )
        assert retried is not None and retried.attempt_number == 2
        assert retried.delivery_state == "unknown_completion"
        final = engine.resolve_unknown(delivery, _delivered("provider-lookup"))
        assert final.delivery_state == "delivered"
        exported = engine.export()["deliveries"][0]
        assert exported["resolutions"][0]["outcome"] == "retryable_failure"
        assert exported["resolutions"][1]["outcome"] == "delivered"
        assert exported["state"] == "delivered"


def test_dead_in_flight_owner_reopens_as_unknown_not_retryable(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    delivery = _delivery(engine, _source(engine))

    def crash_after_claim(_: object) -> DeliveryOutcome:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        engine.run_due(crash_after_claim)
    assert engine.export()["deliveries"][0]["state"] == "in_flight"
    engine.close()

    with _engine(tmp_path) as reopened:
        record = reopened.export()["deliveries"][0]
        assert record["delivery_id"] == delivery
        assert record["state"] == "unknown_completion"
        assert record["attempts"][0]["outcome"] == "unknown_completion"
        assert record["attempts"][0]["error_code"] == "delivery_owner_lost"
        assert reopened.run_due(lambda _: _delivered()) is None
        resolved = reopened.resolve_unknown(delivery, _delivered("provider-lookup"))
        assert resolved.delivery_state == "delivered"


def test_two_live_engines_claim_each_delivery_once(tmp_path: Path) -> None:
    first = _engine(tmp_path)
    second = _engine(tmp_path)
    try:
        first_delivery = _delivery(first, _source(first, suffix="1"), suffix="1")
        second_delivery = _delivery(first, _source(first, suffix="2"), suffix="2")
        first_started = threading.Event()
        release_first = threading.Event()
        results: list[str] = []

        def blocking_executor(command: object) -> DeliveryOutcome:
            results.append(command.delivery_id)  # type: ignore[attr-defined]
            first_started.set()
            assert release_first.wait(timeout=5)
            return _delivered()

        worker = threading.Thread(target=lambda: first.run_due(blocking_executor), daemon=True)
        worker.start()
        assert first_started.wait(timeout=5)
        other = second.run_due(lambda command: results.append(command.delivery_id) or _delivered())
        assert other is not None
        release_first.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert sorted(results) == sorted([first_delivery, second_delivery])
        assert first.export()["deliveries"][0]["state"] == "delivered"
        assert first.export()["deliveries"][1]["state"] == "delivered"
    finally:
        first.close()
        second.close()


def test_same_ordering_stream_blocks_later_delivery_until_predecessor_finishes(
    tmp_path: Path,
) -> None:
    first = _engine(tmp_path)
    second = _engine(tmp_path)
    try:
        earlier = _delivery(
            first,
            _source(first, suffix="1"),
            suffix="1",
            ordering_key="workflow",
        )
        later = _delivery(
            first,
            _source(first, suffix="2"),
            suffix="2",
            ordering_key="workflow",
        )
        started = threading.Event()
        release = threading.Event()

        def blocked(command: object) -> DeliveryOutcome:
            assert command.delivery_id == earlier  # type: ignore[attr-defined]
            started.set()
            assert release.wait(timeout=5)
            return _delivered()

        worker = threading.Thread(target=lambda: first.run_due(blocked), daemon=True)
        worker.start()
        assert started.wait(timeout=5)
        assert second.run_due(lambda _: _delivered()) is None
        release.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        result = second.run_due(lambda _: _delivered())
        assert result is not None and result.delivery_id == later
    finally:
        first.close()
        second.close()


def test_unknown_predecessor_blocks_its_ordering_stream_until_resolution(
    tmp_path: Path,
) -> None:
    with _engine(tmp_path) as engine:
        first = _delivery(
            engine,
            _source(engine, suffix="1"),
            suffix="1",
            ordering_key="workflow",
        )
        later = _delivery(
            engine,
            _source(engine, suffix="2"),
            suffix="2",
            ordering_key="workflow",
        )
        unknown = engine.run_due(
            lambda _: DeliveryOutcome(
                kind="unknown_completion",
                receipt={"timeout": True},
                error_code="timeout_after_send",
                error_message="The response did not arrive.",
            )
        )
        assert unknown is not None and unknown.delivery_id == first
        assert engine.run_due(lambda _: _delivered()) is None
        engine.resolve_unknown(first, _delivered("provider-lookup"))
        delivered = engine.run_due(lambda _: _delivered())
        assert delivered is not None and delivered.delivery_id == later


def test_partial_failures_do_not_block_independent_deliveries(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        failed = _delivery(engine, _source(engine, suffix="1"), suffix="1")
        delivered = _delivery(engine, _source(engine, suffix="2"), suffix="2")
        first = engine.run_due(
            lambda _: DeliveryOutcome(
                kind="terminal_failure",
                receipt={"provider_receipt": "invalid"},
                status_code=422,
                error_code="invalid_mapping",
                error_message="The declared mapping was rejected.",
            )
        )
        second = engine.run_due(lambda _: _delivered())
        assert first is not None and first.delivery_id == failed
        assert second is not None and second.delivery_id == delivered
        assert [item["state"] for item in engine.export()["deliveries"]] == [
            "terminal_failure",
            "delivered",
        ]


def test_reverse_clock_and_invalid_outcomes_are_structured(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        engine.advance_to("2026-08-25T01:00:00Z")
        with pytest.raises(SessionEventError) as reverse:
            engine.advance_to(START)
        assert reverse.value.code == "session_event_reverse_time_forbidden"

        _delivery(engine, _source(engine), available_at="2026-08-25T01:00:00Z")
        result = engine.run_due(lambda _: object())  # type: ignore[arg-type,return-value]
        assert result is not None and result.delivery_state == "unknown_completion"
        attempt = engine.export()["deliveries"][0]["attempts"][0]
        assert attempt["error_code"] == "session_event_executor_outcome_invalid"


def test_retry_preserves_immutable_delivery_content_digest(tmp_path: Path) -> None:
    with _engine(tmp_path) as engine:
        delivery = _delivery(engine, _source(engine), retry_delays_seconds=(5,))
        engine.run_due(lambda _: _retryable())
        record = engine.export()["deliveries"][0]

    assert record["delivery_id"] == delivery
    assert record["initial_available_at"] == "2026-08-25T00:00:00.000000Z"
    assert record["available_at"] == "2026-08-25T00:00:05.000000Z"
    assert record["content_digest"] == _digest(
        {
            "episode_seed": "episode-0042",
            "edge_id": "lims-to-venus",
            "idempotency_key": "delivery-1",
            "source_event_id": record["source_event_id"],
            "ordering_key": "workflow-1",
            "target_provider_id": "venus",
            "target_operation_id": "initialize_run",
            "target_principal_context_id": "automation-service",
            "request": {"run_id": "1"},
            "initial_available_at": "2026-08-25T00:00:00.000000Z",
            "retry_delays_seconds": [5],
            "correlation_ids": {"workflow": "wf-1"},
        }
    )


def test_executor_exception_text_is_not_persisted(tmp_path: Path) -> None:
    secret = "credential-that-must-not-enter-evidence"
    with _engine(tmp_path) as engine:
        _delivery(engine, _source(engine))

        def fail(_: object) -> DeliveryOutcome:
            raise RuntimeError(secret)

        result = engine.run_due(fail)
        exported = engine.export()

    assert result is not None and result.delivery_state == "unknown_completion"
    assert secret not in json.dumps(exported)
    attempt = exported["deliveries"][0]["attempts"][0]
    assert attempt["error_code"] == "delivery_executor_exception"
    assert attempt["error_message"] == (
        "The delivery executor did not produce a trusted completion outcome."
    )


def test_session_storage_files_are_private_and_symlinks_are_rejected(tmp_path: Path) -> None:
    database = tmp_path / "private-state" / "events.sqlite3"
    engine = SessionEventEngine(database, episode_seed="episode-0042", initial_time=START)
    try:
        assert stat.S_IMODE(database.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(database.stat().st_mode) == 0o600
        assert stat.S_IMODE(engine._owner_lock_path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(engine._owner_lock_path.stat().st_mode) == 0o600
    finally:
        owner_lock = engine._owner_lock_path
        engine.close()
    assert not owner_lock.exists()

    target = tmp_path / "target.sqlite3"
    target.touch(mode=0o600)
    link = tmp_path / "linked.sqlite3"
    os.symlink(target, link)
    with pytest.raises(SessionEventError) as unsafe:
        SessionEventEngine(link, episode_seed="episode-0042", initial_time=START)
    assert unsafe.value.code == "session_event_storage_file_unsafe"


def test_aggregate_json_quota_is_enforced_transactionally(tmp_path: Path) -> None:
    payload = {"blob": "x" * 250_000}
    with _engine(tmp_path) as engine:
        inserted = 0
        while True:
            try:
                engine.record_source_event(
                    source_provider_id="lims",
                    provider_event_id=f"large.{inserted}",
                    event_type="large",
                    payload=payload,
                )
            except SessionEventError as exc:
                assert exc.code == "session_event_json_quota_reached"
                break
            inserted += 1
        assert inserted > 1
        connection = engine._connection()
        try:
            stored = connection.execute(
                "SELECT stored_json_bytes FROM session_metadata WHERE singleton = 1"
            ).fetchone()[0]
        finally:
            connection.close()
        assert stored <= MAX_SESSION_STORED_JSON_BYTES


def test_export_preflight_rejects_oversized_in_memory_export(tmp_path: Path) -> None:
    payload = {"blob": "x" * 220_000}
    with _engine(tmp_path) as engine:
        for index in range(26):
            engine.record_source_event(
                source_provider_id="lims",
                provider_event_id=f"export.{index}",
                event_type="large",
                payload=payload,
            )
        with pytest.raises(SessionEventError) as oversized:
            engine.export()
    assert oversized.value.code == "session_event_export_too_large"
    assert oversized.value.details["max_bytes"] == MAX_SESSION_EVENT_EXPORT_BYTES
