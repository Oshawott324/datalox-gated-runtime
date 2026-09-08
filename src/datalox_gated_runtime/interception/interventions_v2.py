"""Durable transport-level delivery interventions for admitted reads and writes."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol

from datalox_gated_runtime.data_plane import (
    NoResponseTransportDirective,
    TrackedResponseTransportDirective,
)
from datalox_gated_runtime.interception.interventions import ProviderBaseBinding
from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.models import CallRequest, GateDecision, GateResponse
from datalox_gated_runtime.provider_runtime.identity import (
    IdentityPolicy,
    redact_external_request,
)

DELIVERY_INTERVENTION_V2_SCHEMA_VERSION = "datalox_delivery_intervention_v2"
DELIVERY_INTERVENTION_V2_POLICY_SCHEMA_VERSION = "datalox_delivery_intervention_policy_v2"
DELIVERY_INTERVENTION_V2_TRACE_SCHEMA_VERSION = "datalox_delivery_intervention_trace_v2"
DELIVERY_INTERVENTION_V2_MAX_JSON_BYTES = 2 * 1024 * 1024

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class DeliveryInterventionV2Error(ValueError):
    """A v2 policy, durable record, or transport lifecycle failed closed."""


class DeliveryInterventionResetConflict(DeliveryInterventionV2Error):
    """Reset was requested while a provider transport outcome is still pending."""


@dataclass(frozen=True)
class NoResponseAction:
    phase: str


@dataclass(frozen=True)
class InterventionDecisionV2:
    decision_id: str
    operation_id: str
    action: NoResponseAction


class DeliveryInterventionPolicyV2(Protocol):
    policy_id: str
    policy_version: str
    policy_sha256: str

    def decide(
        self,
        *,
        seed: str,
        logical_request_index: int,
        operation_id: str,
        request: CallRequest,
    ) -> InterventionDecisionV2 | None: ...


@dataclass(frozen=True)
class ScheduledDeliveryInterventionPolicyV2:
    policy_id: str
    policy_version: str
    policy_sha256: str
    schedules: Mapping[str, Mapping[int, InterventionDecisionV2]]

    def decide(
        self,
        *,
        seed: str,
        logical_request_index: int,
        operation_id: str,
        request: CallRequest,
    ) -> InterventionDecisionV2 | None:
        del operation_id, request
        schedule = self.schedules.get(seed)
        if schedule is None:
            raise DeliveryInterventionV2Error("the intervention policy does not declare this seed")
        return schedule.get(logical_request_index)


@dataclass(frozen=True)
class LoadedDeliveryInterventionV2:
    provider_id: str
    enabled: bool
    seed: str
    policy: ScheduledDeliveryInterventionPolicyV2
    path: Path


class _DecisionJournal:
    """SQLite journal whose commits bracket dispatch and transport completion."""

    def __init__(self, path: Path, *, lifecycle: Literal["create", "resume"]) -> None:
        if lifecycle == "create" and (path.exists() or path.is_symlink()):
            raise DeliveryInterventionV2Error("v2 decision journal must not already exist")
        if lifecycle == "resume" and (path.is_symlink() or not path.is_file()):
            raise DeliveryInterventionV2Error("v2 decision journal is unavailable for resume")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        if lifecycle == "create":
            self.connection.execute(
                """
                CREATE TABLE events (
                    logical_request_index INTEGER PRIMARY KEY,
                    phase TEXT NOT NULL,
                    event_json TEXT NOT NULL
                )
                """
            )
            self.connection.execute(
                "CREATE TABLE session_state (key TEXT PRIMARY KEY, value_json TEXT NOT NULL)"
            )
        else:
            tables = {
                row[0]
                for row in self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            if not {"events", "session_state"}.issubset(tables):
                raise DeliveryInterventionV2Error("v2 decision journal schema is invalid")

    def insert_decision(self, index: int, event: dict[str, Any]) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                "INSERT INTO events(logical_request_index, phase, event_json) VALUES (?, ?, ?)",
                (index, "decision_recorded", _canonical_text(event)),
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def update(self, index: int, phase: str, event: dict[str, Any]) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = self.connection.execute(
                "UPDATE events SET phase = ?, event_json = ? WHERE logical_request_index = ?",
                (phase, _canonical_text(event), index),
            )
            if cursor.rowcount != 1:
                raise DeliveryInterventionV2Error("decision journal event is unavailable")
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def events(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT event_json FROM events ORDER BY logical_request_index"
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def clear(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute("DELETE FROM events")
            self.connection.execute("DELETE FROM session_state WHERE key = 'terminal_failure'")
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def set_terminal(self, failure: dict[str, Any]) -> None:
        self.set_state("terminal_failure", failure)

    def set_state(self, key: str, value: dict[str, Any]) -> None:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute(
                """
                INSERT INTO session_state(key, value_json) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
                """,
                (key, _canonical_text(value)),
            )
            self.connection.execute("COMMIT")
        except BaseException:
            self.connection.execute("ROLLBACK")
            raise

    def state(self, key: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT value_json FROM session_state WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else json.loads(row[0])

    def close(self) -> None:
        self.connection.close()


class DeliveryInterventionSessionV2:
    """One controller-fixed, durable, transport-level intervention session."""

    def __init__(
        self,
        policy: DeliveryInterventionPolicyV2,
        *,
        provider: ProviderBaseBinding,
        operation_mutability: Mapping[str, str],
        seed: str,
        enabled: bool,
        journal_path: Path,
        identity_policy: IdentityPolicy | None = None,
        lifecycle: Literal["create", "resume"] = "create",
    ) -> None:
        _validate_policy_identity(policy)
        _validate_provider_binding(provider)
        _validate_operation_mutability(operation_mutability)
        if not isinstance(seed, str) or not seed or len(seed) > 256:
            raise DeliveryInterventionV2Error(
                "intervention seed must be a bounded non-empty string"
            )
        if type(enabled) is not bool:
            raise DeliveryInterventionV2Error("intervention enabled mode must be a boolean")
        self.policy = policy
        self.provider = provider
        self.operation_mutability = dict(operation_mutability)
        self.operation_contract_sha256 = canonical_json_sha256(self.operation_mutability)
        self.identity_policy = identity_policy
        self.identity_policy_sha256 = canonical_json_sha256(
            {"mode": "standard_secret_headers_only"}
            if identity_policy is None
            else identity_policy.to_dict()
        )
        self.seed = seed
        self.enabled = enabled
        if lifecycle not in {"create", "resume"}:
            raise DeliveryInterventionV2Error("intervention lifecycle must be create or resume")
        self._journal = _DecisionJournal(journal_path, lifecycle=lifecycle)
        self._lock = threading.Lock()
        self._next_request_index = 1
        self._pending: dict[str, int] = {}
        self._aborted_transport_ids: set[str] = set()
        self._terminal_failure: dict[str, Any] | None = None
        self._closed = False
        binding = {
            "schema_version": DELIVERY_INTERVENTION_V2_SCHEMA_VERSION,
            "provider": _provider_payload(provider),
            "operation_mutability": dict(sorted(self.operation_mutability.items())),
            "policy_id": policy.policy_id,
            "policy_version": policy.policy_version,
            "policy_sha256": policy.policy_sha256,
            "seed": seed,
            "enabled": enabled,
            "identity_policy_sha256": self.identity_policy_sha256,
        }
        if lifecycle == "create":
            self._journal.set_state("binding", binding)
        elif self._journal.state("binding") != binding:
            self._journal.close()
            raise DeliveryInterventionV2Error("resumed v2 journal binding does not match")
        else:
            events = self._journal.events()
            self._next_request_index = 1 + max(
                (event["logical_request_index"] for event in events), default=0
            )
            self._terminal_failure = self._journal.state("terminal_failure")
            incomplete = [
                event
                for event in events
                if event["outcome"] in {"decision_recorded", "transport_pending"}
            ]
            if incomplete:
                failure = {
                    "logical_request_index": incomplete[0]["logical_request_index"],
                    "code": "delivery_intervention_v2_process_loss",
                    "message": (
                        "Process loss ended an incomplete delivery record; dispatch or client "
                        "completion may be unknown and reset is required."
                    ),
                }
                for event in incomplete:
                    if event["outcome"] == "decision_recorded":
                        event["base"].update(
                            {
                                "invoked": None,
                                "completion_certainty": "unknown",
                                "provider_state_after_sha256": None,
                                "provider_state_relation": "unknown",
                            }
                        )
                    event["outcome"] = "transport_aborted"
                    if (
                        isinstance(event.get("delivered"), dict)
                        and event["delivered"].get("kind") == "response"
                    ):
                        event["delivered"].update(
                            {
                                "transport_status": "process_loss_aborted",
                                "client_completion_certainty": "unknown",
                            }
                        )
                    else:
                        event["delivered"] = _no_response_payload("process_loss_aborted")
                    event["error"] = {"code": failure["code"], "message": failure["message"]}
                    self._journal.update(event["logical_request_index"], "transport_aborted", event)
                self._terminal_failure = failure
                self._journal.set_terminal(failure)

    @property
    def admitted_operation_ids(self) -> frozenset[str]:
        return frozenset(self.operation_mutability)

    def handle(
        self,
        request: CallRequest,
        invoke_base: Callable[[], GateResponse],
        observe_provider_state: Callable[[], str],
        *,
        operation_id: str,
    ) -> GateResponse | NoResponseTransportDirective | TrackedResponseTransportDirective:
        """Evaluate once, journal before dispatch, and never retry the base."""

        with self._lock:
            self._require_operation(operation_id)
            if self._terminal_failure is not None:
                return self._terminal_response(operation_id)
            index = self._next_request_index
            self._next_request_index += 1
            decision: InterventionDecisionV2 | None = None
            decision_valid = False
            pre_state_sha256: str | None = None
            try:
                decision = self.policy.decide(
                    seed=self.seed,
                    logical_request_index=index,
                    operation_id=operation_id,
                    request=request,
                )
                _validate_decision(decision, index=index, operation_id=operation_id)
                decision_valid = True
                pre_state_sha256 = _state_digest(observe_provider_state())
                event = self._decision_event(
                    index=index,
                    operation_id=operation_id,
                    decision=decision,
                    pre_state_sha256=pre_state_sha256,
                    request_sha256=_request_sha256(request, self.identity_policy),
                )
                self._journal.insert_decision(index, event)
            except Exception:  # noqa: BLE001 - policy, state observer, and journal are boundaries
                failure = {
                    "logical_request_index": index,
                    "code": "delivery_intervention_v2_decision_record_failed",
                    "message": "The intervention decision could not be durably recorded.",
                }
                self._terminal_failure = failure
                failure_event = self._pre_dispatch_failure_event(
                    index=index,
                    operation_id=operation_id,
                    request=request,
                    decision=decision if decision_valid else None,
                    pre_state_sha256=pre_state_sha256,
                    failure=failure,
                )
                try:
                    self._journal.insert_decision(index, failure_event)
                except Exception:  # noqa: BLE001, S110 - the journal is already unusable
                    pass
                try:
                    self._journal.set_terminal(failure)
                except Exception:  # noqa: BLE001, S110 - in-memory terminal state remains closed
                    pass
                return self._terminal_response(operation_id)

            action = None if decision is None else decision.action
            if self.enabled and action is not None and action.phase == "pre_dispatch":
                event["applied"] = True
                event["outcome"] = "transport_pending"
                event["base"].update(
                    {
                        "completion_certainty": "not_dispatched",
                        "provider_state_after_sha256": pre_state_sha256,
                        "provider_state_relation": "unchanged",
                    }
                )
                event["delivered"] = _no_response_payload("pending")
                return self._register_pending(index, event)

            try:
                base = invoke_base()
                if not isinstance(base, GateResponse):
                    raise TypeError("base provider returned a non-GateResponse outcome")
                post_state_sha256 = _state_digest(observe_provider_state())
            except Exception:  # noqa: BLE001 - an unbound plugin outcome means unknown completion
                try:
                    after = _state_digest(observe_provider_state())
                except Exception:  # noqa: BLE001 - state certainty is explicitly recorded unknown
                    after = None
                event["base"].update(
                    {
                        "invoked": True,
                        "completion_certainty": "unknown",
                        "provider_state_after_sha256": after,
                        "provider_state_relation": (
                            "unknown"
                            if after is None
                            else "unchanged"
                            if after == pre_state_sha256
                            else "changed"
                        ),
                    }
                )
                return self._terminal_no_response_after_base(
                    index=index,
                    event=event,
                    code="delivery_intervention_v2_base_completion_unknown",
                    message=(
                        "The base provider invocation ended without a bound response; "
                        "client completion is unknown."
                    ),
                )

            event["base"] = {
                "invoked": True,
                "completion_certainty": "known_completed",
                "event_id": base.event_id,
                "response_sha256": _response_sha256(base),
                "response": _response_payload(base),
                "provider_state_before_sha256": pre_state_sha256,
                "provider_state_after_sha256": post_state_sha256,
                "provider_state_relation": (
                    "unchanged" if pre_state_sha256 == post_state_sha256 else "changed"
                ),
            }
            if self.enabled and action is not None and action.phase == "post_dispatch":
                event["applied"] = True
                event["outcome"] = "transport_pending"
                event["delivered"] = _no_response_payload("pending")
                return self._register_pending(index, event)

            event["outcome"] = "transport_pending"
            event["delivered"] = _response_transport_payload(base, "pending", False, 0)
            return self._register_response_pending(index, event, base)

    def ensure_resettable(self) -> None:
        with self._lock:
            if self._pending:
                raise DeliveryInterventionResetConflict(
                    "provider reset is blocked until all transport outcomes finish"
                )

    def reset(self) -> dict[str, Any]:
        with self._lock:
            if self._pending:
                raise DeliveryInterventionResetConflict(
                    "provider reset is blocked until all transport outcomes finish"
                )
            self._journal.clear()
            self._next_request_index = 1
            self._terminal_failure = None
            self._aborted_transport_ids.clear()
            return self._export_unlocked()

    def export(self) -> dict[str, Any]:
        with self._lock:
            return self._export_unlocked()

    def latch_reset_failure(self, message: str) -> None:
        with self._lock:
            failure = {
                "logical_request_index": self._next_request_index,
                "code": "delivery_intervention_v2_reset_desynchronized",
                "message": message,
            }
            self._terminal_failure = failure
            self._journal.set_terminal(failure)

    def shutdown(self) -> None:
        """Durably abort pending transports, then close the journal."""

        with self._lock:
            if self._closed:
                return
            failure: Exception | None = None
            for outcome_id, index in tuple(self._pending.items()):
                try:
                    event = self._event_at(index)
                    event["outcome"] = "transport_aborted"
                    if (
                        isinstance(event.get("delivered"), dict)
                        and event["delivered"].get("kind") == "response"
                    ):
                        event["delivered"].update(
                            {
                                "transport_status": "trusted_shutdown_aborted",
                                "client_completion_certainty": "unknown",
                            }
                        )
                    else:
                        event["delivered"] = _no_response_payload("trusted_shutdown_aborted")
                    event["error"] = {
                        "code": "delivery_intervention_v2_transport_aborted",
                        "message": "The trusted runtime shut down before the transport outcome completed.",
                    }
                    self._journal.update(index, "transport_aborted", event)
                    self._journal.set_terminal(
                        {
                            "logical_request_index": index,
                            "code": event["error"]["code"],
                            "message": event["error"]["message"],
                        }
                    )
                except Exception as exc:  # noqa: BLE001 - continue aborting remaining transports
                    failure = failure or exc
                self._aborted_transport_ids.add(outcome_id)
            self._pending.clear()
            try:
                self._journal.close()
            except Exception as exc:  # noqa: BLE001 - report after attempting journal closure
                failure = failure or exc
            self._closed = True
            if failure is not None:
                raise DeliveryInterventionV2Error(
                    "delivery intervention shutdown could not durably close every outcome"
                ) from failure

    def _register_pending(self, index: int, event: dict[str, Any]) -> NoResponseTransportDirective:
        outcome_id = event["event_id"]
        try:
            self._journal.update(index, "transport_pending", event)
        except Exception:  # noqa: BLE001 - missing durability converts delivery to no-response
            return self._terminal_no_response_after_base(
                index=index,
                event=event,
                code="delivery_intervention_v2_transport_outcome_record_failed",
                message="The no-response transport outcome could not be durably recorded.",
            )
        self._pending[outcome_id] = index
        return NoResponseTransportDirective(
            outcome_id=outcome_id,
            on_disconnect=lambda: self._complete_disconnect(outcome_id),
        )

    def _register_response_pending(
        self,
        index: int,
        event: dict[str, Any],
        response: GateResponse,
    ) -> TrackedResponseTransportDirective | NoResponseTransportDirective:
        outcome_id = event["event_id"]
        try:
            self._journal.update(index, "transport_pending", event)
        except Exception:  # noqa: BLE001 - an unjournaled committed write is withheld
            return self._terminal_no_response_after_base(
                index=index,
                event=event,
                code="delivery_intervention_v2_base_outcome_record_failed",
                message="The committed base outcome could not be durably recorded.",
            )
        self._pending[outcome_id] = index
        return TrackedResponseTransportDirective(
            outcome_id=outcome_id,
            response=response,
            on_asgi_send_completed=lambda started, sent: self._complete_response_transport(
                outcome_id,
                sent=True,
                response_start_sent=started,
                response_body_bytes_sent=sent,
            ),
            on_response_aborted=lambda started, sent: self._complete_response_transport(
                outcome_id,
                sent=False,
                response_start_sent=started,
                response_body_bytes_sent=sent,
            ),
        )

    def _complete_response_transport(
        self,
        outcome_id: str,
        *,
        sent: bool,
        response_start_sent: bool,
        response_body_bytes_sent: int,
    ) -> None:
        with self._lock:
            if outcome_id in self._aborted_transport_ids:
                return
            index = self._pending.get(outcome_id)
            if index is None:
                raise DeliveryInterventionV2Error("response transport outcome is not pending")
            event = self._event_at(index)
            event["outcome"] = "asgi_send_completed" if sent else "transport_aborted"
            event["delivered"].update(
                {
                    "response_start_sent": response_start_sent,
                    "response_body_bytes_sent": response_body_bytes_sent,
                    "transport_status": ("asgi_send_completed" if sent else "send_aborted"),
                    "client_completion_certainty": "unknown",
                }
            )
            if not sent:
                event["error"] = {
                    "code": "delivery_intervention_v2_response_send_aborted",
                    "message": "The provider response transport ended before ASGI accepted the exact response.",
                }
            try:
                self._journal.update(index, event["outcome"], event)
                if not sent:
                    failure = {
                        "logical_request_index": index,
                        "code": event["error"]["code"],
                        "message": event["error"]["message"],
                    }
                    self._terminal_failure = failure
                    self._journal.set_terminal(failure)
            except Exception:  # noqa: BLE001 - transport completion journaling is a boundary
                failure = {
                    "logical_request_index": index,
                    "code": "delivery_intervention_v2_response_send_record_failed",
                    "message": "Response send completion could not be durably recorded.",
                }
                self._terminal_failure = failure
                try:
                    self._journal.set_terminal(failure)
                except Exception:  # noqa: BLE001, S110 - in-memory state remains terminal
                    pass
            self._pending.pop(outcome_id, None)

    def _complete_disconnect(self, outcome_id: str) -> None:
        with self._lock:
            if outcome_id in self._aborted_transport_ids:
                return
            index = self._pending.get(outcome_id)
            if index is None:
                raise DeliveryInterventionV2Error("transport outcome is not pending")
            event = self._event_at(index)
            event["outcome"] = "transport_disconnected"
            event["delivered"] = _no_response_payload("client_disconnected")
            try:
                self._journal.update(index, "transport_disconnected", event)
            except Exception:  # noqa: BLE001 - a disconnect journal failure terminally latches
                failure = {
                    "logical_request_index": index,
                    "code": "delivery_intervention_v2_disconnect_record_failed",
                    "message": "Client disconnect could not be durably recorded.",
                }
                self._terminal_failure = failure
                try:
                    self._journal.set_terminal(failure)
                except Exception:  # noqa: BLE001, S110 - in-memory terminal state remains closed
                    pass
                self._pending.pop(outcome_id)
                return
            self._pending.pop(outcome_id)

    def _terminal_no_response_after_base(
        self,
        *,
        index: int,
        event: dict[str, Any],
        code: str,
        message: str,
    ) -> NoResponseTransportDirective:
        event["outcome"] = "terminal_failure"
        event["delivered"] = _no_response_payload("pending")
        event["error"] = {"code": code, "message": message}
        failure = {"logical_request_index": index, "code": code, "message": message}
        self._terminal_failure = failure
        try:
            self._journal.update(index, "terminal_failure", event)
            self._journal.set_terminal(failure)
        except Exception:  # noqa: BLE001, S110 - the session is already terminal in memory
            pass
        outcome_id = event["event_id"]
        self._pending[outcome_id] = index
        return NoResponseTransportDirective(
            outcome_id=outcome_id,
            on_disconnect=lambda: self._complete_disconnect(outcome_id),
        )

    def _event_at(self, index: int) -> dict[str, Any]:
        return next(
            event for event in self._journal.events() if event["logical_request_index"] == index
        )

    def _require_operation(self, operation_id: str) -> None:
        if operation_id not in self.operation_mutability:
            raise DeliveryInterventionV2Error(
                "operation is outside the session's admitted operation set"
            )

    def _terminal_response(self, operation_id: str) -> GateResponse:
        return GateResponse(
            status_code=503,
            headers={"content-type": "application/json"},
            body={
                "error": {
                    "code": "delivery_intervention_session_terminal",
                    "message": "This provider session requires a trusted reset.",
                }
            },
            decision=GateDecision(
                "deny",
                "delivery_intervention_session_terminal",
                "This provider session requires a trusted reset.",
            ),
            event_id="intv2_terminal_"
            + canonical_json_sha256(
                {
                    "provider_id": self.provider.provider_id,
                    "operation_id": operation_id,
                }
            ).removeprefix("sha256:")[:16],
        )

    def _pre_dispatch_failure_event(
        self,
        *,
        index: int,
        operation_id: str,
        request: CallRequest,
        decision: InterventionDecisionV2 | None,
        pre_state_sha256: str | None,
        failure: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            request_sha256 = _request_sha256(request, self.identity_policy)
        except Exception:  # noqa: BLE001 - malformed request evidence remains unavailable
            request_sha256 = None
        event = self._decision_event(
            index=index,
            operation_id=operation_id,
            decision=decision,
            pre_state_sha256=pre_state_sha256,
            request_sha256=request_sha256,
        )
        event["stage"] = "pre_dispatch"
        event["outcome"] = "terminal_failure"
        event["base"].update(
            {
                "completion_certainty": "not_dispatched",
                "provider_state_after_sha256": pre_state_sha256,
                "provider_state_relation": (
                    "unchanged" if pre_state_sha256 is not None else "unknown"
                ),
            }
        )
        event["error"] = {"code": failure["code"], "message": failure["message"]}
        return event

    def _decision_event(
        self,
        *,
        index: int,
        operation_id: str,
        decision: InterventionDecisionV2 | None,
        pre_state_sha256: str | None,
        request_sha256: str | None,
    ) -> dict[str, Any]:
        action = None if decision is None else decision.action
        return {
            "event_id": _event_id(self, index, operation_id),
            "provider": _provider_payload(self.provider),
            "admitted_operation_mutability_sha256": self.operation_contract_sha256,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "policy_sha256": self.policy.policy_sha256,
            "seed": self.seed,
            "logical_request_index": index,
            "operation_id": operation_id,
            "operation_mutability": self.operation_mutability[operation_id],
            "request_sha256": request_sha256,
            "enabled": self.enabled,
            "decision": {
                "decision_id": None if decision is None else decision.decision_id,
                "kind": "none" if action is None else "no_response",
                "action": (
                    None if action is None else {"kind": "no_response", "phase": action.phase}
                ),
            },
            "stage": "none" if action is None else action.phase,
            "applied": False,
            "outcome": "decision_recorded",
            "base": {
                "invoked": False,
                "completion_certainty": "not_dispatched",
                "event_id": None,
                "response_sha256": None,
                "response": None,
                "provider_state_before_sha256": pre_state_sha256,
                "provider_state_after_sha256": None,
                "provider_state_relation": "unknown",
            },
            "delivered": None,
            "error": None,
        }

    def _export_unlocked(self) -> dict[str, Any]:
        return {
            "schema_version": DELIVERY_INTERVENTION_V2_TRACE_SCHEMA_VERSION,
            "provider": _provider_payload(self.provider),
            "admitted_operations": [
                {"operation_id": key, "mutability": self.operation_mutability[key]}
                for key in sorted(self.operation_mutability)
            ],
            "admitted_operation_mutability_sha256": self.operation_contract_sha256,
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.policy_version,
            "policy_sha256": self.policy.policy_sha256,
            "seed": self.seed,
            "enabled": self.enabled,
            "next_request_index": self._next_request_index,
            "pending_transport_count": len(self._pending),
            "terminal_failure": deepcopy(self._terminal_failure),
            "events": self._journal.events(),
        }


class DeliveryInterventionHandlerV2:
    def __init__(
        self,
        *,
        base_handler: Any,
        session: DeliveryInterventionSessionV2,
        resolve_operation_id: Callable[[CallRequest], str | None],
    ) -> None:
        self.base_handler = base_handler
        self.session = session
        self.resolve_operation_id = resolve_operation_id

    def handle(
        self, request: CallRequest
    ) -> GateResponse | NoResponseTransportDirective | TrackedResponseTransportDirective:
        operation_id = self.resolve_operation_id(request)
        if (
            operation_id is None
            or operation_id not in self.session.admitted_operation_ids
            or any(name.lower().startswith("x-datalox-") for name in request.headers)
        ):
            return self.base_handler.handle(request)
        return self.session.handle(
            request,
            lambda: self.base_handler.handle(request),
            self.base_handler.behavior_state_sha256,
            operation_id=operation_id,
        )


def load_delivery_intervention_v2(path: Path) -> LoadedDeliveryInterventionV2:
    raw, resolved = _load_object(path)
    _require_fields(
        raw,
        {"schema_version", "provider_id", "mode", "seed", "policy", "policy_sha256"},
        "delivery intervention config",
    )
    if raw["schema_version"] != DELIVERY_INTERVENTION_V2_SCHEMA_VERSION:
        raise DeliveryInterventionV2Error("unsupported delivery intervention v2 schema")
    provider_id = _identifier(raw["provider_id"], "provider_id")
    if raw["mode"] not in {"off", "on"}:
        raise DeliveryInterventionV2Error("delivery intervention mode must be off or on")
    seed = raw["seed"]
    if not isinstance(seed, str) or not seed or len(seed) > 256:
        raise DeliveryInterventionV2Error("delivery intervention seed is invalid")
    policy_raw = raw["policy"]
    digest = raw["policy_sha256"]
    if (
        not isinstance(policy_raw, dict)
        or not isinstance(digest, str)
        or not _SHA256.fullmatch(digest)
    ):
        raise DeliveryInterventionV2Error("delivery intervention policy or digest is invalid")
    if canonical_json_sha256(policy_raw) != digest:
        raise DeliveryInterventionV2Error("delivery intervention policy digest does not match")
    policy = _parse_policy(policy_raw, digest)
    if seed not in policy.schedules:
        raise DeliveryInterventionV2Error("selected seed is absent from the intervention policy")
    return LoadedDeliveryInterventionV2(
        provider_id=provider_id,
        enabled=raw["mode"] == "on",
        seed=seed,
        policy=policy,
        path=resolved,
    )


def validate_v2_policy_for_operations(
    policy: ScheduledDeliveryInterventionPolicyV2,
    *,
    operation_mutability: Mapping[str, str],
) -> None:
    _validate_operation_mutability(operation_mutability)
    for schedule in policy.schedules.values():
        for decision in schedule.values():
            if decision.operation_id not in operation_mutability:
                raise DeliveryInterventionV2Error(
                    f"intervention operation is not admitted: {decision.operation_id}"
                )


def intervention_schema_version(path: Path) -> str:
    raw, _ = _load_object(path)
    value = raw.get("schema_version")
    if not isinstance(value, str):
        raise DeliveryInterventionV2Error("delivery intervention schema_version is invalid")
    return value


def _parse_policy(raw: dict[str, Any], digest: str) -> ScheduledDeliveryInterventionPolicyV2:
    _require_fields(raw, {"schema_version", "policy_id", "policy_version", "schedules"}, "policy")
    if raw["schema_version"] != DELIVERY_INTERVENTION_V2_POLICY_SCHEMA_VERSION:
        raise DeliveryInterventionV2Error("unsupported delivery intervention policy v2 schema")
    schedules_raw = raw["schedules"]
    if not isinstance(schedules_raw, list) or not schedules_raw:
        raise DeliveryInterventionV2Error("intervention policy requires schedules")
    schedules: dict[str, dict[int, InterventionDecisionV2]] = {}
    for schedule_raw in schedules_raw:
        if not isinstance(schedule_raw, dict):
            raise DeliveryInterventionV2Error("intervention schedule must be an object")
        _require_fields(schedule_raw, {"seed", "decisions"}, "schedule")
        seed = schedule_raw["seed"]
        if not isinstance(seed, str) or not seed or len(seed) > 256 or seed in schedules:
            raise DeliveryInterventionV2Error("intervention schedule seed is invalid or duplicated")
        if not isinstance(schedule_raw["decisions"], list):
            raise DeliveryInterventionV2Error("intervention decisions must be an array")
        decisions: dict[int, InterventionDecisionV2] = {}
        decision_ids: set[str] = set()
        for item in schedule_raw["decisions"]:
            if not isinstance(item, dict):
                raise DeliveryInterventionV2Error("intervention decision must be an object")
            _require_fields(
                item,
                {"decision_id", "request_index", "operation_id", "action"},
                "decision",
            )
            index = item["request_index"]
            if type(index) is not int or index < 1 or index in decisions:
                raise DeliveryInterventionV2Error("request_index is invalid or duplicated")
            decision_id = _identifier(item["decision_id"], "decision_id")
            if decision_id in decision_ids:
                raise DeliveryInterventionV2Error("decision_id is duplicated")
            operation_id = _identifier(item["operation_id"], "operation_id")
            action_raw = item["action"]
            if not isinstance(action_raw, dict):
                raise DeliveryInterventionV2Error("intervention action must be an object")
            _require_fields(action_raw, {"kind", "phase"}, "action")
            if action_raw["kind"] != "no_response" or action_raw["phase"] not in {
                "pre_dispatch",
                "post_dispatch",
            }:
                raise DeliveryInterventionV2Error("unsupported delivery intervention v2 action")
            decisions[index] = InterventionDecisionV2(
                decision_id,
                operation_id,
                NoResponseAction(action_raw["phase"]),
            )
            decision_ids.add(decision_id)
        schedules[seed] = decisions
    return ScheduledDeliveryInterventionPolicyV2(
        policy_id=_identifier(raw["policy_id"], "policy_id"),
        policy_version=_identifier(raw["policy_version"], "policy_version"),
        policy_sha256=digest,
        schedules=schedules,
    )


def _validate_decision(
    decision: InterventionDecisionV2 | None, *, index: int, operation_id: str
) -> None:
    if decision is None:
        return
    if not isinstance(decision, InterventionDecisionV2):
        raise DeliveryInterventionV2Error("policy returned an invalid decision")
    _identifier(decision.decision_id, "decision_id")
    if decision.operation_id != operation_id:
        raise DeliveryInterventionV2Error(
            f"decision at request index {index} targets another operation"
        )
    if not isinstance(decision.action, NoResponseAction) or decision.action.phase not in {
        "pre_dispatch",
        "post_dispatch",
    }:
        raise DeliveryInterventionV2Error("policy returned an invalid action")


def _validate_policy_identity(policy: DeliveryInterventionPolicyV2) -> None:
    _identifier(policy.policy_id, "policy_id")
    _identifier(policy.policy_version, "policy_version")
    if not isinstance(policy.policy_sha256, str) or not _SHA256.fullmatch(policy.policy_sha256):
        raise DeliveryInterventionV2Error("policy_sha256 is invalid")


def _validate_provider_binding(provider: ProviderBaseBinding) -> None:
    for value in (
        provider.provider_id,
        provider.release_version,
        provider.profile_id,
        provider.bundle_version,
    ):
        if not isinstance(value, str) or not value:
            raise DeliveryInterventionV2Error("provider binding identity is invalid")
    for value in (
        provider.release_config_sha256,
        provider.provider_runtime_sha256,
        provider.provider_admission_sha256,
        provider.operation_contract_sha256,
    ):
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise DeliveryInterventionV2Error("provider binding digest is invalid")


def _validate_operation_mutability(value: Mapping[str, str]) -> None:
    if not isinstance(value, Mapping) or not value:
        raise DeliveryInterventionV2Error("admitted operation mutability must be non-empty")
    for operation_id, mutability in value.items():
        _identifier(operation_id, "operation_id")
        if mutability not in {"read", "write"}:
            raise DeliveryInterventionV2Error("operation mutability must be read or write")


def _provider_payload(provider: ProviderBaseBinding) -> dict[str, str]:
    return {
        "provider_id": provider.provider_id,
        "release_version": provider.release_version,
        "profile_id": provider.profile_id,
        "bundle_version": provider.bundle_version,
        "release_config_sha256": provider.release_config_sha256,
        "provider_runtime_sha256": provider.provider_runtime_sha256,
        "provider_admission_sha256": provider.provider_admission_sha256,
        "operation_contract_sha256": provider.operation_contract_sha256,
    }


def _response_payload(response: GateResponse) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "headers": deepcopy(response.headers),
        "body": deepcopy(response.body),
    }


def _request_sha256(request: CallRequest, identity_policy: IdentityPolicy | None) -> str:
    """Bind the evidence-safe provider request after exact policy redaction."""

    safe_request = redact_external_request(request, identity_policy)
    return canonical_json_sha256(
        {
            "method": safe_request.normalized_method(),
            "authority": safe_request.authority,
            "path": safe_request.path,
            "query": safe_request.query,
            "headers": [
                [name, value]
                for name, value in sorted(
                    (name.lower(), value) for name, value in safe_request.headers.items()
                )
            ],
            "body": safe_request.body,
            "raw_body_sha256": safe_request.raw_body_sha256,
        }
    )


def _response_sha256(response: GateResponse) -> str:
    return canonical_json_sha256(_response_payload(response))


def _state_digest(value: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise DeliveryInterventionV2Error("provider state observer returned an invalid digest")
    return value


def _no_response_payload(status: str) -> dict[str, Any]:
    return {
        "kind": "no_response",
        "response_start_sent": False,
        "response_body_bytes_sent": 0,
        "transport_status": status,
        "client_completion_certainty": "unknown",
    }


def _response_transport_payload(
    response: GateResponse,
    status: str,
    response_start_sent: bool,
    response_body_bytes_sent: int,
) -> dict[str, Any]:
    return {
        "kind": "response",
        "response_sha256": _response_sha256(response),
        "response": _response_payload(response),
        "response_start_sent": response_start_sent,
        "response_body_bytes_sent": response_body_bytes_sent,
        "transport_status": status,
        "client_completion_certainty": "unknown",
    }


def _event_id(session: DeliveryInterventionSessionV2, index: int, operation_id: str) -> str:
    digest = canonical_json_sha256(
        {
            "provider": _provider_payload(session.provider),
            "policy_sha256": session.policy.policy_sha256,
            "seed": session.seed,
            "logical_request_index": index,
            "operation_id": operation_id,
        }
    )
    return "intv2_" + digest.removeprefix("sha256:")[:24]


def _load_object(path: Path) -> tuple[dict[str, Any], Path]:
    if path.is_symlink():
        raise DeliveryInterventionV2Error("delivery intervention config must not be a symlink")
    try:
        resolved = path.resolve(strict=True)
        if (
            not resolved.is_file()
            or resolved.stat().st_size > DELIVERY_INTERVENTION_V2_MAX_JSON_BYTES
        ):
            raise DeliveryInterventionV2Error("delivery intervention config is not a bounded file")
        payload = resolved.read_bytes()
        raw = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DeliveryInterventionV2Error(
            f"delivery intervention config is invalid: {exc}"
        ) from exc
    if not isinstance(raw, dict):
        raise DeliveryInterventionV2Error("delivery intervention config must contain an object")
    return raw, resolved


def _require_fields(raw: dict[str, Any], fields: set[str], label: str) -> None:
    if set(raw) != fields:
        raise DeliveryInterventionV2Error(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise DeliveryInterventionV2Error(f"{label} is invalid")
    return value


def _canonical_text(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
