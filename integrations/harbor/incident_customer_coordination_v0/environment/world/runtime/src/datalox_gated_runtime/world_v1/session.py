from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from datalox_gated_runtime.json_digest import canonical_json_sha256
from datalox_gated_runtime.world_v1.contracts import ActorContext
from datalox_gated_runtime.world_v1.errors import WorldSessionError


def _json_dump(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise WorldSessionError(
            "world_session_json_invalid",
            f"Value is not canonical JSON: {exc}.",
        ) from exc


def _json_load(value: str) -> Any:
    return json.loads(value)


def _timestamp(value: str | datetime) -> str:
    try:
        parsed = (
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            if isinstance(value, str)
            else value
        )
    except ValueError as exc:
        raise WorldSessionError(
            "world_clock_timestamp_invalid",
            f"Invalid simulation timestamp {value!r}.",
            timestamp=str(value),
        ) from exc
    if parsed.tzinfo is None:
        raise WorldSessionError(
            "world_clock_timestamp_invalid",
            "Simulation timestamps must include an explicit UTC offset.",
            timestamp=str(value),
        )
    return parsed.astimezone(UTC).isoformat()


def _non_empty(value: str, *, name: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise WorldSessionError(
            "world_session_identifier_invalid",
            f"{name} must be a non-empty, trimmed string.",
            field=name,
        )
    return value


def _strings(values: Sequence[str], *, name: str, allow_empty: bool = True) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise WorldSessionError(
            "world_session_value_invalid",
            f"{name} must be a sequence of strings.",
            field=name,
        )
    normalized = tuple(_non_empty(value, name=name) for value in values)
    if not allow_empty and not normalized:
        raise WorldSessionError(
            "world_session_value_invalid",
            f"{name} may not be empty.",
            field=name,
        )
    if len(set(normalized)) != len(normalized):
        raise WorldSessionError(
            "world_session_value_invalid",
            f"{name} may not contain duplicates.",
            field=name,
        )
    return normalized


@dataclass
class WorldTransaction:
    operation_id: str | None
    actor: ActorContext | None
    tool_name: str | None
    request: Mapping[str, Any] | None
    mutation_scope: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class ScheduledWorldEvent:
    id: str
    deliver_at: str
    kind: str
    payload: Any


class WorldSession:
    """Per-run SQLite state with deterministic time and transactional primitives."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # HTTP adapters serialize access with their runtime lock but execute the
        # request handler on a server thread that may differ from construction.
        self._connection = sqlite3.connect(
            str(db_path),
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._active_transaction: WorldTransaction | None = None
        self._create_schema()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS state_views (
                name TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS world_events (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                simulated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                author_role TEXT NOT NULL,
                visibility_json TEXT NOT NULL,
                status TEXT NOT NULL,
                structured_body_json TEXT NOT NULL,
                text_body TEXT,
                source_artifact_ids_json TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                revision INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifact_revisions (
                artifact_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                snapshot_json TEXT NOT NULL,
                event_sequence INTEGER NOT NULL,
                PRIMARY KEY (artifact_id, revision),
                FOREIGN KEY (artifact_id) REFERENCES artifacts(id),
                FOREIGN KEY (event_sequence) REFERENCES world_events(sequence)
            );
            CREATE TABLE IF NOT EXISTS scheduled_events (
                id TEXT PRIMARY KEY,
                deliver_at TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'delivered')),
                created_event_sequence INTEGER NOT NULL,
                delivered_event_sequence INTEGER,
                FOREIGN KEY (created_event_sequence) REFERENCES world_events(sequence),
                FOREIGN KEY (delivered_event_sequence) REFERENCES world_events(sequence)
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                participant_roles_json TEXT NOT NULL,
                visibility_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('open', 'closed')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversation_simulator_context (
                conversation_id TEXT PRIMARY KEY,
                context_json TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );
            CREATE TABLE IF NOT EXISTS conversation_messages (
                sequence INTEGER PRIMARY KEY,
                id TEXT UNIQUE NOT NULL,
                conversation_id TEXT NOT NULL,
                sender_role TEXT NOT NULL,
                visibility_json TEXT NOT NULL,
                text_body TEXT,
                structured_body_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id)
            );
            CREATE TABLE IF NOT EXISTS handoffs (
                id TEXT PRIMARY KEY,
                source_role TEXT NOT NULL,
                destination_role TEXT NOT NULL,
                artifact_ids_json TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('draft', 'committed')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                committed_event_sequence INTEGER,
                FOREIGN KEY (committed_event_sequence) REFERENCES world_events(sequence)
            );
            """
        )

    def close(self) -> None:
        if self._active_transaction is not None:
            raise WorldSessionError(
                "world_transaction_active",
                "Cannot close a world session during an active transaction.",
            )
        self._connection.close()

    def __enter__(self) -> WorldSession:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    @contextmanager
    def transaction(
        self,
        *,
        operation_id: str | None = None,
        actor: ActorContext | None = None,
        tool_name: str | None = None,
        request: Mapping[str, Any] | None = None,
    ) -> Iterator[WorldTransaction]:
        if self._active_transaction is not None:
            raise WorldSessionError(
                "world_transaction_nested",
                "Nested world transactions are not supported.",
            )
        if operation_id is not None:
            _non_empty(operation_id, name="operation_id")
        transaction = WorldTransaction(
            operation_id=operation_id,
            actor=actor,
            tool_name=tool_name,
            request=request,
        )
        self._connection.execute("BEGIN IMMEDIATE")
        self._active_transaction = transaction
        try:
            yield transaction
            if self._metadata_optional("simulation_time") is not None:
                self._append_event_raw(
                    "transaction_committed",
                    {
                        "operation_id": operation_id,
                        "actor_id": actor.actor_id if actor is not None else None,
                        "actor_role": actor.role if actor is not None else None,
                        "mutation_scope": sorted(transaction.mutation_scope),
                        "decision": ("shadow_write" if transaction.mutation_scope else "replay"),
                        "tool_id": tool_name,
                        "tool_name": tool_name,
                        "request": dict(request) if request is not None else None,
                    },
                )
            self._connection.execute("COMMIT")
        except BaseException:
            self._connection.execute("ROLLBACK")
            raise
        finally:
            self._active_transaction = None

    def _require_transaction(self) -> WorldTransaction:
        if self._active_transaction is None:
            raise WorldSessionError(
                "world_transaction_required",
                "World mutations must run inside WorldSession.transaction().",
            )
        return self._active_transaction

    def _mark_mutation(self, scope: str) -> None:
        self._require_transaction().mutation_scope.add(scope)

    def _metadata_optional(self, key: str) -> Any | None:
        row = self._connection.execute(
            "SELECT value_json FROM metadata WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else _json_load(row["value_json"])

    def _set_metadata(self, key: str, value: Any) -> None:
        self._require_transaction()
        self._connection.execute(
            """
            INSERT INTO metadata(key, value_json) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json
            """,
            (key, _json_dump(value)),
        )

    def reset(
        self,
        *,
        episode_id: str,
        initial_state: Mapping[str, Any],
        initial_time: str | datetime,
    ) -> None:
        _non_empty(episode_id, name="episode_id")
        normalized_time = _timestamp(initial_time)
        with self.transaction(operation_id="world.reset"):
            for table in (
                "artifact_revisions",
                "scheduled_events",
                "conversation_messages",
                "conversation_simulator_context",
                "handoffs",
                "artifacts",
                "conversations",
                "state_views",
                "metadata",
                "world_events",
            ):
                self._connection.execute(f"DELETE FROM {table}")
            self._set_metadata("episode_id", episode_id)
            self._set_metadata("simulation_time", normalized_time)
            for name, value in sorted(initial_state.items()):
                self.set_state(name, value)
            self._mark_mutation("world:reset")
            self.append_event(
                "world_reset",
                {
                    "episode_id": episode_id,
                    "initial_state_views": sorted(initial_state),
                    "initial_time": normalized_time,
                },
            )

    @property
    def episode_id(self) -> str:
        value = self._metadata_optional("episode_id")
        if not isinstance(value, str):
            raise WorldSessionError(
                "world_session_not_initialized",
                "World session has not been reset from an episode.",
            )
        return value

    @property
    def is_initialized(self) -> bool:
        return isinstance(self._metadata_optional("episode_id"), str) and isinstance(
            self._metadata_optional("simulation_time"), str
        )

    def get_state(self, name: str) -> Any:
        _non_empty(name, name="state name")
        row = self._connection.execute(
            "SELECT value_json FROM state_views WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            raise WorldSessionError(
                "world_state_missing",
                f"State view {name!r} does not exist.",
                state=name,
            )
        return _json_load(row["value_json"])

    def list_state(self) -> dict[str, Any]:
        rows = self._connection.execute(
            "SELECT name, value_json FROM state_views ORDER BY name"
        ).fetchall()
        return {row["name"]: _json_load(row["value_json"]) for row in rows}

    def set_state(self, name: str, value: Any) -> None:
        _non_empty(name, name="state name")
        self._require_transaction()
        self._connection.execute(
            """
            INSERT INTO state_views(name, value_json) VALUES (?, ?)
            ON CONFLICT(name) DO UPDATE SET value_json = excluded.value_json
            """,
            (name, _json_dump(value)),
        )
        self._mark_mutation(f"state:{name}")

    def compare_and_set_state(self, name: str, *, expected: Any, value: Any) -> bool:
        self._require_transaction()
        try:
            current = self.get_state(name)
        except WorldSessionError as exc:
            if exc.code != "world_state_missing":
                raise
            current = None
        if current != expected:
            return False
        self.set_state(name, value)
        return True

    def current_time(self) -> str:
        value = self._metadata_optional("simulation_time")
        if not isinstance(value, str):
            raise WorldSessionError(
                "world_session_not_initialized",
                "World session has no simulation clock. Reset it from an episode first.",
            )
        return value

    def advance_clock(
        self,
        new_time: str | datetime,
        *,
        handler: Callable[[WorldSession, ScheduledWorldEvent], None] | None = None,
    ) -> tuple[ScheduledWorldEvent, ...]:
        self._require_transaction()
        current = datetime.fromisoformat(self.current_time())
        normalized = _timestamp(new_time)
        target = datetime.fromisoformat(normalized)
        if target < current:
            raise WorldSessionError(
                "world_clock_reverse_forbidden",
                "Simulation time may not move backwards.",
                current=self.current_time(),
                requested=normalized,
            )
        self._set_metadata("simulation_time", normalized)
        self._mark_mutation("clock")
        self.append_event("clock_advanced", {"from": current.isoformat(), "to": normalized})
        return self.deliver_due_events(handler=handler)

    def advance_clock_by(
        self,
        delta: timedelta,
        *,
        handler: Callable[[WorldSession, ScheduledWorldEvent], None] | None = None,
    ) -> tuple[ScheduledWorldEvent, ...]:
        if delta.total_seconds() < 0:
            raise WorldSessionError(
                "world_clock_reverse_forbidden",
                "Simulation clock delta may not be negative.",
            )
        return self.advance_clock(
            datetime.fromisoformat(self.current_time()) + delta, handler=handler
        )

    def append_event(self, event_type: str, payload: Any) -> str:
        self._require_transaction()
        return self._event_id(self._append_event_raw(event_type, payload))

    def _append_event_raw(self, event_type: str, payload: Any) -> int:
        _non_empty(event_type, name="event_type")
        self._require_transaction()
        sequence_row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM world_events"
        ).fetchone()
        sequence = int(sequence_row["next_sequence"])
        self._connection.execute(
            "INSERT INTO world_events(sequence, event_type, simulated_at, payload_json) VALUES (?, ?, ?, ?)",
            (sequence, event_type, self.current_time(), _json_dump(payload)),
        )
        return sequence

    @staticmethod
    def _event_id(sequence: int) -> str:
        return f"event:{sequence:08d}"

    def list_events(self) -> tuple[dict[str, Any], ...]:
        rows = self._connection.execute(
            "SELECT sequence, event_type, simulated_at, payload_json FROM world_events ORDER BY sequence"
        ).fetchall()
        return tuple(
            {
                "id": self._event_id(row["sequence"]),
                "sequence": row["sequence"],
                "type": row["event_type"],
                "simulated_at": row["simulated_at"],
                "payload": _json_load(row["payload_json"]),
            }
            for row in rows
        )

    def verifier_events(self) -> tuple[dict[str, Any], ...]:
        """Project ordered events into the stable compositional-verifier shape."""

        projected: list[dict[str, Any]] = []
        for event in self.list_events():
            payload = event["payload"] if isinstance(event["payload"], dict) else {}
            event_type = event["type"]
            projected.append(
                {
                    "event_id": event["id"],
                    "sequence": event["sequence"],
                    "event_type": event_type,
                    "simulated_at": event["simulated_at"],
                    "operation_id": payload.get("operation_id"),
                    "decision": (
                        "deny"
                        if event_type == "tool_invocation_denied"
                        else payload.get("decision")
                    ),
                    "mutation_scope": payload.get("mutation_scope", []),
                    "actor_id": payload.get("actor_id"),
                    "actor_role": payload.get("actor_role"),
                    "tool_id": payload.get("tool_id"),
                    "tool_name": payload.get("tool_name", payload.get("tool_id")),
                    "reason_code": payload.get("reason_code"),
                    "request": payload.get("request"),
                    "status_code": payload.get("status_code"),
                    "body_sha256": payload.get("body_sha256"),
                    "payload": event["payload"],
                }
            )
        return tuple(projected)

    def record_response_digest(
        self,
        *,
        actor: ActorContext,
        operation_id: str | None,
        tool_id: str | None,
        request: Mapping[str, Any] | None,
        status_code: int,
        body: Any,
    ) -> str:
        self._require_transaction()
        return self.append_event(
            "world_response_digest_recorded",
            {
                "actor_id": actor.actor_id,
                "actor_role": actor.role,
                "operation_id": operation_id,
                "tool_id": tool_id,
                "tool_name": tool_id,
                "request": dict(request) if request is not None else None,
                "status_code": status_code,
                "body_sha256": canonical_json_sha256(body),
            },
        )

    def record_denied_tool_attempt(
        self,
        *,
        actor: ActorContext,
        tool_id: str,
        arguments: Mapping[str, Any],
        reason_code: str,
        request: Mapping[str, Any] | None = None,
        within_transaction: bool = False,
    ) -> str:
        if within_transaction:
            return self.append_event(
                "tool_invocation_denied",
                {
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "tool_id": tool_id,
                    "tool_name": tool_id,
                    "arguments": dict(arguments),
                    "reason_code": reason_code,
                    "request": dict(request) if request is not None else None,
                },
            )
        if self._active_transaction is not None:
            raise WorldSessionError(
                "world_denial_recording_invalid",
                "Denied tool attempts must be recorded before an invocation transaction starts.",
            )
        with self.transaction(operation_id="world.tool_denied", actor=actor):
            return self.append_event(
                "tool_invocation_denied",
                {
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "tool_id": tool_id,
                    "tool_name": tool_id,
                    "arguments": dict(arguments),
                    "reason_code": reason_code,
                    "request": dict(request) if request is not None else None,
                },
            )

    def _artifact_snapshot(self, artifact_id: str) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT * FROM artifacts WHERE id = ?", (artifact_id,)
        ).fetchone()
        if row is None:
            raise WorldSessionError(
                "world_artifact_missing",
                f"Artifact {artifact_id!r} does not exist.",
                artifact_id=artifact_id,
            )
        return {
            "id": row["id"],
            "kind": row["kind"],
            "author_role": row["author_role"],
            "visibility": _json_load(row["visibility_json"]),
            "status": row["status"],
            "structured_body": _json_load(row["structured_body_json"]),
            "text_body": row["text_body"],
            "source_artifact_ids": _json_load(row["source_artifact_ids_json"]),
            "evidence_refs": _json_load(row["evidence_refs_json"]),
            "revision": row["revision"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _record_artifact_revision(self, artifact_id: str, event_sequence: int) -> None:
        snapshot = self._artifact_snapshot(artifact_id)
        self._connection.execute(
            "INSERT INTO artifact_revisions(artifact_id, revision, snapshot_json, event_sequence) VALUES (?, ?, ?, ?)",
            (artifact_id, snapshot["revision"], _json_dump(snapshot), event_sequence),
        )

    def create_artifact(
        self,
        *,
        artifact_id: str,
        kind: str,
        author_role: str,
        visibility: Sequence[str],
        status: str,
        structured_body: Any,
        text_body: str | None = None,
        source_artifact_ids: Sequence[str] = (),
        evidence_refs: Sequence[str] = (),
    ) -> dict[str, Any]:
        self._require_transaction()
        for value, name in (
            (artifact_id, "artifact_id"),
            (kind, "artifact kind"),
            (author_role, "author_role"),
            (status, "artifact status"),
        ):
            _non_empty(value, name=name)
        if text_body is not None and not isinstance(text_body, str):
            raise WorldSessionError(
                "world_artifact_invalid",
                "Artifact text_body must be a string or null.",
                artifact_id=artifact_id,
            )
        now = self.current_time()
        try:
            self._connection.execute(
                """
                INSERT INTO artifacts(
                    id, kind, author_role, visibility_json, status, structured_body_json,
                    text_body, source_artifact_ids_json, evidence_refs_json, revision,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    artifact_id,
                    kind,
                    author_role,
                    _json_dump(_strings(visibility, name="visibility", allow_empty=False)),
                    status,
                    _json_dump(structured_body),
                    text_body,
                    _json_dump(_strings(source_artifact_ids, name="source_artifact_ids")),
                    _json_dump(_strings(evidence_refs, name="evidence_refs")),
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise WorldSessionError(
                "world_artifact_exists",
                f"Artifact {artifact_id!r} already exists.",
                artifact_id=artifact_id,
            ) from exc
        sequence = self._append_event_raw(
            "artifact_created", {"artifact_id": artifact_id, "revision": 1}
        )
        self._record_artifact_revision(artifact_id, sequence)
        self._mark_mutation(f"artifact:{artifact_id}")
        return self._artifact_snapshot(artifact_id)

    def revise_artifact(
        self,
        artifact_id: str,
        *,
        status: str,
        structured_body: Any,
        text_body: str | None = None,
        source_artifact_ids: Sequence[str] = (),
        evidence_refs: Sequence[str] = (),
    ) -> dict[str, Any]:
        self._require_transaction()
        previous = self._artifact_snapshot(artifact_id)
        _non_empty(status, name="artifact status")
        if text_body is not None and not isinstance(text_body, str):
            raise WorldSessionError(
                "world_artifact_invalid",
                "Artifact text_body must be a string or null.",
                artifact_id=artifact_id,
            )
        revision = previous["revision"] + 1
        self._connection.execute(
            """
            UPDATE artifacts SET status = ?, structured_body_json = ?, text_body = ?,
                source_artifact_ids_json = ?, evidence_refs_json = ?, revision = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                status,
                _json_dump(structured_body),
                text_body,
                _json_dump(_strings(source_artifact_ids, name="source_artifact_ids")),
                _json_dump(_strings(evidence_refs, name="evidence_refs")),
                revision,
                self.current_time(),
                artifact_id,
            ),
        )
        sequence = self._append_event_raw(
            "artifact_revised", {"artifact_id": artifact_id, "revision": revision}
        )
        self._record_artifact_revision(artifact_id, sequence)
        self._mark_mutation(f"artifact:{artifact_id}")
        return self._artifact_snapshot(artifact_id)

    def get_artifact(self, artifact_id: str) -> dict[str, Any]:
        return self._artifact_snapshot(artifact_id)

    def list_artifacts(self) -> tuple[dict[str, Any], ...]:
        ids = self._connection.execute("SELECT id FROM artifacts ORDER BY id").fetchall()
        return tuple(self._artifact_snapshot(row["id"]) for row in ids)

    def artifact_revisions(self, artifact_id: str) -> tuple[dict[str, Any], ...]:
        self._artifact_snapshot(artifact_id)
        rows = self._connection.execute(
            """
            SELECT revision, snapshot_json, event_sequence FROM artifact_revisions
            WHERE artifact_id = ? ORDER BY revision
            """,
            (artifact_id,),
        ).fetchall()
        return tuple(
            {
                "revision": row["revision"],
                "snapshot": _json_load(row["snapshot_json"]),
                "event_ref": self._event_id(row["event_sequence"]),
            }
            for row in rows
        )

    def schedule_event(
        self,
        *,
        event_id: str,
        deliver_at: str | datetime,
        kind: str,
        payload: Any,
    ) -> ScheduledWorldEvent:
        self._require_transaction()
        _non_empty(event_id, name="scheduled event id")
        _non_empty(kind, name="scheduled event kind")
        normalized = _timestamp(deliver_at)
        sequence = self._append_event_raw(
            "scheduled_event_created",
            {"scheduled_event_id": event_id, "deliver_at": normalized, "kind": kind},
        )
        try:
            self._connection.execute(
                """
                INSERT INTO scheduled_events(
                    id, deliver_at, kind, payload_json, status, created_event_sequence
                ) VALUES (?, ?, ?, ?, 'pending', ?)
                """,
                (event_id, normalized, kind, _json_dump(payload), sequence),
            )
        except sqlite3.IntegrityError as exc:
            raise WorldSessionError(
                "world_scheduled_event_exists",
                f"Scheduled event {event_id!r} already exists.",
                event_id=event_id,
            ) from exc
        self._mark_mutation(f"scheduled_event:{event_id}")
        return ScheduledWorldEvent(id=event_id, deliver_at=normalized, kind=kind, payload=payload)

    def deliver_due_events(
        self,
        *,
        handler: Callable[[WorldSession, ScheduledWorldEvent], None] | None = None,
    ) -> tuple[ScheduledWorldEvent, ...]:
        self._require_transaction()
        rows = self._connection.execute(
            """
            SELECT id, deliver_at, kind, payload_json FROM scheduled_events
            WHERE status = 'pending' AND deliver_at <= ? ORDER BY deliver_at, id
            """,
            (self.current_time(),),
        ).fetchall()
        delivered: list[ScheduledWorldEvent] = []
        for row in rows:
            event = ScheduledWorldEvent(
                id=row["id"],
                deliver_at=row["deliver_at"],
                kind=row["kind"],
                payload=_json_load(row["payload_json"]),
            )
            if handler is not None:
                handler(self, event)
            sequence = self._append_event_raw(
                "scheduled_event_delivered",
                {
                    "scheduled_event_id": event.id,
                    "deliver_at": event.deliver_at,
                    "kind": event.kind,
                },
            )
            cursor = self._connection.execute(
                """
                UPDATE scheduled_events SET status = 'delivered', delivered_event_sequence = ?
                WHERE id = ? AND status = 'pending'
                """,
                (sequence, event.id),
            )
            if cursor.rowcount != 1:
                raise WorldSessionError(
                    "world_scheduled_event_delivery_conflict",
                    f"Scheduled event {event.id!r} was not pending at delivery time.",
                    event_id=event.id,
                )
            self._mark_mutation(f"scheduled_event:{event.id}")
            delivered.append(event)
        return tuple(delivered)

    def list_scheduled_events(self) -> tuple[dict[str, Any], ...]:
        rows = self._connection.execute(
            "SELECT * FROM scheduled_events ORDER BY deliver_at, id"
        ).fetchall()
        return tuple(
            {
                "id": row["id"],
                "deliver_at": row["deliver_at"],
                "kind": row["kind"],
                "payload": _json_load(row["payload_json"]),
                "status": row["status"],
                "created_event_ref": self._event_id(row["created_event_sequence"]),
                "delivered_event_ref": (
                    self._event_id(row["delivered_event_sequence"])
                    if row["delivered_event_sequence"] is not None
                    else None
                ),
            }
            for row in rows
        )

    def create_conversation(
        self,
        *,
        conversation_id: str,
        participant_roles: Sequence[str],
        visibility: Sequence[str],
        simulator_context: Any,
    ) -> None:
        self._require_transaction()
        _non_empty(conversation_id, name="conversation_id")
        now = self.current_time()
        try:
            self._connection.execute(
                """
                INSERT INTO conversations(
                    id, participant_roles_json, visibility_json, status, created_at, updated_at
                ) VALUES (?, ?, ?, 'open', ?, ?)
                """,
                (
                    conversation_id,
                    _json_dump(
                        _strings(participant_roles, name="participant_roles", allow_empty=False)
                    ),
                    _json_dump(_strings(visibility, name="visibility", allow_empty=False)),
                    now,
                    now,
                ),
            )
            self._connection.execute(
                "INSERT INTO conversation_simulator_context(conversation_id, context_json) VALUES (?, ?)",
                (conversation_id, _json_dump(simulator_context)),
            )
        except sqlite3.IntegrityError as exc:
            raise WorldSessionError(
                "world_conversation_exists",
                f"Conversation {conversation_id!r} already exists.",
                conversation_id=conversation_id,
            ) from exc
        self.append_event("conversation_created", {"conversation_id": conversation_id})
        self._mark_mutation(f"conversation:{conversation_id}")

    def _conversation_row(self, conversation_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM conversations WHERE id = ?", (conversation_id,)
        ).fetchone()
        if row is None:
            raise WorldSessionError(
                "world_conversation_missing",
                f"Conversation {conversation_id!r} does not exist.",
                conversation_id=conversation_id,
            )
        return row

    def simulator_context(self, conversation_id: str) -> Any:
        self._conversation_row(conversation_id)
        row = self._connection.execute(
            "SELECT context_json FROM conversation_simulator_context WHERE conversation_id = ?",
            (conversation_id,),
        ).fetchone()
        return _json_load(row["context_json"])

    def append_message(
        self,
        *,
        conversation_id: str,
        message_id: str,
        sender_role: str,
        visibility: Sequence[str],
        text_body: str | None,
        structured_body: Any,
    ) -> None:
        self._require_transaction()
        conversation = self._conversation_row(conversation_id)
        if conversation["status"] != "open":
            raise WorldSessionError(
                "world_conversation_closed",
                f"Conversation {conversation_id!r} is closed.",
                conversation_id=conversation_id,
            )
        _non_empty(message_id, name="message_id")
        _non_empty(sender_role, name="sender_role")
        if text_body is not None and not isinstance(text_body, str):
            raise WorldSessionError(
                "world_conversation_message_invalid",
                "Conversation message text_body must be a string or null.",
                message_id=message_id,
            )
        sequence_row = self._connection.execute(
            "SELECT COALESCE(MAX(sequence), 0) + 1 AS next_sequence FROM conversation_messages"
        ).fetchone()
        try:
            self._connection.execute(
                """
                INSERT INTO conversation_messages(
                    sequence, id, conversation_id, sender_role, visibility_json,
                    text_body, structured_body_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence_row["next_sequence"],
                    message_id,
                    conversation_id,
                    sender_role,
                    _json_dump(_strings(visibility, name="visibility", allow_empty=False)),
                    text_body,
                    _json_dump(structured_body),
                    self.current_time(),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise WorldSessionError(
                "world_conversation_message_exists",
                f"Conversation message {message_id!r} already exists.",
                message_id=message_id,
            ) from exc
        self._connection.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?",
            (self.current_time(), conversation_id),
        )
        self.append_event(
            "conversation_message_added",
            {
                "conversation_id": conversation_id,
                "message_id": message_id,
                "sender_role": sender_role,
            },
        )
        self._mark_mutation(f"conversation:{conversation_id}")
        self._mark_mutation(f"conversation_message:{message_id}")

    def close_conversation(self, conversation_id: str) -> None:
        self._require_transaction()
        conversation = self._conversation_row(conversation_id)
        if conversation["status"] == "closed":
            return
        self._connection.execute(
            "UPDATE conversations SET status = 'closed', updated_at = ? WHERE id = ?",
            (self.current_time(), conversation_id),
        )
        self.append_event("conversation_closed", {"conversation_id": conversation_id})
        self._mark_mutation(f"conversation:{conversation_id}")

    @staticmethod
    def _visible(visibility: Sequence[str], role: str) -> bool:
        return "*" in visibility or role in visibility

    def get_conversation(self, conversation_id: str, *, actor: ActorContext) -> dict[str, Any]:
        conversation = self._conversation_row(conversation_id)
        visibility = _json_load(conversation["visibility_json"])
        if not self._visible(visibility, actor.role):
            raise WorldSessionError(
                "world_conversation_hidden",
                f"Conversation {conversation_id!r} is hidden from role {actor.role!r}.",
                conversation_id=conversation_id,
                actor_role=actor.role,
            )
        message_rows = self._connection.execute(
            """
            SELECT * FROM conversation_messages
            WHERE conversation_id = ? ORDER BY sequence
            """,
            (conversation_id,),
        ).fetchall()
        messages = []
        for row in message_rows:
            message_visibility = _json_load(row["visibility_json"])
            if not self._visible(message_visibility, actor.role):
                continue
            messages.append(
                {
                    "id": row["id"],
                    "sequence": row["sequence"],
                    "sender_role": row["sender_role"],
                    "visibility": message_visibility,
                    "text_body": row["text_body"],
                    "structured_body": _json_load(row["structured_body_json"]),
                    "created_at": row["created_at"],
                }
            )
        return {
            "id": conversation["id"],
            "participant_roles": _json_load(conversation["participant_roles_json"]),
            "visibility": visibility,
            "status": conversation["status"],
            "created_at": conversation["created_at"],
            "updated_at": conversation["updated_at"],
            "messages": messages,
        }

    def list_conversations(self, *, actor: ActorContext) -> tuple[dict[str, Any], ...]:
        ids = self._connection.execute("SELECT id FROM conversations ORDER BY id").fetchall()
        visible: list[dict[str, Any]] = []
        for row in ids:
            try:
                visible.append(self.get_conversation(row["id"], actor=actor))
            except WorldSessionError as exc:
                if exc.code != "world_conversation_hidden":
                    raise
        return tuple(visible)

    def export_conversations(self) -> tuple[dict[str, Any], ...]:
        """Export authoritative conversation data without hidden simulator context."""

        conversation_rows = self._connection.execute(
            "SELECT * FROM conversations ORDER BY id"
        ).fetchall()
        result: list[dict[str, Any]] = []
        for conversation in conversation_rows:
            message_rows = self._connection.execute(
                """
                SELECT * FROM conversation_messages
                WHERE conversation_id = ? ORDER BY sequence
                """,
                (conversation["id"],),
            ).fetchall()
            result.append(
                {
                    "id": conversation["id"],
                    "participant_roles": _json_load(conversation["participant_roles_json"]),
                    "visibility": _json_load(conversation["visibility_json"]),
                    "status": conversation["status"],
                    "created_at": conversation["created_at"],
                    "updated_at": conversation["updated_at"],
                    "messages": [
                        {
                            "id": row["id"],
                            "sequence": row["sequence"],
                            "sender_role": row["sender_role"],
                            "visibility": _json_load(row["visibility_json"]),
                            "text_body": row["text_body"],
                            "structured_body": _json_load(row["structured_body_json"]),
                            "created_at": row["created_at"],
                        }
                        for row in message_rows
                    ],
                }
            )
        return tuple(result)

    def create_handoff(
        self,
        *,
        handoff_id: str,
        source_role: str,
        destination_role: str,
        artifact_ids: Sequence[str] = (),
        evidence_refs: Sequence[str] = (),
    ) -> dict[str, Any]:
        self._require_transaction()
        for value, name in (
            (handoff_id, "handoff_id"),
            (source_role, "source_role"),
            (destination_role, "destination_role"),
        ):
            _non_empty(value, name=name)
        now = self.current_time()
        try:
            self._connection.execute(
                """
                INSERT INTO handoffs(
                    id, source_role, destination_role, artifact_ids_json, evidence_refs_json,
                    status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'draft', ?, ?)
                """,
                (
                    handoff_id,
                    source_role,
                    destination_role,
                    _json_dump(_strings(artifact_ids, name="artifact_ids")),
                    _json_dump(_strings(evidence_refs, name="evidence_refs")),
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise WorldSessionError(
                "world_handoff_exists",
                f"Handoff {handoff_id!r} already exists.",
                handoff_id=handoff_id,
            ) from exc
        self.append_event("handoff_created", {"handoff_id": handoff_id})
        self._mark_mutation(f"handoff:{handoff_id}")
        return self.get_handoff(handoff_id)

    def _handoff_row(self, handoff_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM handoffs WHERE id = ?", (handoff_id,)
        ).fetchone()
        if row is None:
            raise WorldSessionError(
                "world_handoff_missing",
                f"Handoff {handoff_id!r} does not exist.",
                handoff_id=handoff_id,
            )
        return row

    def update_handoff(
        self,
        handoff_id: str,
        *,
        destination_role: str,
        artifact_ids: Sequence[str] = (),
        evidence_refs: Sequence[str] = (),
    ) -> dict[str, Any]:
        self._require_transaction()
        row = self._handoff_row(handoff_id)
        if row["status"] == "committed":
            raise WorldSessionError(
                "world_handoff_committed",
                f"Committed handoff {handoff_id!r} is immutable.",
                handoff_id=handoff_id,
            )
        _non_empty(destination_role, name="destination_role")
        self._connection.execute(
            """
            UPDATE handoffs SET destination_role = ?, artifact_ids_json = ?,
                evidence_refs_json = ?, updated_at = ? WHERE id = ?
            """,
            (
                destination_role,
                _json_dump(_strings(artifact_ids, name="artifact_ids")),
                _json_dump(_strings(evidence_refs, name="evidence_refs")),
                self.current_time(),
                handoff_id,
            ),
        )
        self.append_event("handoff_updated", {"handoff_id": handoff_id})
        self._mark_mutation(f"handoff:{handoff_id}")
        return self.get_handoff(handoff_id)

    def commit_handoff(self, handoff_id: str) -> dict[str, Any]:
        self._require_transaction()
        row = self._handoff_row(handoff_id)
        if row["status"] == "committed":
            raise WorldSessionError(
                "world_handoff_committed",
                f"Handoff {handoff_id!r} is already committed and immutable.",
                handoff_id=handoff_id,
            )
        sequence = self._append_event_raw(
            "handoff_committed",
            {
                "handoff_id": handoff_id,
                "source_role": row["source_role"],
                "destination_role": row["destination_role"],
            },
        )
        self._connection.execute(
            """
            UPDATE handoffs SET status = 'committed', updated_at = ?,
                committed_event_sequence = ? WHERE id = ?
            """,
            (self.current_time(), sequence, handoff_id),
        )
        self._mark_mutation(f"handoff:{handoff_id}")
        return self.get_handoff(handoff_id)

    def get_handoff(self, handoff_id: str) -> dict[str, Any]:
        row = self._handoff_row(handoff_id)
        return {
            "id": row["id"],
            "source_role": row["source_role"],
            "destination_role": row["destination_role"],
            "artifact_ids": _json_load(row["artifact_ids_json"]),
            "evidence_refs": _json_load(row["evidence_refs_json"]),
            "status": row["status"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "committed_at": row["updated_at"] if row["status"] == "committed" else None,
            "commit_event_ref": (
                self._event_id(row["committed_event_sequence"])
                if row["committed_event_sequence"] is not None
                else None
            ),
        }

    def list_handoffs(self) -> tuple[dict[str, Any], ...]:
        ids = self._connection.execute("SELECT id FROM handoffs ORDER BY id").fetchall()
        return tuple(self.get_handoff(row["id"]) for row in ids)

    def export(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "simulation_time": self.current_time(),
            "state": self.list_state(),
            "events": list(self.list_events()),
            "verifier_events": list(self.verifier_events()),
            "artifacts": [
                {
                    **artifact,
                    "revisions": list(self.artifact_revisions(artifact["id"])),
                }
                for artifact in self.list_artifacts()
            ],
            "scheduled_events": list(self.list_scheduled_events()),
            "conversations": list(self.export_conversations()),
            "handoffs": list(self.list_handoffs()),
        }
