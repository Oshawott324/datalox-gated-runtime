from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

_SCHEMA_VERSION = "datalox_session_event_export_v1"
_SQLITE_APPLICATION_ID = 0x444C4556  # DLEV
_SQLITE_SCHEMA_VERSION = 2
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$")
MAX_EVENT_JSON_BYTES = 256 * 1024
MAX_SESSION_SOURCE_EVENTS = 4_096
MAX_SESSION_DELIVERIES = 8_192
MAX_SESSION_DELIVERY_ATTEMPTS = 32_768
MAX_SESSION_UNKNOWN_RESOLUTIONS = 32_768
MAX_SESSION_POST_OUTCOME_EFFECTS = 16_384
MAX_SESSION_STORED_JSON_BYTES = 16 * 1024 * 1024
MAX_SESSION_EVENT_EXPORT_BYTES = 32 * 1024 * 1024
MAX_DELIVERY_RETRY_DELAYS = 32
MAX_DELIVERY_ATTEMPTS = MAX_DELIVERY_RETRY_DELAYS + 1
_MAX_ERROR_MESSAGE = 4096
_MAX_CORRELATIONS = 32
_MAX_RETRY_DELAY_SECONDS = 30 * 24 * 60 * 60
_EXPORT_ROW_OVERHEAD_BYTES = 2_048

DeliveryOutcomeKind = Literal[
    "delivered", "retryable_failure", "terminal_failure", "unknown_completion"
]
DeliveryState = Literal[
    "queued",
    "retry_scheduled",
    "in_flight",
    "delivered",
    "terminal_failure",
    "unknown_completion",
]


@dataclass(frozen=True)
class SessionEventError(ValueError):
    """A stable, controller-readable composition error."""

    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class DeliveryCommand:
    delivery_id: str
    edge_id: str
    ordering_key: str
    source_event_id: str
    target_provider_id: str
    target_operation_id: str
    target_principal_context_id: str
    request: dict[str, Any]
    correlation_ids: dict[str, str]
    attempt_number: int
    available_at: str


@dataclass(frozen=True)
class DeliveryOutcome:
    kind: DeliveryOutcomeKind
    receipt: dict[str, Any]
    status_code: int | None = None
    error_code: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class DeliveryRequest:
    """One explicitly declared downstream delivery in an atomic source fan-out."""

    edge_id: str
    ordering_key: str
    target_provider_id: str
    target_operation_id: str
    target_principal_context_id: str
    request: Mapping[str, Any]
    available_at: datetime | str
    retry_delays_seconds: Sequence[int]
    correlation_ids: Mapping[str, str] | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True)
class SourceFanoutRequest:
    """One durable source event and its complete declared downstream fan-out."""

    source_provider_id: str
    provider_event_id: str
    event_type: str
    payload: Mapping[str, Any]
    deliveries: Sequence[DeliveryRequest]
    correlation_ids: Mapping[str, str] | None = None
    idempotency_key: str | None = None


@dataclass(frozen=True)
class ExistingSourceDeliveryRequest:
    """One durable follow-up delivery attached to an existing source event."""

    source_event_id: str
    delivery: DeliveryRequest


PostOutcomeEffect = SourceFanoutRequest | ExistingSourceDeliveryRequest
PostOutcomeEffectFactory = Callable[
    [DeliveryCommand, DeliveryOutcome, DeliveryState], Sequence[PostOutcomeEffect]
]


@dataclass(frozen=True)
class DeliveryRunResult:
    delivery_id: str
    attempt_number: int
    attempt_outcome: DeliveryOutcomeKind
    delivery_state: DeliveryState
    next_available_at: str | None


def _canonical_json(value: Any, *, field_name: str) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise SessionEventError(
            "session_event_json_invalid",
            f"{field_name} must be finite JSON data.",
            {"field": field_name},
        ) from exc
    if len(encoded.encode("utf-8")) > MAX_EVENT_JSON_BYTES:
        raise SessionEventError(
            "session_event_json_too_large",
            f"{field_name} exceeds the {MAX_EVENT_JSON_BYTES}-byte limit.",
            {"field": field_name, "max_bytes": MAX_EVENT_JSON_BYTES},
        )
    return encoded


def _json_object(value: Mapping[str, Any], *, field_name: str) -> tuple[dict[str, Any], str]:
    if not isinstance(value, Mapping):
        raise SessionEventError(
            "session_event_json_object_required",
            f"{field_name} must be a JSON object.",
            {"field": field_name},
        )
    encoded = _canonical_json(dict(value), field_name=field_name)
    return json.loads(encoded), encoded


def _identifier(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SessionEventError(
            "session_event_identifier_invalid",
            f"{field_name} is not a canonical identifier.",
            {"field": field_name},
        )
    return value


def _optional_identifier(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, field_name=field_name)


def _utc(value: datetime | str, *, field_name: str) -> datetime:
    if isinstance(value, str):
        if not value.endswith("Z"):
            raise SessionEventError(
                "session_event_time_invalid",
                f"{field_name} must be an RFC 3339 UTC timestamp ending in Z.",
                {"field": field_name},
            )
        try:
            parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        except ValueError as exc:
            raise SessionEventError(
                "session_event_time_invalid",
                f"{field_name} must be a valid RFC 3339 UTC timestamp.",
                {"field": field_name},
            ) from exc
    elif isinstance(value, datetime):
        parsed = value
    else:
        raise SessionEventError(
            "session_event_time_invalid",
            f"{field_name} must be an aware UTC datetime or RFC 3339 UTC timestamp.",
            {"field": field_name},
        )
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise SessionEventError(
            "session_event_time_not_utc",
            f"{field_name} must use UTC.",
            {"field": field_name},
        )
    return parsed.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _stable_id(prefix: str, value: Any) -> str:
    return f"{prefix}_{_digest(value).split(':', 1)[1][:32]}"


def _correlations(value: Mapping[str, str] | None) -> tuple[dict[str, str], str]:
    raw = {} if value is None else value
    if not isinstance(raw, Mapping) or len(raw) > _MAX_CORRELATIONS:
        raise SessionEventError(
            "session_event_correlations_invalid",
            f"correlation_ids must be an object with at most {_MAX_CORRELATIONS} entries.",
        )
    normalized: dict[str, str] = {}
    for key, item in raw.items():
        normalized[_identifier(key, field_name="correlation_ids key")] = _identifier(
            item, field_name=f"correlation_ids[{key}]"
        )
    return normalized, _canonical_json(normalized, field_name="correlation_ids")


def _retry_delays(value: Sequence[int]) -> tuple[tuple[int, ...], str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise SessionEventError(
            "session_event_retry_schedule_invalid",
            "retry_delays_seconds must be a finite sequence of integer delays.",
        )
    if len(value) > MAX_DELIVERY_RETRY_DELAYS:
        raise SessionEventError(
            "session_event_retry_schedule_too_long",
            f"retry_delays_seconds may contain at most {MAX_DELIVERY_RETRY_DELAYS} delays.",
        )
    normalized: list[int] = []
    for delay in value:
        if (
            isinstance(delay, bool)
            or not isinstance(delay, int)
            or not (1 <= delay <= _MAX_RETRY_DELAY_SECONDS)
        ):
            raise SessionEventError(
                "session_event_retry_delay_invalid",
                "Every retry delay must be an integer from 1 through 2592000 seconds.",
            )
        normalized.append(delay)
    result = tuple(normalized)
    return result, _canonical_json(list(result), field_name="retry_delays_seconds")


def _encoded_bytes(value: str) -> int:
    return len(value.encode("utf-8"))


def _private_directory(path: Path, *, field_name: str) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SessionEventError(
            "session_event_storage_not_private",
            f"{field_name} must be a private directory with mode 0700.",
            {"path": str(path), "field": field_name},
        )


def _regular_private_file(path: Path, *, field_name: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise SessionEventError(
            "session_event_storage_missing",
            f"{field_name} is missing.",
            {"path": str(path), "field": field_name},
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise SessionEventError(
            "session_event_storage_file_unsafe",
            f"{field_name} must be an owner-only regular file.",
            {"path": str(path), "field": field_name},
        )
    return info


def _open_private_lock(path: Path, *, exclusive_create: bool) -> Any:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if exclusive_create:
        flags |= os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise SessionEventError(
            "session_event_claim_lock_unsafe",
            "The session claim lock could not be opened safely.",
            {"path": str(path)},
        ) from exc
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "a+b")


class SessionEventEngine:
    """Persistent controller-side event delivery for one isolated provider session.

    The engine executes only explicitly enqueued delivery commands. It never infers
    provider integrations from source events, tasks, agent actions, or payloads.
    """

    def __init__(
        self,
        database_path: Path,
        *,
        episode_seed: str,
        initial_time: datetime | str,
    ) -> None:
        requested_path = Path(database_path).expanduser()
        if not requested_path.is_absolute():
            requested_path = Path.cwd() / requested_path
        storage_directory = requested_path.parent.resolve()
        _private_directory(storage_directory, field_name="session event storage directory")
        self.database_path = storage_directory / requested_path.name
        self.episode_seed = _identifier(episode_seed, field_name="episode_seed")
        self.initial_time = _format_time(_utc(initial_time, field_name="initial_time"))
        self._created_database = False
        if self.database_path.exists() or self.database_path.is_symlink():
            _regular_private_file(self.database_path, field_name="session event database")
        else:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(self.database_path, flags, 0o600)
            except OSError as exc:
                raise SessionEventError(
                    "session_event_storage_create_failed",
                    "The session event database could not be created safely.",
                    {"path": str(self.database_path)},
                ) from exc
            os.close(descriptor)
            self._created_database = True
        database_info = _regular_private_file(
            self.database_path, field_name="session event database"
        )
        self._database_identity = (database_info.st_dev, database_info.st_ino)
        self._owner_id = secrets.token_hex(16)
        lock_dir = self.database_path.with_name(f"{self.database_path.name}.claims")
        _private_directory(lock_dir, field_name="session claim directory")
        self._owner_lock_path = lock_dir / f"{self._owner_id}.lock"
        self._owner_lock = _open_private_lock(self._owner_lock_path, exclusive_create=True)
        fcntl.flock(self._owner_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        self._closed = False
        try:
            self._initialize()
            self._recover_orphaned_claims(lock_dir)
        except BaseException:
            self.close()
            if self._created_database:
                for path in (
                    self.database_path.with_name(f"{self.database_path.name}-shm"),
                    self.database_path.with_name(f"{self.database_path.name}-wal"),
                    self.database_path,
                ):
                    path.unlink(missing_ok=True)
            raise

    def __enter__(self) -> SessionEventEngine:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        fcntl.flock(self._owner_lock.fileno(), fcntl.LOCK_UN)
        self._owner_lock.close()
        self._owner_lock_path.unlink(missing_ok=True)

    def _connection(self) -> sqlite3.Connection:
        if self._closed:
            raise SessionEventError(
                "session_event_engine_closed", "Session event engine is closed."
            )
        info = _regular_private_file(self.database_path, field_name="session event database")
        if (info.st_dev, info.st_ino) != self._database_identity:
            raise SessionEventError(
                "session_event_database_replaced",
                "The session event database changed after the engine opened it.",
            )
        connection = sqlite3.connect(str(self.database_path), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA synchronous = FULL")
        for suffix in ("-wal", "-shm"):
            sidecar = self.database_path.with_name(f"{self.database_path.name}{suffix}")
            if sidecar.exists() or sidecar.is_symlink():
                info = sidecar.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                    connection.close()
                    raise SessionEventError(
                        "session_event_storage_file_unsafe",
                        "A SQLite sidecar is not an owner-controlled regular file.",
                        {"path": str(sidecar)},
                    )
                sidecar.chmod(0o600)
        return connection

    def _initialize(self) -> None:
        connection = self._connection()
        try:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            table_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'"
                ).fetchone()[0]
            )
            if table_count and (
                application_id != _SQLITE_APPLICATION_ID or user_version != _SQLITE_SCHEMA_VERSION
            ):
                raise SessionEventError(
                    "session_event_database_schema_conflict",
                    "The existing database is not a Datalox session-event v1 database.",
                    {"application_id": application_id, "user_version": user_version},
                )
            if application_id not in {0, _SQLITE_APPLICATION_ID} or user_version not in {
                0,
                _SQLITE_SCHEMA_VERSION,
            }:
                raise SessionEventError(
                    "session_event_database_schema_conflict",
                    "The database declares a different application or schema version.",
                    {"application_id": application_id, "user_version": user_version},
                )
            connection.executescript(
                f"""
                PRAGMA journal_mode = WAL;
                PRAGMA application_id = {_SQLITE_APPLICATION_ID};
                PRAGMA user_version = {_SQLITE_SCHEMA_VERSION};
                CREATE TABLE IF NOT EXISTS session_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    episode_seed TEXT NOT NULL,
                    initial_time TEXT NOT NULL,
                    logical_time TEXT NOT NULL,
                    next_event_sequence INTEGER NOT NULL CHECK (next_event_sequence >= 0),
                    next_delivery_sequence INTEGER NOT NULL CHECK (next_delivery_sequence >= 0),
                    next_effect_sequence INTEGER NOT NULL CHECK (next_effect_sequence >= 0),
                    stored_json_bytes INTEGER NOT NULL CHECK (stored_json_bytes >= 0),
                    reserved_json_bytes INTEGER NOT NULL CHECK (reserved_json_bytes >= 0),
                    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
                    resolution_count INTEGER NOT NULL CHECK (resolution_count >= 0),
                    CHECK (stored_json_bytes + reserved_json_bytes <= {MAX_SESSION_STORED_JSON_BYTES}),
                    CHECK (attempt_count <= {MAX_SESSION_DELIVERY_ATTEMPTS}),
                    CHECK (resolution_count <= {MAX_SESSION_UNKNOWN_RESOLUTIONS})
                );
                CREATE TABLE IF NOT EXISTS source_events (
                    source_event_id TEXT PRIMARY KEY,
                    source_provider_id TEXT NOT NULL,
                    provider_event_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    correlation_ids_json TEXT NOT NULL,
                    idempotency_key TEXT,
                    content_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL UNIQUE,
                    recorded_at TEXT NOT NULL,
                    UNIQUE(source_provider_id, provider_event_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS source_event_idempotency
                    ON source_events(source_provider_id, idempotency_key)
                    WHERE idempotency_key IS NOT NULL;
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    edge_id TEXT NOT NULL,
                    ordering_key TEXT NOT NULL,
                    source_event_id TEXT NOT NULL REFERENCES source_events(source_event_id),
                    target_provider_id TEXT NOT NULL,
                    target_operation_id TEXT NOT NULL,
                    target_principal_context_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    correlation_ids_json TEXT NOT NULL,
                    idempotency_key TEXT,
                    retry_delays_json TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL UNIQUE,
                    enqueued_at TEXT NOT NULL,
                    initial_available_at TEXT NOT NULL,
                    available_at TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN (
                        'queued', 'retry_scheduled', 'in_flight', 'delivered',
                        'terminal_failure', 'unknown_completion'
                    )),
                    claim_owner TEXT,
                    claim_attempt_number INTEGER,
                    CHECK (
                        (state = 'in_flight' AND claim_owner IS NOT NULL AND claim_attempt_number IS NOT NULL)
                        OR
                        (state != 'in_flight' AND claim_owner IS NULL AND claim_attempt_number IS NULL)
                    )
                );
                CREATE UNIQUE INDEX IF NOT EXISTS delivery_idempotency
                    ON deliveries(edge_id, idempotency_key)
                    WHERE idempotency_key IS NOT NULL;
                CREATE INDEX IF NOT EXISTS delivery_ordering_stream
                    ON deliveries(edge_id, ordering_key, sequence, state);
                CREATE TABLE IF NOT EXISTS delivery_attempts (
                    delivery_id TEXT NOT NULL REFERENCES deliveries(delivery_id) ON DELETE CASCADE,
                    attempt_number INTEGER NOT NULL CHECK (
                        attempt_number BETWEEN 1 AND {MAX_DELIVERY_ATTEMPTS}
                    ),
                    available_at TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    outcome TEXT NOT NULL CHECK (outcome IN (
                        'in_flight', 'delivered', 'retryable_failure',
                        'terminal_failure', 'unknown_completion'
                    )),
                    receipt_json TEXT,
                    status_code INTEGER,
                    error_code TEXT,
                    error_message TEXT,
                    retry_delay_seconds INTEGER,
                    PRIMARY KEY(delivery_id, attempt_number)
                );
                CREATE TABLE IF NOT EXISTS unknown_resolutions (
                    delivery_id TEXT NOT NULL REFERENCES deliveries(delivery_id) ON DELETE CASCADE,
                    attempt_number INTEGER NOT NULL CHECK (
                        attempt_number BETWEEN 1 AND {MAX_DELIVERY_ATTEMPTS}
                    ),
                    resolved_at TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (outcome IN (
                        'delivered', 'retryable_failure', 'terminal_failure'
                    )),
                    receipt_json TEXT NOT NULL,
                    status_code INTEGER,
                    error_code TEXT,
                    error_message TEXT,
                    retry_delay_seconds INTEGER,
                    PRIMARY KEY(delivery_id, attempt_number)
                );
                CREATE TABLE IF NOT EXISTS post_outcome_effects (
                    effect_id TEXT PRIMARY KEY,
                    origin_delivery_id TEXT NOT NULL
                        REFERENCES deliveries(delivery_id) ON DELETE CASCADE,
                    origin_attempt_number INTEGER NOT NULL CHECK (origin_attempt_number >= 1),
                    origin_kind TEXT NOT NULL CHECK (origin_kind IN ('attempt', 'resolution')),
                    effect_kind TEXT NOT NULL CHECK (
                        effect_kind IN ('source_fanout', 'existing_source_delivery')
                    ),
                    payload_json TEXT NOT NULL,
                    content_digest TEXT NOT NULL,
                    sequence INTEGER NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('pending', 'applied')),
                    applied_at TEXT
                );
                CREATE INDEX IF NOT EXISTS post_outcome_effect_state
                    ON post_outcome_effects(state, sequence);
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM session_metadata WHERE singleton = 1"
            ).fetchone()
            if row is None:
                connection.execute(
                    """INSERT INTO session_metadata(
                           singleton, episode_seed, initial_time, logical_time,
                           next_event_sequence, next_delivery_sequence, next_effect_sequence,
                           stored_json_bytes, reserved_json_bytes, attempt_count,
                           resolution_count
                       ) VALUES (1, ?, ?, ?, 0, 0, 0, 0, 0, 0, 0)""",
                    (self.episode_seed, self.initial_time, self.initial_time),
                )
            elif (
                row["episode_seed"] != self.episode_seed or row["initial_time"] != self.initial_time
            ):
                raise SessionEventError(
                    "session_event_configuration_conflict",
                    "The existing session database has a different episode seed or initial time.",
                )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _recover_orphaned_claims(self, lock_dir: Path) -> None:
        connection = self._connection()
        acquired: list[tuple[Any, Path]] = []
        recovery_receipt = _canonical_json(
            {"recovery": "orphaned_in_flight_claim"}, field_name="receipt"
        )
        recovered_claims = 0
        try:
            connection.execute("BEGIN IMMEDIATE")
            logical_time = connection.execute(
                "SELECT logical_time FROM session_metadata WHERE singleton = 1"
            ).fetchone()[0]
            rows = connection.execute(
                "SELECT DISTINCT claim_owner FROM deliveries WHERE state = 'in_flight'"
            ).fetchall()
            for row in rows:
                owner = row["claim_owner"]
                if owner == self._owner_id:
                    continue
                if not isinstance(owner, str) or re.fullmatch(r"[0-9a-f]{32}", owner) is None:
                    raise SessionEventError(
                        "session_event_claim_owner_invalid",
                        "Persisted in-flight delivery state has an invalid claim owner.",
                    )
                lock_path = lock_dir / f"{owner}.lock"
                handle = _open_private_lock(lock_path, exclusive_create=False)
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    handle.close()
                    continue
                acquired.append((handle, lock_path))
                claims = connection.execute(
                    """SELECT delivery_id, claim_attempt_number FROM deliveries
                       WHERE state = 'in_flight' AND claim_owner = ?""",
                    (owner,),
                ).fetchall()
                for claim in claims:
                    changed = connection.execute(
                        """UPDATE delivery_attempts
                           SET finished_at = ?, outcome = 'unknown_completion',
                               receipt_json = ?, error_code = ?, error_message = ?
                           WHERE delivery_id = ? AND attempt_number = ? AND outcome = 'in_flight'""",
                        (
                            logical_time,
                            recovery_receipt,
                            "delivery_owner_lost",
                            "The delivery executor ended without recording an outcome.",
                            claim["delivery_id"],
                            claim["claim_attempt_number"],
                        ),
                    ).rowcount
                    if changed != 1:
                        raise SessionEventError(
                            "session_event_claim_state_invalid",
                            "An orphaned claim has no matching in-flight attempt.",
                            {"delivery_id": claim["delivery_id"]},
                        )
                    delivery_changed = connection.execute(
                        """UPDATE deliveries
                           SET state = 'unknown_completion', claim_owner = NULL,
                               claim_attempt_number = NULL
                           WHERE delivery_id = ? AND state = 'in_flight'""",
                        (claim["delivery_id"],),
                    ).rowcount
                    if delivery_changed != 1:
                        raise SessionEventError(
                            "session_event_claim_state_invalid",
                            "An orphaned claim changed during recovery.",
                            {"delivery_id": claim["delivery_id"]},
                        )
                    recovered_claims += 1
            if recovered_claims:
                changed = connection.execute(
                    """UPDATE session_metadata
                       SET stored_json_bytes = stored_json_bytes + ?,
                           reserved_json_bytes = reserved_json_bytes - ?
                       WHERE singleton = 1 AND reserved_json_bytes >= ?""",
                    (
                        recovered_claims * _encoded_bytes(recovery_receipt),
                        recovered_claims * MAX_EVENT_JSON_BYTES,
                        recovered_claims * MAX_EVENT_JSON_BYTES,
                    ),
                ).rowcount
                if changed != 1:
                    raise SessionEventError(
                        "session_event_quota_state_invalid",
                        "Claim receipt reservations do not match persisted in-flight claims.",
                    )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
            for handle, lock_path in acquired:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()
                lock_path.unlink(missing_ok=True)

    @property
    def logical_time(self) -> str:
        connection = self._connection()
        try:
            row = connection.execute(
                "SELECT logical_time FROM session_metadata WHERE singleton = 1"
            ).fetchone()
            return str(row[0])
        finally:
            connection.close()

    def advance_to(self, value: datetime | str) -> str:
        target = _format_time(_utc(value, field_name="logical_time"))
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT logical_time FROM session_metadata WHERE singleton = 1"
            ).fetchone()[0]
            if target < current:
                raise SessionEventError(
                    "session_event_reverse_time_forbidden",
                    "Logical time may only stay fixed or move forward.",
                    {"current_time": current, "requested_time": target},
                )
            connection.execute(
                "UPDATE session_metadata SET logical_time = ? WHERE singleton = 1", (target,)
            )
            connection.commit()
            return target
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def reset(self) -> None:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            in_flight = connection.execute(
                "SELECT COUNT(*) FROM deliveries WHERE state = 'in_flight'"
            ).fetchone()[0]
            if in_flight:
                raise SessionEventError(
                    "session_event_reset_in_flight",
                    "Reset requires every claimed delivery to have a recorded outcome.",
                    {"in_flight_count": in_flight},
                )
            connection.execute("DELETE FROM post_outcome_effects")
            connection.execute("DELETE FROM unknown_resolutions")
            connection.execute("DELETE FROM delivery_attempts")
            connection.execute("DELETE FROM deliveries")
            connection.execute("DELETE FROM source_events")
            connection.execute(
                """UPDATE session_metadata
                   SET logical_time = initial_time,
                       next_event_sequence = 0,
                       next_delivery_sequence = 0,
                       next_effect_sequence = 0,
                       stored_json_bytes = 0,
                       reserved_json_bytes = 0,
                       attempt_count = 0,
                       resolution_count = 0
                   WHERE singleton = 1"""
            )
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def source_event_identity(
        self,
        *,
        source_provider_id: str,
        provider_event_id: str,
    ) -> str:
        """Return the exact deterministic identity used by source-event insertion."""

        source_provider_id = _identifier(source_provider_id, field_name="source_provider_id")
        provider_event_id = _identifier(provider_event_id, field_name="provider_event_id")
        return _stable_id(
            "evt",
            {
                "episode_seed": self.episode_seed,
                "source_provider_id": source_provider_id,
                "provider_event_id": provider_event_id,
            },
        )

    def record_source_event(
        self,
        *,
        source_provider_id: str,
        provider_event_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        correlation_ids: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> str:
        source_provider_id = _identifier(source_provider_id, field_name="source_provider_id")
        provider_event_id = _identifier(provider_event_id, field_name="provider_event_id")
        event_type = _identifier(event_type, field_name="event_type")
        idempotency_key = _optional_identifier(idempotency_key, field_name="idempotency_key")
        normalized_payload, payload_json = _json_object(payload, field_name="payload")
        normalized_correlations, correlation_json = _correlations(correlation_ids)
        identity = {
            "episode_seed": self.episode_seed,
            "source_provider_id": source_provider_id,
            "provider_event_id": provider_event_id,
        }
        content = {
            **identity,
            "event_type": event_type,
            "payload": normalized_payload,
            "correlation_ids": normalized_correlations,
            "idempotency_key": idempotency_key,
        }
        source_event_id = self.source_event_identity(
            source_provider_id=source_provider_id,
            provider_event_id=provider_event_id,
        )
        content_digest = _digest(content)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """SELECT source_event_id, content_digest FROM source_events
                   WHERE source_event_id = ? OR (
                       source_provider_id = ? AND idempotency_key = ? AND ? IS NOT NULL
                   )""",
                (source_event_id, source_provider_id, idempotency_key, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["content_digest"] != content_digest:
                    raise SessionEventError(
                        "session_event_idempotency_conflict",
                        "The source-event identity was already used for different content.",
                        {"source_event_id": existing["source_event_id"]},
                    )
                connection.commit()
                return str(existing["source_event_id"])
            metadata = connection.execute(
                """SELECT logical_time, next_event_sequence, stored_json_bytes,
                          reserved_json_bytes
                   FROM session_metadata WHERE singleton = 1"""
            ).fetchone()
            if metadata["next_event_sequence"] >= MAX_SESSION_SOURCE_EVENTS:
                raise SessionEventError(
                    "session_event_source_limit_reached",
                    f"A session may contain at most {MAX_SESSION_SOURCE_EVENTS} source events.",
                )
            added_json_bytes = _encoded_bytes(payload_json) + _encoded_bytes(correlation_json)
            if (
                metadata["stored_json_bytes"] + metadata["reserved_json_bytes"] + added_json_bytes
                > MAX_SESSION_STORED_JSON_BYTES
            ):
                raise SessionEventError(
                    "session_event_json_quota_reached",
                    "The session event JSON storage quota is exhausted.",
                    {"max_bytes": MAX_SESSION_STORED_JSON_BYTES},
                )
            sequence = metadata["next_event_sequence"]
            connection.execute(
                """INSERT INTO source_events(
                       source_event_id, source_provider_id, provider_event_id, event_type,
                       payload_json, correlation_ids_json, idempotency_key, content_digest,
                       sequence, recorded_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_event_id,
                    source_provider_id,
                    provider_event_id,
                    event_type,
                    payload_json,
                    correlation_json,
                    idempotency_key,
                    content_digest,
                    sequence,
                    metadata["logical_time"],
                ),
            )
            connection.execute(
                """UPDATE session_metadata
                   SET next_event_sequence = next_event_sequence + 1,
                       stored_json_bytes = stored_json_bytes + ?
                   WHERE singleton = 1""",
                (added_json_bytes,),
            )
            connection.commit()
            return source_event_id
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def enqueue_delivery(
        self,
        *,
        edge_id: str,
        ordering_key: str,
        source_event_id: str,
        target_provider_id: str,
        target_operation_id: str,
        target_principal_context_id: str,
        request: Mapping[str, Any],
        available_at: datetime | str,
        retry_delays_seconds: Sequence[int],
        correlation_ids: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> str:
        edge_id = _identifier(edge_id, field_name="edge_id")
        ordering_key = _identifier(ordering_key, field_name="ordering_key")
        source_event_id = _identifier(source_event_id, field_name="source_event_id")
        target_provider_id = _identifier(target_provider_id, field_name="target_provider_id")
        target_operation_id = _identifier(target_operation_id, field_name="target_operation_id")
        target_principal_context_id = _identifier(
            target_principal_context_id, field_name="target_principal_context_id"
        )
        idempotency_key = _optional_identifier(idempotency_key, field_name="idempotency_key")
        normalized_request, request_json = _json_object(request, field_name="request")
        normalized_correlations, correlation_json = _correlations(correlation_ids)
        retry_delays, retry_json = _retry_delays(retry_delays_seconds)
        available = _format_time(_utc(available_at, field_name="available_at"))
        identity = {
            "episode_seed": self.episode_seed,
            "edge_id": edge_id,
            "idempotency_key": idempotency_key,
            "source_event_id": source_event_id,
        }
        content = {
            **identity,
            "ordering_key": ordering_key,
            "target_provider_id": target_provider_id,
            "target_operation_id": target_operation_id,
            "target_principal_context_id": target_principal_context_id,
            "request": normalized_request,
            "initial_available_at": available,
            "retry_delays_seconds": list(retry_delays),
            "correlation_ids": normalized_correlations,
        }
        delivery_id = _stable_id("dlv", identity if idempotency_key is not None else content)
        content_digest = _digest(content)
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            source = connection.execute(
                "SELECT source_event_id FROM source_events WHERE source_event_id = ?",
                (source_event_id,),
            ).fetchone()
            if source is None:
                raise SessionEventError(
                    "session_event_source_missing",
                    "The delivery references an unknown source event.",
                    {"source_event_id": source_event_id},
                )
            existing = connection.execute(
                """SELECT delivery_id, content_digest FROM deliveries
                   WHERE delivery_id = ? OR (
                       edge_id = ? AND idempotency_key = ? AND ? IS NOT NULL
                   )""",
                (delivery_id, edge_id, idempotency_key, idempotency_key),
            ).fetchone()
            if existing is not None:
                if existing["content_digest"] != content_digest:
                    raise SessionEventError(
                        "session_event_idempotency_conflict",
                        "The delivery idempotency key was already used for different content.",
                        {"delivery_id": existing["delivery_id"]},
                    )
                connection.commit()
                return str(existing["delivery_id"])
            metadata = connection.execute(
                """SELECT logical_time, next_delivery_sequence, stored_json_bytes,
                          reserved_json_bytes
                   FROM session_metadata WHERE singleton = 1"""
            ).fetchone()
            if metadata["next_delivery_sequence"] >= MAX_SESSION_DELIVERIES:
                raise SessionEventError(
                    "session_event_delivery_limit_reached",
                    f"A session may contain at most {MAX_SESSION_DELIVERIES} deliveries.",
                )
            added_json_bytes = (
                _encoded_bytes(request_json)
                + _encoded_bytes(correlation_json)
                + _encoded_bytes(retry_json)
            )
            if (
                metadata["stored_json_bytes"] + metadata["reserved_json_bytes"] + added_json_bytes
                > MAX_SESSION_STORED_JSON_BYTES
            ):
                raise SessionEventError(
                    "session_event_json_quota_reached",
                    "The session event JSON storage quota is exhausted.",
                    {"max_bytes": MAX_SESSION_STORED_JSON_BYTES},
                )
            sequence = metadata["next_delivery_sequence"]
            connection.execute(
                """INSERT INTO deliveries(
                       delivery_id, edge_id, ordering_key, source_event_id, target_provider_id,
                       target_operation_id, target_principal_context_id, request_json,
                       correlation_ids_json, idempotency_key, retry_delays_json,
                       content_digest, sequence, enqueued_at, initial_available_at,
                       available_at, state,
                       claim_owner, claim_attempt_number
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                             'queued', NULL, NULL)""",
                (
                    delivery_id,
                    edge_id,
                    ordering_key,
                    source_event_id,
                    target_provider_id,
                    target_operation_id,
                    target_principal_context_id,
                    request_json,
                    correlation_json,
                    idempotency_key,
                    retry_json,
                    content_digest,
                    sequence,
                    metadata["logical_time"],
                    available,
                    available,
                ),
            )
            connection.execute(
                """UPDATE session_metadata
                   SET next_delivery_sequence = next_delivery_sequence + 1,
                       stored_json_bytes = stored_json_bytes + ?
                   WHERE singleton = 1""",
                (added_json_bytes,),
            )
            connection.commit()
            return delivery_id
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise SessionEventError(
                "session_event_delivery_conflict",
                "The delivery conflicts with existing session state.",
            ) from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def record_source_event_with_deliveries(
        self,
        *,
        source_provider_id: str,
        provider_event_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        deliveries: Sequence[DeliveryRequest],
        correlation_ids: Mapping[str, str] | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[str, tuple[str, ...]]:
        """Atomically record one source event and its complete declared fan-out.

        The method is intentionally separate from the single-record authoring methods:
        a composition session must never expose a source event whose downstream fan-out
        was only partly scheduled.
        """

        if isinstance(deliveries, (str, bytes)) or not isinstance(deliveries, Sequence):
            raise SessionEventError(
                "session_event_delivery_batch_invalid",
                "deliveries must be a finite sequence of DeliveryRequest values.",
            )
        if not deliveries:
            raise SessionEventError(
                "session_event_delivery_batch_empty",
                "An atomic source fan-out must contain at least one delivery.",
            )
        if len(deliveries) > MAX_SESSION_DELIVERIES:
            raise SessionEventError(
                "session_event_delivery_limit_reached",
                f"A session may contain at most {MAX_SESSION_DELIVERIES} deliveries.",
            )

        source_provider_id = _identifier(source_provider_id, field_name="source_provider_id")
        provider_event_id = _identifier(provider_event_id, field_name="provider_event_id")
        event_type = _identifier(event_type, field_name="event_type")
        idempotency_key = _optional_identifier(idempotency_key, field_name="idempotency_key")
        normalized_payload, payload_json = _json_object(payload, field_name="payload")
        normalized_correlations, correlation_json = _correlations(correlation_ids)
        source_identity = {
            "episode_seed": self.episode_seed,
            "source_provider_id": source_provider_id,
            "provider_event_id": provider_event_id,
        }
        source_content = {
            **source_identity,
            "event_type": event_type,
            "payload": normalized_payload,
            "correlation_ids": normalized_correlations,
            "idempotency_key": idempotency_key,
        }
        source_event_id = self.source_event_identity(
            source_provider_id=source_provider_id,
            provider_event_id=provider_event_id,
        )
        source_content_digest = _digest(source_content)

        prepared: list[dict[str, Any]] = []
        delivery_ids: set[str] = set()
        idempotency_identities: set[tuple[str, str]] = set()
        for index, item in enumerate(deliveries):
            if not isinstance(item, DeliveryRequest):
                raise SessionEventError(
                    "session_event_delivery_batch_invalid",
                    "Every deliveries entry must be a DeliveryRequest.",
                    {"index": index},
                )
            edge_id = _identifier(item.edge_id, field_name=f"deliveries[{index}].edge_id")
            ordering_key = _identifier(
                item.ordering_key, field_name=f"deliveries[{index}].ordering_key"
            )
            target_provider_id = _identifier(
                item.target_provider_id,
                field_name=f"deliveries[{index}].target_provider_id",
            )
            target_operation_id = _identifier(
                item.target_operation_id,
                field_name=f"deliveries[{index}].target_operation_id",
            )
            target_principal_context_id = _identifier(
                item.target_principal_context_id,
                field_name=f"deliveries[{index}].target_principal_context_id",
            )
            delivery_idempotency_key = _optional_identifier(
                item.idempotency_key,
                field_name=f"deliveries[{index}].idempotency_key",
            )
            normalized_request, request_json = _json_object(
                item.request, field_name=f"deliveries[{index}].request"
            )
            delivery_correlations, delivery_correlation_json = _correlations(item.correlation_ids)
            retry_delays, retry_json = _retry_delays(item.retry_delays_seconds)
            available = _format_time(
                _utc(item.available_at, field_name=f"deliveries[{index}].available_at")
            )
            delivery_identity = {
                "episode_seed": self.episode_seed,
                "edge_id": edge_id,
                "idempotency_key": delivery_idempotency_key,
                "source_event_id": source_event_id,
            }
            delivery_content = {
                **delivery_identity,
                "ordering_key": ordering_key,
                "target_provider_id": target_provider_id,
                "target_operation_id": target_operation_id,
                "target_principal_context_id": target_principal_context_id,
                "request": normalized_request,
                "initial_available_at": available,
                "retry_delays_seconds": list(retry_delays),
                "correlation_ids": delivery_correlations,
            }
            delivery_id = _stable_id(
                "dlv",
                delivery_identity if delivery_idempotency_key is not None else delivery_content,
            )
            if delivery_id in delivery_ids:
                raise SessionEventError(
                    "session_event_delivery_batch_duplicate",
                    "An atomic source fan-out must not repeat a delivery identity.",
                    {"delivery_id": delivery_id},
                )
            delivery_ids.add(delivery_id)
            if delivery_idempotency_key is not None:
                identity_key = (edge_id, delivery_idempotency_key)
                if identity_key in idempotency_identities:
                    raise SessionEventError(
                        "session_event_delivery_batch_duplicate",
                        "An atomic source fan-out must not repeat an edge idempotency key.",
                        {"edge_id": edge_id, "idempotency_key": delivery_idempotency_key},
                    )
                idempotency_identities.add(identity_key)
            prepared.append(
                {
                    "delivery_id": delivery_id,
                    "edge_id": edge_id,
                    "ordering_key": ordering_key,
                    "target_provider_id": target_provider_id,
                    "target_operation_id": target_operation_id,
                    "target_principal_context_id": target_principal_context_id,
                    "request_json": request_json,
                    "correlation_json": delivery_correlation_json,
                    "idempotency_key": delivery_idempotency_key,
                    "retry_json": retry_json,
                    "content_digest": _digest(delivery_content),
                    "available": available,
                    "json_bytes": _encoded_bytes(request_json)
                    + _encoded_bytes(delivery_correlation_json)
                    + _encoded_bytes(retry_json),
                }
            )

        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_source = connection.execute(
                """SELECT source_event_id, content_digest FROM source_events
                   WHERE source_event_id = ? OR (
                       source_provider_id = ? AND idempotency_key = ? AND ? IS NOT NULL
                   )""",
                (
                    source_event_id,
                    source_provider_id,
                    idempotency_key,
                    idempotency_key,
                ),
            ).fetchone()
            if existing_source is not None:
                if existing_source["content_digest"] != source_content_digest:
                    raise SessionEventError(
                        "session_event_idempotency_conflict",
                        "The source-event identity was already used for different content.",
                        {"source_event_id": existing_source["source_event_id"]},
                    )
                for item in prepared:
                    existing_delivery = connection.execute(
                        """SELECT delivery_id, content_digest FROM deliveries
                           WHERE delivery_id = ? OR (
                               edge_id = ? AND idempotency_key = ? AND ? IS NOT NULL
                           )""",
                        (
                            item["delivery_id"],
                            item["edge_id"],
                            item["idempotency_key"],
                            item["idempotency_key"],
                        ),
                    ).fetchone()
                    if existing_delivery is None:
                        raise SessionEventError(
                            "session_event_batch_replay_incomplete",
                            "The source event already exists without the complete declared fan-out.",
                            {"source_event_id": source_event_id},
                        )
                    if existing_delivery["content_digest"] != item["content_digest"]:
                        raise SessionEventError(
                            "session_event_idempotency_conflict",
                            "A delivery identity was already used for different content.",
                            {"delivery_id": existing_delivery["delivery_id"]},
                        )
                connection.commit()
                return source_event_id, tuple(item["delivery_id"] for item in prepared)

            metadata = connection.execute(
                """SELECT logical_time, next_event_sequence, next_delivery_sequence,
                          stored_json_bytes, reserved_json_bytes
                   FROM session_metadata WHERE singleton = 1"""
            ).fetchone()
            if metadata["next_event_sequence"] >= MAX_SESSION_SOURCE_EVENTS:
                raise SessionEventError(
                    "session_event_source_limit_reached",
                    f"A session may contain at most {MAX_SESSION_SOURCE_EVENTS} source events.",
                )
            if metadata["next_delivery_sequence"] + len(prepared) > MAX_SESSION_DELIVERIES:
                raise SessionEventError(
                    "session_event_delivery_limit_reached",
                    f"A session may contain at most {MAX_SESSION_DELIVERIES} deliveries.",
                )
            added_json_bytes = (
                _encoded_bytes(payload_json)
                + _encoded_bytes(correlation_json)
                + sum(int(item["json_bytes"]) for item in prepared)
            )
            if (
                metadata["stored_json_bytes"] + metadata["reserved_json_bytes"] + added_json_bytes
                > MAX_SESSION_STORED_JSON_BYTES
            ):
                raise SessionEventError(
                    "session_event_json_quota_reached",
                    "The session event JSON storage quota is exhausted.",
                    {"max_bytes": MAX_SESSION_STORED_JSON_BYTES},
                )

            connection.execute(
                """INSERT INTO source_events(
                       source_event_id, source_provider_id, provider_event_id, event_type,
                       payload_json, correlation_ids_json, idempotency_key, content_digest,
                       sequence, recorded_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    source_event_id,
                    source_provider_id,
                    provider_event_id,
                    event_type,
                    payload_json,
                    correlation_json,
                    idempotency_key,
                    source_content_digest,
                    metadata["next_event_sequence"],
                    metadata["logical_time"],
                ),
            )
            for offset, item in enumerate(prepared):
                connection.execute(
                    """INSERT INTO deliveries(
                           delivery_id, edge_id, ordering_key, source_event_id,
                           target_provider_id, target_operation_id,
                           target_principal_context_id, request_json,
                           correlation_ids_json, idempotency_key, retry_delays_json,
                           content_digest, sequence, enqueued_at, initial_available_at,
                           available_at, state, claim_owner, claim_attempt_number
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                 'queued', NULL, NULL)""",
                    (
                        item["delivery_id"],
                        item["edge_id"],
                        item["ordering_key"],
                        source_event_id,
                        item["target_provider_id"],
                        item["target_operation_id"],
                        item["target_principal_context_id"],
                        item["request_json"],
                        item["correlation_json"],
                        item["idempotency_key"],
                        item["retry_json"],
                        item["content_digest"],
                        metadata["next_delivery_sequence"] + offset,
                        metadata["logical_time"],
                        item["available"],
                        item["available"],
                    ),
                )
            connection.execute(
                """UPDATE session_metadata
                   SET next_event_sequence = next_event_sequence + 1,
                       next_delivery_sequence = next_delivery_sequence + ?,
                       stored_json_bytes = stored_json_bytes + ?
                   WHERE singleton = 1""",
                (len(prepared), added_json_bytes),
            )
            connection.commit()
            return source_event_id, tuple(item["delivery_id"] for item in prepared)
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise SessionEventError(
                "session_event_delivery_conflict",
                "The atomic source fan-out conflicts with existing session state.",
            ) from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _normalize_post_outcome_effects(
        self,
        value: Sequence[PostOutcomeEffect],
    ) -> tuple[tuple[str, dict[str, Any], str], ...]:
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise SessionEventError(
                "session_event_post_effects_invalid",
                "Post-outcome effects must be a finite sequence.",
            )
        if len(value) > MAX_SESSION_POST_OUTCOME_EFFECTS:
            raise SessionEventError(
                "session_event_post_effect_limit_reached",
                f"One outcome may schedule at most {MAX_SESSION_POST_OUTCOME_EFFECTS} effects.",
            )
        result: list[tuple[str, dict[str, Any], str]] = []
        digests: set[str] = set()
        for index, effect in enumerate(value):
            if isinstance(effect, SourceFanoutRequest):
                if (
                    isinstance(effect.deliveries, (str, bytes))
                    or not isinstance(effect.deliveries, Sequence)
                    or not effect.deliveries
                ):
                    raise SessionEventError(
                        "session_event_post_effect_invalid",
                        "A source-fanout effect requires at least one delivery.",
                        {"index": index},
                    )
                payload = {
                    "source_provider_id": _identifier(
                        effect.source_provider_id,
                        field_name=f"effects[{index}].source_provider_id",
                    ),
                    "provider_event_id": _identifier(
                        effect.provider_event_id,
                        field_name=f"effects[{index}].provider_event_id",
                    ),
                    "event_type": _identifier(
                        effect.event_type,
                        field_name=f"effects[{index}].event_type",
                    ),
                    "payload": _json_object(effect.payload, field_name=f"effects[{index}].payload")[
                        0
                    ],
                    "correlation_ids": _correlations(effect.correlation_ids)[0],
                    "idempotency_key": _optional_identifier(
                        effect.idempotency_key,
                        field_name=f"effects[{index}].idempotency_key",
                    ),
                    "deliveries": [
                        self._delivery_request_payload(
                            delivery,
                            field_name=f"effects[{index}].deliveries[{delivery_index}]",
                        )
                        for delivery_index, delivery in enumerate(effect.deliveries)
                    ],
                }
                effect_kind = "source_fanout"
            elif isinstance(effect, ExistingSourceDeliveryRequest):
                payload = {
                    "source_event_id": _identifier(
                        effect.source_event_id,
                        field_name=f"effects[{index}].source_event_id",
                    ),
                    "delivery": self._delivery_request_payload(
                        effect.delivery,
                        field_name=f"effects[{index}].delivery",
                    ),
                }
                effect_kind = "existing_source_delivery"
            else:
                raise SessionEventError(
                    "session_event_post_effect_invalid",
                    "Every post-outcome effect must use a declared effect type.",
                    {"index": index},
                )
            payload_json = _canonical_json(payload, field_name=f"effects[{index}]")
            digest = _digest({"effect_kind": effect_kind, "payload": payload})
            if digest in digests:
                raise SessionEventError(
                    "session_event_post_effect_duplicate",
                    "One outcome must not repeat the same post-outcome effect.",
                    {"index": index},
                )
            digests.add(digest)
            result.append((effect_kind, payload, payload_json))
        return tuple(result)

    def _delivery_request_payload(
        self,
        value: DeliveryRequest,
        *,
        field_name: str,
    ) -> dict[str, Any]:
        if not isinstance(value, DeliveryRequest):
            raise SessionEventError(
                "session_event_post_effect_invalid",
                f"{field_name} must be a DeliveryRequest.",
            )
        return {
            "edge_id": _identifier(value.edge_id, field_name=f"{field_name}.edge_id"),
            "ordering_key": _identifier(
                value.ordering_key, field_name=f"{field_name}.ordering_key"
            ),
            "target_provider_id": _identifier(
                value.target_provider_id,
                field_name=f"{field_name}.target_provider_id",
            ),
            "target_operation_id": _identifier(
                value.target_operation_id,
                field_name=f"{field_name}.target_operation_id",
            ),
            "target_principal_context_id": _identifier(
                value.target_principal_context_id,
                field_name=f"{field_name}.target_principal_context_id",
            ),
            "request": _json_object(value.request, field_name=f"{field_name}.request")[0],
            "available_at": _format_time(
                _utc(value.available_at, field_name=f"{field_name}.available_at")
            ),
            "retry_delays_seconds": list(_retry_delays(value.retry_delays_seconds)[0]),
            "correlation_ids": _correlations(value.correlation_ids)[0],
            "idempotency_key": _optional_identifier(
                value.idempotency_key,
                field_name=f"{field_name}.idempotency_key",
            ),
        }

    def _persist_post_outcome_effects(
        self,
        connection: sqlite3.Connection,
        *,
        command: DeliveryCommand,
        origin_kind: Literal["attempt", "resolution"],
        effects: tuple[tuple[str, dict[str, Any], str], ...],
    ) -> None:
        if not effects:
            return
        metadata = connection.execute(
            """SELECT logical_time, next_effect_sequence, stored_json_bytes,
                      reserved_json_bytes
               FROM session_metadata WHERE singleton = 1"""
        ).fetchone()
        if metadata["next_effect_sequence"] + len(effects) > MAX_SESSION_POST_OUTCOME_EFFECTS:
            raise SessionEventError(
                "session_event_post_effect_limit_reached",
                f"A session may contain at most {MAX_SESSION_POST_OUTCOME_EFFECTS} post-outcome effects.",
            )
        added_json_bytes = sum(_encoded_bytes(item[2]) for item in effects)
        if (
            metadata["stored_json_bytes"] + metadata["reserved_json_bytes"] + added_json_bytes
            > MAX_SESSION_STORED_JSON_BYTES
        ):
            raise SessionEventError(
                "session_event_json_quota_reached",
                "The session has no remaining post-outcome effect capacity.",
                {"max_bytes": MAX_SESSION_STORED_JSON_BYTES},
            )
        for offset, (effect_kind, payload, payload_json) in enumerate(effects):
            identity = {
                "episode_seed": self.episode_seed,
                "origin_delivery_id": command.delivery_id,
                "origin_attempt_number": command.attempt_number,
                "origin_kind": origin_kind,
                "effect_index": offset,
                "effect_kind": effect_kind,
                "payload": payload,
            }
            connection.execute(
                """INSERT INTO post_outcome_effects(
                       effect_id, origin_delivery_id, origin_attempt_number, origin_kind,
                       effect_kind, payload_json, content_digest, sequence, created_at,
                       state, applied_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL)""",
                (
                    _stable_id("efx", identity),
                    command.delivery_id,
                    command.attempt_number,
                    origin_kind,
                    effect_kind,
                    payload_json,
                    _digest({"effect_kind": effect_kind, "payload": payload}),
                    metadata["next_effect_sequence"] + offset,
                    metadata["logical_time"],
                ),
            )
        connection.execute(
            """UPDATE session_metadata
               SET next_effect_sequence = next_effect_sequence + ?,
                   stored_json_bytes = stored_json_bytes + ?
               WHERE singleton = 1""",
            (len(effects), added_json_bytes),
        )

    def apply_pending_effects(self) -> tuple[str, ...]:
        """Idempotently apply every durable post-outcome effect in sequence order."""

        applied: list[str] = []
        for _ in range(MAX_SESSION_POST_OUTCOME_EFFECTS):
            connection = self._connection()
            try:
                row = connection.execute(
                    """SELECT * FROM post_outcome_effects
                       WHERE state = 'pending' ORDER BY sequence ASC LIMIT 1"""
                ).fetchone()
            finally:
                connection.close()
            if row is None:
                return tuple(applied)
            payload = json.loads(row["payload_json"])
            if row["effect_kind"] == "source_fanout":
                self.record_source_event_with_deliveries(
                    source_provider_id=payload["source_provider_id"],
                    provider_event_id=payload["provider_event_id"],
                    event_type=payload["event_type"],
                    payload=payload["payload"],
                    deliveries=tuple(
                        self._delivery_request_from_payload(item) for item in payload["deliveries"]
                    ),
                    correlation_ids=payload["correlation_ids"],
                    idempotency_key=payload["idempotency_key"],
                )
            elif row["effect_kind"] == "existing_source_delivery":
                delivery = self._delivery_request_from_payload(payload["delivery"])
                self.enqueue_delivery(
                    edge_id=delivery.edge_id,
                    ordering_key=delivery.ordering_key,
                    source_event_id=payload["source_event_id"],
                    target_provider_id=delivery.target_provider_id,
                    target_operation_id=delivery.target_operation_id,
                    target_principal_context_id=delivery.target_principal_context_id,
                    request=delivery.request,
                    available_at=delivery.available_at,
                    retry_delays_seconds=delivery.retry_delays_seconds,
                    correlation_ids=delivery.correlation_ids,
                    idempotency_key=delivery.idempotency_key,
                )
            else:
                raise SessionEventError(
                    "session_event_post_effect_state_invalid",
                    "A persisted post-outcome effect has an invalid kind.",
                )
            connection = self._connection()
            try:
                connection.execute("BEGIN IMMEDIATE")
                applied_at = connection.execute(
                    "SELECT logical_time FROM session_metadata WHERE singleton = 1"
                ).fetchone()[0]
                connection.execute(
                    """UPDATE post_outcome_effects SET state = 'applied', applied_at = ?
                       WHERE effect_id = ? AND state = 'pending'""",
                    (applied_at, row["effect_id"]),
                )
                connection.commit()
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            finally:
                connection.close()
            applied.append(str(row["effect_id"]))
        raise SessionEventError(
            "session_event_post_effect_limit_reached",
            "The bounded post-outcome effect drain did not reach an empty queue.",
        )

    @staticmethod
    def _delivery_request_from_payload(payload: Mapping[str, Any]) -> DeliveryRequest:
        return DeliveryRequest(
            edge_id=payload["edge_id"],
            ordering_key=payload["ordering_key"],
            target_provider_id=payload["target_provider_id"],
            target_operation_id=payload["target_operation_id"],
            target_principal_context_id=payload["target_principal_context_id"],
            request=payload["request"],
            available_at=payload["available_at"],
            retry_delays_seconds=payload["retry_delays_seconds"],
            correlation_ids=payload["correlation_ids"],
            idempotency_key=payload["idempotency_key"],
        )

    def _claim_due(self) -> DeliveryCommand | None:
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            metadata = connection.execute(
                """SELECT logical_time, stored_json_bytes, reserved_json_bytes,
                          attempt_count
                   FROM session_metadata WHERE singleton = 1"""
            ).fetchone()
            now = metadata["logical_time"]
            row = connection.execute(
                """SELECT d.* FROM deliveries d
                   WHERE d.state IN ('queued', 'retry_scheduled') AND d.available_at <= ?
                     AND NOT EXISTS (
                         SELECT 1 FROM deliveries predecessor
                          WHERE predecessor.edge_id = d.edge_id
                            AND predecessor.ordering_key = d.ordering_key
                            AND predecessor.sequence < d.sequence
                            AND predecessor.state IN (
                                'queued', 'retry_scheduled', 'in_flight',
                                'unknown_completion'
                            )
                     )
                   ORDER BY d.available_at ASC, d.sequence ASC, d.delivery_id ASC LIMIT 1""",
                (now,),
            ).fetchone()
            if row is None:
                connection.commit()
                return None
            if metadata["attempt_count"] >= MAX_SESSION_DELIVERY_ATTEMPTS:
                raise SessionEventError(
                    "session_event_attempt_limit_reached",
                    "The session delivery-attempt quota is exhausted.",
                    {"max_attempts": MAX_SESSION_DELIVERY_ATTEMPTS},
                )
            if (
                metadata["stored_json_bytes"]
                + metadata["reserved_json_bytes"]
                + MAX_EVENT_JSON_BYTES
                > MAX_SESSION_STORED_JSON_BYTES
            ):
                raise SessionEventError(
                    "session_event_json_quota_reached",
                    "The session has no remaining receipt reservation capacity.",
                    {"max_bytes": MAX_SESSION_STORED_JSON_BYTES},
                )
            attempt_number = connection.execute(
                """SELECT COALESCE(MAX(attempt_number), 0) + 1 FROM delivery_attempts
                   WHERE delivery_id = ?""",
                (row["delivery_id"],),
            ).fetchone()[0]
            connection.execute(
                """INSERT INTO delivery_attempts(
                       delivery_id, attempt_number, available_at, started_at, outcome
                   ) VALUES (?, ?, ?, ?, 'in_flight')""",
                (row["delivery_id"], attempt_number, row["available_at"], now),
            )
            changed = connection.execute(
                """UPDATE deliveries
                   SET state = 'in_flight', claim_owner = ?, claim_attempt_number = ?
                   WHERE delivery_id = ? AND state IN ('queued', 'retry_scheduled')""",
                (self._owner_id, attempt_number, row["delivery_id"]),
            ).rowcount
            if changed != 1:
                raise SessionEventError(
                    "session_event_claim_conflict", "The due delivery could not be claimed."
                )
            connection.execute(
                """UPDATE session_metadata
                   SET attempt_count = attempt_count + 1,
                       reserved_json_bytes = reserved_json_bytes + ?
                   WHERE singleton = 1""",
                (MAX_EVENT_JSON_BYTES,),
            )
            connection.commit()
            return DeliveryCommand(
                delivery_id=row["delivery_id"],
                edge_id=row["edge_id"],
                ordering_key=row["ordering_key"],
                source_event_id=row["source_event_id"],
                target_provider_id=row["target_provider_id"],
                target_operation_id=row["target_operation_id"],
                target_principal_context_id=row["target_principal_context_id"],
                request=json.loads(row["request_json"]),
                correlation_ids=json.loads(row["correlation_ids_json"]),
                attempt_number=attempt_number,
                available_at=row["available_at"],
            )
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def run_due(
        self,
        executor: Callable[[DeliveryCommand], DeliveryOutcome],
        *,
        effect_factory: PostOutcomeEffectFactory | None = None,
    ) -> DeliveryRunResult | None:
        command = self._claim_due()
        if command is None:
            return None
        try:
            outcome = executor(command)
        except Exception:
            normalized = self._validate_outcome(
                DeliveryOutcome(
                    kind="unknown_completion",
                    receipt={"executor_error": "delivery_executor_exception"},
                    error_code="delivery_executor_exception",
                    error_message=(
                        "The delivery executor did not produce a trusted completion outcome."
                    ),
                ),
                allow_unknown=True,
            )
        else:
            try:
                if not isinstance(outcome, DeliveryOutcome):
                    raise SessionEventError(
                        "session_event_executor_outcome_invalid",
                        "The delivery executor must return DeliveryOutcome.",
                    )
                normalized = self._validate_outcome(outcome, allow_unknown=True)
            except SessionEventError as exc:
                normalized = self._validate_outcome(
                    DeliveryOutcome(
                        kind="unknown_completion",
                        receipt={"executor_error": exc.code},
                        error_code=exc.code,
                        error_message=(
                            "The delivery executor returned an invalid completion outcome."
                        ),
                    ),
                    allow_unknown=True,
                )
            except Exception:
                normalized = self._validate_outcome(
                    DeliveryOutcome(
                        kind="unknown_completion",
                        receipt={"executor_error": "session_event_executor_outcome_invalid"},
                        error_code="session_event_executor_outcome_invalid",
                        error_message=(
                            "The delivery executor returned an invalid completion outcome."
                        ),
                    ),
                    allow_unknown=True,
                )
        return self._finish_claim(command, normalized, effect_factory=effect_factory)

    def _validate_outcome(
        self, outcome: DeliveryOutcome, *, allow_unknown: bool
    ) -> DeliveryOutcome:
        kinds = {"delivered", "retryable_failure", "terminal_failure"}
        if allow_unknown:
            kinds.add("unknown_completion")
        if outcome.kind not in kinds:
            raise SessionEventError(
                "session_event_outcome_kind_invalid",
                "The delivery outcome kind is not allowed here.",
                {"kind": outcome.kind},
            )
        receipt, _ = _json_object(outcome.receipt, field_name="receipt")
        status_code = outcome.status_code
        if status_code is not None and (
            isinstance(status_code, bool)
            or not isinstance(status_code, int)
            or not 100 <= status_code <= 599
        ):
            raise SessionEventError(
                "session_event_status_code_invalid",
                "status_code must be an HTTP status from 100 through 599.",
            )
        error_code = outcome.error_code
        error_message = outcome.error_message
        if outcome.kind == "delivered":
            if error_code is not None or error_message is not None:
                raise SessionEventError(
                    "session_event_delivered_error_invalid",
                    "A delivered outcome cannot include error metadata.",
                )
        else:
            error_code = _identifier(error_code or "delivery_failure", field_name="error_code")
            if (
                not isinstance(error_message, str)
                or not error_message
                or len(error_message) > _MAX_ERROR_MESSAGE
            ):
                raise SessionEventError(
                    "session_event_error_message_invalid",
                    f"Failure outcomes require an error_message up to {_MAX_ERROR_MESSAGE} characters.",
                )
        return DeliveryOutcome(
            kind=outcome.kind,
            receipt=receipt,
            status_code=status_code,
            error_code=error_code,
            error_message=error_message,
        )

    def _finish_claim(
        self,
        command: DeliveryCommand,
        outcome: DeliveryOutcome,
        *,
        effect_factory: PostOutcomeEffectFactory | None,
    ) -> DeliveryRunResult:
        receipt_json = _canonical_json(outcome.receipt, field_name="receipt")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT d.*, a.started_at FROM deliveries d
                   JOIN delivery_attempts a
                     ON a.delivery_id = d.delivery_id
                    AND a.attempt_number = d.claim_attempt_number
                   WHERE d.delivery_id = ? AND d.state = 'in_flight'
                     AND d.claim_owner = ? AND d.claim_attempt_number = ?
                     AND a.outcome = 'in_flight'""",
                (command.delivery_id, self._owner_id, command.attempt_number),
            ).fetchone()
            if row is None:
                raise SessionEventError(
                    "session_event_claim_lost",
                    "The delivery claim is no longer owned by this executor.",
                    {"delivery_id": command.delivery_id},
                )
            delivery_state: DeliveryState
            next_available: str | None = None
            retry_delay: int | None = None
            if outcome.kind == "delivered":
                delivery_state = "delivered"
            elif outcome.kind == "terminal_failure":
                delivery_state = "terminal_failure"
            elif outcome.kind == "unknown_completion":
                delivery_state = "unknown_completion"
            else:
                retry_delays = json.loads(row["retry_delays_json"])
                retry_index = command.attempt_number - 1
                if retry_index < len(retry_delays):
                    retry_delay = retry_delays[retry_index]
                    next_available = _format_time(
                        _utc(row["started_at"], field_name="started_at")
                        + timedelta(seconds=retry_delay)
                    )
                    delivery_state = "retry_scheduled"
                else:
                    delivery_state = "terminal_failure"
            effects = self._normalize_post_outcome_effects(
                () if effect_factory is None else effect_factory(command, outcome, delivery_state)
            )
            finished_at = connection.execute(
                "SELECT logical_time FROM session_metadata WHERE singleton = 1"
            ).fetchone()[0]
            attempt_changed = connection.execute(
                """UPDATE delivery_attempts
                   SET finished_at = ?, outcome = ?, receipt_json = ?, status_code = ?,
                       error_code = ?, error_message = ?, retry_delay_seconds = ?
                   WHERE delivery_id = ? AND attempt_number = ? AND outcome = 'in_flight'""",
                (
                    finished_at,
                    outcome.kind,
                    receipt_json,
                    outcome.status_code,
                    outcome.error_code,
                    outcome.error_message,
                    retry_delay,
                    command.delivery_id,
                    command.attempt_number,
                ),
            ).rowcount
            if attempt_changed != 1:
                raise SessionEventError(
                    "session_event_claim_state_invalid",
                    "The claimed attempt changed before its outcome was recorded.",
                    {"delivery_id": command.delivery_id},
                )
            delivery_changed = connection.execute(
                """UPDATE deliveries
                   SET state = ?, available_at = COALESCE(?, available_at),
                       claim_owner = NULL, claim_attempt_number = NULL
                   WHERE delivery_id = ?""",
                (delivery_state, next_available, command.delivery_id),
            ).rowcount
            if delivery_changed != 1:
                raise SessionEventError(
                    "session_event_claim_state_invalid",
                    "The claimed delivery changed before its outcome was recorded.",
                    {"delivery_id": command.delivery_id},
                )
            quota_changed = connection.execute(
                """UPDATE session_metadata
                   SET stored_json_bytes = stored_json_bytes + ?,
                       reserved_json_bytes = reserved_json_bytes - ?
                   WHERE singleton = 1 AND reserved_json_bytes >= ?""",
                (
                    _encoded_bytes(receipt_json),
                    MAX_EVENT_JSON_BYTES,
                    MAX_EVENT_JSON_BYTES,
                ),
            ).rowcount
            if quota_changed != 1:
                raise SessionEventError(
                    "session_event_quota_state_invalid",
                    "The claimed delivery has no matching receipt reservation.",
                    {"delivery_id": command.delivery_id},
                )
            self._persist_post_outcome_effects(
                connection,
                command=command,
                origin_kind="attempt",
                effects=effects,
            )
            connection.commit()
            return DeliveryRunResult(
                delivery_id=command.delivery_id,
                attempt_number=command.attempt_number,
                attempt_outcome=outcome.kind,
                delivery_state=delivery_state,
                next_available_at=next_available,
            )
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def resolve_unknown(
        self,
        delivery_id: str,
        outcome: DeliveryOutcome,
        *,
        effect_factory: PostOutcomeEffectFactory | None = None,
    ) -> DeliveryRunResult:
        delivery_id = _identifier(delivery_id, field_name="delivery_id")
        normalized = self._validate_outcome(outcome, allow_unknown=False)
        receipt_json = _canonical_json(normalized.receipt, field_name="receipt")
        connection = self._connection()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """SELECT d.*,
                          (SELECT MAX(attempt_number) FROM delivery_attempts a
                           WHERE a.delivery_id = d.delivery_id) AS attempt_number,
                          (SELECT started_at FROM delivery_attempts a
                           WHERE a.delivery_id = d.delivery_id
                           ORDER BY attempt_number DESC LIMIT 1) AS started_at
                   FROM deliveries d WHERE delivery_id = ?""",
                (delivery_id,),
            ).fetchone()
            if row is None:
                raise SessionEventError(
                    "session_event_delivery_missing",
                    "The delivery does not exist.",
                    {"delivery_id": delivery_id},
                )
            if row["state"] != "unknown_completion":
                raise SessionEventError(
                    "session_event_resolution_state_invalid",
                    "Only a delivery with unknown completion may be resolved.",
                    {"delivery_id": delivery_id, "state": row["state"]},
                )
            delivery_state: DeliveryState
            next_available: str | None = None
            retry_delay: int | None = None
            if normalized.kind == "delivered":
                delivery_state = "delivered"
            elif normalized.kind == "terminal_failure":
                delivery_state = "terminal_failure"
            else:
                retry_delays = json.loads(row["retry_delays_json"])
                retry_index = row["attempt_number"] - 1
                if retry_index < len(retry_delays):
                    retry_delay = retry_delays[retry_index]
                    next_available = _format_time(
                        _utc(row["started_at"], field_name="started_at")
                        + timedelta(seconds=retry_delay)
                    )
                    delivery_state = "retry_scheduled"
                else:
                    delivery_state = "terminal_failure"
            command = DeliveryCommand(
                delivery_id=row["delivery_id"],
                edge_id=row["edge_id"],
                ordering_key=row["ordering_key"],
                source_event_id=row["source_event_id"],
                target_provider_id=row["target_provider_id"],
                target_operation_id=row["target_operation_id"],
                target_principal_context_id=row["target_principal_context_id"],
                request=json.loads(row["request_json"]),
                correlation_ids=json.loads(row["correlation_ids_json"]),
                attempt_number=row["attempt_number"],
                available_at=row["available_at"],
            )
            effects = self._normalize_post_outcome_effects(
                ()
                if effect_factory is None
                else effect_factory(command, normalized, delivery_state)
            )
            resolved_at = connection.execute(
                "SELECT logical_time FROM session_metadata WHERE singleton = 1"
            ).fetchone()[0]
            quota = connection.execute(
                """SELECT stored_json_bytes, reserved_json_bytes, resolution_count
                   FROM session_metadata WHERE singleton = 1"""
            ).fetchone()
            if quota["resolution_count"] >= MAX_SESSION_UNKNOWN_RESOLUTIONS:
                raise SessionEventError(
                    "session_event_resolution_limit_reached",
                    "The session unknown-resolution quota is exhausted.",
                    {"max_resolutions": MAX_SESSION_UNKNOWN_RESOLUTIONS},
                )
            resolution_json_bytes = _encoded_bytes(receipt_json)
            if (
                quota["stored_json_bytes"] + quota["reserved_json_bytes"] + resolution_json_bytes
                > MAX_SESSION_STORED_JSON_BYTES
            ):
                raise SessionEventError(
                    "session_event_json_quota_reached",
                    "The session has no remaining resolution-receipt capacity.",
                    {"max_bytes": MAX_SESSION_STORED_JSON_BYTES},
                )
            connection.execute(
                """INSERT INTO unknown_resolutions(
                       delivery_id, attempt_number, resolved_at, outcome, receipt_json, status_code,
                       error_code, error_message, retry_delay_seconds
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    delivery_id,
                    row["attempt_number"],
                    resolved_at,
                    normalized.kind,
                    receipt_json,
                    normalized.status_code,
                    normalized.error_code,
                    normalized.error_message,
                    retry_delay,
                ),
            )
            connection.execute(
                "UPDATE deliveries SET state = ?, available_at = COALESCE(?, available_at) WHERE delivery_id = ?",
                (delivery_state, next_available, delivery_id),
            )
            connection.execute(
                """UPDATE session_metadata
                   SET resolution_count = resolution_count + 1,
                       stored_json_bytes = stored_json_bytes + ?
                   WHERE singleton = 1""",
                (resolution_json_bytes,),
            )
            self._persist_post_outcome_effects(
                connection,
                command=command,
                origin_kind="resolution",
                effects=effects,
            )
            connection.commit()
            return DeliveryRunResult(
                delivery_id=delivery_id,
                attempt_number=row["attempt_number"],
                attempt_outcome=normalized.kind,
                delivery_state=delivery_state,
                next_available_at=next_available,
            )
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.rollback()
            raise SessionEventError(
                "session_event_resolution_exists",
                "The unknown completion already has a trusted resolution.",
                {"delivery_id": delivery_id},
            ) from exc
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def export(self) -> dict[str, Any]:
        connection = self._connection()
        try:
            connection.execute("BEGIN")
            metadata = connection.execute(
                "SELECT * FROM session_metadata WHERE singleton = 1"
            ).fetchone()
            counts = connection.execute(
                """SELECT
                       (SELECT COUNT(*) FROM source_events) AS source_count,
                       (SELECT COUNT(*) FROM deliveries) AS delivery_count,
                       (SELECT COUNT(*) FROM delivery_attempts) AS attempt_count,
                       (SELECT COUNT(*) FROM unknown_resolutions) AS resolution_count,
                       (SELECT COUNT(*) FROM post_outcome_effects) AS effect_count,
                       (SELECT COUNT(*) FROM deliveries WHERE state = 'in_flight') AS in_flight_count
                """
            ).fetchone()
            stored_json_bytes = int(
                connection.execute(
                    """SELECT
                           COALESCE((SELECT SUM(
                               length(CAST(payload_json AS BLOB))
                               + length(CAST(correlation_ids_json AS BLOB))
                           ) FROM source_events), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(request_json AS BLOB))
                               + length(CAST(correlation_ids_json AS BLOB))
                               + length(CAST(retry_delays_json AS BLOB))
                           ) FROM deliveries), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(receipt_json AS BLOB))
                           ) FROM delivery_attempts WHERE receipt_json IS NOT NULL), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(receipt_json AS BLOB))
                           ) FROM unknown_resolutions), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(payload_json AS BLOB))
                           ) FROM post_outcome_effects), 0)
                    """
                ).fetchone()[0]
            )
            expected_reserved_bytes = counts["in_flight_count"] * MAX_EVENT_JSON_BYTES
            if (
                metadata["stored_json_bytes"] != stored_json_bytes
                or metadata["reserved_json_bytes"] != expected_reserved_bytes
                or metadata["attempt_count"] != counts["attempt_count"]
                or metadata["resolution_count"] != counts["resolution_count"]
                or metadata["next_event_sequence"] != counts["source_count"]
                or metadata["next_delivery_sequence"] != counts["delivery_count"]
                or metadata["next_effect_sequence"] != counts["effect_count"]
            ):
                raise SessionEventError(
                    "session_event_quota_state_invalid",
                    "Session event counters do not match persisted state.",
                )
            text_bytes = int(
                connection.execute(
                    """SELECT
                           COALESCE((SELECT SUM(
                               length(CAST(source_event_id AS BLOB))
                               + length(CAST(source_provider_id AS BLOB))
                               + length(CAST(provider_event_id AS BLOB))
                               + length(CAST(event_type AS BLOB))
                               + length(CAST(payload_json AS BLOB))
                               + length(CAST(correlation_ids_json AS BLOB))
                               + length(CAST(COALESCE(idempotency_key, '') AS BLOB))
                               + length(CAST(content_digest AS BLOB))
                               + length(CAST(recorded_at AS BLOB))
                           ) FROM source_events), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(delivery_id AS BLOB))
                               + length(CAST(edge_id AS BLOB))
                               + length(CAST(ordering_key AS BLOB))
                               + length(CAST(source_event_id AS BLOB))
                               + length(CAST(target_provider_id AS BLOB))
                               + length(CAST(target_operation_id AS BLOB))
                               + length(CAST(target_principal_context_id AS BLOB))
                               + length(CAST(request_json AS BLOB))
                               + length(CAST(correlation_ids_json AS BLOB))
                               + length(CAST(COALESCE(idempotency_key, '') AS BLOB))
                               + length(CAST(retry_delays_json AS BLOB))
                               + length(CAST(content_digest AS BLOB))
                               + length(CAST(enqueued_at AS BLOB))
                               + length(CAST(initial_available_at AS BLOB))
                               + length(CAST(available_at AS BLOB))
                               + length(CAST(state AS BLOB))
                           ) FROM deliveries), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(delivery_id AS BLOB))
                               + length(CAST(available_at AS BLOB))
                               + length(CAST(started_at AS BLOB))
                               + length(CAST(COALESCE(finished_at, '') AS BLOB))
                               + length(CAST(outcome AS BLOB))
                               + length(CAST(COALESCE(receipt_json, '') AS BLOB))
                               + length(CAST(COALESCE(error_code, '') AS BLOB))
                               + length(CAST(COALESCE(error_message, '') AS BLOB))
                           ) FROM delivery_attempts), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(delivery_id AS BLOB))
                               + length(CAST(resolved_at AS BLOB))
                               + length(CAST(outcome AS BLOB))
                               + length(CAST(receipt_json AS BLOB))
                               + length(CAST(COALESCE(error_code, '') AS BLOB))
                               + length(CAST(COALESCE(error_message, '') AS BLOB))
                           ) FROM unknown_resolutions), 0)
                           + COALESCE((SELECT SUM(
                               length(CAST(effect_id AS BLOB))
                               + length(CAST(origin_delivery_id AS BLOB))
                               + length(CAST(origin_kind AS BLOB))
                               + length(CAST(effect_kind AS BLOB))
                               + length(CAST(payload_json AS BLOB))
                               + length(CAST(content_digest AS BLOB))
                               + length(CAST(created_at AS BLOB))
                               + length(CAST(state AS BLOB))
                               + length(CAST(COALESCE(applied_at, '') AS BLOB))
                           ) FROM post_outcome_effects), 0)
                    """
                ).fetchone()[0]
            )
            total_rows = (
                counts["source_count"]
                + counts["delivery_count"]
                + counts["attempt_count"]
                + counts["resolution_count"]
                + counts["effect_count"]
                + 1
            )
            export_upper_bound = text_bytes * 6 + total_rows * _EXPORT_ROW_OVERHEAD_BYTES
            if export_upper_bound > MAX_SESSION_EVENT_EXPORT_BYTES:
                raise SessionEventError(
                    "session_event_export_too_large",
                    "The session event export exceeds the bounded in-memory export size.",
                    {
                        "upper_bound_bytes": export_upper_bound,
                        "max_bytes": MAX_SESSION_EVENT_EXPORT_BYTES,
                    },
                )
            source_events = [
                {
                    "source_event_id": row["source_event_id"],
                    "source_provider_id": row["source_provider_id"],
                    "provider_event_id": row["provider_event_id"],
                    "event_type": row["event_type"],
                    "payload": json.loads(row["payload_json"]),
                    "correlation_ids": json.loads(row["correlation_ids_json"]),
                    "idempotency_key": row["idempotency_key"],
                    "sequence": row["sequence"],
                    "recorded_at": row["recorded_at"],
                    "content_digest": row["content_digest"],
                }
                for row in connection.execute(
                    "SELECT * FROM source_events ORDER BY sequence ASC, source_event_id ASC"
                )
            ]
            attempts_by_delivery: dict[str, list[dict[str, Any]]] = {}
            for attempt in connection.execute(
                """SELECT * FROM delivery_attempts
                   ORDER BY delivery_id ASC, attempt_number ASC"""
            ):
                attempts_by_delivery.setdefault(attempt["delivery_id"], []).append(
                    {
                        "attempt_number": attempt["attempt_number"],
                        "available_at": attempt["available_at"],
                        "started_at": attempt["started_at"],
                        "finished_at": attempt["finished_at"],
                        "outcome": attempt["outcome"],
                        "receipt": (
                            None
                            if attempt["receipt_json"] is None
                            else json.loads(attempt["receipt_json"])
                        ),
                        "status_code": attempt["status_code"],
                        "error_code": attempt["error_code"],
                        "error_message": attempt["error_message"],
                        "retry_delay_seconds": attempt["retry_delay_seconds"],
                    }
                )
            resolutions_by_delivery: dict[str, list[dict[str, Any]]] = {}
            for resolution in connection.execute(
                """SELECT * FROM unknown_resolutions
                   ORDER BY delivery_id ASC, attempt_number ASC"""
            ):
                resolutions_by_delivery.setdefault(resolution["delivery_id"], []).append(
                    {
                        "attempt_number": resolution["attempt_number"],
                        "resolved_at": resolution["resolved_at"],
                        "outcome": resolution["outcome"],
                        "receipt": json.loads(resolution["receipt_json"]),
                        "status_code": resolution["status_code"],
                        "error_code": resolution["error_code"],
                        "error_message": resolution["error_message"],
                        "retry_delay_seconds": resolution["retry_delay_seconds"],
                    }
                )
            deliveries: list[dict[str, Any]] = []
            for row in connection.execute(
                "SELECT * FROM deliveries ORDER BY sequence ASC, delivery_id ASC"
            ):
                deliveries.append(
                    {
                        "delivery_id": row["delivery_id"],
                        "edge_id": row["edge_id"],
                        "ordering_key": row["ordering_key"],
                        "source_event_id": row["source_event_id"],
                        "target_provider_id": row["target_provider_id"],
                        "target_operation_id": row["target_operation_id"],
                        "target_principal_context_id": row["target_principal_context_id"],
                        "request": json.loads(row["request_json"]),
                        "correlation_ids": json.loads(row["correlation_ids_json"]),
                        "idempotency_key": row["idempotency_key"],
                        "retry_delays_seconds": json.loads(row["retry_delays_json"]),
                        "sequence": row["sequence"],
                        "enqueued_at": row["enqueued_at"],
                        "initial_available_at": row["initial_available_at"],
                        "available_at": row["available_at"],
                        "state": row["state"],
                        "content_digest": row["content_digest"],
                        "attempts": attempts_by_delivery.pop(row["delivery_id"], []),
                        "resolutions": resolutions_by_delivery.pop(row["delivery_id"], []),
                    }
                )
            if attempts_by_delivery or resolutions_by_delivery:
                raise SessionEventError(
                    "session_event_evidence_state_invalid",
                    "Attempt or resolution evidence references an unknown delivery.",
                )
            post_outcome_effects = [
                {
                    "effect_id": row["effect_id"],
                    "origin_delivery_id": row["origin_delivery_id"],
                    "origin_attempt_number": row["origin_attempt_number"],
                    "origin_kind": row["origin_kind"],
                    "effect_kind": row["effect_kind"],
                    "payload": json.loads(row["payload_json"]),
                    "content_digest": row["content_digest"],
                    "sequence": row["sequence"],
                    "created_at": row["created_at"],
                    "state": row["state"],
                    "applied_at": row["applied_at"],
                }
                for row in connection.execute(
                    "SELECT * FROM post_outcome_effects ORDER BY sequence ASC, effect_id ASC"
                )
            ]
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()
        state = {
            "episode_seed": metadata["episode_seed"],
            "initial_time": metadata["initial_time"],
            "logical_time": metadata["logical_time"],
            "source_events": source_events,
            "deliveries": deliveries,
            "post_outcome_effects": post_outcome_effects,
        }
        result = {
            "schema_version": _SCHEMA_VERSION,
            **state,
            "state_digest": _digest(state),
        }
        encoded_size = len(
            json.dumps(
                result,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
        )
        if encoded_size > MAX_SESSION_EVENT_EXPORT_BYTES:
            raise SessionEventError(
                "session_event_export_too_large",
                "The session event export exceeds the bounded in-memory export size.",
                {"actual_bytes": encoded_size, "max_bytes": MAX_SESSION_EVENT_EXPORT_BYTES},
            )
        return result
