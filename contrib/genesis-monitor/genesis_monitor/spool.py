"""Bounded SQLite event spool with monotonic sequence IDs and retry records."""

from __future__ import annotations

import hashlib
import json
import math
import os
import sqlite3
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .protocol import ProtocolError, canonical_json, parse_event, validate_event


class SpoolError(RuntimeError):
    """The local event spool could not safely accept or return an event."""


class SpoolFull(SpoolError):
    """Pending event count or serialized-byte limit has been reached."""


class DuplicateEventConflict(SpoolError):
    """An idempotency key was reused for different event content."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("retry timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_now(value: datetime | None) -> str:
    return _timestamp(value or datetime.now(timezone.utc))


_SENDER_LOCKS = threading.local()


class _SenderOwnershipToken:
    def __init__(self, identity: tuple[int, int]) -> None:
        self.identity = identity


class EventSpool:
    """Local retry queue. It performs no network access and drops no pending event."""

    def __init__(
        self,
        database: str | Path,
        *,
        max_pending_events: int = 10_000,
        max_pending_bytes: int = 16 * 1024 * 1024,
        receipt_verifier: Any = None,
    ) -> None:
        if max_pending_events <= 0 or max_pending_bytes <= 0:
            raise ValueError("spool limits must be positive")
        raw_path = str(database)
        self.path = (
            raw_path
            if raw_path == ":memory:" or raw_path.startswith("file:")
            else str(Path(raw_path).resolve())
        )
        self.max_pending_events = max_pending_events
        self.max_pending_bytes = max_pending_bytes
        self.receipt_verifier = receipt_verifier
        self._file_identity: tuple[int, int] | None = None
        try:
            if self.path != ":memory:" and not self.path.startswith("file:"):
                try:
                    descriptor = os.open(
                        self.path,
                        os.O_CREAT | os.O_EXCL | os.O_RDWR,
                        0o600,
                    )
                except FileExistsError:
                    pass
                else:
                    os.close(descriptor)
                self._file_identity = self._read_file_identity()
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        machine_id TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        content_hash TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        byte_size INTEGER NOT NULL,
                        created_at TEXT NOT NULL,
                        retry_attempt_count INTEGER NOT NULL DEFAULT 0
                            CHECK (retry_attempt_count >= 0),
                        next_retry_at TEXT,
                        last_retry_error TEXT
                    )
                """)
                columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(events)")
                }
                if "retry_attempt_count" not in columns:
                    connection.execute(
                        "ALTER TABLE events ADD COLUMN retry_attempt_count "
                        "INTEGER NOT NULL DEFAULT 0 CHECK (retry_attempt_count >= 0)"
                    )
                if "next_retry_at" not in columns:
                    connection.execute("ALTER TABLE events ADD COLUMN next_retry_at TEXT")
                if "last_retry_error" not in columns:
                    connection.execute("ALTER TABLE events ADD COLUMN last_retry_error TEXT")
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS dedupe_window (
                        idempotency_key TEXT PRIMARY KEY,
                        sequence INTEGER NOT NULL,
                        content_hash TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                connection.execute("""
                    CREATE TABLE IF NOT EXISTS latest_observations (
                        machine_id TEXT PRIMARY KEY,
                        content_hash TEXT NOT NULL
                    )
                """)
                connection.commit()
                connection.execute("PRAGMA journal_mode=DELETE")
        except (sqlite3.Error, OSError, SpoolError) as error:
            raise SpoolError(f"cannot initialize event spool: {error}") from error

    def _connect(self) -> sqlite3.Connection:
        identity_required = self.path != ":memory:" and not self.path.startswith("file:")
        before = self._read_file_identity() if identity_required else None
        if identity_required and self._file_identity is not None and before != self._file_identity:
            raise SpoolError("spool file identity changed before SQLite open")
        try:
            connection = sqlite3.connect(self.path, timeout=5)
        except sqlite3.Error:
            raise
        try:
            if identity_required:
                after = self._read_file_identity()
                database_path = connection.execute("PRAGMA database_list").fetchone()[2]
                opened_path = str(Path(database_path).resolve())
                if (
                    before != after
                    or (self._file_identity is not None and after != self._file_identity)
                    or opened_path.casefold() != self.path.casefold()
                ):
                    raise SpoolError("spool path changed identity while SQLite was opening it")
        except BaseException:
            connection.close()
            raise
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @contextmanager
    def sender_run_lock(
        self,
        *,
        owner_token: _SenderOwnershipToken | None = None,
    ) -> Iterator[_SenderOwnershipToken]:
        """Exclusively own this spool for one sender run across processes."""
        if self.path == ":memory:" or self.path.startswith("file:"):
            raise SpoolError("sender ownership requires a file-backed spool path")
        identity = self._read_file_identity()
        if identity != self._file_identity:
            raise SpoolError("spool file identity changed after it was opened")
        held = getattr(_SENDER_LOCKS, "held", None)
        if held is None:
            held = {}
            _SENDER_LOCKS.held = held
        current = held.get(identity)
        if current is not None:
            if owner_token is None or owner_token is not current[1]:
                raise SpoolError("another sender run owns this spool")
            yield owner_token
            return
        if owner_token is not None:
            raise SpoolError("sender ownership token is not active for this spool")

        lock_name = hashlib.sha256(
            f"{identity[0]}:{identity[1]}".encode("ascii")
        ).hexdigest()
        lock_directory = Path(tempfile.gettempdir()) / "vaqyron-genesis-monitor-locks"
        lock_path = lock_directory / f"{lock_name}.sqlite"
        connection: sqlite3.Connection | None = None
        try:
            lock_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            connection = sqlite3.connect(lock_path, timeout=0, isolation_level=None)
            connection.execute(
                "CREATE TABLE IF NOT EXISTS sender_lock (id INTEGER PRIMARY KEY CHECK(id=1))"
            )
            connection.execute("BEGIN IMMEDIATE")
        except (sqlite3.Error, OSError) as error:
            if connection is not None:
                connection.close()
            raise SpoolError(
                "another sender run owns this spool or ownership could not be acquired"
            ) from error
        token = _SenderOwnershipToken(identity)
        held[identity] = (connection, token)
        try:
            yield token
        finally:
            held.pop(identity, None)
            try:
                if connection.in_transaction:
                    connection.rollback()
            finally:
                connection.close()

    def _read_file_identity(self) -> tuple[int, int]:
        if self.path == ":memory:" or self.path.startswith("file:"):
            raise SpoolError("sender ownership requires a file-backed spool path")
        try:
            stat = os.stat(self.path, follow_symlinks=True)
        except OSError as error:
            raise SpoolError(f"cannot identify spool database file: {error}") from error
        if not stat.st_ino or not stat.st_dev:
            raise SpoolError("filesystem does not expose a reliable spool file identity")
        return int(stat.st_dev), int(stat.st_ino)

    def _require_sender_owner(self, owner_token: _SenderOwnershipToken) -> None:
        identity = self._read_file_identity()
        if identity != self._file_identity:
            raise SpoolError("spool file identity changed during sender operation")
        held = getattr(_SENDER_LOCKS, "held", {})
        current = held.get(identity)
        if (
            current is None
            or current[1] is not owner_token
            or owner_token.identity != identity
        ):
            raise SpoolError("valid sender ownership is required")

    def enqueue(
        self,
        machine_id: str,
        observed_at: str,
        payload: dict[str, Any],
        idempotency_key: str,
    ) -> tuple[dict[str, Any], bool]:
        """Persist an event; return (event, was_duplicate)."""
        if not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 256:
            raise SpoolError("idempotency key must contain 1..256 characters")
        try:
            validate_event({
                "protocol_version": 1,
                "event_id": f"{machine_id}:1",
                "sequence": 1,
                "machine_id": machine_id,
                "observed_at": observed_at,
                "payload": payload,
            })
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                duplicate = connection.execute(
                    "SELECT sequence, content_hash, payload FROM events WHERE idempotency_key=? "
                    "UNION ALL SELECT sequence, content_hash, NULL AS payload FROM dedupe_window "
                    "WHERE idempotency_key=? LIMIT 1",
                    (idempotency_key, idempotency_key),
                ).fetchone()
                # The idempotency key binds to the observed payload, not to a regenerated sequence.
                content_hash = hashlib.sha256(
                    json.dumps(
                        {"machine_id": machine_id, "observed_at": observed_at, "payload": payload},
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=True,
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest()
                if duplicate is not None:
                    if duplicate["content_hash"] != content_hash:
                        raise DuplicateEventConflict("idempotency key was already used for different telemetry")
                    if duplicate["payload"] is None:
                        raise SpoolError("duplicate telemetry was already acknowledged and compacted")
                    return parse_event(duplicate["payload"]), True

                pending = connection.execute(
                    "SELECT COUNT(*) AS count, COALESCE(SUM(byte_size), 0) AS bytes FROM events"
                ).fetchone()
                if pending["count"] >= self.max_pending_events:
                    raise SpoolFull("pending event count limit reached; no event was discarded")
                sequence = connection.execute(
                    "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='events'), 0) + 1"
                ).fetchone()[0]
                event = {
                    "protocol_version": 1,
                    "event_id": f"{machine_id}:{sequence}",
                    "sequence": sequence,
                    "machine_id": machine_id,
                    "observed_at": observed_at,
                    "payload": payload,
                }
                serialized = canonical_json(event)
                encoded_size = len(serialized.encode("utf-8"))
                if pending["bytes"] + encoded_size > self.max_pending_bytes:
                    raise SpoolFull("pending event byte limit reached; no event was discarded")
                connection.execute(
                    "INSERT INTO events(event_id,machine_id,idempotency_key,content_hash,payload,byte_size,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        event["event_id"], machine_id, idempotency_key, content_hash,
                        serialized, encoded_size, _now(),
                    ),
                )
                return event, False
        except (ProtocolError, SpoolError):
            raise
        except sqlite3.Error as error:
            raise SpoolError(f"cannot enqueue telemetry event: {error}") from error

    def enqueue_observation(
        self,
        machine_id: str,
        observed_at: str,
        payload: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, bool]:
        """Atomically persist a changed snapshot; return (event, was_unchanged)."""
        try:
            validate_event({
                "protocol_version": 1,
                "event_id": f"{machine_id}:1",
                "sequence": 1,
                "machine_id": machine_id,
                "observed_at": observed_at,
                "payload": payload,
            })
            snapshot_hash = hashlib.sha256(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest()
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                previous = connection.execute(
                    "SELECT content_hash FROM latest_observations WHERE machine_id=?",
                    (machine_id,),
                ).fetchone()
                if previous is not None and previous["content_hash"] == snapshot_hash:
                    return None, True

                event = self._enqueue_in_transaction(
                    connection,
                    machine_id,
                    observed_at,
                    payload,
                    f"snapshot:{hashlib.sha256(machine_id.encode('utf-8')).hexdigest()}:{snapshot_hash}:{observed_at}",
                )
                connection.execute(
                    "INSERT INTO latest_observations(machine_id,content_hash) VALUES(?,?) "
                    "ON CONFLICT(machine_id) DO UPDATE SET content_hash=excluded.content_hash",
                    (machine_id, snapshot_hash),
                )
                return event, False
        except (ProtocolError, SpoolError):
            raise
        except sqlite3.Error as error:
            raise SpoolError(f"cannot enqueue telemetry observation: {error}") from error

    def _enqueue_in_transaction(
        self,
        connection: sqlite3.Connection,
        machine_id: str,
        observed_at: str,
        payload: dict[str, Any],
        idempotency_key: str,
    ) -> dict[str, Any]:
        pending = connection.execute(
            "SELECT COUNT(*) AS count, COALESCE(SUM(byte_size), 0) AS bytes FROM events"
        ).fetchone()
        if pending["count"] >= self.max_pending_events:
            raise SpoolFull("pending event count limit reached; no event was discarded")
        sequence = connection.execute(
            "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='events'), 0) + 1"
        ).fetchone()[0]
        event = {
            "protocol_version": 1,
            "event_id": f"{machine_id}:{sequence}",
            "sequence": sequence,
            "machine_id": machine_id,
            "observed_at": observed_at,
            "payload": payload,
        }
        serialized = canonical_json(event)
        encoded_size = len(serialized.encode("utf-8"))
        if pending["bytes"] + encoded_size > self.max_pending_bytes:
            raise SpoolFull("pending event byte limit reached; no event was discarded")
        content_hash = hashlib.sha256(
            json.dumps(
                {"machine_id": machine_id, "observed_at": observed_at, "payload": payload},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
        connection.execute(
            "INSERT INTO events(event_id,machine_id,idempotency_key,content_hash,payload,byte_size,created_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                event["event_id"], machine_id, idempotency_key, content_hash,
                serialized, encoded_size, _now(),
            ),
        )
        return event

    def pending(self, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise ValueError("limit must be an integer in 1..10000")
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT sequence,payload FROM events ORDER BY sequence LIMIT ?", (limit,)
                ).fetchall()
            return [parse_event(row["payload"]) for row in rows]
        except ProtocolError as error:
            raise SpoolError(f"spooled event failed protocol validation: {error}") from error
        except sqlite3.Error as error:
            raise SpoolError(f"cannot read pending telemetry events: {error}") from error

    def due_pending(
        self,
        limit: int = 100,
        *,
        now: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return a bounded batch whose persistent retry time is due."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer in 1..1000")
        instant = _utc_now(now)
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT sequence,payload,retry_attempt_count FROM events "
                    "WHERE next_retry_at IS NULL OR next_retry_at<=? "
                    "ORDER BY sequence LIMIT ?",
                    (instant, limit),
                ).fetchall()
            return [
                {
                    "event": parse_event(row["payload"]),
                    "attempt_count": int(row["retry_attempt_count"]),
                }
                for row in rows
            ]
        except ProtocolError as error:
            raise SpoolError(f"spooled event failed protocol validation: {error}") from error
        except sqlite3.Error as error:
            raise SpoolError(f"cannot read due telemetry events: {error}") from error

    def schedule_retry(
        self,
        event_id: str,
        *,
        delay_seconds: float,
        now: datetime | None = None,
        error: str,
        _owner_token: _SenderOwnershipToken | None = None,
    ) -> int:
        """Persist one bounded retry attempt and its next eligible UTC time."""
        with self.sender_run_lock(owner_token=_owner_token) as owner_token:
            return self._schedule_retry_owned(
                event_id,
                owner_token=owner_token,
                delay_seconds=delay_seconds,
                now=now,
                error=error,
            )

    def _schedule_retry_owned(
        self,
        event_id: str,
        *,
        owner_token: _SenderOwnershipToken,
        delay_seconds: float,
        now: datetime | None,
        error: str,
    ) -> int:
        self._require_sender_owner(owner_token)
        if not isinstance(event_id, str):
            raise ValueError("event_id must be text")
        if (
            isinstance(delay_seconds, bool)
            or not isinstance(delay_seconds, (int, float))
            or not math.isfinite(delay_seconds)
            or delay_seconds < 0
            or delay_seconds > 86_400
        ):
            raise ValueError("retry delay must be in 0..86400 seconds")
        if not isinstance(error, str) or not error:
            raise ValueError("retry error must be non-empty text")
        error = error[:512]
        now_dt = now or datetime.now(timezone.utc)
        now_text = _timestamp(now_dt)
        next_retry = _timestamp(
            datetime.fromisoformat(now_text.replace("Z", "+00:00"))
            + timedelta(seconds=delay_seconds)
        )
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT retry_attempt_count FROM events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    raise SpoolError("cannot schedule retry for an unknown event")
                attempt_count = int(row["retry_attempt_count"]) + 1
                connection.execute(
                    "UPDATE events SET retry_attempt_count=?,next_retry_at=?,last_retry_error=? "
                    "WHERE event_id=?",
                    (attempt_count, next_retry, error, event_id),
                )
                return attempt_count
        except SpoolError:
            raise
        except sqlite3.Error as error:
            raise SpoolError(f"cannot persist telemetry retry state: {error}") from error

    def acknowledge(self, event_id: str, *, receipt: Any) -> None:
        with self.sender_run_lock() as owner_token:
            self._acknowledge_owned(event_id, receipt=receipt, owner_token=owner_token)

    def _acknowledge_owned(
        self,
        event_id: str,
        *,
        receipt: Any,
        owner_token: _SenderOwnershipToken,
    ) -> None:
        self._require_sender_owner(owner_token)
        if not isinstance(event_id, str):
            raise ValueError("event_id must be text")
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT sequence,idempotency_key,content_hash,payload FROM events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                if row is None:
                    raise SpoolError("cannot acknowledge an unknown event")
                from .receipts import ReceiptError, validate_committed_receipt

                try:
                    if self.receipt_verifier is None:
                        raise ReceiptError("no trusted receipt verifier is configured")
                    validate_committed_receipt(
                        receipt, parse_event(row["payload"]), self.receipt_verifier
                    )
                except (ReceiptError, TypeError) as error:
                    raise SpoolError(f"cannot acknowledge without a matching committed receipt: {error}") from error
                connection.execute(
                    "INSERT OR REPLACE INTO dedupe_window(idempotency_key,sequence,content_hash,created_at) "
                    "VALUES(?,?,?,?)",
                    (row["idempotency_key"], row["sequence"], row["content_hash"], _now()),
                )
                connection.execute("DELETE FROM events WHERE sequence=?", (row["sequence"],))
                # Keep a bounded duplicate-protection window; pending events are never evicted.
                connection.execute("""
                    DELETE FROM dedupe_window
                    WHERE idempotency_key IN (
                        SELECT idempotency_key FROM dedupe_window
                        ORDER BY sequence DESC LIMIT -1 OFFSET ?
                    )
                """, (self.max_pending_events,))
        except SpoolError:
            raise
        except sqlite3.Error as error:
            raise SpoolError(f"cannot acknowledge telemetry event: {error}") from error

    def pending_size(self) -> tuple[int, int]:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT COUNT(*) AS count, COALESCE(SUM(byte_size),0) AS bytes FROM events"
                ).fetchone()
            return int(row["count"]), int(row["bytes"])
        except sqlite3.Error as error:
            raise SpoolError(f"cannot inspect event spool size: {error}") from error
