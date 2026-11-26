"""Local SQLite event store for validated Genesis Monitor telemetry."""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from contextlib import contextmanager

from .protocol import ProtocolError, canonical_json, parse_event


def _canonical_data(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _stored_object(value: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise StoreError("stored central-store JSON is corrupted") from error
    if not isinstance(parsed, dict):
        raise StoreError("stored central-store JSON is not an object")
    return parsed


def parse_event_configuration(value: str | None) -> dict[str, Any] | None:
    return _stored_object(value)


def parse_event_claim(value: str | None) -> dict[str, Any] | None:
    return _stored_object(value)


class StoreError(RuntimeError):
    """The local telemetry store rejected or could not persist an operation."""


class MachineIdentityError(StoreError):
    """The event's machine identity does not match an enrolled machine."""


class EventConflictError(StoreError):
    """An event ID or machine sequence was reused for different content."""


_COMMITTED_RESULT_MARKER = object()


@dataclass(frozen=True)
class IngestResult:
    sequence: int
    event_id: str
    disposition: str
    current_updated: bool
    _commit_marker: object | None = field(default=None, repr=False, compare=False)


def _utc(value: str | datetime, name: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise StoreError(f"{name} is not a valid ISO-8601 timestamp") from error
    else:
        raise StoreError(f"{name} must be a UTC timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StoreError(f"{name} must be timezone-aware")
    normalized = parsed.astimezone(timezone.utc)
    return (
        normalized.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        normalized,
    )


def _age_seconds(timestamp: str | None, now: datetime) -> float | None:
    if timestamp is None:
        return None
    _, parsed = _utc(timestamp, "stored timestamp")
    age = (now - parsed).total_seconds()
    return age if age >= 0 else None


class CentralStore:
    """Single-host SQLite history and latest-state store; this class has no network API."""

    SCHEMA_VERSION = 3

    def __init__(self, database: str | Path) -> None:
        self.path = str(database)
        if self.path == ":memory:":
            raise ValueError("use a filesystem database path so connections share durable state")
        try:
            with self._connection() as connection:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version not in (0, 1, 2, self.SCHEMA_VERSION):
                    raise StoreError(f"unsupported central-store schema version: {version}")
                connection.executescript("""
                    CREATE TABLE IF NOT EXISTS machines (
                        machine_id TEXT PRIMARY KEY,
                        display_name TEXT NOT NULL,
                        current_sequence INTEGER,
                        last_received_at TEXT,
                        search_configuration TEXT,
                        created_at TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS telemetry_events (
                        machine_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        event_id TEXT NOT NULL UNIQUE,
                        content_hash TEXT NOT NULL,
                        canonical_event TEXT NOT NULL,
                        received_at TEXT NOT NULL,
                        is_current INTEGER NOT NULL CHECK (is_current IN (0, 1)),
                        PRIMARY KEY (machine_id, sequence),
                        FOREIGN KEY (machine_id) REFERENCES machines(machine_id)
                    );
                    CREATE UNIQUE INDEX IF NOT EXISTS one_current_event_per_machine
                        ON telemetry_events(machine_id) WHERE is_current = 1;
                    CREATE INDEX IF NOT EXISTS telemetry_history_by_machine
                        ON telemetry_events(machine_id, sequence DESC);
                    CREATE TABLE IF NOT EXISTS found_verifications (
                        verification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        machine_id TEXT NOT NULL,
                        claim_hash TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        source TEXT NOT NULL,
                        claim_json TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('PENDING','VERIFIED','REJECTED','ERROR')),
                        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                        detail TEXT NOT NULL,
                        verifier_result TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        UNIQUE(machine_id, claim_hash),
                        FOREIGN KEY (machine_id) REFERENCES machines(machine_id),
                        FOREIGN KEY (event_id) REFERENCES telemetry_events(event_id)
                    );
                    CREATE TABLE IF NOT EXISTS local_alerts (
                        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        verification_id INTEGER NOT NULL UNIQUE,
                        machine_id TEXT NOT NULL,
                        claim_json TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY (verification_id) REFERENCES found_verifications(verification_id),
                        FOREIGN KEY (machine_id) REFERENCES machines(machine_id)
                    );
                """)
                columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(machines)")
                }
                if "search_configuration" not in columns:
                    connection.execute("ALTER TABLE machines ADD COLUMN search_configuration TEXT")
                verification_columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(found_verifications)")
                }
                if "attempt_count" not in verification_columns:
                    connection.execute(
                        "ALTER TABLE found_verifications ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0"
                    )
                connection.execute(f"PRAGMA user_version={self.SCHEMA_VERSION}")
        except sqlite3.Error as error:
            raise StoreError(f"cannot initialize central telemetry store: {error}") from error

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def register_machine(
        self,
        machine_id: str,
        display_name: str,
        *,
        search_configuration: dict[str, Any] | None = None,
    ) -> None:
        if not isinstance(machine_id, str) or not isinstance(display_name, str) or not display_name.strip():
            raise ValueError("machine_id and a non-empty display_name are required")
        if search_configuration is not None:
            search_configuration = self._validate_search_configuration(search_configuration)
            configuration_json = _canonical_data(search_configuration)
        else:
            configuration_json = None
        now, _ = _utc(datetime.now(timezone.utc), "registration time")
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT display_name,search_configuration FROM machines WHERE machine_id=?",
                    (machine_id,),
                ).fetchone()
                if existing is not None:
                    if existing["display_name"] != display_name:
                        raise MachineIdentityError("machine is already registered with a different display name")
                    if configuration_json is not None:
                        old = existing["search_configuration"]
                        if old is not None and old != configuration_json:
                            raise MachineIdentityError("machine is already registered with a different search configuration")
                        connection.execute(
                            "UPDATE machines SET search_configuration=? WHERE machine_id=?",
                            (configuration_json, machine_id),
                        )
                    return
                connection.execute(
                    "INSERT INTO machines(machine_id,display_name,search_configuration,created_at) "
                    "VALUES(?,?,?,?)",
                    (machine_id, display_name, configuration_json, now),
                )
        except sqlite3.Error as error:
            raise StoreError(f"cannot register machine: {error}") from error

    @staticmethod
    def _validate_search_configuration(configuration: Any) -> dict[str, Any]:
        if not isinstance(configuration, dict) or set(configuration) != {
            "time", "start_nonce", "end_nonce", "requested_worker_count",
            "nbits", "block_version", "pow_limit",
        }:
            raise ValueError("search_configuration must use the exact checkpoint configuration fields")
        for field in ("time", "start_nonce", "end_nonce", "requested_worker_count", "nbits"):
            value = configuration[field]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
                raise ValueError(f"search_configuration.{field} must be uint32")
        version = configuration["block_version"]
        if isinstance(version, bool) or not isinstance(version, int) or not -(1 << 31) <= version < (1 << 31):
            raise ValueError("search_configuration.block_version must be int32")
        pow_limit = configuration["pow_limit"]
        if not isinstance(pow_limit, str) or len(pow_limit) != 64 or any(c not in "0123456789abcdef" for c in pow_limit):
            raise ValueError("search_configuration.pow_limit must be 64 lowercase hexadecimal characters")
        if configuration["start_nonce"] > configuration["end_nonce"]:
            raise ValueError("search configuration range start exceeds its end")
        if not 1 <= configuration["requested_worker_count"] <= 1024:
            raise ValueError("search configuration worker count must be in 1..1024")
        return dict(configuration)

    def search_configuration(self, machine_id: str) -> dict[str, Any] | None:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT search_configuration FROM machines WHERE machine_id=?",
                    (machine_id,),
                ).fetchone()
            if row is None:
                raise MachineIdentityError("machine identity is not registered")
            configuration = parse_event_configuration(row["search_configuration"])
            if configuration is None:
                return None
            try:
                return self._validate_search_configuration(configuration)
            except ValueError as error:
                raise StoreError("registered search configuration is corrupted") from error
        except sqlite3.Error as error:
            raise StoreError(f"cannot read registered search configuration: {error}") from error

    def event_for_verification(self, machine_id: str, event_id: str) -> dict[str, Any]:
        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT canonical_event FROM telemetry_events WHERE machine_id=? AND event_id=?",
                    (machine_id, event_id),
                ).fetchone()
            if row is None:
                raise StoreError("telemetry event does not exist for this machine")
            return parse_event(row["canonical_event"])
        except ProtocolError as error:
            raise StoreError(f"stored telemetry failed protocol validation: {error}") from error
        except sqlite3.Error as error:
            raise StoreError(f"cannot read telemetry event: {error}") from error

    def create_verification(
        self,
        *,
        machine_id: str,
        event_id: str,
        source: str,
        claim: dict[str, Any],
        now: str | datetime,
    ) -> dict[str, Any]:
        timestamp, _ = _utc(now, "verification time")
        claim_json = _canonical_data(claim)
        identity = {
            key: claim[key]
            for key in ("nonce", "block_hash", "pow_digest_raw")
            if key in claim
        }
        identity_json = _canonical_data(identity if len(identity) == 3 else claim)
        claim_hash = hashlib.sha256(identity_json.encode("utf-8")).hexdigest()
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM telemetry_events WHERE machine_id=? AND event_id=?",
                    (machine_id, event_id),
                ).fetchone() is None:
                    raise StoreError("telemetry event does not exist for this machine")
                row = connection.execute(
                    "SELECT * FROM found_verifications WHERE machine_id=? AND claim_hash=?",
                    (machine_id, claim_hash),
                ).fetchone()
                if row is None:
                    cursor = connection.execute(
                        "INSERT INTO found_verifications"
                        "(machine_id,claim_hash,event_id,source,claim_json,status,detail,"
                        "created_at,updated_at) VALUES(?,?,?,?,?,'PENDING','verification queued',?,?)",
                        (machine_id, claim_hash, event_id, source, claim_json, timestamp, timestamp),
                    )
                    row = connection.execute(
                        "SELECT * FROM found_verifications WHERE verification_id=?",
                        (cursor.lastrowid,),
                    ).fetchone()
                return self._verification_row(row)
        except sqlite3.Error as error:
            raise StoreError(f"cannot persist pending verification: {error}") from error

    @staticmethod
    def _verification_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "verification_id": int(row["verification_id"]),
            "machine_id": row["machine_id"],
            "event_id": row["event_id"],
            "source": row["source"],
            "claim": parse_event_claim(row["claim_json"]),
            "status": row["status"],
            "attempt_count": int(row["attempt_count"]),
            "detail": row["detail"],
            "verifier_result": parse_event_claim(row["verifier_result"]) if row["verifier_result"] else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def begin_verification_attempt(
        self,
        verification_id: int,
        *,
        max_attempts: int,
        lease_seconds: float,
        now: str | datetime,
    ) -> dict[str, Any]:
        if isinstance(max_attempts, bool) or not isinstance(max_attempts, int) or max_attempts < 1:
            raise ValueError("max_attempts must be a positive integer")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        timestamp, now_dt = _utc(now, "verification attempt time")
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM found_verifications WHERE verification_id=?",
                    (verification_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("verification record does not exist")
                if row["status"] != "PENDING":
                    result = self._verification_row(row)
                    result["attempt_claimed"] = False
                    return result
                if row["attempt_count"] > 0:
                    _, started_at = _utc(row["updated_at"], "stored attempt time")
                    elapsed = (now_dt - started_at).total_seconds()
                    if elapsed < 0 or elapsed < lease_seconds:
                        result = self._verification_row(row)
                        result["attempt_claimed"] = False
                        return result
                if row["attempt_count"] >= max_attempts:
                    connection.execute(
                        "UPDATE found_verifications SET status='ERROR',"
                        "detail='verification retry limit exhausted',updated_at=? "
                        "WHERE verification_id=? AND status='PENDING'",
                        (timestamp, verification_id),
                    )
                else:
                    connection.execute(
                        "UPDATE found_verifications SET attempt_count=attempt_count+1,"
                        "detail='verification attempt in progress',updated_at=? "
                        "WHERE verification_id=? AND status='PENDING'",
                        (timestamp, verification_id),
                    )
                updated = connection.execute(
                    "SELECT * FROM found_verifications WHERE verification_id=?",
                    (verification_id,),
                ).fetchone()
                result = self._verification_row(updated)
                result["attempt_claimed"] = result["status"] == "PENDING"
                return result
        except sqlite3.Error as error:
            raise StoreError(f"cannot claim verification attempt: {error}") from error

    def finish_verification(
        self,
        verification_id: int,
        *,
        status: str,
        detail: str,
        verifier_result: dict[str, Any] | None,
        now: str | datetime,
    ) -> dict[str, Any]:
        if status not in ("VERIFIED", "REJECTED", "ERROR"):
            raise ValueError("verification completion status must be VERIFIED, REJECTED, or ERROR")
        if not isinstance(detail, str) or len(detail) > 2048:
            raise ValueError("verification detail must be a string of at most 2048 characters")
        timestamp, _ = _utc(now, "verification completion time")
        result_json = _canonical_data(verifier_result) if verifier_result is not None else None
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM found_verifications WHERE verification_id=?",
                    (verification_id,),
                ).fetchone()
                if row is None:
                    raise StoreError("verification record does not exist")
                connection.execute(
                    "UPDATE found_verifications SET status=?,detail=?,verifier_result=?,updated_at=? "
                    "WHERE verification_id=? AND status='PENDING'",
                    (status, detail, result_json, timestamp, verification_id),
                )
                updated = connection.execute(
                    "SELECT * FROM found_verifications WHERE verification_id=?",
                    (verification_id,),
                ).fetchone()
                if updated["status"] == "VERIFIED":
                    connection.execute(
                        "INSERT OR IGNORE INTO local_alerts"
                        "(verification_id,machine_id,claim_json,created_at) VALUES(?,?,?,?)",
                        (verification_id, row["machine_id"], row["claim_json"], updated["updated_at"]),
                    )
                return self._verification_row(updated)
        except sqlite3.Error as error:
            raise StoreError(f"cannot persist verification outcome: {error}") from error

    def verification_records(self, machine_id: str | None = None) -> list[dict[str, Any]]:
        try:
            with self._connection() as connection:
                if machine_id is None:
                    rows = connection.execute(
                        "SELECT * FROM found_verifications ORDER BY verification_id"
                    ).fetchall()
                else:
                    rows = connection.execute(
                        "SELECT * FROM found_verifications WHERE machine_id=? ORDER BY verification_id",
                        (machine_id,),
                    ).fetchall()
            return [self._verification_row(row) for row in rows]
        except sqlite3.Error as error:
            raise StoreError(f"cannot read verification records: {error}") from error

    def local_alerts(self) -> list[dict[str, Any]]:
        try:
            with self._connection() as connection:
                rows = connection.execute("""
                    SELECT a.alert_id,a.machine_id,a.claim_json,a.created_at,
                           v.verification_id,v.event_id,v.source
                    FROM local_alerts AS a
                    JOIN found_verifications AS v ON v.verification_id=a.verification_id
                    ORDER BY a.alert_id
                """).fetchall()
            return [{
                "alert_id": int(row["alert_id"]),
                "machine_id": row["machine_id"],
                "claim": parse_event_claim(row["claim_json"]),
                "created_at": row["created_at"],
                "verification_id": int(row["verification_id"]),
                "event_id": row["event_id"],
                "source": row["source"],
            } for row in rows]
        except sqlite3.Error as error:
            raise StoreError(f"cannot read local FOUND alerts: {error}") from error

    def ingest(
        self,
        event: Any,
        *,
        authenticated_machine_id: str,
        received_at: str | datetime,
    ) -> IngestResult:
        """Validate, bind to a registered identity, and persist one event.

        The caller-supplied expected identity enforces local identity matching;
        it does not authenticate a remote machine.
        """
        try:
            validated = parse_event(canonical_json(event))
        except ProtocolError as error:
            raise StoreError(f"invalid telemetry event: {error}") from error
        if not isinstance(authenticated_machine_id, str) or validated["machine_id"] != authenticated_machine_id:
            raise MachineIdentityError("event machine_id does not match the expected machine identity")
        received_text, _ = _utc(received_at, "received_at")
        canonical = canonical_json(validated)
        content_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        machine_id = validated["machine_id"]
        sequence = validated["sequence"]
        event_id = validated["event_id"]
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                machine = connection.execute(
                    "SELECT current_sequence FROM machines WHERE machine_id=?", (machine_id,)
                ).fetchone()
                if machine is None:
                    raise MachineIdentityError("machine identity is not registered")

                by_id = connection.execute(
                    "SELECT machine_id,sequence,content_hash FROM telemetry_events WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                if by_id is not None:
                    if (
                        by_id["machine_id"] != machine_id
                        or by_id["sequence"] != sequence
                        or by_id["content_hash"] != content_hash
                    ):
                        raise EventConflictError("event_id was already used for different telemetry")
                    connection.execute(
                        "UPDATE machines SET last_received_at=? WHERE machine_id=?",
                        (received_text, machine_id),
                    )
                    return IngestResult(
                        sequence, event_id, "duplicate", False, _COMMITTED_RESULT_MARKER
                    )

                by_sequence = connection.execute(
                    "SELECT event_id,content_hash FROM telemetry_events WHERE machine_id=? AND sequence=?",
                    (machine_id, sequence),
                ).fetchone()
                if by_sequence is not None:
                    raise EventConflictError(
                        "machine sequence was already used by a different event_id"
                    )

                current_sequence = machine["current_sequence"]
                is_current = current_sequence is None or sequence > current_sequence
                if is_current:
                    connection.execute(
                        "UPDATE telemetry_events SET is_current=0 WHERE machine_id=? AND is_current=1",
                        (machine_id,),
                    )
                connection.execute(
                    "INSERT INTO telemetry_events"
                    "(machine_id,sequence,event_id,content_hash,canonical_event,received_at,is_current) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (machine_id, sequence, event_id, content_hash, canonical, received_text, int(is_current)),
                )
                new_high_water = sequence if is_current else current_sequence
                connection.execute(
                    "UPDATE machines SET current_sequence=?,last_received_at=? WHERE machine_id=?",
                    (new_high_water, received_text, machine_id),
                )
                return IngestResult(
                    sequence,
                    event_id,
                    "accepted_current" if is_current else "accepted_stale",
                    is_current,
                    _COMMITTED_RESULT_MARKER,
                )
        except (MachineIdentityError, EventConflictError):
            raise
        except sqlite3.Error as error:
            raise StoreError(f"cannot ingest telemetry event: {error}") from error

    def _ingest_with_signed_receipt(
        self,
        event: Any,
        *,
        authenticated_machine_id: str,
        received_at: str | datetime,
        signer: Any,
    ) -> dict[str, Any]:
        """Internal trusted-server path: commit first, then issue a signed receipt."""
        from .protocol import validate_event
        from .receipts import CommittedReceiptSigner, _create_committed_receipt

        if not isinstance(signer, CommittedReceiptSigner):
            raise TypeError("signer must be a CommittedReceiptSigner")
        validated = validate_event(event)
        result = self.ingest(
            validated,
            authenticated_machine_id=authenticated_machine_id,
            received_at=received_at,
        )
        return _create_committed_receipt(event, result, signer)

    def history(self, machine_id: str, *, after_sequence: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        if isinstance(after_sequence, bool) or not isinstance(after_sequence, int) or after_sequence < 0:
            raise ValueError("after_sequence must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10_000:
            raise ValueError("limit must be an integer in 1..10000")
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    "SELECT sequence,event_id,received_at,is_current,canonical_event "
                    "FROM telemetry_events WHERE machine_id=? AND sequence>? "
                    "ORDER BY sequence LIMIT ?",
                    (machine_id, after_sequence, limit),
                ).fetchall()
            return [
                {
                    "sequence": int(row["sequence"]),
                    "event_id": row["event_id"],
                    "received_at": row["received_at"],
                    "is_current": bool(row["is_current"]),
                    "event": parse_event(row["canonical_event"]),
                }
                for row in rows
            ]
        except ProtocolError as error:
            raise StoreError(f"stored telemetry failed protocol validation: {error}") from error
        except sqlite3.Error as error:
            raise StoreError(f"cannot read telemetry history: {error}") from error

    def snapshot(
        self,
        *,
        now: str | datetime,
        local_ingestion_timeout_seconds: float = 30,
        activity_timeout_seconds: float = 90,
        checkpoint_timeout_seconds: float = 15,
    ) -> dict[str, Any]:
        for name, timeout in (
            ("local_ingestion_timeout_seconds", local_ingestion_timeout_seconds),
            ("activity_timeout_seconds", activity_timeout_seconds),
            ("checkpoint_timeout_seconds", checkpoint_timeout_seconds),
        ):
            if (
                isinstance(timeout, bool)
                or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout)
                or timeout < 0
            ):
                raise ValueError(f"{name} must be a finite non-negative number")
        now_text, now_dt = _utc(now, "snapshot time")
        try:
            with self._connection() as connection:
                rows = connection.execute("""
                    SELECT m.machine_id,m.display_name,m.last_received_at,
                           e.sequence,e.event_id,e.received_at,e.canonical_event
                    FROM machines AS m
                    LEFT JOIN telemetry_events AS e
                      ON e.machine_id=m.machine_id AND e.sequence=m.current_sequence
                    ORDER BY m.machine_id
                """).fetchall()
            machines: list[dict[str, Any]] = []
            for row in rows:
                received_at = row["last_received_at"]
                ingestion_age = _age_seconds(received_at, now_dt)
                if ingestion_age is None:
                    ingestion_status = "unknown"
                elif ingestion_age <= local_ingestion_timeout_seconds:
                    ingestion_status = "recent"
                else:
                    ingestion_status = "stale"

                event = parse_event(row["canonical_event"]) if row["canonical_event"] else None
                log = event["payload"]["log"] if event is not None else None
                checkpoint = event["payload"]["checkpoint"] if event is not None else None
                observed_at = event["observed_at"] if event is not None else None
                telemetry_age = _age_seconds(observed_at, now_dt)
                if log is None or log["status"] != "available" or not log["workers"]:
                    search_status = "unknown"
                elif log["worker_ranges_status"] == "inconsistent":
                    search_status = "inconsistent"
                elif log["result"] == "FOUND":
                    search_status = "found"
                elif log["result"] == "NOT FOUND":
                    search_status = "completed_without_found"
                elif telemetry_age is None:
                    search_status = "unknown"
                elif log["worker_ranges_status"] == "valid" and telemetry_age <= activity_timeout_seconds:
                    search_status = "active"
                else:
                    search_status = "stale"

                checkpoint_age = None
                checkpoint_age_status = checkpoint["status"] if checkpoint else "unknown"
                if checkpoint and checkpoint["status"] == "valid":
                    checkpoint_age = _age_seconds(checkpoint["observed_at"], now_dt)
                    if checkpoint_age is None:
                        checkpoint_age_status = "clock_skew"
                    elif checkpoint_age > checkpoint_timeout_seconds:
                        checkpoint_age_status = "stale"
                    else:
                        checkpoint_age_status = "available"

                machines.append({
                    "machine_id": row["machine_id"],
                    "display_name": row["display_name"],
                    "ingestion_status": ingestion_status,
                    "last_local_ingestion_at": received_at,
                    "local_ingestion_age_seconds": ingestion_age,
                    "search_status": search_status,
                    "telemetry_observed_at": observed_at,
                    "telemetry_age_seconds": telemetry_age,
                    "current_sequence": row["sequence"],
                    "current_event_id": row["event_id"],
                    "log": log,
                    "checkpoint": checkpoint,
                    "checkpoint_age_seconds": checkpoint_age,
                    "checkpoint_age_status": checkpoint_age_status,
                })
            records = self.verification_records()
            for machine in machines:
                machine["found_verifications"] = [
                    record for record in records if record["machine_id"] == machine["machine_id"]
                ]
            return {
                "generated_at": now_text,
                "machines": machines,
                "alerts": self.local_alerts(),
            }
        except ProtocolError as error:
            raise StoreError(f"stored current telemetry failed protocol validation: {error}") from error
        except sqlite3.Error as error:
            raise StoreError(f"cannot read central telemetry snapshot: {error}") from error
