"""Persistent certificate-fingerprint identity registry and TLS adapter boundary."""

from __future__ import annotations

import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import quote


_MACHINE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_FINGERPRINT_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_IDENTITY_SCHEMA_VERSION = 1


class IdentityAuthorizationError(ValueError):
    """A certificate fingerprint is not currently authorized for an identity."""


class IdentityRegistryError(RuntimeError):
    """The persistent identity registry is unavailable or invalid."""


def _utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    return _utc(value, "credential timestamp").isoformat(timespec="microseconds").replace("+00:00", "Z")


def _machine_id(value: str) -> str:
    if not isinstance(value, str) or _MACHINE_ID_RE.fullmatch(value) is None:
        raise ValueError("machine_id has invalid syntax")
    return value


def _fingerprint(value: str) -> str:
    if not isinstance(value, str) or _FINGERPRINT_RE.fullmatch(value) is None:
        raise ValueError("certificate fingerprint must be 64 hexadecimal SHA256 characters")
    return value.lower()


@dataclass(frozen=True)
class CertificateCredential:
    """One registered certificate fingerprint and bounded validity window."""

    fingerprint_sha256: str
    not_before: datetime
    expires_at: datetime


class CertificateIdentityRegistry:
    """SQLite-backed registry; construction opens existing state without mutation."""

    SCHEMA_VERSION = _IDENTITY_SCHEMA_VERSION

    def __init__(self, database: str | Path) -> None:
        self.path = str(database)
        if self.path == ":memory:":
            raise ValueError("identity registry requires durable filesystem storage")
        if not os.path.isfile(self.path):
            raise IdentityRegistryError("identity registry file is missing; bootstrap explicitly first")
        self._lock = threading.RLock()
        try:
            with self._connection() as connection:
                integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
                if integrity != "ok":
                    raise IdentityRegistryError(
                        f"identity registry integrity check failed: {integrity}"
                    )
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version != self.SCHEMA_VERSION:
                    raise IdentityRegistryError(
                        f"unsupported identity registry schema version: {version}"
                    )
                existing_tables = {
                    row[0] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if "certificate_credentials" not in existing_tables:
                    raise IdentityRegistryError("versioned identity registry is missing its credential table")
                column_rows = connection.execute(
                    "PRAGMA table_info(certificate_credentials)"
                ).fetchall()
                actual_schema = {
                    row["name"]: (row["type"].upper(), row["notnull"], row["pk"])
                    for row in column_rows
                }
                expected_schema = {
                    "fingerprint_sha256": ("TEXT", 1, 1),
                    "machine_id": ("TEXT", 1, 0),
                    "not_before": ("TEXT", 1, 0),
                    "expires_at": ("TEXT", 1, 0),
                    "revoked": ("INTEGER", 1, 0),
                }
                if actual_schema != expected_schema:
                    raise IdentityRegistryError("identity registry schema is incomplete or incompatible")
                indexes = {
                    row["name"]: row
                    for row in connection.execute("PRAGMA index_list(certificate_credentials)")
                }
                index = indexes.get("credentials_by_machine")
                if index is None or index["unique"] != 0:
                    raise IdentityRegistryError("identity registry is missing a required credential index")
                index_columns = [
                    row["name"]
                    for row in connection.execute(
                        "PRAGMA index_info(credentials_by_machine)"
                    )
                ]
                if index_columns != ["machine_id", "not_before", "expires_at"]:
                    raise IdentityRegistryError("identity registry credential index is incompatible")
                schema_sql = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='certificate_credentials'"
                ).fetchone()
                if schema_sql is None or not re.search(
                    r"CHECK\s*\(\s*revoked\s+IN\s*\(\s*0\s*,\s*1\s*\)\s*\)",
                    schema_sql["sql"],
                    re.IGNORECASE,
                ):
                    raise IdentityRegistryError("identity registry credential constraints are incomplete")
        except IdentityRegistryError:
            raise
        except sqlite3.Error as error:
            raise IdentityRegistryError(f"cannot initialize identity registry: {error}") from error

    @classmethod
    def bootstrap(cls, database: str | Path) -> "CertificateIdentityRegistry":
        """Create a new registry exactly once; never overwrite existing state."""
        path = str(database)
        if path == ":memory:":
            raise ValueError("identity registry requires durable filesystem storage")
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        except FileExistsError as error:
            raise IdentityRegistryError("refusing to bootstrap over an existing registry path") from error
        except OSError as error:
            raise IdentityRegistryError(f"cannot create identity registry file: {error}") from error
        os.close(descriptor)

        try:
            database_uri = cls._database_uri(path)
            connection = sqlite3.connect(database_uri, uri=True, timeout=10)
            try:
                with connection:
                    connection.execute("PRAGMA busy_timeout=10000")
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("""
                        CREATE TABLE certificate_credentials (
                            fingerprint_sha256 TEXT NOT NULL PRIMARY KEY,
                            machine_id TEXT NOT NULL,
                            not_before TEXT NOT NULL,
                            expires_at TEXT NOT NULL,
                            revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
                        )
                    """)
                    connection.execute("""
                        CREATE INDEX credentials_by_machine
                        ON certificate_credentials(machine_id, not_before, expires_at)
                    """)
                    connection.execute(f"PRAGMA user_version={cls.SCHEMA_VERSION}")
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise IdentityRegistryError(
                f"registry bootstrap failed; the created file was preserved for operator inspection: {error}"
            ) from error
        return cls(path)

    @classmethod
    def open(cls, database: str | Path) -> "CertificateIdentityRegistry":
        """Open and validate an existing registry without creating or migrating it."""
        return cls(database)

    @staticmethod
    def _database_uri(database: str | Path) -> str:
        path_uri = Path(database).resolve().as_uri()
        return f"{path_uri}?mode=rw"

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._database_uri(self.path), uri=True, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=10000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _credential_values(credential: CertificateCredential) -> tuple[str, str, str]:
        if not isinstance(credential, CertificateCredential):
            raise TypeError("credential must be a CertificateCredential")
        fingerprint = _fingerprint(credential.fingerprint_sha256)
        not_before = _utc(credential.not_before, "not_before")
        expires_at = _utc(credential.expires_at, "expires_at")
        if expires_at <= not_before:
            raise ValueError("credential expiry must be after not_before")
        return fingerprint, _timestamp(not_before), _timestamp(expires_at)

    def enroll(
        self,
        machine_id: str,
        credential: CertificateCredential,
        *,
        allow_overlap: bool = False,
        overlap_until: datetime | None = None,
    ) -> None:
        """Enroll one fingerprint, requiring explicit bounded overlap if needed."""
        machine_id = _machine_id(machine_id)
        fingerprint, not_before_text, expires_text = self._credential_values(credential)
        not_before = _utc(credential.not_before, "not_before")
        expires_at = _utc(credential.expires_at, "expires_at")
        if not isinstance(allow_overlap, bool):
            raise ValueError("allow_overlap must be an explicit boolean")
        overlap_end = _utc(overlap_until, "overlap_until") if overlap_until is not None else None
        try:
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute(
                    "SELECT 1 FROM certificate_credentials WHERE fingerprint_sha256=?",
                    (fingerprint,),
                ).fetchone():
                    raise IdentityAuthorizationError("certificate fingerprint is already registered")
                active = connection.execute(
                    "SELECT fingerprint_sha256,not_before,expires_at,revoked "
                    "FROM certificate_credentials WHERE machine_id=?",
                    (machine_id,),
                ).fetchall()
                overlaps = []
                for existing in active:
                    old_start = _utc(datetime.fromisoformat(existing["not_before"]), "stored not_before")
                    old_end = _utc(datetime.fromisoformat(existing["expires_at"]), "stored expires_at")
                    if not existing["revoked"] and not_before < old_end and old_start < expires_at:
                        overlaps.append((existing, old_start, old_end))
                if overlaps:
                    if not allow_overlap or overlap_end is None:
                        raise IdentityAuthorizationError(
                            "overlapping credentials require explicit bounded overlap authorization"
                        )
                    latest_start = max(not_before, *(entry[1] for entry in overlaps))
                    earliest_end = min(expires_at, *(entry[2] for entry in overlaps))
                    if not latest_start < overlap_end <= earliest_end:
                        raise ValueError(
                            "overlap_until must bound the intersection with every active credential"
                        )
                    for existing, _, _ in overlaps:
                        connection.execute(
                            "UPDATE certificate_credentials SET expires_at=? WHERE fingerprint_sha256=?",
                            (_timestamp(overlap_end), existing["fingerprint_sha256"]),
                        )
                elif allow_overlap or overlap_end is not None:
                    raise ValueError("overlap authorization was supplied but no credentials overlap")
                connection.execute(
                    "INSERT INTO certificate_credentials"
                    "(fingerprint_sha256,machine_id,not_before,expires_at,revoked) "
                    "VALUES(?,?,?,?,0)",
                    (fingerprint, machine_id, not_before_text, expires_text),
                )
        except (IdentityAuthorizationError, ValueError, TypeError):
            raise
        except sqlite3.Error as error:
            raise IdentityRegistryError(f"cannot enroll certificate credential: {error}") from error

    def authorize_offline_simulation(
        self,
        fingerprint_sha256: str,
        claimed_machine_id: str,
        *,
        simulated_at: datetime,
    ) -> str:
        """Check registry policy for synthetic tests; this is not TLS authentication."""
        return self._authorize_fingerprint(
            fingerprint_sha256,
            claimed_machine_id=claimed_machine_id,
            at=simulated_at,
        )

    def _authorize_tls_fingerprint(
        self,
        fingerprint_sha256: str,
        *,
        at: datetime,
    ) -> str:
        """Resolve a fingerprint obtained from the accepted TLS peer certificate."""
        return self._authorize_fingerprint(
            fingerprint_sha256,
            claimed_machine_id=None,
            at=at,
        )

    def _authorize_fingerprint(
        self,
        fingerprint_sha256: str,
        *,
        claimed_machine_id: str | None,
        at: datetime,
    ) -> str:
        fingerprint = _fingerprint(fingerprint_sha256)
        if claimed_machine_id is not None:
            claimed_machine_id = _machine_id(claimed_machine_id)
        instant = _utc(at, "authorization time")
        try:
            with self._lock, self._connection() as connection:
                row = connection.execute(
                    "SELECT machine_id,not_before,expires_at,revoked "
                    "FROM certificate_credentials WHERE fingerprint_sha256=?",
                    (fingerprint,),
                ).fetchone()
            if row is None:
                raise IdentityAuthorizationError("certificate fingerprint is not registered")
            if row["revoked"]:
                raise IdentityAuthorizationError("certificate credential is revoked")
            if instant < _utc(datetime.fromisoformat(row["not_before"]), "stored not_before"):
                raise IdentityAuthorizationError("certificate credential is not yet valid")
            if instant >= _utc(datetime.fromisoformat(row["expires_at"]), "stored expires_at"):
                raise IdentityAuthorizationError("certificate credential is expired")
            if claimed_machine_id is not None and row["machine_id"] != claimed_machine_id:
                raise IdentityAuthorizationError(
                    "claimed machine_id does not match the certificate-bound identity"
                )
            return row["machine_id"]
        except IdentityAuthorizationError:
            raise
        except (sqlite3.Error, ValueError) as error:
            raise IdentityRegistryError(f"cannot authorize certificate identity: {error}") from error

    def revoke(self, fingerprint_sha256: str) -> None:
        fingerprint = _fingerprint(fingerprint_sha256)
        try:
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                updated = connection.execute(
                    "UPDATE certificate_credentials SET revoked=1 WHERE fingerprint_sha256=?",
                    (fingerprint,),
                ).rowcount
                if updated != 1:
                    raise IdentityAuthorizationError("cannot revoke an unknown certificate fingerprint")
        except IdentityAuthorizationError:
            raise
        except sqlite3.Error as error:
            raise IdentityRegistryError(f"cannot revoke certificate credential: {error}") from error

    def rotate(
        self,
        machine_id: str,
        old_fingerprint_sha256: str,
        new_credential: CertificateCredential,
        *,
        rotation_at: datetime,
        overlap_until: datetime,
        allow_overlap: bool,
    ) -> None:
        machine_id = _machine_id(machine_id)
        old_fingerprint = _fingerprint(old_fingerprint_sha256)
        rotation_time = _utc(rotation_at, "rotation_at")
        overlap_end = _utc(overlap_until, "overlap_until")
        new_fingerprint, new_start_text, new_end_text = self._credential_values(new_credential)
        new_start = _utc(new_credential.not_before, "new credential not_before")
        if not isinstance(allow_overlap, bool):
            raise ValueError("allow_overlap must be an explicit boolean")
        if overlap_end < rotation_time:
            raise ValueError("overlap_until cannot precede rotation_at")
        if overlap_end > rotation_time and not allow_overlap:
            raise ValueError("overlapping credentials require explicit allow_overlap=True")
        if new_start < rotation_time or new_start > overlap_end:
            raise ValueError("new credential validity must begin between rotation and overlap end")
        try:
            with self._lock, self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                old = connection.execute(
                    "SELECT machine_id,not_before,expires_at,revoked FROM certificate_credentials "
                    "WHERE fingerprint_sha256=?",
                    (old_fingerprint,),
                ).fetchone()
                if old is None or old["machine_id"] != machine_id:
                    raise IdentityAuthorizationError(
                        "old certificate fingerprint is not registered to this machine"
                    )
                if old["revoked"]:
                    raise IdentityAuthorizationError("cannot rotate a revoked certificate")
                if not _utc(
                    datetime.fromisoformat(old["not_before"]), "stored not_before"
                ) <= rotation_time < _utc(
                    datetime.fromisoformat(old["expires_at"]), "stored expires_at"
                ):
                    raise IdentityAuthorizationError("old credential is not valid at rotation_at")
                if new_fingerprint in {
                    row["fingerprint_sha256"] for row in connection.execute(
                        "SELECT fingerprint_sha256 FROM certificate_credentials"
                    )
                }:
                    raise IdentityAuthorizationError("certificate fingerprint is already registered")
                new_end = _utc(new_credential.expires_at, "new credential expires_at")
                overlaps = []
                rows = connection.execute(
                    "SELECT fingerprint_sha256,not_before,expires_at,revoked "
                    "FROM certificate_credentials WHERE machine_id=?",
                    (machine_id,),
                ).fetchall()
                for row in rows:
                    if row["revoked"]:
                        continue
                    row_start = _utc(datetime.fromisoformat(row["not_before"]), "stored not_before")
                    row_end = _utc(datetime.fromisoformat(row["expires_at"]), "stored expires_at")
                    if row["fingerprint_sha256"] == old_fingerprint and not allow_overlap:
                        row_end = rotation_time
                    if new_start < row_end and row_start < new_end:
                        overlaps.append((row, row_start, row_end))

                if overlaps:
                    if not allow_overlap:
                        raise ValueError(
                            "overlapping credentials require explicit allow_overlap=True"
                        )
                    latest_start = max(new_start, *(item[1] for item in overlaps))
                    earliest_end = min(new_end, *(item[2] for item in overlaps))
                    if not latest_start < overlap_end <= earliest_end:
                        raise ValueError(
                            "overlap_until must bound the intersection with every active credential"
                        )
                    for row, _, row_end in overlaps:
                        if row_end > overlap_end:
                            connection.execute(
                                "UPDATE certificate_credentials SET expires_at=? "
                                "WHERE fingerprint_sha256=?",
                                (_timestamp(overlap_end), row["fingerprint_sha256"]),
                            )
                elif allow_overlap or overlap_end != rotation_time:
                    raise ValueError("overlap authorization was supplied but no credentials overlap")

                if not allow_overlap:
                    connection.execute(
                        "UPDATE certificate_credentials SET expires_at=? WHERE fingerprint_sha256=?",
                        (_timestamp(rotation_time), old_fingerprint),
                    )
                connection.execute(
                    "INSERT INTO certificate_credentials"
                    "(fingerprint_sha256,machine_id,not_before,expires_at,revoked) "
                    "VALUES(?,?,?,?,0)",
                    (new_fingerprint, machine_id, new_start_text, new_end_text),
                )
        except (IdentityAuthorizationError, ValueError):
            raise
        except sqlite3.Error as error:
            raise IdentityRegistryError(f"cannot rotate certificate credential: {error}") from error
