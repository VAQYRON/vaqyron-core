"""Ed25519-signed committed-ingestion receipts and spool acknowledgement checks."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .protocol import ProtocolError, canonical_json, parse_event, validate_event


RECEIPT_VERSION = 3
TRUST_BUNDLE_VERSION = 1
MAX_RECEIPT_BYTES = 4096
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ReceiptError(ValueError):
    """A committed receipt is malformed, unrelated, or not safe to acknowledge."""


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("receipt and trust timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str):
        raise ReceiptError(f"{name} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ReceiptError(f"{name} must be a canonical UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None or _timestamp(parsed) != value:
        raise ReceiptError(f"{name} must be a canonical UTC timestamp")
    return parsed.astimezone(timezone.utc)


def _validate_key_id(value: Any) -> str:
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise ValueError("key_id has invalid syntax")
    return value


@dataclass(frozen=True)
class _TrustedReceiptKey:
    key_id: str
    public_key: Ed25519PublicKey
    not_before: datetime
    expires_at: datetime
    revoked: bool


class ReceiptTrustBundle:
    """Versioned, public-key-only receipt trust configuration."""

    def __init__(
        self,
        keys: Mapping[str, _TrustedReceiptKey],
        rotations: tuple[tuple[str, str, datetime], ...],
    ) -> None:
        self._keys = dict(keys)
        self._rotations = rotations
        self._validate_rotations()

    @classmethod
    def from_mapping(cls, value: Any) -> "ReceiptTrustBundle":
        if not isinstance(value, dict) or set(value) != {"bundle_version", "keys", "rotations"}:
            raise ReceiptError("trust bundle must contain exactly bundle_version, keys, and rotations")
        if (
            isinstance(value["bundle_version"], bool)
            or not isinstance(value["bundle_version"], int)
            or value["bundle_version"] != TRUST_BUNDLE_VERSION
        ):
            raise ReceiptError("unsupported receipt trust-bundle version")
        if not isinstance(value["keys"], list) or not value["keys"]:
            raise ReceiptError("trust bundle keys must be a non-empty list")
        if not isinstance(value["rotations"], list):
            raise ReceiptError("trust bundle rotations must be a list")
        keys: dict[str, _TrustedReceiptKey] = {}
        for item in value["keys"]:
            if not isinstance(item, dict) or set(item) != {
                "key_id", "public_key", "not_before", "expires_at", "revoked"
            }:
                raise ReceiptError("trust-bundle key entry has invalid fields")
            try:
                key_id = _validate_key_id(item["key_id"])
            except ValueError as error:
                raise ReceiptError(str(error)) from error
            if key_id in keys:
                raise ReceiptError("duplicate key_id in receipt trust bundle")
            public_key_hex = item["public_key"]
            if (
                not isinstance(public_key_hex, str)
                or re.fullmatch(r"[0-9a-f]{64}", public_key_hex) is None
            ):
                raise ReceiptError("Ed25519 public_key must be 64 lowercase hexadecimal characters")
            if not isinstance(item["revoked"], bool):
                raise ReceiptError("trust-bundle revoked field must be boolean")
            not_before = _parse_timestamp(item["not_before"], "not_before")
            expires_at = _parse_timestamp(item["expires_at"], "expires_at")
            if expires_at <= not_before:
                raise ReceiptError("trust-bundle key expiry must be after not_before")
            try:
                public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            except ValueError as error:
                raise ReceiptError("trust-bundle Ed25519 public key is invalid") from error
            keys[key_id] = _TrustedReceiptKey(
                key_id, public_key, not_before, expires_at, item["revoked"]
            )

        rotations: list[tuple[str, str, datetime]] = []
        seen_pairs: set[frozenset[str]] = set()
        for item in value["rotations"]:
            if not isinstance(item, dict) or set(item) != {
                "old_key_id", "new_key_id", "overlap_until"
            }:
                raise ReceiptError("trust-bundle rotation entry has invalid fields")
            old_key_id = item["old_key_id"]
            new_key_id = item["new_key_id"]
            try:
                _validate_key_id(old_key_id)
                _validate_key_id(new_key_id)
            except ValueError as error:
                raise ReceiptError(str(error)) from error
            if old_key_id == new_key_id or old_key_id not in keys or new_key_id not in keys:
                raise ReceiptError("trust-bundle rotation refers to invalid key IDs")
            pair = frozenset((old_key_id, new_key_id))
            if pair in seen_pairs:
                raise ReceiptError("duplicate trust-bundle rotation authorization")
            seen_pairs.add(pair)
            rotations.append(
                (old_key_id, new_key_id, _parse_timestamp(item["overlap_until"], "overlap_until"))
            )
        return cls(keys, tuple(rotations))

    def _validate_rotations(self) -> None:
        used_pairs: set[frozenset[str]] = set()
        active_keys = list(self._keys.values())
        for index, first in enumerate(active_keys):
            for second in active_keys[index + 1:]:
                overlap_start = max(first.not_before, second.not_before)
                overlap_end = min(first.expires_at, second.expires_at)
                if overlap_start >= overlap_end:
                    continue
                pair = frozenset((first.key_id, second.key_id))
                matches = [
                    (old_key_id, new_key_id, until)
                    for old_key_id, new_key_id, until in self._rotations
                    if frozenset((old_key_id, new_key_id)) == pair
                ]
                if len(matches) != 1:
                    raise ReceiptError("overlapping receipt keys require explicit rotation authorization")
                old_key_id, new_key_id, overlap_until = matches[0]
                old_key = self._keys[old_key_id]
                new_key = self._keys[new_key_id]
                if (
                    old_key.expires_at != overlap_until
                    or not overlap_start < overlap_until <= overlap_end
                    or new_key.not_before > overlap_until
                ):
                    raise ReceiptError("receipt key rotation overlap is not explicitly bounded")
                used_pairs.add(pair)
        if any(
            frozenset((old_key_id, new_key_id)) not in used_pairs
            for old_key_id, new_key_id, _ in self._rotations
        ):
            raise ReceiptError("trust-bundle rotation authorization does not describe an overlap")

    def _key_for_receipt(self, key_id: str, issued_at: datetime, now: datetime) -> Ed25519PublicKey:
        key = self._keys.get(key_id)
        if key is None:
            raise ReceiptError("receipt key_id is not trusted")
        if key.revoked:
            raise ReceiptError("receipt signing key is revoked")
        if not key.not_before <= issued_at < key.expires_at:
            raise ReceiptError("receipt was issued outside the signing key validity window")
        if not key.not_before <= now < key.expires_at:
            raise ReceiptError("receipt signing key is not currently valid")
        return key.public_key

    def to_mapping(self) -> dict[str, Any]:
        keys = []
        for key_id, key in sorted(self._keys.items()):
            raw = key.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            keys.append({
                "key_id": key_id,
                "public_key": raw.hex(),
                "not_before": _timestamp(key.not_before),
                "expires_at": _timestamp(key.expires_at),
                "revoked": key.revoked,
            })
        rotations = [
            {
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "overlap_until": _timestamp(overlap_until),
            }
            for old_key_id, new_key_id, overlap_until in self._rotations
        ]
        return {"bundle_version": TRUST_BUNDLE_VERSION, "keys": keys, "rotations": rotations}


class CommittedReceiptSigner:
    """Server-side Ed25519 signer; private keys must never be sent to agents."""

    def __init__(
        self,
        private_keys: Mapping[str, Ed25519PrivateKey],
        *,
        active_key_id: str,
        trust_bundle: ReceiptTrustBundle,
    ) -> None:
        if not isinstance(private_keys, Mapping) or not private_keys:
            raise ValueError("at least one Ed25519 signing key is required")
        self._private_keys: dict[str, Ed25519PrivateKey] = {}
        for key_id, private_key in private_keys.items():
            try:
                _validate_key_id(key_id)
            except ValueError as error:
                raise ValueError(str(error)) from error
            if not isinstance(private_key, Ed25519PrivateKey):
                raise TypeError("server signer accepts Ed25519 private keys only")
            self._private_keys[key_id] = private_key
        try:
            _validate_key_id(active_key_id)
        except ValueError as error:
            raise ValueError(str(error)) from error
        if active_key_id not in self._private_keys:
            raise ValueError("active signing key_id is not configured")
        if not isinstance(trust_bundle, ReceiptTrustBundle):
            raise TypeError("server signer requires its versioned ReceiptTrustBundle")
        for key_id, private_key in self._private_keys.items():
            trusted_key = trust_bundle._keys.get(key_id)
            if trusted_key is None:
                raise ValueError(f"signing key {key_id} is absent from the trust bundle")
            private_public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            trusted_public_bytes = trusted_key.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            if private_public_bytes != trusted_public_bytes:
                raise ValueError(f"signing key {key_id} does not match its trust-bundle public key")
        self._trust_bundle = trust_bundle
        self.active_key_id = active_key_id

    def _sign(self, fields: dict[str, Any]) -> str:
        encoded = json.dumps(
            fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("utf-8")
        try:
            private_key = self._private_keys[fields["key_id"]]
        except KeyError as error:
            raise ReceiptError("server signing key_id is not configured") from error
        issued_at = _parse_timestamp(fields["issued_at"], "issued_at")
        self._trust_bundle._key_for_receipt(fields["key_id"], issued_at, issued_at)
        return private_key.sign(encoded).hex()


class CommittedReceiptVerifier:
    """Client-side receipt verifier constructed only from public trust-bundle keys."""

    def __init__(self, trust_bundle: ReceiptTrustBundle) -> None:
        if not isinstance(trust_bundle, ReceiptTrustBundle):
            raise TypeError("receipt verifier requires a ReceiptTrustBundle")
        self.trust_bundle = trust_bundle

    def verify(self, receipt: Any, event: Any, *, now: datetime | None = None) -> dict[str, Any]:
        return validate_committed_receipt(receipt, event, self, now=now)


def trust_bundle_from_public_keys(
    keys: Mapping[str, tuple[Ed25519PublicKey, datetime, datetime, bool]],
    *,
    rotations: tuple[tuple[str, str, datetime], ...] = (),
) -> ReceiptTrustBundle:
    """Build a trust bundle from public keys and explicit validity/rotation policy."""
    records = []
    for key_id, (public_key, not_before, expires_at, revoked) in keys.items():
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("receipt trust bundles accept public keys only")
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        records.append({
            "key_id": key_id,
            "public_key": raw.hex(),
            "not_before": _timestamp(not_before),
            "expires_at": _timestamp(expires_at),
            "revoked": revoked,
        })
    return ReceiptTrustBundle.from_mapping({
        "bundle_version": TRUST_BUNDLE_VERSION,
        "keys": records,
        "rotations": [
            {
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "overlap_until": _timestamp(overlap_until),
            }
            for old_key_id, new_key_id, overlap_until in rotations
        ],
    })


def canonical_event_hash(event: Any) -> str:
    """Return SHA256 over the protocol's canonical event JSON bytes."""
    try:
        validated = validate_event(event)
        encoded = canonical_json(validated).encode("utf-8")
    except ProtocolError as error:
        raise ReceiptError(f"cannot hash invalid telemetry event: {error}") from error
    return hashlib.sha256(encoded).hexdigest()


def canonical_receipt_json(receipt: dict[str, Any]) -> str:
    """Serialize a receipt using its unique UTF-8 JSON representation."""
    if not isinstance(receipt, dict):
        raise ReceiptError("receipt must be an object")
    try:
        return json.dumps(
            receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
    except (TypeError, ValueError) as error:
        raise ReceiptError(f"receipt cannot be serialized canonically: {error}") from error


def _create_committed_receipt(
    event: dict[str, Any],
    ingest_result: Any,
    signer: CommittedReceiptSigner,
    *,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    """Sign a receipt only for a successful CentralStore committed result."""
    from .store import IngestResult, _COMMITTED_RESULT_MARKER

    if (
        not isinstance(ingest_result, IngestResult)
        or ingest_result._commit_marker is not _COMMITTED_RESULT_MARKER
    ):
        raise ReceiptError("receipt requires a CentralStore committed ingestion result")
    if not isinstance(signer, CommittedReceiptSigner):
        raise TypeError("signer must be a CommittedReceiptSigner")
    validated = validate_event(event)
    if (
        ingest_result.event_id != validated["event_id"]
        or ingest_result.sequence != validated["sequence"]
    ):
        raise ReceiptError("ingestion result does not identify the submitted event")
    if ingest_result.disposition == "duplicate":
        if ingest_result.current_updated:
            raise ReceiptError("duplicate ingestion result has an invalid current-state flag")
        outcome = "duplicate"
    elif ingest_result.disposition == "accepted_current" and ingest_result.current_updated:
        outcome = "accepted"
    elif ingest_result.disposition == "accepted_stale" and not ingest_result.current_updated:
        outcome = "accepted"
    else:
        raise ReceiptError("ingestion result is not a successful committed outcome")
    instant = _timestamp(issued_at or datetime.now(timezone.utc))
    fields = {
        "receipt_version": RECEIPT_VERSION,
        "key_id": signer.active_key_id,
        "machine_id": validated["machine_id"],
        "event_id": validated["event_id"],
        "sequence": validated["sequence"],
        "canonical_event_hash": canonical_event_hash(validated),
        "outcome": outcome,
        "issued_at": instant,
    }
    return {**fields, "signature": signer._sign(fields)}


def validate_committed_receipt(
    receipt: Any,
    event: Any,
    verifier: CommittedReceiptVerifier,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Validate canonical receipt schema, signature, key status and event binding."""
    if not isinstance(verifier, CommittedReceiptVerifier):
        raise TypeError("verifier must be a CommittedReceiptVerifier")
    try:
        validated_event = validate_event(event)
    except ProtocolError as error:
        raise ReceiptError(f"cannot acknowledge invalid telemetry event: {error}") from error
    expected_fields = {
        "receipt_version", "key_id", "machine_id", "event_id", "sequence",
        "canonical_event_hash", "outcome", "issued_at", "signature",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_fields:
        raise ReceiptError("receipt must contain exactly the versioned Ed25519 receipt fields")
    if (
        isinstance(receipt["receipt_version"], bool)
        or not isinstance(receipt["receipt_version"], int)
        or receipt["receipt_version"] != RECEIPT_VERSION
    ):
        raise ReceiptError(f"unsupported receipt version: {receipt['receipt_version']!r}")
    try:
        key_id = _validate_key_id(receipt["key_id"])
    except ValueError as error:
        raise ReceiptError(str(error)) from error
    if receipt["machine_id"] != validated_event["machine_id"]:
        raise ReceiptError("receipt machine_id does not match the submitted event")
    if not isinstance(receipt["machine_id"], str):
        raise ReceiptError("receipt machine_id must be text")
    if receipt["event_id"] != validated_event["event_id"]:
        raise ReceiptError("receipt event_id does not match the submitted event")
    if not isinstance(receipt["event_id"], str):
        raise ReceiptError("receipt event_id must be text")
    if (
        isinstance(receipt["sequence"], bool)
        or not isinstance(receipt["sequence"], int)
        or receipt["sequence"] != validated_event["sequence"]
    ):
        raise ReceiptError("receipt sequence does not match the submitted event")
    digest = receipt["canonical_event_hash"]
    if not isinstance(digest, str) or _HASH_RE.fullmatch(digest) is None:
        raise ReceiptError("receipt canonical_event_hash must be 64 lowercase hexadecimal characters")
    if digest != canonical_event_hash(validated_event):
        raise ReceiptError("receipt canonical event hash does not match the submitted event")
    if not isinstance(receipt["outcome"], str) or receipt["outcome"] not in ("accepted", "duplicate"):
        raise ReceiptError("receipt outcome must be accepted or duplicate")
    issued_at = _parse_timestamp(receipt["issued_at"], "issued_at")
    verification_time = now or datetime.now(timezone.utc)
    if verification_time.tzinfo is None or verification_time.utcoffset() is None:
        raise ValueError("verification time must be timezone-aware")
    verification_time = verification_time.astimezone(timezone.utc)
    if issued_at > verification_time:
        raise ReceiptError("receipt issued_at is in the future")
    signature = receipt["signature"]
    if not isinstance(signature, str) or _SIGNATURE_RE.fullmatch(signature) is None:
        raise ReceiptError("receipt signature must be 128 lowercase hexadecimal characters")
    public_key = verifier.trust_bundle._key_for_receipt(key_id, issued_at, verification_time)
    signed_fields = {field: receipt[field] for field in expected_fields if field != "signature"}
    encoded = json.dumps(
        signed_fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    try:
        public_key.verify(bytes.fromhex(signature), encoded)
    except (InvalidSignature, ValueError) as error:
        raise ReceiptError("receipt Ed25519 signature verification failed") from error
    return dict(receipt)


def parse_committed_receipt(
    data: str | bytes,
    event: Any,
    verifier: CommittedReceiptVerifier,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Parse bounded UTF-8 JSON, reject duplicate keys, and verify the receipt."""
    if isinstance(data, bytes):
        if len(data) > MAX_RECEIPT_BYTES:
            raise ReceiptError("receipt exceeds the maximum encoded size")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ReceiptError("receipt is not valid UTF-8") from error
    elif isinstance(data, str):
        text = data
    else:
        raise ReceiptError("receipt must be UTF-8 JSON text or bytes")
    if len(text.encode("utf-8")) > MAX_RECEIPT_BYTES:
        raise ReceiptError("receipt exceeds the maximum encoded size")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReceiptError(f"duplicate receipt key: {key}")
            result[key] = value
        return result

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReceiptError(f"invalid JSON constant: {value}")
            ),
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ReceiptError("receipt is not valid JSON") from error
    if not isinstance(parsed, dict) or canonical_receipt_json(parsed) != text:
        raise ReceiptError("receipt JSON is not in canonical form")
    return validate_committed_receipt(parsed, event, verifier, now=now)


def acknowledge_spooled_event(
    spool: Any,
    event: Any,
    receipt: Any,
    verifier: CommittedReceiptVerifier,
) -> None:
    """Acknowledge exactly the submitted spool event after signature verification."""
    validated_event = validate_event(event)
    validated_receipt = validate_committed_receipt(receipt, validated_event, verifier)
    spool.acknowledge(validated_event["event_id"], receipt=validated_receipt)
