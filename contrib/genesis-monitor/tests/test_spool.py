import tempfile
import sqlite3
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_monitor.protocol import ProtocolError
from genesis_monitor.protocol import canonical_json
from genesis_monitor.receipts import (
    CommittedReceiptSigner,
    CommittedReceiptVerifier,
    canonical_event_hash,
    trust_bundle_from_public_keys,
)
from genesis_monitor.spool import DuplicateEventConflict, EventSpool, SpoolError, SpoolFull
from tests.test_protocol import valid_event


class SpoolTests(unittest.TestCase):
    def test_legacy_spool_migrates_retry_state_without_losing_pending_event(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite"
            source = valid_event()
            payload = canonical_json(source)
            connection = sqlite3.connect(path)
            try:
                connection.execute("""
                    CREATE TABLE events (
                        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        machine_id TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL UNIQUE,
                        content_hash TEXT NOT NULL,
                        payload TEXT NOT NULL,
                        byte_size INTEGER NOT NULL,
                        created_at TEXT NOT NULL
                    )
                """)
                connection.execute(
                    "INSERT INTO events(event_id,machine_id,idempotency_key,content_hash,"
                    "payload,byte_size,created_at) VALUES(?,?,?,?,?,?,?)",
                    (
                        source["event_id"],
                        source["machine_id"],
                        "legacy-key",
                        "legacy-hash",
                        payload,
                        len(payload.encode("utf-8")),
                        "2029-01-01T00:00:00Z",
                    ),
                )
                connection.commit()
            finally:
                connection.close()
            now = datetime(2030, 1, 1, tzinfo=timezone.utc)
            spool = EventSpool(path)
            self.assertEqual(spool.pending(), [source])
            self.assertEqual(spool.due_pending(now=now)[0]["attempt_count"], 0)
            spool.schedule_retry(
                source["event_id"],
                delay_seconds=5,
                now=now,
                error="offline",
            )
            reopened = EventSpool(path)
            self.assertEqual(reopened.pending(), [source])
            self.assertEqual(reopened.due_pending(now=now), [])
            self.assertEqual(
                reopened.due_pending(now=now + timedelta(seconds=5))[0]["attempt_count"],
                1,
            )

    def test_sequence_pending_ack_and_duplicate_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            private_key = Ed25519PrivateKey.generate()
            now = datetime.now(timezone.utc)
            bundle = trust_bundle_from_public_keys({
                "test-server-key": (
                    private_key.public_key(), now - timedelta(days=1), now + timedelta(days=1), False
                )
            })
            signer = CommittedReceiptSigner(
                {"test-server-key": private_key},
                active_key_id="test-server-key",
                trust_bundle=bundle,
            )
            verifier = CommittedReceiptVerifier(bundle)
            spool = EventSpool(
                Path(directory) / "events.sqlite",
                max_pending_events=3,
                receipt_verifier=verifier,
            )
            source = valid_event()
            event, duplicate = spool.enqueue(
                source["machine_id"], source["observed_at"], source["payload"], "heartbeat-1"
            )
            self.assertFalse(duplicate)
            self.assertEqual(event["sequence"], 1)
            with self.assertRaises(TypeError):
                spool.acknowledge(event["event_id"])
            self.assertEqual(spool.pending(), [event])
            repeated, duplicate = spool.enqueue(
                source["machine_id"], source["observed_at"], source["payload"], "heartbeat-1"
            )
            self.assertTrue(duplicate)
            self.assertEqual(repeated, event)
            self.assertEqual(spool.pending(), [event])
            receipt = {
                "receipt_version": 3,
                "key_id": signer.active_key_id,
                "machine_id": event["machine_id"],
                "event_id": event["event_id"],
                "sequence": event["sequence"],
                "canonical_event_hash": canonical_event_hash(event),
                "outcome": "accepted",
                "issued_at": now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            }
            receipt["signature"] = signer._sign(receipt)
            forged = dict(receipt, canonical_event_hash="0" * 64)
            with self.assertRaises(SpoolError):
                spool.acknowledge(event["event_id"], receipt=forged)
            self.assertEqual(spool.pending(), [event])
            spool.acknowledge(event["event_id"], receipt=receipt)
            self.assertEqual(spool.pending(), [])
            second, duplicate = spool.enqueue(
                source["machine_id"], source["observed_at"], source["payload"], "heartbeat-2"
            )
            self.assertFalse(duplicate)
            self.assertEqual(second["sequence"], 2)

    def test_reusing_key_for_different_payload_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            spool = EventSpool(Path(directory) / "events.sqlite")
            source = valid_event()
            spool.enqueue(source["machine_id"], source["observed_at"], source["payload"], "same-key")
            changed = source["payload"]
            changed["log"]["aggregate_candidates"] = 26
            with self.assertRaises(DuplicateEventConflict):
                spool.enqueue(source["machine_id"], source["observed_at"], changed, "same-key")

    def test_idempotency_key_is_bound_to_machine_and_observation_time(self):
        with tempfile.TemporaryDirectory() as directory:
            source = valid_event()
            spool = EventSpool(Path(directory) / "events.sqlite")
            spool.enqueue(source["machine_id"], source["observed_at"], source["payload"], "same-key")
            with self.assertRaises(DuplicateEventConflict):
                spool.enqueue("other-machine", source["observed_at"], source["payload"], "same-key")

    def test_spool_limits_fail_without_dropping_pending_events(self):
        with tempfile.TemporaryDirectory() as directory:
            source = valid_event()
            spool = EventSpool(Path(directory) / "events.sqlite", max_pending_events=1)
            spool.enqueue(source["machine_id"], source["observed_at"], source["payload"], "first")
            with self.assertRaises(SpoolFull):
                spool.enqueue(source["machine_id"], source["observed_at"], source["payload"], "second")
            self.assertEqual(len(spool.pending()), 1)

    def test_serialized_byte_limit_fails_without_persisting_event(self):
        with tempfile.TemporaryDirectory() as directory:
            source = valid_event()
            spool = EventSpool(Path(directory) / "events.sqlite", max_pending_bytes=10)
            with self.assertRaises(SpoolFull):
                spool.enqueue(source["machine_id"], source["observed_at"], source["payload"], "too-large")
            self.assertEqual(spool.pending_size(), (0, 0))

    def test_invalid_event_fails_before_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            source = valid_event()
            source["payload"]["log"]["worker_count"] = True
            spool = EventSpool(Path(directory) / "events.sqlite")
            with self.assertRaises(ProtocolError):
                spool.enqueue(source["machine_id"], source["observed_at"], source["payload"], "bad")
            self.assertEqual(spool.pending_size()[0], 0)


if __name__ == "__main__":
    unittest.main()
