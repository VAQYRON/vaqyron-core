import sqlite3
import tempfile
import unittest
from pathlib import Path

from genesis_monitor.store import (
    CentralStore,
    EventConflictError,
    MachineIdentityError,
    StoreError,
)
from tests.test_protocol import valid_event


class CentralStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.store = CentralStore(Path(self.tempdir.name) / "central.sqlite")
        self.store.register_machine("laptop-1", "Main synthetic worker")

    @staticmethod
    def at(seconds: int) -> str:
        return f"2026-10-14T07:00:{seconds:02d}Z"

    def event(self, sequence: int, *, current_nonce: int = 124, observed_at: str | None = None):
        event = valid_event()
        event["sequence"] = sequence
        event["event_id"] = f"laptop-1:{sequence}"
        event["observed_at"] = observed_at or self.at(min(sequence, 59))
        event["payload"]["log"]["workers"][0]["current_nonce"] = current_nonce
        event["payload"]["log"]["workers"][0]["shared_candidates_at_observation"] = sequence * 10
        event["payload"]["log"]["aggregate_candidates"] = sequence * 10
        return event

    def test_persistence_and_machine_identity_binding(self):
        result = self.store.ingest(
            self.event(1), authenticated_machine_id="laptop-1", received_at=self.at(1)
        )
        self.assertEqual(result.disposition, "accepted_current")
        reopened = CentralStore(Path(self.tempdir.name) / "central.sqlite")
        self.assertEqual(len(reopened.history("laptop-1")), 1)
        with self.assertRaises(MachineIdentityError):
            reopened.ingest(self.event(2), authenticated_machine_id="other", received_at=self.at(2))
        unregistered = self.event(1)
        unregistered["machine_id"] = "unknown"
        unregistered["event_id"] = "unknown:1"
        with self.assertRaises(MachineIdentityError):
            reopened.ingest(unregistered, authenticated_machine_id="unknown", received_at=self.at(2))

    def test_identical_duplicate_is_idempotent_and_refreshes_agent_contact(self):
        event = self.event(1)
        first = self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=self.at(1))
        duplicate = self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=self.at(3))
        self.assertEqual(first.disposition, "accepted_current")
        self.assertEqual(duplicate.disposition, "duplicate")
        self.assertEqual(len(self.store.history("laptop-1")), 1)
        machine = self.store.snapshot(now=self.at(4))["machines"][0]
        self.assertEqual(machine["last_local_ingestion_at"], self.at(3).replace("Z", ".000000Z"))
        self.assertEqual(machine["ingestion_status"], "recent")

    def test_event_id_and_machine_sequence_reuse_with_changed_content_rejected(self):
        self.store.ingest(self.event(1), authenticated_machine_id="laptop-1", received_at=self.at(1))
        changed_same_id = self.event(1, current_nonce=125)
        with self.assertRaises(EventConflictError):
            self.store.ingest(changed_same_id, authenticated_machine_id="laptop-1", received_at=self.at(2))
        changed_id_same_sequence = self.event(1)
        changed_id_same_sequence["event_id"] = "laptop-1:another"
        with self.assertRaises(EventConflictError):
            self.store.ingest(changed_id_same_sequence, authenticated_machine_id="laptop-1", received_at=self.at(2))

    def test_stale_out_of_order_event_remains_history_without_replacing_current(self):
        current = self.event(10, current_nonce=180)
        self.store.ingest(current, authenticated_machine_id="laptop-1", received_at=self.at(10))
        stale = self.event(4, current_nonce=140)
        outcome = self.store.ingest(stale, authenticated_machine_id="laptop-1", received_at=self.at(11))
        self.assertEqual(outcome.disposition, "accepted_stale")
        history = self.store.history("laptop-1")
        self.assertEqual([entry["sequence"] for entry in history], [4, 10])
        self.assertFalse(history[0]["is_current"])
        self.assertTrue(history[1]["is_current"])
        machine = self.store.snapshot(now=self.at(12))["machines"][0]
        self.assertEqual(machine["current_sequence"], 10)
        self.assertEqual(machine["log"]["workers"][0]["current_nonce"], 180)
        self.assertEqual(machine["last_local_ingestion_at"], self.at(11).replace("Z", ".000000Z"))

    def test_local_ingestion_recency_is_separate_from_search_activity(self):
        event = self.event(1, observed_at=self.at(0))
        event["payload"]["checkpoint"]["status"] = "unavailable"
        event["payload"]["checkpoint"]["error"] = "not readable"
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=self.at(1))
        fresh = self.store.snapshot(
            now=self.at(20), local_ingestion_timeout_seconds=30, activity_timeout_seconds=10
        )["machines"][0]
        self.assertEqual(fresh["ingestion_status"], "recent")
        self.assertEqual(fresh["search_status"], "stale")
        expired = self.store.snapshot(
            now=self.at(40), local_ingestion_timeout_seconds=30, activity_timeout_seconds=10
        )["machines"][0]
        self.assertEqual(expired["ingestion_status"], "stale")
        self.assertEqual(expired["search_status"], "stale")

    def test_unknown_agent_and_unavailable_telemetry_are_explicit(self):
        self.store.register_machine("laptop-2", "Acer synthetic")
        machines = self.store.snapshot(now=self.at(1))["machines"]
        self.assertEqual(machines[0]["ingestion_status"], "unknown")
        self.assertEqual(machines[1]["ingestion_status"], "unknown")
        event = self.event(1)
        event["payload"]["log"] = {
            "status": "unavailable", "worker_ranges_status": "unavailable",
            "source_mtime": None, "search_time": None,
            "range_start": None, "range_end": None, "worker_count": None,
            "aggregate_candidates": None, "aggregate_candidates_per_second": None,
            "result": None, "found_candidate": None, "workers": [], "parse_errors": 0,
        }
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=self.at(1))
        machine = self.store.snapshot(now=self.at(2))["machines"][0]
        self.assertEqual(machine["ingestion_status"], "recent")
        self.assertEqual(machine["search_status"], "unknown")

    def test_reconnect_with_new_sequence_updates_current_but_retains_history(self):
        self.store.ingest(self.event(1), authenticated_machine_id="laptop-1", received_at=self.at(1))
        reconnect = self.event(2, current_nonce=125)
        outcome = self.store.ingest(reconnect, authenticated_machine_id="laptop-1", received_at=self.at(20))
        self.assertTrue(outcome.current_updated)
        machine = self.store.snapshot(now=self.at(21))["machines"][0]
        self.assertEqual(machine["ingestion_status"], "recent")
        self.assertEqual(machine["current_sequence"], 2)
        self.assertEqual(len(self.store.history("laptop-1")), 2)

    def test_stale_replay_recency_means_local_acceptance_not_agent_presence(self):
        event = self.event(4)
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=self.at(2))
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=self.at(20))
        machine = self.store.snapshot(now=self.at(21))["machines"][0]
        self.assertEqual(machine["ingestion_status"], "recent")
        self.assertEqual(machine["last_local_ingestion_at"], self.at(20).replace("Z", ".000000Z"))
        self.assertNotIn("agent_status", machine)

    def test_checkpoint_age_and_future_timestamp_clock_skew(self):
        event = self.event(1)
        event["payload"]["checkpoint"] = {
            "status": "valid",
            "observed_at": self.at(5),
            "format_version": 2,
            "configuration": {
                "time": 1791363600, "start_nonce": 100, "end_nonce": 199,
                "requested_worker_count": 1, "nbits": 0x1D00FFFF,
                "block_version": 1, "pow_limit": "f" * 64,
            },
            "workers": [{
                "worker_index": 0, "start_nonce": 100, "end_nonce": 199,
                "last_completed_nonce": 124, "last_pow_digest_raw": "a" * 64,
            }],
            "found": None, "error": None,
        }
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=self.at(6))
        aged = self.store.snapshot(now=self.at(16))["machines"][0]
        self.assertEqual(aged["checkpoint_age_status"], "available")
        self.assertEqual(aged["checkpoint_age_seconds"], 11.0)
        future = self.store.snapshot(now=self.at(4))["machines"][0]
        self.assertEqual(future["checkpoint_age_status"], "clock_skew")
        self.assertIsNone(future["checkpoint_age_seconds"])

    def test_naive_receive_time_is_rejected(self):
        with self.assertRaises(StoreError):
            self.store.ingest(
                self.event(1), authenticated_machine_id="laptop-1", received_at="2026-10-14T07:00:00"
            )

    def test_phase_2a_database_migrates_without_losing_machine_registration(self):
        database = Path(self.tempdir.name) / "phase-2a.sqlite"
        connection = sqlite3.connect(database)
        connection.executescript("""
            CREATE TABLE machines (
                machine_id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                current_sequence INTEGER,
                last_received_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE telemetry_events (
                machine_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_id TEXT NOT NULL UNIQUE,
                content_hash TEXT NOT NULL,
                canonical_event TEXT NOT NULL,
                received_at TEXT NOT NULL,
                is_current INTEGER NOT NULL,
                PRIMARY KEY (machine_id, sequence)
            );
            INSERT INTO machines(machine_id,display_name,created_at)
                VALUES('legacy-worker','Legacy worker','2026-10-14T00:00:00Z');
            PRAGMA user_version=1;
        """)
        connection.close()
        migrated = CentralStore(database)
        self.assertIsNone(migrated.search_configuration("legacy-worker"))
        migrated.register_machine("legacy-worker", "Legacy worker")
        check = sqlite3.connect(database)
        try:
            self.assertEqual(check.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual(check.execute("SELECT display_name FROM machines").fetchone()[0], "Legacy worker")
        finally:
            check.close()


if __name__ == "__main__":
    unittest.main()
