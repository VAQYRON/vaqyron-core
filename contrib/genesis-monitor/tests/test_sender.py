import multiprocessing
import os
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_monitor.receipts import CommittedReceiptVerifier, trust_bundle_from_public_keys
from genesis_monitor.sender import DurableEventSender
from genesis_monitor.spool import EventSpool, SpoolError, SpoolFull
from genesis_monitor.transport import TransportError
from tests.test_protocol import valid_event


def _hold_spool_sender_lock(database, ready):
    spool = EventSpool(database)
    with spool.sender_run_lock():
        ready.set()
        time.sleep(30)


class DurableEventSenderTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "spool.sqlite"
        now = datetime(2030, 1, 1, tzinfo=timezone.utc)
        private_key = Ed25519PrivateKey.generate()
        bundle = trust_bundle_from_public_keys({
            "test-key": (
                private_key.public_key(),
                now - timedelta(days=1),
                now + timedelta(days=1),
                False,
            )
        })
        self.verifier = CommittedReceiptVerifier(bundle)
        self.spool = EventSpool(self.path, receipt_verifier=self.verifier)
        source = valid_event()
        self.event, _ = self.spool.enqueue(
            source["machine_id"],
            source["observed_at"],
            source["payload"],
            "sender-test-event",
        )
        self.now = now
        self.tls_context = ssl.create_default_context()

    def _sender(self, **kwargs):
        options = {
            "port": 12345,
            "tls_context": self.tls_context,
            "receipt_verifier": self.verifier,
            "wall_clock": lambda: self.now,
            "monotonic_clock": lambda: self.now.timestamp(),
            "random_value": lambda: 0.5,
        }
        options.update(kwargs)
        return DurableEventSender(self.spool, **options)

    def test_retry_state_and_eligibility_survive_spool_reopen(self):
        self.spool.schedule_retry(
            self.event["event_id"],
            delay_seconds=10,
            now=self.now,
            error="temporary offline",
        )
        reopened = EventSpool(self.path, receipt_verifier=self.verifier)
        self.assertEqual(reopened.pending(), [self.event])
        self.assertEqual(reopened.due_pending(now=self.now), [])
        self.assertEqual(
            reopened.due_pending(now=self.now + timedelta(seconds=10))[0]["attempt_count"],
            1,
        )

    def test_retry_after_is_capped_and_invalid_receipt_keeps_event_pending(self):
        sender = self._sender(base_backoff_seconds=2, max_backoff_seconds=10, jitter_fraction=0)
        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=TransportError("HTTP 429", status=429, retry_after="9999"),
        ):
            result = sender.run_once()
        self.assertEqual((result.attempted, result.delivered, result.deferred), (1, 0, 1))
        self.assertEqual(self.spool.due_pending(now=self.now + timedelta(seconds=299)), [])
        due = self.spool.due_pending(now=self.now + timedelta(seconds=300))
        self.assertEqual(due[0]["attempt_count"], 1)

        self.now += timedelta(seconds=300)
        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=TransportError("server returned an invalid committed receipt"),
        ):
            result = sender.run_once()
        self.assertEqual(result.deferred, 1)
        self.assertEqual(self.spool.pending(), [self.event])
        self.assertEqual(
            self.spool.due_pending(now=self.now + timedelta(seconds=3)),
            [],
        )
        self.assertEqual(
            self.spool.due_pending(now=self.now + timedelta(seconds=4))[0]["attempt_count"],
            2,
        )

    def test_sender_processes_only_bounded_batches_and_spool_capacity_is_preserved(self):
        source = valid_event()
        with self.assertRaises(SpoolFull):
            EventSpool(
                self.path,
                max_pending_events=1,
                receipt_verifier=self.verifier,
            ).enqueue(
                source["machine_id"],
                source["observed_at"],
                source["payload"],
                "overflow",
            )
        with self.assertRaises(ValueError):
            self._sender(batch_size=101)
        sender = self._sender(batch_size=1)
        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=OSError("offline"),
        ) as send:
            result = sender.run_once()
        self.assertEqual(send.call_count, 1)
        self.assertEqual(result.attempted, 1)
        self.assertEqual(result.deferred, 1)
        self.assertEqual(len(self.spool.pending()), 1)

    def test_zero_past_and_malformed_retry_after_never_cause_immediate_retries(self):
        retry_after_values = (
            "0",
            format_datetime(self.now - timedelta(minutes=1), usegmt=True),
            "not-a-date-or-delay",
        )
        for index, retry_after in enumerate(retry_after_values):
            with self.subTest(retry_after=retry_after):
                if index:
                    self.now += timedelta(seconds=2)
                sender = self._sender(
                    base_backoff_seconds=2,
                    max_backoff_seconds=2,
                    jitter_fraction=0,
                )
                with patch(
                    "genesis_monitor.sender._send_spooled_event_owned",
                    side_effect=TransportError(
                        "HTTP 429",
                        status=429,
                        retry_after=retry_after,
                    ),
                ) as send:
                    first = sender.run_once()
                    self.assertEqual(first.deferred, 1)
                    immediate = sender.run_once()
                    self.assertEqual(immediate.attempted, 0)
                    self.assertEqual(send.call_count, 1)
                    self.now += timedelta(seconds=2)
                    eligible = sender.run_once()
                self.assertEqual(eligible.deferred, 1)
                self.assertEqual(send.call_count, 2)

    def test_slow_failed_attempt_schedules_backoff_from_failure_time(self):
        monotonic = [100.0]
        sender = self._sender(
            base_backoff_seconds=2,
            max_backoff_seconds=2,
            jitter_fraction=0,
            monotonic_clock=lambda: monotonic[0],
        )

        def slow_failure(*args, **kwargs):
            monotonic[0] += 5
            raise TimeoutError("synthetic slow timeout")

        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=slow_failure,
        ) as send:
            first = sender.run_once()
            self.assertEqual(first.deferred, 1)
            immediate = sender.run_once()

        self.assertEqual(immediate.attempted, 0)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(
            self.spool.due_pending(now=self.now + timedelta(seconds=6)),
            [],
        )
        self.assertEqual(
            self.spool.due_pending(now=self.now + timedelta(seconds=7))[0]["attempt_count"],
            1,
        )

    def test_http_date_retry_after_is_relative_to_failure_time(self):
        monotonic = [200.0]
        sender = self._sender(
            base_backoff_seconds=2,
            max_backoff_seconds=10,
            jitter_fraction=0,
            monotonic_clock=lambda: monotonic[0],
        )
        failure_time = self.now + timedelta(seconds=10)
        retry_after = format_datetime(failure_time + timedelta(seconds=10), usegmt=True)

        def delayed_429(*args, **kwargs):
            monotonic[0] += 10
            raise TransportError("HTTP 429", status=429, retry_after=retry_after)

        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=delayed_429,
        ) as send:
            first = sender.run_once()
            self.assertEqual(first.deferred, 1)
            monotonic[0] += 9
            before_date = sender.run_once()

        self.assertEqual(before_date.attempted, 0)
        self.assertEqual(send.call_count, 1)
        eligible_at = self.now + timedelta(seconds=20)
        self.assertEqual(self.spool.due_pending(now=eligible_at - timedelta(microseconds=1)), [])
        self.assertEqual(
            self.spool.due_pending(now=eligible_at)[0]["attempt_count"],
            1,
        )

    def test_competing_sender_runs_fail_safely_and_leave_event_pending(self):
        sender_one = self._sender()
        sender_two = self._sender()
        entered = threading.Event()
        release = threading.Event()
        first_errors = []

        def blocked_failure(*args, **kwargs):
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test did not release first sender")
            raise OSError("simulated temporary failure")

        def first_run():
            try:
                sender_one.run_once()
            except Exception as error:
                first_errors.append(error)

        with patch("genesis_monitor.sender._send_spooled_event_owned", side_effect=blocked_failure):
            thread = threading.Thread(target=first_run)
            thread.start()
            self.assertTrue(entered.wait(timeout=5))
            with self.assertRaisesRegex(SpoolError, "another sender run owns"):
                sender_two.run_once()
            release.set()
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(first_errors, [])
        self.assertEqual(self.spool.pending(), [self.event])
        with self.spool.sender_run_lock():
            pass

    def test_distinct_sender_on_same_thread_cannot_inherit_active_ownership(self):
        sender_one = self._sender()
        sender_two = self._sender()
        nested_errors = []
        attempts = []

        def nested_attempt(*args, **kwargs):
            attempts.append(1)
            try:
                sender_two.run_once()
            except Exception as error:
                nested_errors.append(error)
            raise OSError("outer send remains pending")

        with patch("genesis_monitor.sender._send_spooled_event_owned", side_effect=nested_attempt):
            result = sender_one.run_once()

        self.assertEqual(result.deferred, 1)
        self.assertEqual(attempts, [1])
        self.assertEqual(len(nested_errors), 1)
        self.assertIsInstance(nested_errors[0], SpoolError)
        self.assertIn("another sender run owns", str(nested_errors[0]))
        self.assertEqual(self.spool.pending(), [self.event])

    def test_interrupted_sender_run_releases_ownership(self):
        with self.assertRaisesRegex(RuntimeError, "interrupted"):
            with self.spool.sender_run_lock():
                raise RuntimeError("interrupted")
        with self.spool.sender_run_lock():
            pass
        self.assertEqual(self.spool.pending(), [self.event])

    def test_hard_link_aliases_share_sender_ownership(self):
        hard_link_path = Path(self.directory.name) / "spool-hardlink.sqlite"
        os.link(self.path, hard_link_path)
        hard_link_spool = EventSpool(hard_link_path, receipt_verifier=self.verifier)
        errors = []

        def attempt_alias_lock():
            try:
                with hard_link_spool.sender_run_lock():
                    pass
            except Exception as error:
                errors.append(error)

        with self.spool.sender_run_lock():
            thread = threading.Thread(target=attempt_alias_lock)
            thread.start()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], SpoolError)
        self.assertIn("another sender run owns", str(errors[0]))

    def test_symlink_aliases_share_sender_ownership(self):
        symlink_path = Path(self.directory.name) / "spool-symlink.sqlite"
        try:
            os.symlink(self.path, symlink_path)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"symlink creation unavailable on this Windows filesystem: {error}")
        symlink_spool = EventSpool(symlink_path, receipt_verifier=self.verifier)
        errors = []

        def attempt_symlink_lock():
            try:
                with symlink_spool.sender_run_lock():
                    pass
            except Exception as error:
                errors.append(error)

        with self.spool.sender_run_lock():
            thread = threading.Thread(target=attempt_symlink_lock)
            thread.start()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], SpoolError)
        self.assertIn("another sender run owns", str(errors[0]))

    def test_lock_initialization_failure_fails_closed_and_recovers(self):
        import genesis_monitor.spool as spool_module

        original_connect = spool_module.sqlite3.connect

        def fail_lock_connect(database, *args, **kwargs):
            if str(database).endswith(".sqlite"):
                raise sqlite3.OperationalError("simulated lock initialization failure")
            return original_connect(database, *args, **kwargs)

        with patch("genesis_monitor.spool.sqlite3.connect", side_effect=fail_lock_connect):
            with self.assertRaisesRegex(SpoolError, "ownership could not be acquired"):
                with self.spool.sender_run_lock():
                    pass
        with self.spool.sender_run_lock():
            pass
        self.assertEqual(self.spool.pending(), [self.event])

    def test_spool_path_replacement_during_sqlite_open_fails_closed(self):
        import genesis_monitor.spool as spool_module

        replacement_path = Path(self.directory.name) / "replacement.sqlite"
        replacement_connection = sqlite3.connect(replacement_path)
        replacement_connection.execute("CREATE TABLE replacement (value INTEGER)")
        replacement_connection.commit()
        replacement_connection.close()
        original_connect = spool_module.sqlite3.connect
        replaced = []

        def replace_before_open(database, *args, **kwargs):
            if str(database) == self.spool.path and not replaced:
                os.replace(replacement_path, self.spool.path)
                replaced.append(True)
            return original_connect(database, *args, **kwargs)

        with patch("genesis_monitor.spool.sqlite3.connect", side_effect=replace_before_open):
            with self.assertRaisesRegex(SpoolError, "changed identity while SQLite was opening"):
                self.spool._connect()
        self.assertEqual(replaced, [True])

    def test_process_crash_releases_sender_ownership_without_losing_pending_event(self):
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        process = context.Process(
            target=_hold_spool_sender_lock,
            args=(self.path, ready),
        )
        process.start()
        try:
            self.assertTrue(ready.wait(timeout=10), "child sender did not acquire ownership")
            with self.assertRaisesRegex(SpoolError, "another sender run owns"):
                with self.spool.sender_run_lock():
                    pass
        finally:
            process.terminate()
            process.join(timeout=10)

        self.assertFalse(process.is_alive())
        self.assertIsNotNone(process.exitcode)
        with self.spool.sender_run_lock():
            pass
        self.assertEqual(self.spool.pending(), [self.event])

    def test_sender_restart_observes_forward_and_backward_utc_clock_jumps(self):
        self.spool.schedule_retry(
            self.event["event_id"],
            delay_seconds=60,
            now=self.now,
            error="waiting",
        )
        forward_now = self.now + timedelta(days=1)
        forward_sender = self._sender(
            wall_clock=lambda: forward_now,
            monotonic_clock=lambda: forward_now.timestamp(),
        )
        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=TransportError("still offline"),
        ) as send:
            forward_result = forward_sender.run_once()
        self.assertEqual(forward_result.attempted, 1)
        self.assertEqual(send.call_count, 1)

        backward_now = self.now - timedelta(days=1)
        backward_sender = self._sender(
            wall_clock=lambda: backward_now,
            monotonic_clock=lambda: backward_now.timestamp(),
        )
        with patch("genesis_monitor.sender._send_spooled_event_owned") as send:
            backward_result = backward_sender.run_once()
        self.assertEqual(backward_result.attempted, 0)
        self.assertEqual(send.call_count, 0)
        self.assertEqual(self.spool.pending(), [self.event])


if __name__ == "__main__":
    unittest.main()
