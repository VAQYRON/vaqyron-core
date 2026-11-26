import io
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from genesis_monitor.store import CentralStore
from genesis_monitor.verification import (
    FoundVerifier,
    MAX_STDOUT_BYTES,
    SUPPORTED_CONSENSUS,
    VerificationError,
    _run_bounded_process,
)
from tests.test_protocol import valid_event


NOW = "2026-10-14T07:00:10Z"
NONCE = 541696
BLOCK_HASH = "a" * 64
POW_DIGEST = "b" * 64


def search_configuration():
    return {
        "time": SUPPORTED_CONSENSUS["time"],
        "start_nonce": NONCE,
        "end_nonce": NONCE + 4,
        "requested_worker_count": 1,
        "nbits": SUPPORTED_CONSENSUS["nbits"],
        "block_version": SUPPORTED_CONSENSUS["block_version"],
        "pow_limit": SUPPORTED_CONSENSUS["pow_limit"],
    }


def found_event(sequence=1, *, timestamp="2026-10-14T07:00:00Z"):
    event = valid_event()
    event["sequence"] = sequence
    event["event_id"] = f"laptop-1:{sequence}"
    event["observed_at"] = timestamp
    log = event["payload"]["log"]
    log.update({
        "search_time": SUPPORTED_CONSENSUS["time"],
        "range_start": NONCE,
        "range_end": NONCE + 4,
        "worker_count": 1,
        "result": "FOUND",
        "found_candidate": {
            "nonce": NONCE,
            "block_hash": BLOCK_HASH,
            "pow_digest_raw": POW_DIGEST,
            "timestamp": timestamp,
        },
    })
    log["workers"][0].update({
        "range_start": NONCE,
        "range_end": NONCE + 4,
        "current_nonce": NONCE,
    })
    event["payload"]["checkpoint"] = {
        "status": "not_configured",
        "observed_at": None,
        "format_version": None,
        "configuration": None,
        "workers": [],
        "found": None,
        "error": None,
    }
    return event


def verifier_output(**overrides):
    result = {
        "nonce": NONCE,
        "time": SUPPORTED_CONSENSUS["time"],
        "version": SUPPORTED_CONSENSUS["block_version"],
        "bits": f'{SUPPORTED_CONSENSUS["nbits"]:08x}',
        "block_id": BLOCK_HASH,
        "pow_digest_raw": POW_DIGEST,
        "candidate_valid": True,
        "pow_valid": True,
        "target_valid": True,
        "result": "PASS",
    }
    result.update(overrides)
    return result


class FoundVerificationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.store = CentralStore(Path(self.tempdir.name) / "central.sqlite")
        self.store.register_machine(
            "laptop-1", "Synthetic worker", search_configuration=search_configuration()
        )
        self.store.ingest(
            found_event(), authenticated_machine_id="laptop-1", received_at=NOW
        )
        self.verifier = FoundVerifier(
            self.store,
            verifier_script=Path(self.tempdir.name) / "synthetic-verifier.py",
            yespower_cli=Path(self.tempdir.name) / "synthetic-helper.exe",
        )
        Path(self.verifier.verifier_script).touch()
        Path(self.verifier.yespower_cli).touch()

    @staticmethod
    def completed(result, code=0, stderr=""):
        return SimpleNamespace(
            returncode=code,
            stdout=json.dumps(result).encode("utf-8"),
            stderr=stderr.encode("utf-8"),
        )

    def test_synthetic_positive_claim_is_verified_and_alert_persisted(self):
        with patch(
            "genesis_monitor.verification._run_bounded_process",
            return_value=self.completed(verifier_output()),
        ) as run:
            records = self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
        self.assertEqual(records[0]["status"], "VERIFIED")
        self.assertEqual(len(self.store.local_alerts()), 1)
        args, kwargs = run.call_args
        self.assertIn("--nonce", args[0])
        self.assertIn(str(NONCE), args[0])
        self.assertIn("--yespower-cli", args[0])
        self.assertEqual(kwargs["timeout_seconds"], 15.0)

    def test_checkpoint_found_claim_uses_registered_worker_partition(self):
        event = found_event(sequence=2)
        event["payload"]["log"]["result"] = None
        event["payload"]["log"]["found_candidate"] = None
        configuration = search_configuration()
        event["payload"]["checkpoint"] = {
            "status": "valid",
            "observed_at": NOW,
            "format_version": 2,
            "configuration": configuration,
            "workers": [{
                "worker_index": 0,
                "start_nonce": NONCE,
                "end_nonce": NONCE + 4,
                "last_completed_nonce": NONCE,
                "last_pow_digest_raw": POW_DIGEST,
            }],
            "found": {
                "nonce": NONCE,
                "header_hash": BLOCK_HASH,
                "pow_digest_raw": POW_DIGEST,
                "independent_verification_status": "not_performed",
            },
            "error": None,
        }
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=NOW)
        with patch(
            "genesis_monitor.verification._run_bounded_process",
            return_value=self.completed(verifier_output()),
        ):
            records = self.verifier.verify_event("laptop-1", "laptop-1:2", now=NOW)
        self.assertEqual(records[0]["source"], "checkpoint")
        self.assertEqual(records[0]["status"], "VERIFIED")

    def test_synthetic_negative_result_is_rejected_without_alert(self):
        negative = verifier_output(
            block_id="c" * 64,
            candidate_valid=False,
            pow_valid=False,
            result="NOT_A_VALID_CANDIDATE",
        )
        with patch(
            "genesis_monitor.verification._run_bounded_process",
            return_value=self.completed(negative, code=1),
        ):
            records = self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
        self.assertEqual(records[0]["status"], "REJECTED")
        self.assertEqual(self.store.local_alerts(), [])

    def test_malformed_found_claim_is_recorded_rejected_before_subprocess(self):
        event = found_event(sequence=2)
        event["payload"]["log"]["found_candidate"] = None
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=NOW)
        with patch("genesis_monitor.verification._run_bounded_process") as run:
            records = self.verifier.verify_event("laptop-1", "laptop-1:2", now=NOW)
        self.assertEqual(records[0]["status"], "REJECTED")
        self.assertIn("malformed", records[0]["detail"])
        run.assert_not_called()

    def test_duplicate_claim_from_later_event_does_not_duplicate_alert_or_run(self):
        with patch(
            "genesis_monitor.verification._run_bounded_process",
            return_value=self.completed(verifier_output()),
        ) as run:
            first = self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
            duplicate_event = found_event(sequence=2, timestamp="2026-10-14T07:00:05Z")
            self.store.ingest(duplicate_event, authenticated_machine_id="laptop-1", received_at=NOW)
            second = self.verifier.verify_event("laptop-1", "laptop-1:2", now=NOW)
        self.assertEqual(first[0]["verification_id"], second[0]["verification_id"])
        self.assertEqual(second[0]["status"], "VERIFIED")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(self.store.local_alerts()), 1)

    def test_timeout_is_durably_recorded_as_error(self):
        timeout = subprocess.TimeoutExpired(["synthetic"], 15)
        def timeout_after_pending(*args, **kwargs):
            self.assertEqual(self.store.verification_records()[0]["status"], "PENDING")
            raise timeout

        with patch("genesis_monitor.verification._run_bounded_process", side_effect=timeout_after_pending):
            records = self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
        self.assertEqual(records[0]["status"], "ERROR")
        self.assertIn("timed out", records[0]["detail"])
        reopened = CentralStore(Path(self.tempdir.name) / "central.sqlite")
        self.assertEqual(reopened.verification_records()[0]["status"], "ERROR")

    def test_crashed_pending_verification_recovers_after_lease_with_bounded_attempts(self):
        crash = SystemExit("synthetic crash after durable attempt claim")
        with patch.object(self.verifier, "_run_verifier", side_effect=crash) as run:
            with self.assertRaises(SystemExit):
                self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
            pending = self.store.verification_records()[0]
            self.assertEqual(pending["status"], "PENDING")
            self.assertEqual(pending["attempt_count"], 1)
            immediate = self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
            self.assertEqual(immediate[0]["status"], "PENDING")
            self.assertFalse(immediate[0]["attempt_claimed"])
            self.assertEqual(run.call_count, 1)

        later = (
            datetime.fromisoformat(NOW.replace("Z", "+00:00")) + timedelta(seconds=46)
        ).isoformat().replace("+00:00", "Z")
        with patch.object(self.verifier, "_run_verifier", side_effect=crash) as run:
            with self.assertRaises(SystemExit):
                self.verifier.verify_event("laptop-1", "laptop-1:1", now=later)
        self.assertEqual(self.store.verification_records()[0]["attempt_count"], 2)

        last_retry = (
            datetime.fromisoformat(later.replace("Z", "+00:00")) + timedelta(seconds=46)
        ).isoformat().replace("+00:00", "Z")
        with patch.object(self.verifier, "_run_verifier", side_effect=crash) as run:
            with self.assertRaises(SystemExit):
                self.verifier.verify_event("laptop-1", "laptop-1:1", now=last_retry)
        self.assertEqual(self.store.verification_records()[0]["attempt_count"], 3)

        after_limit = (
            datetime.fromisoformat(last_retry.replace("Z", "+00:00")) + timedelta(seconds=46)
        ).isoformat().replace("+00:00", "Z")
        exhausted = self.verifier.verify_event("laptop-1", "laptop-1:1", now=after_limit)
        self.assertEqual(exhausted[0]["status"], "ERROR")
        self.assertEqual(exhausted[0]["attempt_count"], 3)
        self.assertIn("retry limit exhausted", exhausted[0]["detail"])
        self.assertEqual(self.store.local_alerts(), [])

    def test_crash_left_pending_record_can_retry_to_verified_once(self):
        crash = SystemExit("synthetic crash after durable attempt claim")
        completed = (verifier_output(), 0)
        later = (
            datetime.fromisoformat(NOW.replace("Z", "+00:00")) + timedelta(seconds=46)
        ).isoformat().replace("+00:00", "Z")
        with patch.object(self.verifier, "_run_verifier", side_effect=[crash, completed]):
            with self.assertRaises(SystemExit):
                self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
            recovered = self.verifier.verify_event("laptop-1", "laptop-1:1", now=later)
        self.assertEqual(recovered[0]["status"], "VERIFIED")
        self.assertEqual(recovered[0]["attempt_count"], 2)
        self.assertEqual(len(self.store.local_alerts()), 1)

    def test_verifier_error_exit_is_durably_recorded_as_error(self):
        with patch(
            "genesis_monitor.verification._run_bounded_process",
            return_value=SimpleNamespace(
                returncode=2, stdout=b"", stderr=b"synthetic helper failure"
            ),
        ):
            records = self.verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
        self.assertEqual(records[0]["status"], "ERROR")
        self.assertIn("synthetic helper failure", records[0]["detail"])
        self.assertEqual(self.store.local_alerts(), [])

    def test_registered_configuration_mismatch_rejected_before_subprocess(self):
        wrong = search_configuration()
        wrong["time"] += 1
        store = CentralStore(Path(self.tempdir.name) / "mismatch.sqlite")
        store.register_machine("laptop-1", "Synthetic worker", search_configuration=wrong)
        event = found_event()
        event["payload"]["log"]["search_time"] = wrong["time"]
        store.ingest(event, authenticated_machine_id="laptop-1", received_at=NOW)
        verifier = FoundVerifier(store, verifier_script=self.verifier.verifier_script, yespower_cli=self.verifier.yespower_cli)
        with patch("genesis_monitor.verification._run_bounded_process") as run:
            records = verifier.verify_event("laptop-1", "laptop-1:1", now=NOW)
        self.assertEqual(records[0]["status"], "REJECTED")
        self.assertIn("incompatible", records[0]["detail"])
        run.assert_not_called()

    def test_candidate_outside_registered_range_rejected(self):
        event = found_event(sequence=2)
        event["payload"]["log"]["found_candidate"]["nonce"] = NONCE + 10
        event["payload"]["log"]["workers"][0]["current_nonce"] = NONCE + 4
        self.store.ingest(event, authenticated_machine_id="laptop-1", received_at=NOW)
        with patch("genesis_monitor.verification._run_bounded_process") as run:
            records = self.verifier.verify_event("laptop-1", "laptop-1:2", now=NOW)
        self.assertEqual(records[0]["status"], "REJECTED")
        self.assertIn("outside the registered search range", records[0]["detail"])
        run.assert_not_called()

    def test_bounded_runner_uses_argument_array_and_caps_captured_output(self):
        class SyntheticProcess:
            def __init__(self, stdout):
                self.stdout = io.BytesIO(stdout)
                self.stderr = io.BytesIO(b"synthetic stderr")

            def wait(self, timeout=None):
                self.timeout = timeout
                return 0

        process = SyntheticProcess(b"synthetic output")
        command = ["python", "verifier.py", "--nonce", str(NONCE)]
        with (
            patch("genesis_monitor.verification._platform_is_windows", return_value=False),
            patch("genesis_monitor.verification.subprocess.Popen", return_value=process) as popen,
        ):
            result = _run_bounded_process(command, timeout_seconds=2)
        self.assertEqual(result.stdout, b"synthetic output")
        self.assertEqual(result.stderr, b"synthetic stderr")
        self.assertEqual(process.timeout, 2)
        self.assertEqual(popen.call_args.args[0], command)
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertIs(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)

        oversized_process = SyntheticProcess(b"x" * (MAX_STDOUT_BYTES + 1))
        with patch(
            "genesis_monitor.verification._platform_is_windows", return_value=False
        ), patch(
            "genesis_monitor.verification.subprocess.Popen", return_value=oversized_process
        ):
            with self.assertRaises(VerificationError):
                _run_bounded_process(command, timeout_seconds=2)

        class TimeoutProcess(SyntheticProcess):
            def __init__(self):
                super().__init__(b"")
                self.wait_calls = 0
                self.killed = False

            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired(command, timeout)
                return -9

            def kill(self):
                self.killed = True

        timeout_process = TimeoutProcess()
        with patch(
            "genesis_monitor.verification._platform_is_windows", return_value=False
        ), patch(
            "genesis_monitor.verification.subprocess.Popen", return_value=timeout_process
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                _run_bounded_process(command, timeout_seconds=2)
        self.assertTrue(timeout_process.killed)

    def test_windows_timeout_terminates_and_closes_verifier_job_tree(self):
        class FakeJob:
            def __init__(self):
                self.terminated = False
                self.closed = False

            def terminate(self):
                self.terminated = True

            def close(self):
                self.closed = True

        class WindowsTimeoutProcess:
            def __init__(self):
                self.stdout = io.BytesIO(b"")
                self.stderr = io.BytesIO(b"")
                self.wait_count = 0

            def wait(self, timeout=None):
                self.wait_count += 1
                if self.wait_count == 1:
                    raise subprocess.TimeoutExpired(["synthetic-verifier"], timeout)
                return -9

        process = WindowsTimeoutProcess()
        job = FakeJob()
        with (
            patch("genesis_monitor.verification._platform_is_windows", return_value=True),
            patch("genesis_monitor.verification._attach_windows_job", return_value=job),
            patch("genesis_monitor.verification._resume_windows_process") as resume,
            patch("genesis_monitor.verification.subprocess.Popen", return_value=process) as popen,
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                _run_bounded_process(["python", "verifier.py"], timeout_seconds=1)
        self.assertTrue(job.terminated)
        self.assertTrue(job.closed)
        self.assertEqual(popen.call_args.kwargs["shell"], False)
        self.assertGreaterEqual(process.wait_count, 2)
        resume.assert_called_once_with(process, job)

    def test_windows_wait_error_terminates_and_closes_verifier_job_tree(self):
        class FakeJob:
            def __init__(self):
                self.terminated = False
                self.closed = False

            def terminate(self):
                self.terminated = True

            def close(self):
                self.closed = True

        class WindowsErrorProcess:
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")

            def __init__(self):
                self.wait_count = 0

            def wait(self, timeout=None):
                self.wait_count += 1
                if self.wait_count == 1:
                    raise OSError("synthetic wait failure")
                return -1

        process = WindowsErrorProcess()
        job = FakeJob()
        with (
            patch("genesis_monitor.verification._platform_is_windows", return_value=True),
            patch("genesis_monitor.verification._attach_windows_job", return_value=job),
            patch("genesis_monitor.verification._resume_windows_process"),
            patch("genesis_monitor.verification.subprocess.Popen", return_value=process),
        ):
            with self.assertRaises(OSError):
                _run_bounded_process(["python", "verifier.py"], timeout_seconds=1)
        self.assertTrue(job.terminated)
        self.assertTrue(job.closed)


if __name__ == "__main__":
    unittest.main()
