import codecs
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from genesis_monitor.collector import CollectorError, LogCollector, parse_complete_log_text
from genesis_monitor.protocol import validate_event


FIXTURE = """GENESIS MESSAGE: VAQYRON - Independent Proof-of-Work Network - 2026
nTime: 1791363600
SEARCH START NONCE: 500
SEARCH END NONCE: 507
SEARCH WORKERS: 4
WORKER RANGE 0: 500..501
WORKER RANGE 1: 502..503
WORKER RANGE 2: 504..505
WORKER RANGE 3: 506..507
2026-10-14T07:00:00Z Progress: worker=0 range=500..501 nonce=501 candidates=25 elapsed_seconds=1.0 candidates_per_second=25.0
Progress: worker=1 range=502..503 nonce=503 candidates=26 elapsed_seconds=1.1 candidates_per_second=23.6
"""


class CollectorTests(unittest.TestCase):
    def test_parses_ranges_and_progress_without_per_worker_counts(self):
        log = parse_complete_log_text(FIXTURE)
        self.assertEqual(log["search_time"], 1791363600)
        self.assertEqual((log["range_start"], log["range_end"]), (500, 507))
        self.assertEqual(log["worker_count"], 4)
        self.assertEqual(log["aggregate_candidates"], 26)
        self.assertEqual(len(log["workers"]), 4)
        self.assertEqual(log["workers"][0]["current_nonce"], 501)
        self.assertEqual(log["workers"][0]["shared_candidates_at_observation"], 25)
        self.assertEqual(log["workers"][1]["shared_candidates_at_observation"], 26)
        self.assertNotIn("per_worker_candidates", log["workers"][0])
        self.assertEqual(log["workers"][0]["progress_timestamp"], "2026-10-14T07:00:00.000000Z")

    def test_utf16_le_and_be_logs_are_supported(self):
        for encoding in ("utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "search.log"
                bom = codecs.BOM_UTF16_LE if encoding.endswith("le") else codecs.BOM_UTF16_BE
                path.write_bytes(bom + FIXTURE.encode(encoding))
                log = LogCollector().collect(path)["log"]
                self.assertEqual(log["aggregate_candidates"], 26)
                self.assertEqual(log["workers"][0]["current_nonce"], 501)

    def test_utf8_bom_and_collected_payload_match_protocol_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "search.log"
            path.write_bytes(codecs.BOM_UTF8 + FIXTURE.encode("utf-8"))
            payload = LogCollector().collect(path)
            event = {
                "protocol_version": 1,
                "event_id": "fixture:1",
                "sequence": 1,
                "machine_id": "fixture",
                "observed_at": "2026-10-14T07:00:00Z",
                "payload": payload,
            }
            self.assertEqual(validate_event(event), event)

    def test_utf8_partial_line_is_retained_then_completed_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "search.log"
            collector = LogCollector()
            raw = FIXTURE.encode("utf-8")
            split = raw.rfind(b"candidates=26") + 10
            path.write_bytes(raw[:split])
            first = collector.collect(path)["log"]
            self.assertEqual(first["aggregate_candidates"], 25)
            with path.open("ab") as stream:
                stream.write(raw[split:])
            second = collector.collect(path)["log"]
            self.assertEqual(second["aggregate_candidates"], 26)
            third = collector.collect(path)["log"]
            self.assertEqual(third["aggregate_candidates"], 26)
            self.assertEqual(len(third["workers"]), 4)

    def test_truncation_and_rotation_reset_log_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "search.log"
            collector = LogCollector()
            path.write_text(FIXTURE, encoding="utf-8")
            self.assertEqual(collector.collect(path)["log"]["aggregate_candidates"], 26)
            path.write_text("SEARCH START NONCE: 900\n", encoding="utf-8")
            reset = collector.collect(path)["log"]
            self.assertIsNone(reset["aggregate_candidates"])
            self.assertEqual(reset["range_start"], 900)
            replacement = Path(directory) / "replacement.log"
            replacement.write_text("SEARCH START NONCE: 1000\n", encoding="utf-8")
            replacement.replace(path)
            rotated = collector.collect(path)["log"]
            self.assertEqual(rotated["range_start"], 1000)
            self.assertEqual(rotated["workers"], [])

    def test_malformed_lines_are_counted_and_out_of_range_progress_ignored(self):
        text = FIXTURE + (
            "Progress: worker=0 range=500..501 nonce=600 candidates=27 "
            "elapsed_seconds=1.2 candidates_per_second=22.5\n"
            "Progress: malformed\n"
        )
        log = parse_complete_log_text(text)
        self.assertEqual(log["workers"][0]["current_nonce"], 501)
        self.assertGreaterEqual(log["parse_errors"], 2)

    def test_worker_range_gaps_and_overlaps_are_explicitly_inconsistent(self):
        variants = {
            "gap": FIXTURE.replace("WORKER RANGE 1: 502..503", "WORKER RANGE 1: 503..503"),
            "overlap": FIXTURE.replace("WORKER RANGE 1: 502..503", "WORKER RANGE 1: 501..503"),
            "out-of-range": FIXTURE.replace("WORKER RANGE 3: 506..507", "WORKER RANGE 3: 506..508"),
        }
        for name, text in variants.items():
            with self.subTest(partition=name):
                log = parse_complete_log_text(text)
                self.assertEqual(log["worker_ranges_status"], "inconsistent")

    def test_partial_worker_range_observation_is_not_trusted(self):
        log = parse_complete_log_text(
            FIXTURE.replace("WORKER RANGE 3: 506..507\n", "")
        )
        self.assertEqual(log["worker_ranges_status"], "incomplete")

    def test_checkpoint_is_separate_from_log_and_corruption_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "search.log"
            checkpoint = Path(directory) / "search.chk"
            path.write_text(FIXTURE, encoding="utf-8")
            checkpoint.write_bytes(b"x" * 100)
            result = LogCollector().collect(
                path, checkpoint, observed_at=datetime(2026, 10, 14, tzinfo=timezone.utc)
            )
            self.assertEqual(result["log"]["aggregate_candidates"], 26)
            self.assertEqual(result["checkpoint"]["status"], "invalid")
            self.assertIn("integrity", result["checkpoint"]["error"])
            self.assertEqual(result["checkpoint"]["workers"], [])

    def test_missing_log_is_not_silently_reported_as_empty(self):
        with self.assertRaises(CollectorError):
            LogCollector().collect("missing-do-not-create.log")


if __name__ == "__main__":
    unittest.main()
