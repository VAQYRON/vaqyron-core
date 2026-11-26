import tempfile
import unittest
from pathlib import Path

from genesis_monitor.dashboard import render_dashboard_html, write_dashboard_snapshot
from genesis_monitor.store import CentralStore
from tests.test_protocol import valid_event


class DashboardTests(unittest.TestCase):
    def test_static_dashboard_renders_multiple_machines_and_progress(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CentralStore(Path(directory) / "central.sqlite")
            for machine_id, display in (("dell-test", "Dell Synthetic"), ("acer-test", "Acer Synthetic")):
                store.register_machine(machine_id, display)
                event = valid_event()
                event["machine_id"] = machine_id
                event["event_id"] = f"{machine_id}:1"
                event["payload"]["log"]["workers"][0]["current_nonce"] = 124 if machine_id.startswith("dell") else 175
                event["payload"]["checkpoint"] = {
                    "status": "valid",
                    "observed_at": "2026-10-14T07:00:00Z",
                    "format_version": 2,
                    "configuration": {
                        "time": 1791363600, "start_nonce": 100, "end_nonce": 199,
                        "requested_worker_count": 1, "nbits": 0x1D00FFFF,
                        "block_version": 1, "pow_limit": "f" * 64,
                    },
                    "workers": [{
                        "worker_index": 0, "start_nonce": 100, "end_nonce": 199,
                        "last_completed_nonce": 123, "last_pow_digest_raw": "a" * 64,
                    }],
                    "found": None, "error": None,
                }
                store.ingest(
                    event, authenticated_machine_id=machine_id, received_at="2026-10-14T07:00:01Z"
                )
            snapshot = store.snapshot(now="2026-10-14T07:00:02Z")
            html = render_dashboard_html(snapshot)
            self.assertIn("Dell Synthetic", html)
            self.assertIn("Acer Synthetic", html)
            self.assertIn("shared_candidates_at_observation", html)
            self.assertIn("Durable checkpoint progress", html)
            self.assertIn("Last definitely completed nonce", html)
            self.assertIn("Local machine identity binding is not authentication", html)
            self.assertIn("accepted local ingestion, not authenticated remote-agent presence", html)
            self.assertIn("Local ingestion:", html)
            self.assertNotIn("Agent:", html)
            self.assertNotIn("<script src=", html)
            self.assertNotIn("http://", html)
            self.assertNotIn("https://", html)

    def test_dashboard_escapes_untrusted_machine_text_for_script_context(self):
        snapshot = {
            "generated_at": "2026-10-14T07:00:00Z",
            "machines": [{
                "machine_id": "</script><script>alert(1)</script>",
                "display_name": "</script><img src=x onerror=alert(1)>",
                "ingestion_status": "unknown", "last_local_ingestion_at": None,
                "local_ingestion_age_seconds": None, "search_status": "unknown",
                "telemetry_observed_at": None, "telemetry_age_seconds": None,
                "current_sequence": None, "current_event_id": None,
                "log": None, "checkpoint": None, "checkpoint_age_seconds": None,
                "checkpoint_age_status": "unknown",
            }],
        }
        html = render_dashboard_html(snapshot)
        self.assertNotIn("</script><img", html)
        self.assertIn("\\u003c/script\\u003e", html)
        self.assertIn("textContent", html)

    def test_dashboard_snapshot_writer_emits_utf8_static_file(self):
        snapshot = {"generated_at": "2026-10-14T07:00:00Z", "machines": []}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dashboard.html"
            write_dashboard_snapshot(snapshot, str(output))
            contents = output.read_text(encoding="utf-8")
        self.assertIn("<!doctype html>", contents)
        self.assertIn("No registered machines.", contents)
        self.assertNotIn("WebSocket", contents)

    def test_dashboard_distinguishes_unverified_claims_and_verified_local_alerts(self):
        snapshot = {
            "generated_at": "2026-10-14T07:00:10Z",
            "alerts": [{
                "alert_id": 1, "machine_id": "worker-1",
                "claim": {"nonce": 541696, "block_hash": "a" * 64, "pow_digest_raw": "b" * 64},
                "created_at": "2026-10-14T07:00:09Z",
            }],
            "machines": [{
                "machine_id": "worker-1", "display_name": "Synthetic worker",
                "ingestion_status": "recent", "last_local_ingestion_at": "2026-10-14T07:00:09Z",
                "local_ingestion_age_seconds": 1, "search_status": "found",
                "telemetry_observed_at": "2026-10-14T07:00:08Z", "telemetry_age_seconds": 2,
                "current_sequence": 2, "current_event_id": "worker-1:2",
                "log": {
                    "status": "available", "worker_ranges_status": "valid",
                    "aggregate_candidates": 10,
                    "aggregate_candidates_per_second": 1.0, "result": "FOUND",
                    "found_candidate": {
                        "nonce": 541696, "block_hash": "c" * 64,
                        "pow_digest_raw": "d" * 64, "timestamp": "2026-10-14T07:00:08Z",
                    },
                    "workers": [],
                },
                "checkpoint": {"status": "not_configured", "found": None, "workers": []},
                "checkpoint_age_seconds": None, "checkpoint_age_status": "not_configured",
                "found_verifications": [],
            }],
        }
        html = render_dashboard_html(snapshot)
        self.assertIn("Locally verified FOUND alerts", html)
        self.assertIn("VERIFIED — ", html)
        self.assertIn("UNVERIFIED WORKER CLAIM", html)

    def test_dashboard_warns_when_worker_ranges_are_not_trustworthy(self):
        snapshot = {
            "generated_at": "2026-10-14T07:00:10Z",
            "machines": [{
                "machine_id": "worker-1", "display_name": "Synthetic worker",
                "ingestion_status": "recent", "last_local_ingestion_at": "2026-10-14T07:00:09Z",
                "local_ingestion_age_seconds": 1, "search_status": "inconsistent",
                "telemetry_observed_at": "2026-10-14T07:00:08Z", "telemetry_age_seconds": 2,
                "current_sequence": 2, "current_event_id": "worker-1:2",
                "log": {
                    "status": "available", "worker_ranges_status": "inconsistent",
                    "workers": [{"worker_index": 0, "range_start": 100, "range_end": 199, "current_nonce": 125}],
                },
                "checkpoint": {"status": "not_configured", "found": None, "workers": []},
                "checkpoint_age_seconds": None, "checkpoint_age_status": "not_configured",
                "found_verifications": [],
            }],
        }
        html = render_dashboard_html(snapshot)
        self.assertIn('"worker_ranges_status": "inconsistent"', html)
        self.assertIn('"Worker ranges: "+fmt(machine.log.worker_ranges_status)', html)
        self.assertIn("observed worker progress is not trusted", html)


if __name__ == "__main__":
    unittest.main()
