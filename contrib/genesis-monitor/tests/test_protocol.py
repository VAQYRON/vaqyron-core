import copy
import json
import unittest

from genesis_monitor.protocol import ProtocolError, canonical_json, parse_event, validate_event


def valid_event():
    return {
        "protocol_version": 1,
        "event_id": "laptop-1:1",
        "sequence": 1,
        "machine_id": "laptop-1",
        "observed_at": "2026-10-14T07:00:00Z",
        "payload": {
            "log": {
                "status": "available",
                "worker_ranges_status": "valid",
                "source_mtime": "2026-10-14T07:00:00Z",
                "search_time": 1791363600,
                "range_start": 100,
                "range_end": 199,
                "worker_count": 1,
                "aggregate_candidates": 25,
                "aggregate_candidates_per_second": 12.5,
                "result": None,
                "found_candidate": None,
                "workers": [{
                    "worker_index": 0,
                    "range_start": 100,
                    "range_end": 199,
                    "current_nonce": 124,
                    "shared_candidates_at_observation": 25,
                    "aggregate_candidates_per_second": 12.5,
                    "progress_timestamp": None,
                }],
                "parse_errors": 0,
            },
            "checkpoint": {
                "status": "not_configured",
                "observed_at": None,
                "format_version": None,
                "configuration": None,
                "workers": [],
                "found": None,
                "error": None,
            },
        },
    }


class ProtocolTests(unittest.TestCase):
    def test_valid_event_round_trips_canonically(self):
        event = valid_event()
        encoded = canonical_json(event)
        self.assertEqual(parse_event(encoded), event)
        self.assertEqual(validate_event(event), event)

    def test_unknown_or_missing_fields_are_rejected(self):
        for mutation in ("missing", "extra"):
            with self.subTest(mutation=mutation):
                event = valid_event()
                if mutation == "missing":
                    del event["payload"]["log"]["workers"][0]["current_nonce"]
                else:
                    event["unexpected"] = True
                with self.assertRaises(ProtocolError):
                    validate_event(event)

    def test_invalid_sequence_timestamp_nonce_and_nonfinite_speed_rejected(self):
        mutations = [
            lambda e: e.update(sequence=True),
            lambda e: e.update(observed_at="2026-10-14T07:00:00"),
            lambda e: e["payload"]["log"]["workers"][0].update(current_nonce=200),
            lambda e: e["payload"]["log"]["workers"][0].update(range_start=101),
            lambda e: e["payload"]["log"].update(aggregate_candidates_per_second=float("nan")),
        ]
        for mutate in mutations:
            event = valid_event()
            mutate(event)
            with self.assertRaises(ProtocolError):
                validate_event(event)

    def test_worker_ranges_marked_valid_must_partition_the_search_range(self):
        event = valid_event()
        event["payload"]["log"]["workers"][0]["range_start"] = 101
        with self.assertRaises(ProtocolError):
            validate_event(event)
        event = valid_event()
        event["payload"]["log"]["worker_ranges_status"] = "inconsistent"
        event["payload"]["log"]["workers"][0]["range_start"] = 101
        self.assertEqual(validate_event(event)["payload"]["log"]["worker_ranges_status"], "inconsistent")

    def test_legacy_v1_log_without_partition_status_is_untrusted(self):
        event = valid_event()
        del event["payload"]["log"]["worker_ranges_status"]

        validated = validate_event(event)
        restored = parse_event(json.dumps(event))

        self.assertEqual(validated["payload"]["log"]["worker_ranges_status"], "incomplete")
        self.assertEqual(validated["payload"]["log"]["workers"][0]["current_nonce"], 124)
        self.assertEqual(restored["payload"]["log"]["worker_ranges_status"], "incomplete")

    def test_shared_candidate_count_is_not_worker_count(self):
        event = valid_event()
        worker = event["payload"]["log"]["workers"][0]
        self.assertEqual(worker["shared_candidates_at_observation"], 25)
        self.assertNotIn("candidates_checked", worker)
        with self.assertRaises(ProtocolError):
            worker["per_worker_candidates"] = 25
            validate_event(event)

    def test_json_duplicate_keys_and_unsupported_version_rejected(self):
        with self.assertRaises(ProtocolError):
            parse_event('{"protocol_version":1,"protocol_version":1}')
        event = valid_event()
        event["protocol_version"] = 2
        with self.assertRaises(ProtocolError):
            validate_event(event)

    def test_unhashable_enum_and_partial_range_values_are_rejected_cleanly(self):
        event = valid_event()
        event["payload"]["log"]["status"] = []
        with self.assertRaises(ProtocolError):
            validate_event(event)
        event = valid_event()
        event["payload"]["log"]["workers"][0]["range_end"] = None
        with self.assertRaises(ProtocolError):
            validate_event(event)

    def test_event_size_is_bounded(self):
        with self.assertRaises(ProtocolError):
            parse_event(b" " * (64 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
