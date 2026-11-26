import hashlib
import struct
import unittest

from genesis_monitor.checkpoint import CheckpointError, parse_checkpoint_bytes


def checkpoint_fixture(*, version=2, corrupt=False, trailing=b"", found=False):
    start, end, requested_workers = 100, 107, 4
    pow_limit = bytes.fromhex("ff" * 32)
    payload = bytearray()
    payload.extend(struct.pack("<8I", 0x56514743, version, 1, 1791363600, start, end, requested_workers, 0x1D00FFFF))
    payload.extend(struct.pack("<i", 1))
    payload.extend(pow_limit)
    payload.extend(struct.pack("<BI", int(found), 103 if found else 0))
    payload.extend(bytes.fromhex("11" * 32 if found else "00" * 32))
    payload.extend(bytes.fromhex("22" * 32 if found else "00" * 32))
    payload.extend(b"\x04")
    for index in range(4):
        worker_start = start + index * 2
        worker_end = worker_start + 1
        payload.extend(struct.pack("<3IBI", index, worker_start, worker_end, 1, worker_end))
        payload.extend(bytes.fromhex(f"{index + 1:02x}" * 32))
    data = bytes(payload) + hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if corrupt:
        data = data[:-1] + bytes((data[-1] ^ 1,))
    return data + trailing


class CheckpointTests(unittest.TestCase):
    def test_valid_v2_checkpoint_preserves_four_worker_ranges(self):
        parsed = parse_checkpoint_bytes(checkpoint_fixture())
        self.assertEqual(parsed["format_version"], 2)
        self.assertTrue(parsed["checksum_valid"])
        self.assertEqual(
            [(worker["start_nonce"], worker["end_nonce"], worker["last_completed_nonce"])
             for worker in parsed["workers"]],
            [(100, 101, 101), (102, 103, 103), (104, 105, 105), (106, 107, 107)],
        )
        self.assertIsNone(parsed["found"])

    def test_valid_found_state_is_marked_unverified(self):
        parsed = parse_checkpoint_bytes(checkpoint_fixture(found=True))
        self.assertEqual(parsed["found"]["nonce"], 103)
        self.assertEqual(parsed["found"]["independent_verification_status"], "not_performed")

    def test_corruption_truncation_and_trailing_data_rejected(self):
        cases = [
            checkpoint_fixture(corrupt=True),
            checkpoint_fixture()[:20],
            checkpoint_fixture(trailing=b"x"),
        ]
        for data in cases:
            with self.subTest(size=len(data)), self.assertRaises(CheckpointError):
                parse_checkpoint_bytes(data)

    def test_unsupported_version_rejected_after_valid_checksum(self):
        with self.assertRaisesRegex(CheckpointError, "unsupported checkpoint version"):
            parse_checkpoint_bytes(checkpoint_fixture(version=3))

    def test_worker_gap_and_out_of_range_progress_rejected(self):
        data = bytearray(checkpoint_fixture())
        # First worker end nonce is at payload offset 32 + 32 + 1 + 4 + 64 + 1 + 8.
        first_worker_end_offset = 32 + 4 + 32 + 1 + 4 + 64 + 1 + 4 + 4
        data[first_worker_end_offset:first_worker_end_offset + 4] = struct.pack("<I", 102)
        payload = bytes(data[:-32])
        data = bytearray(payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest())
        with self.assertRaisesRegex(CheckpointError, "worker ranges"):
            parse_checkpoint_bytes(bytes(data))

        data = bytearray(checkpoint_fixture())
        # First record's last-completed nonce follows index/start/end/flag.
        completed_offset = 32 + 4 + 32 + 1 + 4 + 64 + 1 + 1 + 12
        data[completed_offset:completed_offset + 4] = struct.pack("<I", 999)
        payload = bytes(data[:-32])
        data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()
        with self.assertRaisesRegex(CheckpointError, "progress is outside"):
            parse_checkpoint_bytes(data)


if __name__ == "__main__":
    unittest.main()
