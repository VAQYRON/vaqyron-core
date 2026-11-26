"""Focused tests for the isolated VAQYRON TESTNET genesis verifier."""

import unittest

from verify_testnet_candidate import (
    BITS,
    CHAIN,
    MARKER,
    MESSAGE,
    POW_LIMIT,
    TIME,
    decode_compact_target,
    reconstruct_header,
    reconstruct_transaction,
    verify_candidate,
)


class TestnetCandidateVerifierTests(unittest.TestCase):
    def test_testnet_inputs_are_distinct_and_fixed(self):
        self.assertEqual(CHAIN, "vaqyron-testnet")
        self.assertEqual(TIME, 1791460800)
        self.assertEqual(BITS, 0x207FFFFF)
        self.assertEqual(POW_LIMIT, int("7f" + "ff" * 31, 16))
        self.assertNotEqual(MESSAGE, b"VAQYRON - Independent Proof-of-Work Network - 2026")
        self.assertNotEqual(MARKER, b"VAQYRON genesis marker v1")
        target, valid = decode_compact_target(BITS)
        self.assertTrue(valid)
        self.assertEqual(
            f"{target:064x}",
            "7fffff0000000000000000000000000000000000000000000000000000000000",
        )
        self.assertLessEqual(target, POW_LIMIT)

    def test_reconstructs_testnet_coinbase_and_header(self):
        transaction, txid, header = reconstruct_header(17)
        self.assertEqual(transaction, reconstruct_transaction())
        self.assertEqual(
            transaction.hex(),
            "01000000010000000000000000000000000000000000000000000000000000000000000000"
            "ffffffff414056415159524f4e20544553544e4554202d20496e646570656e64656e742050"
            "726f6f662d6f662d576f726b204e6574776f726b202d20323032362d31302d3038ffffffff"
            "010000000000000000236a2156415159524f4e20544553544e45542067656e65736973206d"
            "61726b657220763100000000",
        )
        self.assertEqual(txid[::-1].hex(), "e7193ffd84a3492d43c7d591d9a9fabe45bc82da68d6767be4a43413d87ed048")
        self.assertEqual(len(header), 80)
        self.assertEqual(header[72:76], BITS.to_bytes(4, "little"))
        self.assertEqual(header[76:80], (17).to_bytes(4, "little"))
        self.assertEqual(
            verify_candidate(17, b"\x00" * 32)["block_id"],
            "2d7a5f2eecdd712e40e73177ca58d409636b2c8ec5f07c2e724796dfc4f4812f",
        )

    def test_wrong_chain_identity_is_rejected(self):
        _, _, header = reconstruct_header(1)
        result = verify_candidate(1, b"\x00" * 32, chain="main", header=header)
        self.assertFalse(result["chain_identity_valid"])
        self.assertFalse(result["candidate_valid"])

    def test_altered_header_is_rejected(self):
        _, _, header = reconstruct_header(1)
        altered = bytearray(header)
        altered[4] = 1
        result = verify_candidate(1, b"\x00" * 32, header=altered)
        self.assertFalse(result["header_matches_reconstruction"])
        self.assertFalse(result["candidate_valid"])

    def test_invalid_nonce_and_insufficient_hash_are_rejected(self):
        with self.assertRaises(ValueError):
            reconstruct_header(-1)
        with self.assertRaises(ValueError):
            reconstruct_header(1 << 32)
        result = verify_candidate(1, b"\xff" * 32)
        self.assertFalse(result["pow_integer_le_target"])
        self.assertFalse(result["candidate_valid"])

    def test_sufficient_hash_is_accepted_for_exact_testnet_header(self):
        result = verify_candidate(1, b"\x00" * 32)
        self.assertTrue(result["chain_identity_valid"])
        self.assertTrue(result["header_matches_reconstruction"])
        self.assertTrue(result["target_valid"])
        self.assertTrue(result["pow_integer_le_target"])
        self.assertTrue(result["candidate_valid"])

    def test_incorrect_target_is_rejected(self):
        _, _, header = reconstruct_header(1)
        altered = bytearray(header)
        altered[72:76] = (0x207FFFFE).to_bytes(4, "little")
        result = verify_candidate(1, b"\x00" * 32, header=altered)
        self.assertTrue(decode_compact_target(0x207FFFFE)[1])
        self.assertFalse(result["target_valid"])
        self.assertFalse(result["candidate_valid"])


if __name__ == "__main__":
    unittest.main()
