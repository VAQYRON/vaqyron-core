"""Focused tests for the isolated VAQYRON genesis verifier."""

import json
import os
import struct
import subprocess
import sys
import unittest
from pathlib import Path

from verify_candidate import reconstruct_candidate


HERE = Path(__file__).resolve().parent
KATS = (
    (
        "040000001f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010000112233445566778899aabbccddeeff00112233445566778899aabbccddeeff01f15365ffff7f1c2a000000",
        "a2358778eec38c3cea83dab72d3bc6187c07451d56971c33d8ef833b2c6e3c5a",
    ),
    (
        "050000003f3e3d3c3b3a393837363534333231302f2e2d2c2b2a2928272625242322212055555555555555555555555555555555555555555555555555555555555555557bf15365ffff7f1c63000000",
        "30736e42eac69d2a67a54d20ec62f933a60b4a10acb518439a04bd2e66b1d6a6",
    ),
)


class CandidateVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = Path(os.environ.get("YESPOWER_REF_CLI", ""))
        if not cls.helper.is_file():
            raise RuntimeError(
                "set YESPOWER_REF_CLI to the compiled yespower-ref-cli executable"
            )

    def test_frozen_yespower_kat_1(self):
        self.assertEqual(self.hash_header(KATS[0][0]), KATS[0][1])

    def test_frozen_yespower_kat_2(self):
        self.assertEqual(self.hash_header(KATS[1][0]), KATS[1][1])

    def test_nonce_zero_reconstruction_is_not_a_candidate(self):
        result = reconstruct_candidate(0, self.helper)
        self.assertEqual(
            result["txid"],
            "401fa2348ee8a6a333e8e40f0b402c14da6887c244f1c1138fd818d581b9736e",
        )
        self.assertEqual(result["txid"], result["merkle_root"])
        self.assertEqual(
            result["pow_digest_raw"],
            "db105bd1ab0ca9c5afeedfa88b2af9fbb96614686eb25bae50ca1edcef7205c0",
        )
        self.assertEqual(
            result["block_id"],
            "1ea224483e79bf747906c947e53f0acc69a7d7629c61c75bd7d78ad61016bd0a",
        )
        header = bytes.fromhex(result["header_hex"])
        self.assertEqual(result["header_length"], 80)
        self.assertEqual(len(header), 80)
        self.assertEqual(struct.unpack_from("<i", header, 0)[0], 1)
        self.assertEqual(header[4:36], b"\x00" * 32)
        self.assertEqual(header[36:68], bytes.fromhex(result["merkle_root"])[::-1])
        self.assertEqual(struct.unpack_from("<III", header, 68), (1791363600, 0x1D00FFFF, 0))
        self.assertEqual(result["coinbase_input_count"], 1)
        self.assertEqual(result["output_count"], 1)
        self.assertEqual(result["output_value"], 0)
        self.assertEqual(
            result["output_script_hex"], "6a1956415159524f4e2067656e65736973206d61726b6572207631"
        )
        self.assertTrue(result["output_unspendable"])
        self.assertFalse(result["founder_allocation"])
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["time"], 1791363600)
        self.assertEqual(result["bits"], "1d00ffff")
        self.assertEqual(
            result["target"],
            "00000000ffff0000000000000000000000000000000000000000000000000000",
        )
        self.assertEqual(
            result["pow_integer"],
            f"{int.from_bytes(bytes.fromhex(result['pow_digest_raw']), 'little'):064x}",
        )
        self.assertTrue(result["target_valid"])
        self.assertFalse(result["pow_integer_le_target"])
        self.assertFalse(result["nonce_in_authorized_search_range"])
        self.assertFalse(result["candidate_valid"])

    def test_nonce_zero_cli_is_explicitly_not_a_candidate(self):
        result = subprocess.run(
            [
                sys.executable,
                str(HERE / "verify_candidate.py"),
                "--nonce",
                "0",
                "--yespower-cli",
                str(self.helper),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        output = json.loads(result.stdout)
        self.assertEqual(output["result"], "NOT_A_VALID_CANDIDATE")
        self.assertFalse(output["candidate_valid"])

    def test_verifier_rejects_malformed_nonce(self):
        for nonce in ("-1", "4294967296", "0x10", "1x"):
            with self.subTest(nonce=nonce):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(HERE / "verify_candidate.py"),
                        "--nonce",
                        nonce,
                        "--yespower-cli",
                        str(self.helper),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)

    def test_reference_helper_rejects_malformed_header(self):
        for header in ("00" * 79, "00" * 81, "gg" * 80):
            with self.subTest(length=len(header)):
                result = subprocess.run(
                    [str(self.helper), header],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_reference_helper_rejects_extra_arguments(self):
        result = subprocess.run(
            [str(self.helper), "00" * 80, "unexpected"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def hash_header(self, header_hex):
        result = subprocess.run(
            [str(self.helper), header_hex],
            capture_output=True,
            text=True,
            check=True,
        )
        prefix, digest = result.stdout.strip().split("=", 1)
        self.assertEqual(prefix, "POW_DIGEST")
        self.assertEqual(len(digest), 64)
        return digest


if __name__ == "__main__":
    unittest.main()
