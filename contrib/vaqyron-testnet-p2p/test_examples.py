"""Offline checks for the inert VAQYRON TESTNET P2P examples."""

from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent
CORE_ROOT = HERE.parents[1]


def read_config(name):
    return [
        line.strip()
        for line in (HERE / name).read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class TestnetPeerExampleTests(unittest.TestCase):
    def test_examples_pin_testnet_and_manual_peering(self):
        for name, expected_peer in (
            ("node-a.conf.example", "198.51.100.20:39733"),
            ("node-b.conf.example", "198.51.100.10:39733"),
        ):
            with self.subTest(name=name):
                options = read_config(name)
                self.assertIn("chain=vaqyron-testnet", options)
                self.assertIn("listen=1", options)
                self.assertIn("port=39733", options)
                self.assertIn("dnsseed=0", options)
                self.assertIn("fixedseeds=0", options)
                self.assertIn(f"addnode={expected_peer}", options)
                self.assertIn("rpcbind=127.0.0.1", options)
                self.assertIn("rpcallowip=127.0.0.1", options)
                self.assertNotIn("rpcbind=0.0.0.0", options)
                self.assertFalse(any(option.startswith("rpcpassword=") for option in options))
                self.assertFalse(any(option.startswith("rpcuser=") for option in options))

    def test_peer_addresses_are_documentation_only_reserved_addresses(self):
        for name in ("node-a.conf.example", "node-b.conf.example"):
            with self.subTest(name=name):
                text = (HERE / name).read_text(encoding="utf-8")
                self.assertIn("INERT EXAMPLE ONLY", text)
                self.assertIn("replace the reserved TEST-NET-2", text)
                peers = [
                    option.split("=", 1)[1]
                    for option in read_config(name)
                    if option.startswith("addnode=")
                ]
                self.assertEqual(len(peers), 1)
                self.assertTrue(peers[0].startswith("198.51.100."))

    def test_source_keeps_testnet_seeds_empty_and_identity_fixed(self):
        source = (CORE_ROOT / "src" / "kernel" / "chainparams.cpp").read_text(
            encoding="utf-8"
        )
        start = source.index("class CVaqyronTestNetParams")
        end = source.index("\nclass ", start + len("class "))
        params = source[start:end]
        self.assertIn("pchMessageStart = MessageStartChars{0x56, 0x51, 0x54, 0x31}", params)
        self.assertIn("nDefaultPort = 39733", params)
        self.assertIn('vSeeds.clear();', params)
        self.assertIn('vFixedSeeds.clear();', params)
        self.assertIn('bech32_hrp = "tvqrn"', params)
        chain_names = (CORE_ROOT / "src" / "util" / "chaintype.cpp").read_text(
            encoding="utf-8"
        )
        self.assertIn('return "vaqyron-testnet";', chain_names)
        self.assertIn('chain == "vaqyron-testnet"', chain_names)


if __name__ == "__main__":
    unittest.main()
