import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from genesis_monitor.cli import main
from genesis_monitor.operational_config import (
    OperationalConfigurationError,
    load_operational_config,
)


class OperationalConfigFixtures:
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name)

    def receiver_config(self):
        return {
            "schema_version": 1,
            "role": "receiver",
            "enabled": True,
            "automatic_start": False,
            "bind_address": "192.168.1.34",
            "interface_guid": "e77a435b-69c7-4886-b1d9-1870252b1eb9",
            "port": 39740,
            "approved_interface_addresses": ["192.168.1.34"],
            "server_identity": "192.168.1.34",
            "server_certificate_file": "C:\\test\\server.pem",
            "server_private_key_file": "C:\\test\\server.key",
            "client_ca_file": "C:\\test\\client-ca.pem",
            "identity_registry_file": "C:\\test\\identity.sqlite",
            "central_store_file": "C:\\test\\central.sqlite",
            "receipt_signing_key_file": "C:\\test\\receipt.key",
            "receipt_signing_key_id": "test-receipt-key",
            "receipt_trust_bundle_file": "C:\\test\\receipt-trust.json",
            "dashboard_output": "C:\\test\\dashboard.html",
            "machines": [{"machine_id": "dell-test", "display_name": "Synthetic Dell"}],
        }

    def agent_config(self):
        return {
            "schema_version": 1,
            "role": "agent",
            "enabled": True,
            "automatic_start": False,
            "machine_id": "dell-test",
            "collection": {
                "log_file": "C:\\test\\search.log",
                "checkpoint_file": None,
            },
            "spool_file": "C:\\test\\spool.sqlite",
            "receiver": {"host": "192.168.1.34", "port": 39740},
            "tls": {
                "server_ca_file": "C:\\test\\server-ca.pem",
                "client_certificate_file": "C:\\test\\client.pem",
                "client_private_key_file": "C:\\test\\client.key",
                "receipt_trust_bundle_file": "C:\\test\\receipt-trust.json",
            },
        }

    def write_config(self, value, name="config.json"):
        path = self.directory / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

class OperationalConfigurationTests(OperationalConfigFixtures, unittest.TestCase):
    def test_valid_receiver_and_agent_configs_load_without_opening_runtime_files(self):
        for config, role in (
            (self.receiver_config(), "receiver"),
            (self.agent_config(), "agent"),
        ):
            with self.subTest(role=role):
                path = self.write_config(config, f"{role}.json")
                loaded = load_operational_config(path, expected_role=role)
                self.assertEqual(loaded, config)
        self.assertEqual(sorted(item.name for item in self.directory.iterdir()), [
            "agent.json", "receiver.json",
        ])

    def test_disabled_unknown_duplicate_and_role_mismatched_configs_fail(self):
        cases = []
        disabled = self.receiver_config()
        disabled["enabled"] = False
        cases.append(disabled)
        automatic = self.receiver_config()
        automatic["automatic_start"] = True
        cases.append(automatic)
        unknown = self.receiver_config()
        unknown["surprise"] = 1
        cases.append(unknown)
        for index, config in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(OperationalConfigurationError):
                    load_operational_config(self.write_config(config, f"invalid-{index}.json"))
        with self.assertRaisesRegex(OperationalConfigurationError, "role"):
            load_operational_config(
                self.write_config(self.agent_config(), "agent-role.json"),
                expected_role="receiver",
            )
        duplicate_path = self.directory / "duplicate.json"
        duplicate_path.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        with self.assertRaisesRegex(OperationalConfigurationError, "duplicate"):
            load_operational_config(duplicate_path)

    def test_private_bind_port_paths_and_identity_are_strict(self):
        mutations = (
            lambda config: config.__setitem__("bind_address", "0.0.0.0"),
            lambda config: config.__setitem__("port", True),
            lambda config: config.__setitem__("interface_guid", "not-a-guid"),
            lambda config: config.__setitem__("server_private_key_file", "<KEY_PATH>"),
            lambda config: config.__setitem__("central_store_file", "C:\\test\\..\\store.db"),
            lambda config: config.__setitem__("approved_interface_addresses", ["192.168.1.35"]),
            lambda config: config.__setitem__("server_identity", "main.example.test"),
        )
        for index, mutate in enumerate(mutations):
            config = self.receiver_config()
            mutate(config)
            with self.subTest(index=index), self.assertRaises(OperationalConfigurationError):
                load_operational_config(self.write_config(config, f"unsafe-{index}.json"))

    def test_agent_rejects_overlapping_spool_and_input_paths(self):
        config = self.agent_config()
        config["spool_file"] = config["collection"]["log_file"]
        with self.assertRaisesRegex(OperationalConfigurationError, "separate"):
            load_operational_config(self.write_config(config), expected_role="agent")

    def test_writable_paths_cannot_overwrite_config_and_symlink_configs_fail(self):
        receiver_path = self.directory / "receiver-overwrite.json"
        receiver_config = self.receiver_config()
        receiver_config["dashboard_output"] = str(receiver_path)
        receiver_path.write_text(json.dumps(receiver_config), encoding="utf-8")
        with self.assertRaisesRegex(OperationalConfigurationError, "overwrite"):
            load_operational_config(receiver_path)

        agent_path = self.directory / "agent-overwrite.json"
        agent_config = self.agent_config()
        agent_config["spool_file"] = str(agent_path)
        agent_path.write_text(json.dumps(agent_config), encoding="utf-8")
        with self.assertRaisesRegex(OperationalConfigurationError, "overwrite"):
            load_operational_config(agent_path)

        config_path = self.write_config(self.agent_config(), "symlink.json")
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaisesRegex(OperationalConfigurationError, "symlink"):
                load_operational_config(config_path)

    def test_agent_requires_private_numeric_receiver_address_and_distinct_inputs(self):
        config = self.agent_config()
        config["receiver"]["host"] = "203.0.113.10"
        with self.assertRaisesRegex(OperationalConfigurationError, "RFC1918"):
            load_operational_config(self.write_config(config, "public-endpoint.json"), expected_role="agent")
        config = self.agent_config()
        config["collection"]["checkpoint_file"] = config["collection"]["log_file"]
        with self.assertRaisesRegex(OperationalConfigurationError, "separate inputs"):
            load_operational_config(self.write_config(config, "same-input.json"), expected_role="agent")


class OperationalCliTests(OperationalConfigFixtures, unittest.TestCase):
    def test_validate_command_only_reads_config_and_never_starts_runtime(self):
        config_path = self.write_config(self.receiver_config())
        output = io.StringIO()
        with (
            patch("genesis_monitor.cli.RemoteMTLSServer.start", side_effect=AssertionError("must not bind")),
            patch("genesis_monitor.cli.PrivateIngressConfig.load", side_effect=AssertionError("must not enumerate or load TLS")),
            patch("socket.create_connection", side_effect=AssertionError("must not connect")),
            patch("sqlite3.connect", side_effect=AssertionError("must not open databases")),
            contextlib.redirect_stdout(output),
        ):
            result = main(["validate", "--config", str(config_path)])
        self.assertEqual(result, 0)
        self.assertIn("configuration valid", output.getvalue())
        self.assertNotIn("server.key", output.getvalue())
        self.assertEqual(sorted(item.name for item in self.directory.iterdir()), ["config.json"])

    def test_runtime_commands_require_explicit_invocation(self):
        agent_path = self.write_config(self.agent_config(), "agent.json")
        receiver_path = self.write_config(self.receiver_config(), "receiver.json")
        output = io.StringIO()
        with (
            patch("genesis_monitor.cli._run_agent_once", return_value=0) as agent_run,
            patch("genesis_monitor.cli._run_receiver", return_value=0) as receiver_run,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(main(["validate", "--config", str(agent_path)]), 0)
            agent_run.assert_not_called()
            receiver_run.assert_not_called()
            self.assertEqual(main(["agent-once", "--config", str(agent_path)]), 0)
            self.assertEqual(main(["receiver-start", "--config", str(receiver_path)]), 0)
        agent_run.assert_called_once()
        receiver_run.assert_called_once()

    def test_dashboard_render_rejects_missing_store_without_creating_it(self):
        config_path = self.write_config(self.receiver_config())
        store_path = Path(self.receiver_config()["central_store_file"])
        with (
            patch("genesis_monitor.cli.CentralStore", side_effect=AssertionError("store must not be opened")) as store,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            result = main(["dashboard-render", "--config", str(config_path)])
        self.assertEqual(result, 1)
        store.assert_not_called()
        self.assertFalse(store_path.exists())


if __name__ == "__main__":
    unittest.main()