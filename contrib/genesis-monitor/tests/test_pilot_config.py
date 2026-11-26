import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from genesis_monitor.pilot_config import (
    PilotConfigurationError,
    load_disabled_pilot_config,
)


_CONFIG_DIRECTORY = Path(__file__).resolve().parents[1] / "config"


class DisabledPilotConfigurationTests(unittest.TestCase):
    def test_all_operator_templates_validate_as_disabled_placeholders(self):
        for role, filename in (
            ("main_receiver", "main-receiver.example.json"),
            ("dell_agent", "dell-agent.example.json"),
            ("acer_agent", "acer-agent.example.json"),
        ):
            with self.subTest(role=role):
                configuration = load_disabled_pilot_config(
                    _CONFIG_DIRECTORY / filename,
                    expected_role=role,
                )
                self.assertIs(configuration["enabled"], False)
                self.assertIs(configuration["automatic_start"], False)

    def test_template_validation_has_no_listener_inventory_or_sender_side_effects(self):
        with (
            patch(
                "genesis_monitor.private_ingress.windows_interface_inventory",
                side_effect=AssertionError("template validation must stay offline"),
            ) as inventory,
            patch(
                "http.server.ThreadingHTTPServer.__init__",
                side_effect=AssertionError("template validation must not bind"),
            ) as server_init,
            patch(
                "genesis_monitor.sender._send_spooled_event_owned",
                side_effect=AssertionError("template validation must not send"),
            ) as send,
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("template validation must not connect"),
            ) as connect,
        ):
            for role, filename in (
                ("main_receiver", "main-receiver.example.json"),
                ("dell_agent", "dell-agent.example.json"),
                ("acer_agent", "acer-agent.example.json"),
            ):
                load_disabled_pilot_config(
                    _CONFIG_DIRECTORY / filename,
                    expected_role=role,
                )
        inventory.assert_not_called()
        server_init.assert_not_called()
        send.assert_not_called()
        connect.assert_not_called()

    def test_enabled_and_automatic_start_are_rejected(self):
        source = json.loads(
            (_CONFIG_DIRECTORY / "main-receiver.example.json").read_text(
                encoding="utf-8"
            )
        )
        for field in ("enabled", "automatic_start"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                source[field] = True
                path = Path(directory) / "receiver.json"
                path.write_text(json.dumps(source), encoding="utf-8")
                with self.assertRaisesRegex(PilotConfigurationError, "disabled|automatic"):
                    load_disabled_pilot_config(path, expected_role="main_receiver")
                source[field] = False

    def test_schema_unknown_fields_and_role_mismatch_are_rejected(self):
        source = json.loads(
            (_CONFIG_DIRECTORY / "dell-agent.example.json").read_text(encoding="utf-8")
        )
        cases = []
        unknown = dict(source)
        unknown["unexpected"] = "value"
        cases.append(unknown)
        wrong_role = dict(source)
        wrong_role["role"] = "acer_agent"
        cases.append(wrong_role)
        for configuration in cases:
            with self.subTest(configuration=configuration), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "agent.json"
                path.write_text(json.dumps(configuration), encoding="utf-8")
                with self.assertRaises(PilotConfigurationError):
                    load_disabled_pilot_config(path, expected_role="dell_agent")

    def test_operational_addresses_paths_secrets_and_ports_are_rejected(self):
        source = json.loads(
            (_CONFIG_DIRECTORY / "main-receiver.example.json").read_text(
                encoding="utf-8"
            )
        )
        mutations = (
            ("bind.address", lambda value: value["bind"].__setitem__("address", "0.0.0.0")),
            ("bind.port", lambda value: value["bind"].__setitem__("port", 443)),
            (
                "tls.private_key_file",
                lambda value: value["tls"].__setitem__(
                    "private_key_file", "C:\\production\\key.pem"
                ),
            ),
            (
                "source_allowlist",
                lambda value: value.__setitem__("source_allowlist", ["192.168.1.20"]),
            ),
        )
        for label, mutate in mutations:
            configuration = json.loads(json.dumps(source))
            mutate(configuration)
            with self.subTest(field=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "receiver.json"
                path.write_text(json.dumps(configuration), encoding="utf-8")
                with self.assertRaises(PilotConfigurationError):
                    load_disabled_pilot_config(path, expected_role="main_receiver")

    def test_duplicate_json_keys_fail_closed(self):
        duplicate = (
            '{"schema_version":1,"schema_version":1,"role":"main_receiver",'
            '"enabled":false}'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(PilotConfigurationError, "duplicate"):
                load_disabled_pilot_config(path, expected_role="main_receiver")

    def test_missing_or_unreadable_config_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(PilotConfigurationError, "cannot read"):
                load_disabled_pilot_config(
                    Path(directory) / "missing.json",
                    expected_role="main_receiver",
                )


if __name__ == "__main__":
    unittest.main()
