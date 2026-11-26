import json
import socket
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from genesis_monitor.private_ingress import (
    PrivateIngressConfig,
    PrivateIngressConfigurationError,
    windows_interface_inventory,
)
from genesis_monitor.sender import DurableEventSender, RemoteSenderEndpoint
from genesis_monitor.identity import CertificateCredential, CertificateIdentityRegistry
from genesis_monitor.ingestion import GenesisIngestionService
from genesis_monitor.receipts import (
    CommittedReceiptSigner,
    CommittedReceiptVerifier,
    trust_bundle_from_public_keys,
)
from genesis_monitor.spool import EventSpool
from genesis_monitor.store import CentralStore
from genesis_monitor.transport import (
    LoopbackMTLSServer,
    create_client_tls_context,
    RemoteMTLSServer,
)
from tests.test_transport import _issue_certificate, _write_certificate
from tests.test_protocol import valid_event


class PrivateIngressConfigurationTests(unittest.TestCase):
    MAIN_INTERFACE = "7f50be91-9b37-41db-bbb5-c2f67e3a7d01"
    OTHER_INTERFACE = "b34af2c8-7904-46c1-a0d4-622c0b7fd7d9"

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="vaqyron-private-config-")
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_certificate = _issue_certificate(
            "private-ingress-test-root",
            self.ca_key.public_key(),
            None,
            self.ca_key,
            is_ca=True,
        )
        self.ca_path, _ = _write_certificate(
            self.directory, "client-root", self.ca_certificate, self.ca_key
        )
        self.server_key = ec.generate_private_key(ec.SECP256R1())
        self.server_certificate = self._server_certificate(
            self.server_key,
            ("10.23.45.6", "127.0.0.1"),
        )
        self.certificate_path, self.key_path = _write_certificate(
            self.directory,
            "private-server",
            self.server_certificate,
            self.server_key,
        )

    def _server_certificate(self, key, ip_sans):
        return _issue_certificate(
            "private-ingress-test-server",
            key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
            subject_alt_names=[
                x509.IPAddress(ip_address(value)) for value in ip_sans
            ],
        )

    def _server_certificate_with_validity(self, key, *, not_before, not_after):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "validity-test-server")
        ])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before.replace(tzinfo=None))
            .not_valid_after(not_after.replace(tzinfo=None))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.IPAddress(ip_address("10.23.45.6"))
                ]),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256())
        )

    def _valid_config(self, **overrides):
        inventory = overrides.pop("interface_inventory", {
            self.MAIN_INTERFACE: ("10.23.45.6", "192.168.1.10"),
            self.OTHER_INTERFACE: ("192.168.1.11",),
        })
        options = {
            "enabled": True,
            "bind_address": "10.23.45.6",
            "interface_identity": self.MAIN_INTERFACE,
            "port": 18443,
            "approved_interface_addresses": ("10.23.45.6",),
            "interface_inventory": inventory,
            "server_identity": "10.23.45.6",
            "server_certificate_file": self.certificate_path,
            "server_private_key_file": self.key_path,
            "client_trust_file": self.ca_path,
        }
        options.update(overrides)
        return PrivateIngressConfig.load(**options)

    def test_disabled_by_default_and_rejects_listener_options(self):
        config = PrivateIngressConfig.load()
        self.assertFalse(config.enabled)
        self.assertFalse(config.listener_available)
        self.assertIsNone(config.interface_identity)
        self.assertIsNone(config.port)
        self.assertIsNone(config.tls_context)
        with self.assertRaisesRegex(
            PrivateIngressConfigurationError, "disabled private ingress"
        ):
            PrivateIngressConfig.load(
                bind_address="10.23.45.6",
                approved_interface_addresses=("10.23.45.6",),
            )

    def test_enabled_config_requires_interface_identity_port_and_inventory(self):
        for overrides in (
            {"interface_identity": None},
            {"port": None},
            {"port": True},
            {"port": 0},
            {"port": 65536},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                self._valid_config(**overrides)
        with patch(
            "genesis_monitor.private_ingress.windows_interface_inventory",
            side_effect=PrivateIngressConfigurationError("inventory unavailable"),
        ):
            with self.assertRaisesRegex(
                PrivateIngressConfigurationError, "inventory unavailable"
            ):
                PrivateIngressConfig.load(
                    enabled=True,
                    bind_address="10.23.45.6",
                    interface_identity=self.MAIN_INTERFACE,
                    port=18443,
                    approved_interface_addresses=("10.23.45.6",),
                    interface_inventory=None,
                    server_identity="10.23.45.6",
                    server_certificate_file=self.certificate_path,
                    server_private_key_file=self.key_path,
                    client_trust_file=self.ca_path,
                )

    def test_interface_inventory_must_uniquely_assign_ipv4_to_selected_interface(self):
        invalid_inventories = (
            {self.OTHER_INTERFACE: ("10.23.45.6",)},
            {
                self.MAIN_INTERFACE: ("10.23.45.6",),
                self.OTHER_INTERFACE: ("10.23.45.6",),
            },
            {self.MAIN_INTERFACE: ("10.23.45.7",)},
        )
        for inventory in invalid_inventories:
            with self.subTest(inventory=inventory), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                self._valid_config(interface_inventory=inventory)

    def test_interface_selection_revalidation_rejects_changed_or_missing_address(self):
        config = self._valid_config()
        config.validate_current_interface_inventory({
            self.MAIN_INTERFACE: ("10.23.45.6",),
        })
        for changed_inventory in (
            {self.MAIN_INTERFACE: ("10.23.45.7",)},
            {self.OTHER_INTERFACE: ("10.23.45.6",)},
            {
                self.MAIN_INTERFACE: ("10.23.45.6",),
                self.OTHER_INTERFACE: ("10.23.45.6",),
            },
        ):
            with self.subTest(inventory=changed_inventory), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                config.validate_current_interface_inventory(changed_inventory)

    def test_ipv6_ula_interface_ownership_is_validated_without_binding(self):
        PrivateIngressConfig._validate_interface_ownership(
            self.MAIN_INTERFACE,
            "fd12:3456:789a::10",
            {self.MAIN_INTERFACE: ("fd12:3456:789a::10",)},
        )
        for address in ("::", "::1", "fe80::1", "2001:4860:4860::8888"):
            with self.subTest(address=address), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                PrivateIngressConfig._private_address(address, "bind_address")

    def test_windows_interface_inventory_uses_guid_and_normalizes_addresses(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps([
                {
                    "InterfaceIdentity": "{" + self.MAIN_INTERFACE.upper() + "}",
                    "Address": "10.23.45.6",
                },
                {
                    "InterfaceIdentity": self.MAIN_INTERFACE,
                    "Address": "fd12:3456:789a::10",
                },
                {
                    "InterfaceIdentity": self.OTHER_INTERFACE,
                    "Address": "192.168.1.11",
                },
            ]),
            stderr="",
        )
        with (
            patch("genesis_monitor.private_ingress.sys.platform", "win32"),
            patch(
                "genesis_monitor.private_ingress.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            inventory = windows_interface_inventory()
        self.assertEqual(
            inventory[self.MAIN_INTERFACE],
            ("10.23.45.6", "fd12:3456:789a::10"),
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 5)
        self.assertIn("InterfaceGuid", run.call_args.args[0][-1])

    def test_windows_interface_inventory_fails_closed_on_unavailable_or_spoofed_data(self):
        with patch("genesis_monitor.private_ingress.sys.platform", "linux"):
            with self.assertRaisesRegex(PrivateIngressConfigurationError, "unavailable"):
                windows_interface_inventory()

        malformed_outputs = (
            "not-json",
            json.dumps([{
                "InterfaceIdentity": "not-a-guid",
                "Address": "10.23.45.6",
            }]),
            json.dumps([{
                "InterfaceIdentity": self.MAIN_INTERFACE,
                "Address": "not-an-ip",
            }]),
        )
        for output in malformed_outputs:
            completed = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=output,
                stderr="",
            )
            with (
                self.subTest(output=output),
                patch("genesis_monitor.private_ingress.sys.platform", "win32"),
                patch(
                    "genesis_monitor.private_ingress.subprocess.run",
                    return_value=completed,
                ),
                self.assertRaises(PrivateIngressConfigurationError),
            ):
                windows_interface_inventory()

    def test_windows_interface_inventory_accepts_powershell_single_object_json(self):
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({
                "InterfaceIdentity": self.MAIN_INTERFACE,
                "Address": "10.23.45.6",
            }),
            stderr="",
        )
        with (
            patch("genesis_monitor.private_ingress.sys.platform", "win32"),
            patch(
                "genesis_monitor.private_ingress.subprocess.run",
                return_value=completed,
            ),
        ):
            inventory = windows_interface_inventory()
        self.assertEqual(inventory, {self.MAIN_INTERFACE: ("10.23.45.6",)})

    def test_spoofed_inventory_cannot_approve_a_different_or_public_address(self):
        spoofed = {
            self.MAIN_INTERFACE: ("8.8.8.8",),
        }
        with patch(
            "genesis_monitor.private_ingress.windows_interface_inventory",
            return_value=spoofed,
        ):
            with self.assertRaises(PrivateIngressConfigurationError):
                PrivateIngressConfig.load(
                    enabled=True,
                    bind_address="10.23.45.6",
                    interface_identity=self.MAIN_INTERFACE,
                    port=18443,
                    approved_interface_addresses=("10.23.45.6",),
                    server_identity="10.23.45.6",
                    server_certificate_file=self.certificate_path,
                    server_private_key_file=self.key_path,
                    client_trust_file=self.ca_path,
                )

    def test_direct_constructor_cannot_bypass_validation(self):
        with self.assertRaisesRegex(TypeError, "use PrivateIngressConfig.load"):
            PrivateIngressConfig(enabled=True, bind_address="0.0.0.0")

    def test_rejects_ipv6_ula_network_boundaries_and_accepts_usable_edges(self):
        for address in (
            "fc00::",
            "::ffff:10.23.45.6",
            "fe80::1",
            "ff02::1",
        ):
            with self.subTest(address=address), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                PrivateIngressConfig._private_address(address, "test address")
        self.assertEqual(
            PrivateIngressConfig._private_address("fc00::1", "test address"),
            "fc00::1",
        )
        self.assertEqual(
            PrivateIngressConfig._private_address(
                "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "test address",
            ),
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        )

    def test_rejects_wildcard_loopback_public_and_unapproved_addresses(self):
        for address in ("0.0.0.0", "::", "127.0.0.1", "8.8.8.8", "169.254.1.1"):
            with self.subTest(address=address), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                self._valid_config(
                    bind_address=address,
                    approved_interface_addresses=(address,),
                )
        with self.assertRaisesRegex(PrivateIngressConfigurationError, "approved"):
            self._valid_config(
                bind_address="10.23.45.6",
                approved_interface_addresses=("10.23.45.7",),
            )
        with self.assertRaisesRegex(PrivateIngressConfigurationError, "numeric private"):
            self._valid_config(bind_address="main.private.example")

    def test_missing_certificate_key_or_trust_file_fails_closed(self):
        for field in (
            "server_certificate_file",
            "server_private_key_file",
            "client_trust_file",
        ):
            with self.subTest(field=field), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                self._valid_config(**{field: self.directory / "missing.pem"})

    def test_rejects_invalid_trust_certificate_and_identity(self):
        invalid_trust = self.directory / "invalid-ca.pem"
        invalid_trust.write_text("not a certificate", encoding="ascii")
        with self.assertRaises(PrivateIngressConfigurationError):
            self._valid_config(client_trust_file=invalid_trust)
        leaf_trust = self.directory / "leaf-trust.pem"
        leaf_trust.write_bytes(self.server_certificate.public_bytes(Encoding.PEM))
        with self.assertRaisesRegex(PrivateIngressConfigurationError, "not a CA"):
            self._valid_config(client_trust_file=leaf_trust)

        with self.assertRaisesRegex(PrivateIngressConfigurationError, "SAN"):
            self._valid_config(server_identity="10.23.45.7")
        with self.assertRaises(PrivateIngressConfigurationError):
            self._valid_config(server_identity="*.private.example")

        wrong_usage_key = ec.generate_private_key(ec.SECP256R1())
        wrong_usage = _issue_certificate(
            "wrong-usage",
            wrong_usage_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
            subject_alt_names=[x509.IPAddress(ip_address("10.23.45.6"))],
        )
        wrong_cert_path, _ = _write_certificate(
            self.directory, "wrong-usage", wrong_usage, wrong_usage_key
        )
        with self.assertRaisesRegex(PrivateIngressConfigurationError, "server-auth"):
            self._valid_config(server_certificate_file=wrong_cert_path)

    def test_valid_synthetic_configuration_builds_tls_context_but_no_listener(self):
        config = self._valid_config()
        self.assertTrue(config.enabled)
        self.assertEqual(config.bind_address, "10.23.45.6")
        self.assertEqual(config.server_identity, "10.23.45.6")
        self.assertEqual(config.tls_context.minimum_version.name, "TLSv1_2")
        self.assertEqual(config.tls_context.verify_mode, 2)
        self.assertGreater(len(config.tls_context.get_ca_certs()), 0)
        self.assertFalse(config.listener_available)

    def test_remote_startup_configuration_revalidates_without_binding(self):
        config = self._valid_config()
        endpoint = RemoteMTLSServer.validate_startup_configuration(
            config,
            interface_inventory={self.MAIN_INTERFACE: ("10.23.45.6",)},
        )
        self.assertEqual(endpoint[:2], ("10.23.45.6", 18443))
        self.assertIs(endpoint[2], config.tls_context)
        for inventory in (
            {self.MAIN_INTERFACE: ("10.23.45.7",)},
            {self.OTHER_INTERFACE: ("10.23.45.6",)},
        ):
            with self.subTest(inventory=inventory), self.assertRaises(
                PrivateIngressConfigurationError
            ):
                RemoteMTLSServer.validate_startup_configuration(
                    config,
                    interface_inventory=inventory,
                )

    def test_remote_startup_rejects_disabled_or_forged_configuration_before_bind(self):
        forged = object.__new__(PrivateIngressConfig)
        with (
            patch(
                "genesis_monitor.transport.windows_interface_inventory",
                side_effect=AssertionError("offline startup must not query host interfaces"),
            ) as inventory,
            patch(
                "http.server.ThreadingHTTPServer.__init__",
                side_effect=AssertionError("socket server must not initialize"),
            ) as bind,
            self.assertRaises(PrivateIngressConfigurationError),
        ):
            RemoteMTLSServer(configuration=PrivateIngressConfig.load(), ingestion_service=None)
        bind.assert_not_called()
        inventory.assert_not_called()
        with self.assertRaises(PrivateIngressConfigurationError):
            forged.require_validated_enabled_configuration()
        with self.assertRaises(PrivateIngressConfigurationError):
            RemoteMTLSServer.validate_startup_configuration(
                forged,
                interface_inventory={self.MAIN_INTERFACE: ("10.23.45.6",)},
            )

    def test_remote_sender_endpoint_rejects_untrusted_host_configuration(self):
        for host in ("", "https://main.private.example", "*.private.example", "main"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                RemoteSenderEndpoint.load(
                    host=host,
                    port=18443,
                    server_ca_file=str(self.ca_path),
                    client_certificate_file=str(self.certificate_path),
                    client_private_key_file=str(self.key_path),
                )
        with self.assertRaisesRegex(TypeError, "RemoteSenderEndpoint.load"):
            RemoteSenderEndpoint(host="main.private.example", port=18443)

    def test_rejects_certificate_private_key_mismatch(self):
        unrelated_key = ec.generate_private_key(ec.SECP256R1())
        _, unrelated_key_path = _write_certificate(
            self.directory,
            "unrelated-key",
            self.server_certificate,
            unrelated_key,
        )
        with self.assertRaises(PrivateIngressConfigurationError):
            self._valid_config(server_private_key_file=unrelated_key_path)

    def test_rejects_expired_and_not_yet_valid_server_certificates(self):
        now = datetime.now(timezone.utc)
        cases = (
            (
                "expired",
                now - timedelta(days=3),
                now - timedelta(days=1),
            ),
            (
                "not-yet-valid",
                now + timedelta(days=1),
                now + timedelta(days=3),
            ),
        )
        for name, not_before, not_after in cases:
            with self.subTest(name=name):
                certificate = self._server_certificate_with_validity(
                    self.server_key,
                    not_before=not_before,
                    not_after=not_after,
                )
                certificate_path, _ = _write_certificate(
                    self.directory,
                    name,
                    certificate,
                    self.server_key,
                )
                with self.assertRaisesRegex(
                    PrivateIngressConfigurationError, "validity period"
                ):
                    self._valid_config(server_certificate_file=certificate_path)

    def test_validated_tls_context_integrates_only_with_loopback_adapter(self):
        config = self._valid_config()
        client_key = ec.generate_private_key(ec.SECP256R1())
        client_certificate = _issue_certificate(
            "loopback-only-client",
            client_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
        )
        client_certificate_path, client_key_path = _write_certificate(
            self.directory, "loopback-client", client_certificate, client_key
        )
        client_context = create_client_tls_context(
            server_ca_file=self.ca_path,
            certificate_file=client_certificate_path,
            private_key_file=client_key_path,
        )
        registry = CertificateIdentityRegistry.bootstrap(
            self.directory / "loopback-identity.sqlite"
        )
        now = datetime.now(timezone.utc)
        registry.enroll(
            "loopback-test",
            CertificateCredential(
                client_certificate.fingerprint(hashes.SHA256()).hex(),
                now - timedelta(days=1),
                now + timedelta(days=1),
            ),
        )
        store = CentralStore(self.directory / "loopback-central.sqlite")
        store.register_machine("loopback-test", "Synthetic loopback")
        receipt_key = Ed25519PrivateKey.generate()
        bundle = trust_bundle_from_public_keys({
            "loopback-receipt": (
                receipt_key.public_key(),
                now - timedelta(days=1),
                now + timedelta(days=1),
                False,
            )
        })
        signer = CommittedReceiptSigner(
            {"loopback-receipt": receipt_key},
            active_key_id="loopback-receipt",
            trust_bundle=bundle,
        )
        receipt_verifier = CommittedReceiptVerifier(bundle)
        service = GenesisIngestionService(registry, store, signer)
        server = LoopbackMTLSServer(
            tls_context=config.tls_context,
            ingestion_service=service,
        )
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        spool = EventSpool(
            self.directory / "loopback-spool.sqlite",
            receipt_verifier=receipt_verifier,
        )
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            thread.start()
            source = valid_event()
            event, duplicate = spool.enqueue(
                "loopback-test",
                source["observed_at"],
                source["payload"],
                "loopback-integration-event",
            )
            self.assertFalse(duplicate)
            endpoint = RemoteSenderEndpoint.load(
                host="127.0.0.1",
                port=server.server_port,
                server_ca_file=self.ca_path,
                client_certificate_file=client_certificate_path,
                client_private_key_file=client_key_path,
            )
            sender = DurableEventSender(
                spool,
                endpoint=endpoint,
                receipt_verifier=receipt_verifier,
                timeout_seconds=3,
                base_backoff_seconds=1,
                max_backoff_seconds=1,
                jitter_fraction=0,
            )
            result = sender.run_once()
            self.assertEqual((result.attempted, result.delivered, result.deferred), (1, 1, 0))
            self.assertEqual(spool.pending(), [])
            self.assertEqual(len(store.history("loopback-test")), 1)

            mismatch_source = valid_event()
            spool.enqueue(
                "loopback-test",
                mismatch_source["observed_at"],
                mismatch_source["payload"],
                "loopback-identity-mismatch",
            )
            mismatch_endpoint = RemoteSenderEndpoint.load(
                host="mismatch.private.example",
                port=server.server_port,
                server_ca_file=self.ca_path,
                client_certificate_file=client_certificate_path,
                client_private_key_file=client_key_path,
            )
            mismatch_sender = DurableEventSender(
                spool,
                endpoint=mismatch_endpoint,
                receipt_verifier=receipt_verifier,
                timeout_seconds=3,
                base_backoff_seconds=1,
                max_backoff_seconds=1,
                jitter_fraction=0,
            )
            with patch(
                "socket.getaddrinfo",
                return_value=[(
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    "",
                    ("127.0.0.1", server.server_port),
                )],
            ):
                mismatch_result = mismatch_sender.run_once()
            self.assertEqual(
                (mismatch_result.attempted, mismatch_result.delivered, mismatch_result.deferred),
                (1, 0, 1),
            )
            self.assertEqual(len(spool.pending()), 1)
            self.assertEqual(len(store.history("loopback-test")), 1)
        finally:
            if thread.is_alive():
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
