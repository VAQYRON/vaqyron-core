import http.client
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_monitor.identity import CertificateCredential, CertificateIdentityRegistry
from genesis_monitor.ingestion import GenesisIngestionService
from genesis_monitor.protocol import MAX_EVENT_BYTES, canonical_json
from genesis_monitor.receipts import (
    CommittedReceiptSigner,
    CommittedReceiptVerifier,
    trust_bundle_from_public_keys,
)
from genesis_monitor.sender import DurableEventSender
from genesis_monitor.spool import EventSpool, SpoolError
from genesis_monitor.store import CentralStore, StoreError
from genesis_monitor.transport import (
    _IngestionHandler,
    LoopbackMTLSServer,
    _RequestRateLimiter,
    TransportError,
    create_client_tls_context,
    create_server_tls_context,
    send_spooled_event,
)
from tests.test_protocol import valid_event


def _issue_certificate(
    common_name,
    public_key,
    issuer_certificate,
    issuer_key,
    *,
    is_ca=False,
    extended_usage=None,
    subject_alt_names=(),
):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_certificate.subject if issuer_certificate else subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    )
    if extended_usage:
        builder = builder.add_extension(x509.ExtendedKeyUsage(extended_usage), critical=False)
    if subject_alt_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(list(subject_alt_names)), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _write_certificate(directory, name, certificate, private_key):
    certificate_path = Path(directory) / f"{name}.pem"
    key_path = Path(directory) / f"{name}.key"
    certificate_path.write_bytes(certificate.public_bytes(Encoding.PEM))
    key_path.write_bytes(
        private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    return str(certificate_path), str(key_path)


class _FakeClock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class LoopbackMTLSTransportTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name)
        self._create_test_pki()

        self.registry = CertificateIdentityRegistry.bootstrap(
            self.directory / "identity.sqlite"
        )
        now = datetime.now(timezone.utc)
        self.registry.enroll(
            "laptop-1",
            CertificateCredential(
                self.client_certificate.fingerprint(hashes.SHA256()).hex(),
                now - timedelta(days=1),
                now + timedelta(days=2),
            ),
        )
        now = datetime.now(timezone.utc)
        self.registry.enroll(
            "laptop-2",
            CertificateCredential(
                self.second_client_certificate.fingerprint(hashes.SHA256()).hex(),
                now - timedelta(days=1),
                now + timedelta(days=2),
            ),
        )
        self.store = CentralStore(self.directory / "central.sqlite")
        self.store.register_machine("laptop-1", "Synthetic laptop")
        self.store.register_machine("laptop-2", "Synthetic second laptop")
        self.receipt_private_key = Ed25519PrivateKey.generate()
        self.receipt_bundle = trust_bundle_from_public_keys({
            "test-receipt-key": (
                self.receipt_private_key.public_key(),
                now - timedelta(hours=1),
                now + timedelta(days=2),
                False,
            )
        })
        self.receipt_signer = CommittedReceiptSigner(
            {"test-receipt-key": self.receipt_private_key},
            active_key_id="test-receipt-key",
            trust_bundle=self.receipt_bundle,
        )
        self.receipt_verifier = CommittedReceiptVerifier(self.receipt_bundle)
        self.service = GenesisIngestionService(
            self.registry, self.store, self.receipt_signer
        )
        self.server_context = create_server_tls_context(
            certificate_file=self.server_certificate_file,
            private_key_file=self.server_key_file,
            client_ca_file=self.ca_certificate_file,
        )
        self.client_context = create_client_tls_context(
            server_ca_file=self.ca_certificate_file,
            certificate_file=self.client_certificate_file,
            private_key_file=self.client_key_file,
        )
        self.server, self.server_thread = self._start_server(self.server_context)
        self.spool = EventSpool(
            self.directory / "spool.sqlite",
            receipt_verifier=self.receipt_verifier,
        )
        source = valid_event()
        self.event, duplicate = self.spool.enqueue(
            source["machine_id"],
            source["observed_at"],
            source["payload"],
            "loopback-event-1",
        )
        self.assertFalse(duplicate)

    def tearDown(self):
        self._stop_server(self.server, self.server_thread)

    def _create_test_pki(self):
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_certificate = _issue_certificate(
            "test-root",
            self.ca_key.public_key(),
            None,
            self.ca_key,
            is_ca=True,
        )
        self.ca_certificate_file, _ = _write_certificate(
            self.directory, "test-root", self.ca_certificate, self.ca_key
        )

        self.server_key = ec.generate_private_key(ec.SECP256R1())
        self.server_certificate = _issue_certificate(
            "test-server",
            self.server_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
            subject_alt_names=[
                x509.DNSName("localhost"),
                x509.IPAddress(ip_address("127.0.0.1")),
            ],
        )
        self.server_certificate_file, self.server_key_file = _write_certificate(
            self.directory, "test-server", self.server_certificate, self.server_key
        )

        self.client_key = ec.generate_private_key(ec.SECP256R1())
        self.client_certificate = _issue_certificate(
            "test-client",
            self.client_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
        )
        self.client_certificate_file, self.client_key_file = _write_certificate(
            self.directory, "test-client", self.client_certificate, self.client_key
        )

        self.second_client_key = ec.generate_private_key(ec.SECP256R1())
        self.second_client_certificate = _issue_certificate(
            "test-client-2",
            self.second_client_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
        )
        (
            self.second_client_certificate_file,
            self.second_client_key_file,
        ) = _write_certificate(
            self.directory,
            "test-client-2",
            self.second_client_certificate,
            self.second_client_key,
        )

        self.unregistered_client_key = ec.generate_private_key(ec.SECP256R1())
        self.unregistered_client_certificate = _issue_certificate(
            "unregistered-client",
            self.unregistered_client_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
        )
        (
            self.unregistered_client_certificate_file,
            self.unregistered_client_key_file,
        ) = _write_certificate(
            self.directory,
            "unregistered-client",
            self.unregistered_client_certificate,
            self.unregistered_client_key,
        )

        self.server_only_client_key = ec.generate_private_key(ec.SECP256R1())
        self.server_only_client_certificate = _issue_certificate(
            "wrong-purpose-client",
            self.server_only_client_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
        )
        (
            self.server_only_client_certificate_file,
            self.server_only_client_key_file,
        ) = _write_certificate(
            self.directory,
            "wrong-purpose-client",
            self.server_only_client_certificate,
            self.server_only_client_key,
        )

        self.untrusted_ca_key = ec.generate_private_key(ec.SECP256R1())
        self.untrusted_ca = _issue_certificate(
            "untrusted-root",
            self.untrusted_ca_key.public_key(),
            None,
            self.untrusted_ca_key,
            is_ca=True,
        )
        self.untrusted_client_key = ec.generate_private_key(ec.SECP256R1())
        self.untrusted_client_certificate = _issue_certificate(
            "untrusted-client",
            self.untrusted_client_key.public_key(),
            self.untrusted_ca,
            self.untrusted_ca_key,
            extended_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
        )
        (
            self.untrusted_client_certificate_file,
            self.untrusted_client_key_file,
        ) = _write_certificate(
            self.directory,
            "untrusted-client",
            self.untrusted_client_certificate,
            self.untrusted_client_key,
        )

    def _start_server(self, tls_context, *, rate_limiter=None):
        server = LoopbackMTLSServer(
            tls_context=tls_context,
            ingestion_service=self.service,
            request_deadline_seconds=0.8,
            rate_limiter=rate_limiter,
        )
        thread = threading.Thread(
            target=server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        thread.start()
        return server, thread

    def _wait_for_slots(self, expected, timeout=2):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.server._connection_slots._value == expected:
                return
            time.sleep(0.01)
        self.fail(
            f"timed out waiting for {expected} free connection slots; "
            f"found {self.server._connection_slots._value}"
        )

    def _open_tls_socket(self):
        raw = socket.create_connection(
            ("127.0.0.1", self.server.server_port),
            timeout=2,
        )
        return self.client_context.wrap_socket(raw, server_hostname="127.0.0.1")

    def _assert_recovered_delivery(self):
        self._wait_for_slots(8)
        receipt = send_spooled_event(
            self.event,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            spool=self.spool,
            timeout=3,
        )
        self.assertEqual(receipt["outcome"], "accepted")
        self.assertEqual(self.spool.pending(), [])

    @staticmethod
    def _stop_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    def _request(self, context, body, *, path="/v1/events", method="POST", headers=None):
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            self.server.server_port,
            context=context,
            timeout=3,
        )
        try:
            request_headers = {"Content-Type": "application/json"}
            if headers:
                request_headers.update(headers)
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            return response.status, response.read(4097)
        finally:
            connection.close()

    def _second_client_context(self):
        return create_client_tls_context(
            server_ca_file=self.ca_certificate_file,
            certificate_file=self.second_client_certificate_file,
            private_key_file=self.second_client_key_file,
        )

    def _event_for_machine(self, machine_id, event_id):
        event = dict(self.event)
        event["machine_id"] = machine_id
        event["event_id"] = event_id
        return event

    def _replace_server_rate_limiter(self, limiter):
        self._stop_server(self.server, self.server_thread)
        self.server, self.server_thread = self._start_server(
            self.server_context,
            rate_limiter=limiter,
        )

    def _assert_tls_handshake_rejected(self, context):
        with self.assertRaises(
            (ssl.SSLError, OSError, http.client.HTTPException, TransportError)
        ):
            send_spooled_event(
                self.event,
                port=self.server.server_port,
                tls_context=context,
                receipt_verifier=self.receipt_verifier,
                spool=self.spool,
                timeout=3,
            )
        self.assertEqual(self.store.history("laptop-1"), [])
        self.assertEqual(self.spool.pending(), [self.event])

    def test_valid_delivery_uses_verified_peer_and_acknowledges_signed_receipt(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        receipt = send_spooled_event(
            self.event,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            spool=self.spool,
        )
        self.assertEqual(receipt["outcome"], "accepted")
        self.assertEqual(self.store.history("laptop-1")[0]["event"], self.event)
        self.assertEqual(self.spool.pending(), [])

    def test_sender_recovers_from_offline_state_after_restart(self):
        now = datetime.now(timezone.utc)
        first_port = self.server.server_port
        self._stop_server(self.server, self.server_thread)
        current_time = [now]
        sender = DurableEventSender(
            self.spool,
            port=first_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            timeout_seconds=0.5,
            base_backoff_seconds=1,
            max_backoff_seconds=10,
            jitter_fraction=0,
            wall_clock=lambda: current_time[0],
            monotonic_clock=lambda: current_time[0].timestamp(),
            random_value=lambda: 0,
        )
        failed = sender.run_once()
        self.assertEqual((failed.attempted, failed.delivered, failed.deferred), (1, 0, 1))
        self.assertEqual(self.spool.pending(), [self.event])
        self.assertEqual(self.spool.due_pending(now=now), [])

        self.server, self.server_thread = self._start_server(self.server_context)
        restarted_sender = DurableEventSender(
            self.spool,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            timeout_seconds=3,
            base_backoff_seconds=1,
            max_backoff_seconds=10,
            jitter_fraction=0,
            wall_clock=lambda: current_time[0],
            monotonic_clock=lambda: current_time[0].timestamp(),
            random_value=lambda: 0,
        )
        not_yet_due = restarted_sender.run_once()
        self.assertEqual(not_yet_due.attempted, 0)
        current_time[0] += timedelta(seconds=1)
        recovered = restarted_sender.run_once()
        self.assertEqual((recovered.attempted, recovered.delivered, recovered.deferred), (1, 1, 0))
        self.assertEqual(self.spool.pending(), [])
        self.assertEqual(self.store.history("laptop-1")[0]["event"], self.event)

    def test_sender_retries_lost_response_and_acknowledges_duplicate_receipt(self):
        now = [datetime.now(timezone.utc)]
        outcomes = []
        original_send_json = _IngestionHandler._send_json

        def drop_first_successful_response(handler, status, value, *, headers=None):
            if status == 200:
                outcomes.append(value["outcome"])
                if len(outcomes) == 1:
                    handler.connection.shutdown(socket.SHUT_RDWR)
                    handler.connection.close()
                    return
            original_send_json(handler, status, value, headers=headers)

        sender = DurableEventSender(
            self.spool,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            timeout_seconds=3,
            base_backoff_seconds=1,
            max_backoff_seconds=10,
            jitter_fraction=0,
            wall_clock=lambda: now[0],
            monotonic_clock=lambda: now[0].timestamp(),
            random_value=lambda: 0,
        )
        with patch.object(_IngestionHandler, "_send_json", drop_first_successful_response):
            failed = sender.run_once()
            self.assertEqual((failed.attempted, failed.delivered, failed.deferred), (1, 0, 1))
            self.assertEqual(len(self.store.history("laptop-1")), 1)
            self.assertEqual(self.spool.pending(), [self.event])
            now[0] += timedelta(seconds=1)
            recovered = sender.run_once()

        self.assertEqual((recovered.attempted, recovered.delivered, recovered.deferred), (1, 1, 0))
        self.assertEqual(outcomes, ["accepted", "duplicate"])
        self.assertEqual(len(self.store.history("laptop-1")), 1)
        self.assertEqual(self.spool.pending(), [])

    def test_direct_transport_helper_cannot_bypass_sender_ownership(self):
        entered = threading.Event()
        release = threading.Event()
        failures = []

        def blocked_sender_attempt(*args, **kwargs):
            entered.set()
            if not release.wait(timeout=5):
                raise TimeoutError("sender test was not released")
            raise OSError("synthetic offline response")

        sender = DurableEventSender(
            self.spool,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            wall_clock=lambda: datetime.now(timezone.utc),
            timeout_seconds=2,
        )

        def run_sender():
            try:
                sender.run_once()
            except Exception as error:
                failures.append(error)

        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=blocked_sender_attempt,
        ):
            thread = threading.Thread(target=run_sender)
            thread.start()
            self.assertTrue(entered.wait(timeout=5))
            with self.assertRaisesRegex(SpoolError, "another sender run owns"):
                send_spooled_event(
                    self.event,
                    port=self.server.server_port,
                    tls_context=self.client_context,
                    receipt_verifier=self.receipt_verifier,
                    spool=self.spool,
                )
            self.assertEqual(self.spool.pending(), [self.event])
            release.set()
            thread.join(timeout=5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(self.store.history("laptop-1"), [])
        self.assertEqual(self.spool.pending(), [self.event])

    def test_same_thread_direct_helper_cannot_inherit_sender_owner_token(self):
        rejected = []

        def nested_direct_send(*args, **kwargs):
            try:
                send_spooled_event(
                    self.event,
                    port=self.server.server_port,
                    tls_context=self.client_context,
                    receipt_verifier=self.receipt_verifier,
                    spool=self.spool,
                )
            except Exception as error:
                rejected.append(error)
            raise OSError("outer sender remains pending")

        sender = DurableEventSender(
            self.spool,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            wall_clock=lambda: datetime.now(timezone.utc),
            timeout_seconds=2,
        )
        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=nested_direct_send,
        ) as send:
            result = sender.run_once()

        self.assertEqual(result.deferred, 1)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(len(rejected), 1)
        self.assertIsInstance(rejected[0], SpoolError)
        self.assertEqual(self.store.history("laptop-1"), [])
        self.assertEqual(self.spool.pending(), [self.event])

    def test_sender_handles_http_429_retry_after_without_acknowledging(self):
        rate_clock = _FakeClock()
        self._replace_server_rate_limiter(
            _RequestRateLimiter(
                global_limit=1,
                per_certificate_limit=10,
                window_seconds=10,
                clock=rate_clock,
            )
        )
        status, _ = self._request(
            self.client_context,
            canonical_json(self.event).encode("utf-8"),
        )
        self.assertEqual(status, 200)

        now = datetime.now(timezone.utc)
        sender = DurableEventSender(
            self.spool,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            timeout_seconds=3,
            base_backoff_seconds=1,
            max_backoff_seconds=10,
            jitter_fraction=0,
            wall_clock=lambda: now,
            monotonic_clock=lambda: now.timestamp(),
            random_value=lambda: 0,
        )
        result = sender.run_once()
        self.assertEqual((result.attempted, result.delivered, result.deferred), (1, 0, 1))
        self.assertEqual(self.spool.pending(), [self.event])
        self.assertEqual(self.spool.due_pending(now=now), [])

    def test_sender_handles_http_503_without_acknowledging(self):
        now = datetime.now(timezone.utc)
        sender = DurableEventSender(
            self.spool,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            timeout_seconds=3,
            base_backoff_seconds=2,
            max_backoff_seconds=10,
            jitter_fraction=0,
            wall_clock=lambda: now,
            monotonic_clock=lambda: now.timestamp(),
            random_value=lambda: 0,
        )
        with patch.object(
            self.service,
            "ingest_verified_tls_connection",
            side_effect=StoreError("synthetic commit outage"),
        ):
            result = sender.run_once()

        self.assertEqual((result.attempted, result.delivered, result.deferred), (1, 0, 1))
        self.assertEqual(self.spool.pending(), [self.event])
        self.assertEqual(self.spool.due_pending(now=now), [])

    def test_missing_client_certificate_is_rejected_during_tls_handshake(self):
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=self.ca_certificate_file,
        )
        context.check_hostname = True
        self._assert_tls_handshake_rejected(context)

    def test_untrusted_client_certificate_is_rejected_during_tls_handshake(self):
        context = create_client_tls_context(
            server_ca_file=self.ca_certificate_file,
            certificate_file=self.untrusted_client_certificate_file,
            private_key_file=self.untrusted_client_key_file,
        )
        self._assert_tls_handshake_rejected(context)

    def test_wrong_purpose_client_certificate_is_rejected_during_tls_handshake(self):
        wrong_fingerprint = self.server_only_client_certificate.fingerprint(
            hashes.SHA256()
        ).hex()
        now = datetime.now(timezone.utc)
        self.registry.enroll(
            "laptop-1",
            CertificateCredential(
                wrong_fingerprint,
                now - timedelta(days=1),
                now + timedelta(days=2),
            ),
            allow_overlap=True,
            overlap_until=now + timedelta(hours=1),
        )
        context = create_client_tls_context(
            server_ca_file=self.ca_certificate_file,
            certificate_file=self.server_only_client_certificate_file,
            private_key_file=self.server_only_client_key_file,
        )
        self._assert_tls_handshake_rejected(context)

    def test_revoked_identity_is_rejected_before_ingestion(self):
        self.registry.revoke(
            self.client_certificate.fingerprint(hashes.SHA256()).hex()
        )
        with self.assertRaisesRegex(TransportError, "HTTP 403"):
            send_spooled_event(
                self.event,
                port=self.server.server_port,
                tls_context=self.client_context,
                receipt_verifier=self.receipt_verifier,
                spool=self.spool,
            )
        self.assertEqual(self.store.history("laptop-1"), [])
        self.assertEqual(self.spool.pending(), [self.event])

    def test_event_machine_id_must_match_verified_certificate_identity(self):
        mismatched = dict(self.event)
        mismatched["machine_id"] = "other-machine"
        mismatched["event_id"] = "other-machine:1"
        status, _ = self._request(
            self.client_context,
            canonical_json(mismatched).encode("utf-8"),
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.store.history("laptop-1"), [])
        self.assertEqual(self.spool.pending(), [self.event])

    def test_malformed_and_oversized_bodies_are_rejected_without_commit(self):
        malformed_status, _ = self._request(self.client_context, b'{"protocol_version":')
        self.assertEqual(malformed_status, 400)
        oversized_status, _ = self._request(
            self.client_context,
            b"x" * (MAX_EVENT_BYTES + 1),
        )
        self.assertEqual(oversized_status, 413)
        self.assertEqual(self.store.history("laptop-1"), [])

    def test_wrong_path_and_method_are_rejected(self):
        for path in ("/dashboard", "/search/start", "/v1/search/control"):
            with self.subTest(path=path):
                status, _ = self._request(
                    self.client_context,
                    canonical_json(self.event).encode("utf-8"),
                    path=path,
                )
                self.assertEqual(status, 404)
        status, _ = self._request(
            self.client_context,
            b"",
            method="GET",
        )
        self.assertEqual(status, 405)
        self.assertEqual(self.store.history("laptop-1"), [])

    def test_header_bytes_and_count_are_bounded(self):
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            self.server.server_port,
            context=self.client_context,
            timeout=3,
        )
        try:
            connection.putrequest("POST", "/v1/events")
            for index in range(32):
                connection.putheader(f"X-Test-{index}", "x")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "2")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 431)
            response.read()
        finally:
            connection.close()
        self.assertEqual(self.store.history("laptop-1"), [])

    def test_ambiguous_content_length_is_rejected(self):
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            self.server.server_port,
            context=self.client_context,
            timeout=3,
        )
        try:
            connection.putrequest("POST", "/v1/events")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "2")
            connection.putheader("Content-Length", "2")
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        finally:
            connection.close()
        self.assertEqual(self.store.history("laptop-1"), [])

    def test_wrong_server_ip_identity_is_rejected_by_client(self):
        wrong_server_key = ec.generate_private_key(ec.SECP256R1())
        wrong_server_certificate = _issue_certificate(
            "wrong-server",
            wrong_server_key.public_key(),
            self.ca_certificate,
            self.ca_key,
            extended_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
            subject_alt_names=[x509.DNSName("wrong.example")],
        )
        certificate_file, key_file = _write_certificate(
            self.directory, "wrong-server", wrong_server_certificate, wrong_server_key
        )
        context = create_server_tls_context(
            certificate_file=certificate_file,
            private_key_file=key_file,
            client_ca_file=self.ca_certificate_file,
        )
        second_server, second_thread = self._start_server(context)
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                send_spooled_event(
                    self.event,
                    port=second_server.server_port,
                    tls_context=self.client_context,
                    receipt_verifier=self.receipt_verifier,
                    spool=self.spool,
                )
        finally:
            self._stop_server(second_server, second_thread)
        self.assertEqual(self.store.history("laptop-1"), [])
        self.assertEqual(self.spool.pending(), [self.event])

    def test_lost_ack_retry_returns_duplicate_receipt_then_acks(self):
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            self.server.server_port,
            context=self.client_context,
            timeout=3,
        )
        connection.request(
            "POST",
            "/v1/events",
            body=canonical_json(self.event).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        deadline = time.monotonic() + 2
        while not self.store.history("laptop-1") and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(len(self.store.history("laptop-1")), 1)
        connection.close()
        self.assertEqual(self.spool.pending(), [self.event])

        receipt = send_spooled_event(
            self.event,
            port=self.server.server_port,
            tls_context=self.client_context,
            receipt_verifier=self.receipt_verifier,
            spool=self.spool,
        )
        self.assertEqual(receipt["outcome"], "duplicate")
        self.assertEqual(len(self.store.history("laptop-1")), 1)
        self.assertEqual(self.spool.pending(), [])

    def test_per_certificate_limit_and_window_recovery(self):
        clock = _FakeClock()
        self._replace_server_rate_limiter(_RequestRateLimiter(
            global_limit=3,
            per_certificate_limit=1,
            window_seconds=10,
            clock=clock,
        ))
        body_a = canonical_json(self.event).encode("utf-8")
        body_b = canonical_json(
            self._event_for_machine("laptop-2", "laptop-2:1")
        ).encode("utf-8")

        self.assertEqual(self._request(self.client_context, body_a)[0], 200)
        throttled_status, _ = self._request(self.client_context, body_a)
        self.assertEqual(throttled_status, 429)
        self.assertEqual(self._request(self._second_client_context(), body_b)[0], 200)

        clock.now += 10.1
        self.assertEqual(self._request(self.client_context, body_a)[0], 200)

    def test_global_limit_applies_across_certificates_and_recovers(self):
        clock = _FakeClock()
        self._replace_server_rate_limiter(_RequestRateLimiter(
            global_limit=2,
            per_certificate_limit=2,
            window_seconds=10,
            clock=clock,
        ))
        body_a = canonical_json(self.event).encode("utf-8")
        body_b = canonical_json(
            self._event_for_machine("laptop-2", "laptop-2:1")
        ).encode("utf-8")

        self.assertEqual(self._request(self.client_context, body_a)[0], 200)
        self.assertEqual(self._request(self._second_client_context(), body_b)[0], 200)
        self.assertEqual(self._request(self.client_context, body_a)[0], 429)
        clock.now += 10.1
        self.assertEqual(self._request(self.client_context, body_a)[0], 200)

    def test_forged_machine_id_and_headers_cannot_bypass_certificate_quota(self):
        clock = _FakeClock()
        self._replace_server_rate_limiter(_RequestRateLimiter(
            global_limit=5,
            per_certificate_limit=1,
            window_seconds=10,
            clock=clock,
        ))
        mismatched = self._event_for_machine("laptop-2", "laptop-2:1")
        status, _ = self._request(
            self.client_context,
            canonical_json(mismatched).encode("utf-8"),
            headers={
                "X-Machine-ID": "laptop-2",
                "X-Certificate-Fingerprint": "f" * 64,
            },
        )
        self.assertEqual(status, 403)

        status, _ = self._request(
            self.client_context,
            canonical_json(self.event).encode("utf-8"),
            headers={
                "X-Machine-ID": "laptop-2",
                "X-Certificate-Fingerprint": "f" * 64,
            },
        )
        self.assertEqual(status, 429)

        clock.now += 10.1
        self.assertEqual(
            self._request(
                self.client_context,
                canonical_json(self.event).encode("utf-8"),
                headers={
                    "X-Machine-ID": "laptop-2",
                    "X-Certificate-Fingerprint": "f" * 64,
                },
            )[0],
            200,
        )
        self.assertEqual(self.store.history("laptop-2"), [])

    def test_unknown_and_revoked_certificates_do_not_consume_global_quota(self):
        clock = _FakeClock()
        self._replace_server_rate_limiter(_RequestRateLimiter(
            global_limit=1,
            per_certificate_limit=1,
            window_seconds=10,
            clock=clock,
        ))
        self.registry.revoke(
            self.client_certificate.fingerprint(hashes.SHA256()).hex()
        )
        body_a = canonical_json(self.event).encode("utf-8")
        body_b = canonical_json(
            self._event_for_machine("laptop-2", "laptop-2:1")
        ).encode("utf-8")
        unregistered_context = create_client_tls_context(
            server_ca_file=self.ca_certificate_file,
            certificate_file=self.unregistered_client_certificate_file,
            private_key_file=self.unregistered_client_key_file,
        )
        self.assertEqual(self._request(unregistered_context, body_a)[0], 403)
        self.assertEqual(self._request(self.client_context, body_a)[0], 403)
        self.assertEqual(self._request(self._second_client_context(), body_b)[0], 200)

    def test_altered_receipt_does_not_ack_pending_event(self):
        original_send_json = _IngestionHandler._send_json

        def send_altered(handler, status, value, *, headers=None):
            if status == 200:
                altered = dict(value)
                altered["signature"] = "0" * 128
                value = altered
            return original_send_json(handler, status, value, headers=headers)

        with patch.object(_IngestionHandler, "_send_json", new=send_altered):
            with self.assertRaisesRegex(TransportError, "invalid committed receipt"):
                send_spooled_event(
                    self.event,
                    port=self.server.server_port,
                    tls_context=self.client_context,
                    receipt_verifier=self.receipt_verifier,
                    spool=self.spool,
                )
        self.assertEqual(len(self.store.history("laptop-1")), 1)
        self.assertEqual(self.spool.pending(), [self.event])

    def test_store_commit_failure_returns_no_receipt_and_leaves_event_pending(self):
        with patch.object(self.store, "ingest", side_effect=StoreError("synthetic failure")):
            status, _ = self._request(
                self.client_context,
                canonical_json(self.event).encode("utf-8"),
            )
        self.assertEqual(status, 503)
        self.assertEqual(self.store.history("laptop-1"), [])
        self.assertEqual(self.spool.pending(), [self.event])

    def test_stalled_handshakes_are_admitted_off_accept_loop_and_release_capacity(self):
        held_sockets = []
        try:
            for _ in range(8):
                held_sockets.append(
                    socket.create_connection(
                        ("127.0.0.1", self.server.server_port),
                        timeout=2,
                    )
                )
            deadline = time.monotonic() + 2
            while (
                self.server._connection_slots._value != 0
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertEqual(self.server._connection_slots._value, 0)

            rejected_before = self.server._rejected_connections
            overflow = socket.create_connection(
                ("127.0.0.1", self.server.server_port),
                timeout=2,
            )
            overflow.settimeout(2)
            deadline = time.monotonic() + 2
            while (
                self.server._rejected_connections == rejected_before
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertEqual(
                self.server._rejected_connections,
                rejected_before + 1,
            )
            self.assertEqual(overflow.recv(1), b"")
            overflow.close()

            started = time.monotonic()
            while (
                self.server._connection_slots._value != 8
                and time.monotonic() - started < 2
            ):
                time.sleep(0.01)
            self.assertEqual(self.server._connection_slots._value, 8)
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(self.store.history("laptop-1"), [])
        finally:
            for held in held_sockets:
                held.close()
        self._assert_recovered_delivery()

    def test_slow_drip_headers_hit_absolute_deadline_and_server_recovers(self):
        connection = self._open_tls_socket()
        started = time.monotonic()
        try:
            connection.sendall(
                b"POST /v1/events HTTP/1.0\r\nHost: localhost\r\nX-Slow: "
            )
            while time.monotonic() - started < 1.2:
                try:
                    connection.sendall(b"x")
                except (OSError, ssl.SSLError):
                    break
                time.sleep(0.15)
            connection.settimeout(1)
            try:
                self.assertEqual(connection.recv(1), b"")
            except (OSError, ssl.SSLError):
                pass
        finally:
            connection.close()
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.store.history("laptop-1"), [])
        self._assert_recovered_delivery()

    def test_slow_drip_body_hits_absolute_deadline_without_partial_ingestion(self):
        body = canonical_json(self.event).encode("utf-8")
        connection = self._open_tls_socket()
        started = time.monotonic()
        try:
            headers = (
                b"POST /v1/events HTTP/1.0\r\n"
                b"Host: localhost\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
            )
            connection.sendall(headers + body[:1])
            sent = 1
            while sent < len(body) and time.monotonic() - started < 1.2:
                try:
                    connection.sendall(body[sent:sent + 1])
                except (OSError, ssl.SSLError):
                    break
                sent += 1
                time.sleep(0.15)
            connection.settimeout(1)
            try:
                self.assertEqual(connection.recv(1), b"")
            except (OSError, ssl.SSLError):
                pass
        finally:
            connection.close()
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(self.store.history("laptop-1"), [])
        self._assert_recovered_delivery()


if __name__ == "__main__":
    unittest.main()
