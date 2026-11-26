import http.client
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_monitor.agent_runner import PassiveAgentRunner
from genesis_monitor.collector import LogCollector
from genesis_monitor.dashboard import write_dashboard_snapshot
from genesis_monitor.identity import CertificateCredential, CertificateIdentityRegistry
from genesis_monitor.ingestion import GenesisIngestionService
from genesis_monitor.private_ingress import PrivateIngressConfig
from genesis_monitor.protocol import canonical_json
from genesis_monitor.receipts import (
    CommittedReceiptSigner,
    CommittedReceiptVerifier,
    trust_bundle_from_public_keys,
)
from genesis_monitor.sender import DurableEventSender
from genesis_monitor.spool import EventSpool
from genesis_monitor.store import CentralStore
from genesis_monitor.transport import (
    LoopbackMTLSServer,
    create_client_tls_context,
    create_server_tls_context,
)
from genesis_monitor.verification import FoundVerifier, SUPPORTED_CONSENSUS
from tests.test_checkpoint import checkpoint_fixture
from tests.test_transport import _issue_certificate, _write_certificate


class SyntheticPilotIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="vaqyron-pilot-")
        self.addCleanup(self.tempdir.cleanup)
        self.directory = Path(self.tempdir.name)
        self.server = None
        self.server_thread = None
        self._create_test_pki()

        now = datetime.now(timezone.utc)
        self.registry = CertificateIdentityRegistry.bootstrap(
            self.directory / "identity.sqlite"
        )
        for machine_id, certificate in (
            ("dell-pilot", self.dell_certificate),
            ("acer-pilot", self.acer_certificate),
        ):
            self.registry.enroll(
                machine_id,
                CertificateCredential(
                    certificate.fingerprint(hashes.SHA256()).hex(),
                    now - timedelta(days=1),
                    now + timedelta(days=2),
                ),
            )

        self.store = CentralStore(self.directory / "central.sqlite")
        self.search_configuration = {
            **SUPPORTED_CONSENSUS,
            "start_nonce": 541696,
            "end_nonce": 541700,
            "requested_worker_count": 1,
        }
        self.store.register_machine(
            "dell-pilot", "Dell synthetic", search_configuration=self.search_configuration
        )
        self.store.register_machine("acer-pilot", "Acer synthetic")

        receipt_key = Ed25519PrivateKey.generate()
        receipt_bundle = trust_bundle_from_public_keys({
            "pilot-receipt-key": (
                receipt_key.public_key(),
                now - timedelta(days=1),
                now + timedelta(days=2),
                False,
            )
        })
        self.receipt_signer = CommittedReceiptSigner(
            {"pilot-receipt-key": receipt_key},
            active_key_id="pilot-receipt-key",
            trust_bundle=receipt_bundle,
        )
        self.receipt_verifier = CommittedReceiptVerifier(receipt_bundle)
        service = GenesisIngestionService(
            self.registry, self.store, self.receipt_signer
        )
        self.server_context = create_server_tls_context(
            certificate_file=self.server_certificate_file,
            private_key_file=self.server_key_file,
            client_ca_file=self.ca_certificate_file,
        )
        self.dell_context = create_client_tls_context(
            server_ca_file=self.ca_certificate_file,
            certificate_file=self.dell_certificate_file,
            private_key_file=self.dell_key_file,
        )
        self.acer_context = create_client_tls_context(
            server_ca_file=self.ca_certificate_file,
            certificate_file=self.acer_certificate_file,
            private_key_file=self.acer_key_file,
        )
        self.service = service
        self._start_server()

    def tearDown(self):
        self._stop_server()
        self.tempdir.cleanup()

    def _create_test_pki(self):
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_certificate = _issue_certificate(
            "pilot-test-root", ca_key.public_key(), None, ca_key, is_ca=True
        )
        self.ca_certificate_file, _ = _write_certificate(
            self.directory, "pilot-root", ca_certificate, ca_key
        )

        server_key = ec.generate_private_key(ec.SECP256R1())
        server_certificate = _issue_certificate(
            "pilot-test-server",
            server_key.public_key(),
            ca_certificate,
            ca_key,
            extended_usage=[ExtendedKeyUsageOID.SERVER_AUTH],
            subject_alt_names=[
                x509.IPAddress(ip_address("127.0.0.1")),
                x509.DNSName("localhost"),
            ],
        )
        self.server_certificate_file, self.server_key_file = _write_certificate(
            self.directory, "pilot-server", server_certificate, server_key
        )

        self.dell_certificate, self.dell_key = self._client_certificate(
            "dell-pilot-client", ca_certificate, ca_key
        )
        self.dell_certificate_file, self.dell_key_file = _write_certificate(
            self.directory, "dell-client", self.dell_certificate, self.dell_key
        )
        self.acer_certificate, self.acer_key = self._client_certificate(
            "acer-pilot-client", ca_certificate, ca_key
        )
        self.acer_certificate_file, self.acer_key_file = _write_certificate(
            self.directory, "acer-client", self.acer_certificate, self.acer_key
        )

    @staticmethod
    def _client_certificate(common_name, ca_certificate, ca_key):
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = _issue_certificate(
            common_name,
            key.public_key(),
            ca_certificate,
            ca_key,
            extended_usage=[ExtendedKeyUsageOID.CLIENT_AUTH],
        )
        return certificate, key

    def _start_server(self):
        self.server = LoopbackMTLSServer(
            tls_context=self.server_context,
            ingestion_service=self.service,
            request_deadline_seconds=3,
        )
        self.server_thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.02},
            daemon=True,
        )
        self.server_thread.start()

    def _stop_server(self):
        if self.server is None:
            return
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=3)
        self.assertFalse(self.server_thread.is_alive())
        self.server = None
        self.server_thread = None

    def _collect_event(self, machine_id, checkpoint_path, observed_at, sequence=1):
        is_dell = machine_id == "dell-pilot"
        start, end = (541696, 541700) if is_dell else (100, 107)
        result = "FOUND" if is_dell else "NOT FOUND"
        log_text = (
            f"nTime: {SUPPORTED_CONSENSUS['time']}\n"
            f"SEARCH START NONCE: {start}\n"
            f"SEARCH END NONCE: {end}\n"
            "SEARCH WORKERS: 1\n"
            f"WORKER RANGE 0: {start}..{end}\n"
            f"Progress: worker=0 range={start}..{end} nonce={start} "
            "candidates=5 elapsed_seconds=1.0 candidates_per_second=5.0\n"
            "CANDIDATES EVALUATED: 5\n"
            "CANDIDATES PER SECOND: 5.0\n"
            f"RESULT: {result}\n"
        )
        if is_dell:
            log_text += (
                f"NONCE: {start}\n"
                f"SHA256d BLOCK_ID: {'a' * 64}\n"
                f"POW_DIGEST (raw): {'b' * 64}\n"
            )
        log_path = self.directory / f"{machine_id}.log"
        log_path.write_text(log_text, encoding="utf-8")
        payload = LogCollector().collect(
            log_path,
            checkpoint_path,
            observed_at=observed_at,
        )
        spool = EventSpool(
            self.directory / f"{machine_id}-spool.sqlite",
            receipt_verifier=self.receipt_verifier,
        )
        event, duplicate = spool.enqueue(
            machine_id,
            observed_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            payload,
            f"{machine_id}-pilot-event-{sequence}",
        )
        self.assertFalse(duplicate)
        return spool, event

    def _sender(self, spool, context, port, wall, monotonic):
        return DurableEventSender(
            spool,
            port=port,
            tls_context=context,
            receipt_verifier=self.receipt_verifier,
            timeout_seconds=1,
            base_backoff_seconds=1,
            max_backoff_seconds=1,
            jitter_fraction=0,
            wall_clock=lambda: wall[0],
            monotonic_clock=lambda: monotonic[0],
            random_value=lambda: 0,
        )

    def _post_event(self, event, context):
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            self.server.server_port,
            context=context,
            timeout=3,
        )
        try:
            connection.request(
                "POST",
                "/v1/events",
                body=canonical_json(event).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read(4097))
        finally:
            connection.close()

    def test_two_machine_synthetic_delivery_recovery_identity_and_dashboard(self):
        observed_at = datetime.now(timezone.utc)
        stale_checkpoint = self.directory / "dell.chk"
        stale_checkpoint.write_bytes(checkpoint_fixture())
        stale_time = time.time() - 60
        os.utime(stale_checkpoint, (stale_time, stale_time))
        missing_checkpoint = self.directory / "acer-missing.chk"
        dell_spool, dell_event = self._collect_event(
            "dell-pilot", stale_checkpoint, observed_at
        )
        acer_spool, acer_event = self._collect_event(
            "acer-pilot", missing_checkpoint, observed_at
        )

        initial_port = self.server.server_port
        self._stop_server()
        wall = [observed_at]
        monotonic = [100.0]
        initial_results = []
        for spool, context in (
            (dell_spool, self.dell_context),
            (acer_spool, self.acer_context),
        ):
            result = self._sender(
                spool, context, initial_port, wall, monotonic
            ).run_once()
            initial_results.append(result)
            self.assertEqual((result.attempted, result.delivered, result.deferred), (1, 0, 1))
            self.assertEqual(len(spool.pending()), 1)

        self.assertEqual(
            sum(len(spool.pending()) for spool in (dell_spool, acer_spool)),
            2,
        )
        dell_spool = EventSpool(
            self.directory / "dell-pilot-spool.sqlite",
            receipt_verifier=self.receipt_verifier,
        )
        acer_spool = EventSpool(
            self.directory / "acer-pilot-spool.sqlite",
            receipt_verifier=self.receipt_verifier,
        )
        self._start_server()
        for event, context in (
            (dell_event, self.dell_context),
            (acer_event, self.acer_context),
        ):
            accepted_status, _lost_receipt = self._post_event(event, context)
            self.assertEqual(accepted_status, 200)
        wall[0] += timedelta(seconds=2)
        monotonic[0] += 2
        recovered = [
            self._sender(
                spool, context, self.server.server_port, wall, monotonic
            ).run_once()
            for spool, context in (
                (dell_spool, self.dell_context),
                (acer_spool, self.acer_context),
            )
        ]
        self.assertEqual(
            [(result.attempted, result.delivered, result.deferred) for result in recovered],
            [(1, 1, 0), (1, 1, 0)],
        )
        self.assertEqual(dell_spool.pending(), [])
        self.assertEqual(acer_spool.pending(), [])
        self.assertEqual(len(self.store.history("dell-pilot")), 1)
        self.assertEqual(len(self.store.history("acer-pilot")), 1)

        status, duplicate_receipt = self._post_event(dell_event, self.dell_context)
        self.assertEqual(status, 200)
        self.assertEqual(duplicate_receipt["outcome"], "duplicate")
        self.receipt_verifier.verify(duplicate_receipt, dell_event)
        self.assertEqual(len(self.store.history("dell-pilot")), 1)

        mismatch_status, _ = self._post_event(dell_event, self.acer_context)
        self.assertEqual(mismatch_status, 403)
        self.assertEqual(len(self.store.history("dell-pilot")), 1)
        self.registry.revoke(
            self.acer_certificate.fingerprint(hashes.SHA256()).hex()
        )
        revoked_status, _ = self._post_event(acer_event, self.acer_context)
        self.assertEqual(revoked_status, 403)
        self.assertEqual(len(self.store.history("acer-pilot")), 1)

        snapshot_now = datetime.now(timezone.utc)
        snapshot = self.store.snapshot(
            now=snapshot_now,
            checkpoint_timeout_seconds=15,
        )
        machines = {machine["machine_id"]: machine for machine in snapshot["machines"]}
        self.assertEqual(machines["dell-pilot"]["ingestion_status"], "recent")
        self.assertEqual(machines["dell-pilot"]["checkpoint_age_status"], "stale")
        self.assertGreaterEqual(machines["dell-pilot"]["checkpoint_age_seconds"], 59)
        self.assertEqual(machines["acer-pilot"]["checkpoint_age_status"], "unavailable")
        self.assertEqual(machines["acer-pilot"]["ingestion_status"], "recent")
        with self.assertRaisesRegex(ValueError, "checkpoint_timeout_seconds"):
            self.store.snapshot(
                now=snapshot_now,
                checkpoint_timeout_seconds=float("nan"),
            )

        dashboard_path = self.directory / "dashboard.html"
        write_dashboard_snapshot(snapshot, str(dashboard_path))
        dashboard = dashboard_path.read_text(encoding="utf-8")
        self.assertIn('"checkpoint_age_status": "stale"', dashboard)
        self.assertIn('"checkpoint_age_status": "unavailable"', dashboard)
        self.assertIn("accepted local ingestion, not authenticated remote-agent presence", dashboard)
        self.assertIn('"ingestion_status": "recent"', dashboard)
        self.assertIn('"aggregate_candidates_per_second": 5.0', dashboard)
        self.assertIn('"current_nonce": 541696', dashboard)
        self.assertNotIn("<script src=", dashboard)
        self.assertNotIn("http://", dashboard)
        self.assertNotIn("https://", dashboard)
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertFalse(PrivateIngressConfig.listener_available)

        os.utime(stale_checkpoint, None)
        fresh_observed_at = datetime.now(timezone.utc)
        refreshed_spool, _ = self._collect_event(
            "dell-pilot",
            stale_checkpoint,
            fresh_observed_at,
            sequence=2,
        )
        refreshed = self._sender(
            refreshed_spool,
            self.dell_context,
            self.server.server_port,
            [fresh_observed_at],
            [200.0],
        ).run_once()
        self.assertEqual((refreshed.attempted, refreshed.delivered, refreshed.deferred), (1, 1, 0))
        self.assertEqual(refreshed_spool.pending(), [])
        self.assertEqual(len(self.store.history("dell-pilot")), 2)
        valid_snapshot = self.store.snapshot(
            now=datetime.now(timezone.utc),
            checkpoint_timeout_seconds=15,
        )
        valid_dashboard_path = self.directory / "dashboard-valid-checkpoint.html"
        write_dashboard_snapshot(valid_snapshot, str(valid_dashboard_path))
        valid_dashboard = valid_dashboard_path.read_text(encoding="utf-8")
        self.assertIn('"checkpoint_age_status": "available"', valid_dashboard)
        self.assertIn('"checkpoint_age_status": "unavailable"', valid_dashboard)
        self.assertIn('"ingestion_status": "recent"', valid_dashboard)

        verifier_script = self.directory / "synthetic-found-verifier.py"
        verifier_script.touch()
        synthetic_helper = self.directory / "unused-synthetic-helper.exe"
        synthetic_helper.touch()
        verifier = FoundVerifier(
            self.store,
            verifier_script=verifier_script,
            yespower_cli=synthetic_helper,
        )
        verification_now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        outcomes = []
        verification_records = []
        passed_result = {
            "nonce": 541696,
            "time": SUPPORTED_CONSENSUS["time"],
            "version": SUPPORTED_CONSENSUS["block_version"],
            "bits": f'{SUPPORTED_CONSENSUS["nbits"]:08x}',
            "block_id": "a" * 64,
            "pow_digest_raw": "b" * 64,
            "candidate_valid": True,
            "pow_valid": True,
            "target_valid": True,
            "result": "PASS",
        }
        rejected_result = {
            **passed_result,
            "nonce": 541697,
            "block_id": "f" * 64,
            "candidate_valid": False,
            "pow_valid": False,
            "target_valid": False,
            "result": "FAIL",
        }
        def synthetic_verifier(command, **kwargs):
            nonce = int(command[command.index("--nonce") + 1])
            if nonce == 541696:
                return SimpleNamespace(
                    returncode=0,
                    stdout=json.dumps(passed_result).encode("utf-8"),
                    stderr=b"",
                )
            if nonce == 541697:
                return SimpleNamespace(
                    returncode=1,
                    stdout=json.dumps(rejected_result).encode("utf-8"),
                    stderr=b"synthetic candidate rejected",
                )
            raise subprocess.TimeoutExpired(["synthetic-verifier"], 15)
        for sequence, nonce, block_hash, digest in (
            (3, 541696, "a" * 64, "b" * 64),
            (4, 541697, "c" * 64, "d" * 64),
            (5, 541698, "e" * 64, "f" * 64),
        ):
            event = json.loads(json.dumps(dell_event))
            event["sequence"] = sequence
            event["event_id"] = f"dell-pilot:synthetic-found-{sequence}"
            event["observed_at"] = verification_now
            candidate = event["payload"]["log"]["found_candidate"]
            candidate.update({
                "nonce": nonce,
                "block_hash": block_hash,
                "pow_digest_raw": digest,
                "timestamp": verification_now,
            })
            event["payload"]["log"]["workers"][0]["current_nonce"] = nonce
            self.store.ingest(
                event,
                authenticated_machine_id="dell-pilot",
                received_at=verification_now,
            )
            with patch(
                "genesis_monitor.verification._run_bounded_process",
                side_effect=synthetic_verifier,
            ):
                records = verifier.verify_event(
                    "dell-pilot",
                    event["event_id"],
                    now=verification_now,
                )
            self.assertEqual(len(records), 1)
            outcomes.append(records[0]["status"])
            verification_records.append(records[0])
        self.assertEqual(
            outcomes,
            ["VERIFIED", "REJECTED", "ERROR"],
            [record["detail"] for record in verification_records],
        )
        self.assertEqual(len(self.store.local_alerts()), 1)
        final_snapshot = self.store.snapshot(now=datetime.now(timezone.utc))
        final_dashboard_path = self.directory / "dashboard-verification-outcomes.html"
        write_dashboard_snapshot(final_snapshot, str(final_dashboard_path))
        final_dashboard = final_dashboard_path.read_text(encoding="utf-8")
        for outcome in ("VERIFIED", "REJECTED", "ERROR"):
            self.assertIn(f'"status": "{outcome}"', final_dashboard)

    def test_manual_runner_persists_before_send_and_deduplicates_after_restart(self):
        log_path = self.directory / "runner-search.log"
        log_path.write_text(
            "nTime: 1791363600\n"
            "SEARCH START NONCE: 541696\n"
            "SEARCH END NONCE: 541700\n"
            "SEARCH WORKERS: 1\n"
            "WORKER RANGE 0: 541696..541700\n"
            "Progress: worker=0 range=541696..541700 nonce=541698 "
            "candidates=3 elapsed_seconds=1.0 candidates_per_second=3.0\n",
            encoding="utf-8",
        )
        spool_path = self.directory / "runner-spool.sqlite"
        spool = EventSpool(spool_path, receipt_verifier=self.receipt_verifier)
        observed_at = datetime.now(timezone.utc)
        sender = self._sender(
            spool,
            self.dell_context,
            self.server.server_port,
            [observed_at],
            [300.0],
        )
        runner = PassiveAgentRunner(
            machine_id="dell-pilot",
            log_path=log_path,
            checkpoint_path=None,
            collector=LogCollector(),
            spool=spool,
            sender=sender,
        )

        from genesis_monitor import sender as sender_module

        send_spooled_event = sender_module._send_spooled_event_owned

        def require_durable_event_before_send(event, **kwargs):
            self.assertEqual(spool.pending(), [event])
            return send_spooled_event(event, **kwargs)

        with patch(
            "genesis_monitor.sender._send_spooled_event_owned",
            side_effect=require_durable_event_before_send,
        ):
            first = runner.run_once(observed_at=observed_at)

        self.assertIsNotNone(first.event_id)
        self.assertFalse(first.observation_unchanged)
        self.assertEqual((first.delivery.attempted, first.delivery.delivered), (1, 1))
        self.assertEqual(spool.pending(), [])
        self.assertEqual(len(self.store.history("dell-pilot")), 1)

        reopened_spool = EventSpool(
            spool_path,
            receipt_verifier=self.receipt_verifier,
        )
        reopened_sender = self._sender(
            reopened_spool,
            self.dell_context,
            self.server.server_port,
            [observed_at + timedelta(seconds=2)],
            [302.0],
        )
        repeated_runner = PassiveAgentRunner(
            machine_id="dell-pilot",
            log_path=log_path,
            checkpoint_path=None,
            collector=LogCollector(),
            spool=reopened_spool,
            sender=reopened_sender,
        )
        repeated = repeated_runner.run_once(
            observed_at=observed_at + timedelta(seconds=2)
        )

        self.assertTrue(repeated.observation_unchanged)
        self.assertIsNone(repeated.event_id)
        self.assertEqual(repeated.delivery.attempted, 0)
        self.assertEqual(reopened_spool.pending(), [])
        self.assertEqual(len(self.store.history("dell-pilot")), 1)


if __name__ == "__main__":
    unittest.main()
