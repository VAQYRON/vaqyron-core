import copy
import concurrent.futures
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_monitor.identity import (
    CertificateCredential,
    CertificateIdentityRegistry,
    IdentityAuthorizationError,
    IdentityRegistryError,
)
from genesis_monitor.ingestion import GenesisIngestionService, OfflineSimulatedPeerEvidence
from genesis_monitor.receipts import (
    CommittedReceiptSigner,
    CommittedReceiptVerifier,
    ReceiptError,
    ReceiptTrustBundle,
    _create_committed_receipt,
    acknowledge_spooled_event,
    canonical_receipt_json,
    parse_committed_receipt,
    trust_bundle_from_public_keys,
    validate_committed_receipt,
)
from genesis_monitor.spool import EventSpool, SpoolError
from genesis_monitor.store import CentralStore, EventConflictError, IngestResult, StoreError
from tests.test_protocol import valid_event


NOW = datetime(2026, 10, 14, 8, 0, tzinfo=timezone.utc)
VALID_FROM = NOW - timedelta(days=1)
EXPIRES_AT = NOW + timedelta(days=30)
FINGERPRINT_A = "a" * 64
FINGERPRINT_B = "b" * 64


def credential(fingerprint, *, not_before=VALID_FROM, expires_at=EXPIRES_AT):
    return CertificateCredential(fingerprint, not_before, expires_at)


def event():
    return valid_event()


def signing_setup(*, key_id="server-test-1", private_key=None, expires_at=EXPIRES_AT):
    private_key = private_key or Ed25519PrivateKey.generate()
    bundle = trust_bundle_from_public_keys({
        key_id: (private_key.public_key(), VALID_FROM, expires_at, False)
    })
    signer = CommittedReceiptSigner(
        {key_id: private_key}, active_key_id=key_id, trust_bundle=bundle
    )
    return signer, CommittedReceiptVerifier(bundle), private_key


def authorize_offline(registry, fingerprint, machine_id, simulated_at=NOW):
    return registry.authorize_offline_simulation(
        fingerprint, machine_id, simulated_at=simulated_at
    )


class CertificateIdentityTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.database = Path(self.tempdir.name) / "identity.sqlite"
        self.registry = CertificateIdentityRegistry.bootstrap(self.database)
        self.registry.enroll("laptop-1", credential(FINGERPRINT_A))
        self.peer_a = FINGERPRINT_A

    def test_offline_registry_check_binds_fingerprint_to_one_machine(self):
        self.assertEqual(authorize_offline(self.registry, self.peer_a, "laptop-1"), "laptop-1")
        with self.assertRaisesRegex(IdentityAuthorizationError, "does not match"):
            authorize_offline(self.registry, self.peer_a, "laptop-2")

    def test_unknown_expired_and_not_yet_valid_credentials_are_rejected(self):
        with self.assertRaisesRegex(IdentityAuthorizationError, "not registered"):
            authorize_offline(self.registry, FINGERPRINT_B, "laptop-1")
        self.registry.enroll(
            "expired-laptop",
            credential(FINGERPRINT_B, not_before=NOW - timedelta(days=2), expires_at=NOW),
        )
        with self.assertRaisesRegex(IdentityAuthorizationError, "expired"):
            authorize_offline(self.registry, FINGERPRINT_B, "expired-laptop")
        fingerprint_c = "c" * 64
        self.registry.enroll(
            "future-laptop",
            credential(fingerprint_c, not_before=NOW + timedelta(seconds=1)),
        )
        with self.assertRaisesRegex(IdentityAuthorizationError, "not yet valid"):
            authorize_offline(self.registry, fingerprint_c, "future-laptop")

    def test_unapproved_initial_enrollment_overlap_is_rejected(self):
        starts = NOW + timedelta(days=5)
        with self.assertRaisesRegex(IdentityAuthorizationError, "bounded overlap"):
            self.registry.enroll(
                "laptop-1",
                credential(FINGERPRINT_B, not_before=starts),
            )
        overlap_end = NOW + timedelta(days=7)
        self.registry.enroll(
            "laptop-1",
            credential(FINGERPRINT_B, not_before=starts),
            allow_overlap=True,
            overlap_until=overlap_end,
        )
        old_peer = FINGERPRINT_A
        new_peer = FINGERPRINT_B
        self.assertEqual(
            authorize_offline(self.registry, old_peer, "laptop-1", NOW + timedelta(days=6)),
            "laptop-1",
        )
        self.assertEqual(
            authorize_offline(self.registry, new_peer, "laptop-1", NOW + timedelta(days=6)),
            "laptop-1",
        )
        with self.assertRaisesRegex(IdentityAuthorizationError, "expired"):
            authorize_offline(self.registry, FINGERPRINT_A, "laptop-1", overlap_end)

    def test_enrollment_checks_overlap_with_every_active_credential(self):
        day = timedelta(days=1)
        self.registry.enroll(
            "laptop-1",
            credential(FINGERPRINT_B, not_before=NOW + 5 * day),
            allow_overlap=True,
            overlap_until=NOW + 7 * day,
        )
        fingerprint_c = "c" * 64
        with self.assertRaisesRegex(ValueError, "every active credential"):
            self.registry.enroll(
                "laptop-1",
                credential(fingerprint_c, not_before=NOW + 6 * day),
                allow_overlap=True,
                overlap_until=NOW + 8 * day,
            )
        self.registry.enroll(
            "laptop-1",
            credential(fingerprint_c, not_before=NOW + 6 * day),
            allow_overlap=True,
            overlap_until=NOW + 6 * day + timedelta(hours=1),
        )

    def test_rotation_requires_explicit_bounded_overlap(self):
        rotation_at = NOW
        overlap_until = NOW + timedelta(hours=2)
        with self.assertRaisesRegex(ValueError, "explicit allow_overlap"):
            self.registry.rotate(
                "laptop-1",
                FINGERPRINT_A,
                credential(FINGERPRINT_B, not_before=rotation_at),
                rotation_at=rotation_at,
                overlap_until=overlap_until,
                allow_overlap=False,
            )
        self.registry.rotate(
            "laptop-1",
            FINGERPRINT_A,
            credential(FINGERPRINT_B, not_before=rotation_at),
            rotation_at=rotation_at,
            overlap_until=overlap_until,
            allow_overlap=True,
        )
        self.assertEqual(authorize_offline(self.registry, self.peer_a, "laptop-1"), "laptop-1")
        self.assertEqual(
            authorize_offline(
                self.registry, FINGERPRINT_B, "laptop-1", NOW + timedelta(hours=1)
            ),
            "laptop-1",
        )
        with self.assertRaisesRegex(IdentityAuthorizationError, "expired"):
            authorize_offline(self.registry, FINGERPRINT_A, "laptop-1", overlap_until)

    def test_rotation_without_overlap_closes_old_credential_at_rotation(self):
        self.registry.rotate(
            "laptop-1",
            FINGERPRINT_A,
            credential(FINGERPRINT_B, not_before=NOW),
            rotation_at=NOW,
            overlap_until=NOW,
            allow_overlap=False,
        )
        with self.assertRaisesRegex(IdentityAuthorizationError, "expired"):
            authorize_offline(self.registry, self.peer_a, "laptop-1")

    def test_enrollment_revocation_and_restart_persistence(self):
        restarted = CertificateIdentityRegistry.open(self.database)
        self.assertEqual(authorize_offline(restarted, self.peer_a, "laptop-1"), "laptop-1")
        restarted.revoke(FINGERPRINT_A)
        reopened = CertificateIdentityRegistry.open(self.database)
        with self.assertRaisesRegex(IdentityAuthorizationError, "revoked"):
            authorize_offline(reopened, self.peer_a, "laptop-1")
        with self.assertRaisesRegex(IdentityAuthorizationError, "unknown"):
            reopened.revoke(FINGERPRINT_B)

    def test_corrupt_or_unversioned_registry_fails_closed(self):
        broken = Path(self.tempdir.name) / "broken.sqlite"
        broken.write_bytes(b"not a sqlite database")
        with self.assertRaises(IdentityRegistryError):
            CertificateIdentityRegistry.open(broken)
        unversioned = Path(self.tempdir.name) / "unversioned.sqlite"
        import sqlite3

        connection = sqlite3.connect(unversioned)
        try:
            connection.execute("CREATE TABLE certificate_credentials (fingerprint_sha256 TEXT)")
        finally:
            connection.close()
        with self.assertRaisesRegex(IdentityRegistryError, "unsupported"):
            CertificateIdentityRegistry.open(unversioned)
        missing_table = Path(self.tempdir.name) / "missing-table.sqlite"
        connection = sqlite3.connect(missing_table)
        try:
            connection.execute("PRAGMA user_version=1")
        finally:
            connection.close()
        with self.assertRaisesRegex(IdentityRegistryError, "missing its credential table"):
            CertificateIdentityRegistry.open(missing_table)

    def test_missing_registry_fails_closed_and_bootstrap_never_overwrites(self):
        missing = Path(self.tempdir.name) / "missing.sqlite"
        with self.assertRaisesRegex(IdentityRegistryError, "file is missing"):
            CertificateIdentityRegistry.open(missing)
        created = CertificateIdentityRegistry.bootstrap(missing)
        created.enroll("laptop-1", credential(FINGERPRINT_A))
        created.revoke(FINGERPRINT_A)
        before = missing.read_bytes()
        with self.assertRaisesRegex(IdentityRegistryError, "refusing to bootstrap"):
            CertificateIdentityRegistry.bootstrap(missing)
        self.assertEqual(missing.read_bytes(), before)
        reopened = CertificateIdentityRegistry.open(missing)
        with self.assertRaisesRegex(IdentityAuthorizationError, "revoked"):
            authorize_offline(reopened, self.peer_a, "laptop-1")

    def test_rotation_checks_overlap_with_third_active_credential(self):
        day = timedelta(days=1)
        self.registry.enroll(
            "laptop-1",
            credential(FINGERPRINT_B, not_before=NOW + day, expires_at=NOW + 10 * day),
            allow_overlap=True,
            overlap_until=NOW + 5 * day,
        )
        fingerprint_c = "c" * 64
        with self.assertRaisesRegex(ValueError, "every active credential"):
            self.registry.rotate(
                "laptop-1",
                FINGERPRINT_A,
                credential(fingerprint_c, not_before=NOW, expires_at=NOW + 20 * day),
                rotation_at=NOW,
                overlap_until=NOW + 7 * day,
                allow_overlap=True,
            )
        self.registry.rotate(
            "laptop-1",
            FINGERPRINT_A,
            credential(fingerprint_c, not_before=NOW, expires_at=NOW + 20 * day),
            rotation_at=NOW,
            overlap_until=NOW + 4 * day,
            allow_overlap=True,
        )

    def test_concurrent_overlapping_enrollments_are_serialized(self):
        barrier = threading.Barrier(2)

        def enroll(fingerprint):
            registry = CertificateIdentityRegistry.open(self.database)
            barrier.wait(timeout=5)
            try:
                registry.enroll("parallel-laptop", credential(fingerprint))
                return "accepted"
            except IdentityAuthorizationError:
                return "rejected"

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(enroll, ("d" * 64, "e" * 64)))
        self.assertCountEqual(outcomes, ["accepted", "rejected"])


class CommittedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.store = CentralStore(Path(self.tempdir.name) / "central.sqlite")
        self.store.register_machine("laptop-1", "Synthetic laptop")
        self.registry = CertificateIdentityRegistry.bootstrap(
            Path(self.tempdir.name) / "identity.sqlite"
        )
        self.registry.enroll("laptop-1", credential(FINGERPRINT_A))
        self.peer = OfflineSimulatedPeerEvidence(FINGERPRINT_A, NOW)
        self.signer, self.verifier, self.private_key = signing_setup()
        self.service = GenesisIngestionService(self.registry, self.store, self.signer)
        self.spool = EventSpool(
            Path(self.tempdir.name) / "spool.sqlite",
            receipt_verifier=self.verifier,
        )
        self.event = event()

    def receipt(self, event_value=None):
        return self.service.ingest_offline_simulated(
            self.event if event_value is None else event_value,
            peer_evidence=self.peer,
            received_at="2026-10-14T08:00:01Z",
        )

    def test_receipt_is_authenticated_and_created_after_committed_ingestion(self):
        receipt = self.receipt()
        self.assertEqual(set(receipt), {
            "receipt_version",
            "key_id",
            "machine_id",
            "event_id",
            "sequence",
            "canonical_event_hash",
            "outcome",
            "issued_at",
            "signature",
        })
        self.assertEqual(receipt["receipt_version"], 3)
        self.assertEqual(receipt["outcome"], "accepted")
        self.assertEqual(
            validate_committed_receipt(receipt, self.event, self.verifier), receipt
        )
        self.assertEqual(len(self.store.history("laptop-1")), 1)
        self.assertFalse(hasattr(self.store, "ingest_with_receipt"))

    def test_receipt_cannot_be_minted_from_caller_constructed_ingest_result(self):
        forged_result = IngestResult(
            self.event["sequence"],
            self.event["event_id"],
            "accepted_current",
            True,
        )
        with self.assertRaisesRegex(ReceiptError, "committed ingestion result"):
            _create_committed_receipt(self.event, forged_result, self.signer)

    def test_duplicate_commit_returns_authenticated_duplicate_receipt(self):
        first = self.receipt()
        second = self.receipt()
        self.assertEqual(first["outcome"], "accepted")
        self.assertEqual(second["outcome"], "duplicate")
        self.assertEqual(
            validate_committed_receipt(second, self.event, self.verifier)["outcome"],
            "duplicate",
        )

    def test_caller_supplied_fingerprint_or_time_cannot_authorize_identity(self):
        with self.assertRaises(TypeError):
            self.service.ingest_offline_simulated(
                self.event,
                peer_evidence=self.peer,
                authorization_time=NOW,
                received_at="2026-10-14T08:00:01Z",
            )
        with self.assertRaises(TypeError):
            self.service.ingest_offline_simulated(
                self.event,
                peer_evidence=self.peer,
                machine_id="laptop-1",
                received_at="2026-10-14T08:00:01Z",
            )
        with self.assertRaises(TypeError):
            self.service.ingest_offline_simulated(
                self.event,
                peer_evidence=self.peer,
                certificate_fingerprint=FINGERPRINT_A,
                received_at="2026-10-14T08:00:01Z",
            )
        self.assertEqual(self.store.history("laptop-1"), [])

    def test_forgeable_identity_objects_are_not_accepted_as_tls_proof(self):
        with self.assertRaises(TypeError):
            self.service.ingest_offline_simulated(
                self.event,
                peer_evidence=object(),
                received_at="2026-10-14T08:00:01Z",
            )
        with self.assertRaises(TypeError):
            self.service.ingest_offline_simulated(
                self.event,
                peer_identity=self.peer,
                received_at="2026-10-14T08:00:01Z",
            )

    def test_event_machine_id_must_match_simulated_registered_fingerprint(self):
        spoofed = copy.deepcopy(self.event)
        spoofed["machine_id"] = "laptop-2"
        spoofed["event_id"] = "laptop-2:1"
        with self.assertRaisesRegex(IdentityAuthorizationError, "does not match"):
            self.service.ingest_offline_simulated(
                spoofed,
                peer_evidence=self.peer,
                received_at="2026-10-14T08:00:01Z",
            )
        self.assertEqual(self.store.history("laptop-1"), [])

    def test_unknown_fingerprint_and_malformed_event_never_ingest(self):
        unknown_evidence = OfflineSimulatedPeerEvidence("f" * 64, NOW)
        with self.assertRaisesRegex(IdentityAuthorizationError, "not registered"):
            self.service.ingest_offline_simulated(
                self.event,
                peer_evidence=unknown_evidence,
                received_at="2026-10-14T08:00:01Z",
            )
        malformed = copy.deepcopy(self.event)
        malformed["sequence"] = True
        with self.assertRaisesRegex(ValueError, "invalid telemetry event"):
            self.service.ingest_offline_simulated(
                malformed,
                peer_evidence=self.peer,
                received_at="2026-10-14T08:00:01Z",
            )
        self.assertEqual(self.store.history("laptop-1"), [])

    def test_conflict_store_failure_or_missing_key_does_not_issue_receipt(self):
        self.receipt()
        changed = copy.deepcopy(self.event)
        changed["payload"]["log"]["aggregate_candidates"] += 1
        with self.assertRaises(EventConflictError):
            self.receipt(changed)
        with patch.object(self.store, "ingest", side_effect=StoreError("synthetic commit failure")):
            with self.assertRaisesRegex(StoreError, "synthetic commit failure"):
                self.service.ingest_offline_simulated(
                    event(),
                    peer_evidence=self.peer,
                    received_at="2026-10-14T08:00:01Z",
                )
    def test_malformed_mutated_and_wrong_key_receipts_are_rejected(self):
        receipt = self.receipt()
        variants = [
            dict(receipt, unexpected=True),
            {key: value for key, value in receipt.items() if key != "event_id"},
            dict(receipt, receipt_version=1),
            dict(receipt, sequence=True),
            dict(receipt, signature="0" * 128),
            dict(receipt, outcome="error"),
        ]
        for variant in variants:
            with self.subTest(receipt=variant), self.assertRaises(ReceiptError):
                validate_committed_receipt(variant, self.event, self.verifier)
        changed_event = copy.deepcopy(self.event)
        changed_event["payload"]["log"]["aggregate_candidates"] += 1
        with self.assertRaisesRegex(ReceiptError, "hash"):
            validate_committed_receipt(receipt, changed_event, self.verifier)
        other_verifier = CommittedReceiptVerifier(
            trust_bundle_from_public_keys({
                "server-test-1": (
                    Ed25519PrivateKey.generate().public_key(), VALID_FROM, EXPIRES_AT, False
                )
            })
        )
        with self.assertRaisesRegex(ReceiptError, "signature verification"):
            validate_committed_receipt(receipt, self.event, other_verifier)
        attacker_key = Ed25519PrivateKey.generate()
        forged_fields = {key: value for key, value in receipt.items() if key != "signature"}
        forged = dict(receipt)
        forged["signature"] = attacker_key.sign(
            json.dumps(
                forged_fields, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False,
            ).encode("utf-8")
        ).hex()
        with self.assertRaisesRegex(ReceiptError, "signature verification"):
            validate_committed_receipt(forged, self.event, self.verifier)

    def test_trust_bundle_rotation_is_bounded_and_revocation_is_fail_closed(self):
        old_private = self.private_key
        new_private = Ed25519PrivateKey.generate()
        overlap_until = NOW + timedelta(hours=2)
        bundle = trust_bundle_from_public_keys(
            {
                "server-test-1": (
                    old_private.public_key(), VALID_FROM, overlap_until, False
                ),
                "server-test-2": (
                    new_private.public_key(), NOW, EXPIRES_AT, False
                ),
            },
            rotations=(("server-test-1", "server-test-2", overlap_until),),
        )
        reopened_bundle = ReceiptTrustBundle.from_mapping(bundle.to_mapping())
        verifier = CommittedReceiptVerifier(reopened_bundle)
        rotated_signer = CommittedReceiptSigner(
            {
                "server-test-1": old_private,
                "server-test-2": new_private,
            },
            active_key_id="server-test-2",
            trust_bundle=bundle,
        )
        receipt = self.receipt_signer_for(
            rotated_signer,
            issued_at=NOW + timedelta(hours=1),
        )
        validate_committed_receipt(
            receipt, self.event, verifier, now=NOW + timedelta(hours=1, minutes=30)
        )
        validate_committed_receipt(
            receipt, self.event, verifier, now=overlap_until
        )
        old_signer = CommittedReceiptSigner(
            {"server-test-1": old_private},
            active_key_id="server-test-1",
            trust_bundle=bundle,
        )
        old_receipt = self.receipt_signer_for(
            old_signer,
            issued_at=NOW + timedelta(hours=1),
        )
        with self.assertRaisesRegex(ReceiptError, "not currently valid"):
            validate_committed_receipt(
                old_receipt, self.event, verifier, now=overlap_until
            )

        revoked_bundle = trust_bundle_from_public_keys({
            "server-test-1": (
                old_private.public_key(), VALID_FROM, EXPIRES_AT, True
            )
        })
        with self.assertRaisesRegex(ReceiptError, "revoked"):
            validate_committed_receipt(
                self.receipt(), self.event, CommittedReceiptVerifier(revoked_bundle)
            )

    def test_trust_bundle_rejects_unsupported_or_unapproved_rotation(self):
        _, verifier, _ = signing_setup()
        mapping = verifier.trust_bundle.to_mapping()
        mapping["bundle_version"] = 99
        with self.assertRaisesRegex(ReceiptError, "unsupported"):
            ReceiptTrustBundle.from_mapping(mapping)

        old_private = Ed25519PrivateKey.generate()
        new_private = Ed25519PrivateKey.generate()
        overlap_until = NOW + timedelta(hours=2)
        key_entries = {
            "old": (old_private.public_key(), VALID_FROM, overlap_until, False),
            "new": (new_private.public_key(), NOW, EXPIRES_AT, False),
        }
        with self.assertRaisesRegex(ReceiptError, "explicit rotation"):
            trust_bundle_from_public_keys(key_entries)
        with self.assertRaisesRegex(ReceiptError, "not explicitly bounded"):
            trust_bundle_from_public_keys(
                key_entries,
                rotations=(("old", "new", NOW + timedelta(hours=1)),),
            )

    def receipt_signer_for(self, signer, *, issued_at):
        result = self.store.ingest(
            self.event,
            authenticated_machine_id="laptop-1",
            received_at="2026-10-14T08:00:01Z",
        )
        return _create_committed_receipt(
            self.event, result, signer, issued_at=issued_at
        )

    def test_unknown_expired_keys_and_malformed_signatures_are_rejected(self):
        receipt = self.receipt()
        with self.assertRaisesRegex(ReceiptError, "not trusted"):
            validate_committed_receipt(
                dict(receipt, key_id="untrusted-key"), self.event, self.verifier
            )
        with self.assertRaisesRegex(ReceiptError, "not currently valid"):
            validate_committed_receipt(
                receipt, self.event, self.verifier, now=EXPIRES_AT
            )
        with self.assertRaisesRegex(ReceiptError, "128 lowercase"):
            validate_committed_receipt(
                dict(receipt, signature="bad"), self.event, self.verifier
            )

    def test_receipt_parser_rejects_duplicate_keys_and_oversize(self):
        receipt = self.receipt()
        serialized = canonical_receipt_json(receipt)
        duplicate_key_json = serialized[:-1] + ',"outcome":"duplicate"}'
        with self.assertRaisesRegex(ReceiptError, "duplicate"):
            parse_committed_receipt(duplicate_key_json, self.event, self.verifier)
        with self.assertRaisesRegex(ReceiptError, "canonical form"):
            parse_committed_receipt(json.dumps(receipt), self.event, self.verifier)
        with self.assertRaisesRegex(ReceiptError, "maximum encoded size"):
            parse_committed_receipt(" " * 4097, self.event, self.verifier)

    def test_spool_ack_requires_authentic_receipt_and_configured_trust_key(self):
        spooled, duplicate = self.spool.enqueue(
            self.event["machine_id"],
            self.event["observed_at"],
            self.event["payload"],
            "source-observation-1",
        )
        self.assertFalse(duplicate)
        forged = {
            "receipt_version": 3,
            "key_id": self.signer.active_key_id,
            "machine_id": "laptop-1",
            "event_id": spooled["event_id"],
            "sequence": spooled["sequence"],
            "canonical_event_hash": "0" * 64,
            "outcome": "accepted",
            "issued_at": "2026-10-14T08:00:00.000000Z",
            "signature": "1" * 128,
        }
        with self.assertRaises(ReceiptError):
            acknowledge_spooled_event(self.spool, spooled, forged, self.verifier)
        self.assertEqual(self.spool.pending(), [spooled])
        no_key_spool = EventSpool(Path(self.tempdir.name) / "no-key.sqlite")
        second, _ = no_key_spool.enqueue(
            self.event["machine_id"],
            self.event["observed_at"],
            self.event["payload"],
            "source-observation-2",
        )
        with self.assertRaisesRegex(SpoolError, "no trusted receipt verifier"):
            no_key_spool.acknowledge(second["event_id"], receipt=forged)

        receipt = self.receipt()
        acknowledge_spooled_event(self.spool, spooled, receipt, self.verifier)
        self.assertEqual(self.spool.pending(), [])

    def test_receipt_for_one_pending_event_cannot_acknowledge_another(self):
        first, _ = self.spool.enqueue(
            self.event["machine_id"],
            self.event["observed_at"],
            self.event["payload"],
            "source-first",
        )
        second_payload = copy.deepcopy(self.event["payload"])
        second_payload["log"]["aggregate_candidates"] += 1
        second, _ = self.spool.enqueue(
            self.event["machine_id"],
            self.event["observed_at"],
            second_payload,
            "source-second",
        )
        receipt = self.receipt()
        with self.assertRaisesRegex(SpoolError, "matching committed receipt"):
            self.spool.acknowledge(second["event_id"], receipt=receipt)
        self.assertEqual(self.spool.pending(), [first, second])

    def test_valid_duplicate_receipt_can_acknowledge_retry_after_commit(self):
        spooled, _ = self.spool.enqueue(
            self.event["machine_id"],
            self.event["observed_at"],
            self.event["payload"],
            "source-observation-duplicate",
        )
        self.receipt()
        duplicate_receipt = self.receipt()
        self.assertEqual(duplicate_receipt["outcome"], "duplicate")
        acknowledge_spooled_event(
            self.spool, spooled, duplicate_receipt, self.verifier
        )
        self.assertEqual(self.spool.pending(), [])


if __name__ == "__main__":
    unittest.main()
