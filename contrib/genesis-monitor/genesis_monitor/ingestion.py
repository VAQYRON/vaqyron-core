"""Telemetry ingestion service for offline simulation and verified TLS peers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ssl
from typing import Any, Callable, Protocol

from .identity import CertificateIdentityRegistry, IdentityAuthorizationError
from .protocol import ProtocolError, canonical_json, parse_event
from .receipts import CommittedReceiptSigner
from .store import CentralStore


class FutureTLSAdapter(Protocol):
    """Contract for a future production adapter.

    The adapter must receive an established server-side TLS connection whose
    handshake required and validated a client certificate. It must derive peer
    identity from that connection, never from request data, and receive only
    the ingestion-service interface rather than a CentralStore or DB handle.
    """

    def handle_verified_connection(
        self,
        tls_connection: ssl.SSLSocket,
        request_body: bytes,
        ingestion_service: "GenesisIngestionService",
    ) -> dict[str, Any]:
        """Handle one request tied to its already verified TLS connection."""
        ...


@dataclass(frozen=True)
class OfflineSimulatedPeerEvidence:
    """Synthetic registry input for offline tests; never evidence of a TLS peer."""

    fingerprint_sha256: str
    simulated_at: datetime


class GenesisIngestionService:
    """Own event validation, registry checks, commits, and signed receipts.

    Offline tests use the explicitly simulated entry point. The TLS entry point
    accepts only a server-side socket and obtains its peer certificate
    directly; production transport and deployment remain out of scope.
    """

    def __init__(
        self,
        registry: CertificateIdentityRegistry,
        store: CentralStore,
        receipt_signer: CommittedReceiptSigner,
    ) -> None:
        if not isinstance(registry, CertificateIdentityRegistry):
            raise TypeError("registry must be a CertificateIdentityRegistry")
        if not isinstance(store, CentralStore):
            raise TypeError("store must be a CentralStore")
        if not isinstance(receipt_signer, CommittedReceiptSigner):
            raise TypeError("receipt_signer must be a CommittedReceiptSigner")
        self.__registry = registry
        self.__store = store
        self.__receipt_signer = receipt_signer

    def ingest_offline_simulated(
        self,
        event: Any,
        *,
        peer_evidence: OfflineSimulatedPeerEvidence,
        received_at: str | datetime,
    ) -> dict[str, Any]:
        """Exercise authorization and commit flow with explicitly synthetic input."""
        if type(peer_evidence) is not OfflineSimulatedPeerEvidence:
            raise TypeError("offline ingestion requires OfflineSimulatedPeerEvidence")
        try:
            validated = parse_event(canonical_json(event))
        except ProtocolError as error:
            raise ValueError(f"invalid telemetry event: {error}") from error
        machine_id = self.__registry.authorize_offline_simulation(
            peer_evidence.fingerprint_sha256,
            validated["machine_id"],
            simulated_at=peer_evidence.simulated_at,
        )
        return self.__store._ingest_with_signed_receipt(
            validated,
            authenticated_machine_id=machine_id,
            received_at=received_at,
            signer=self.__receipt_signer,
        )

    def ingest_verified_tls_connection(
        self,
        event_data: bytes,
        *,
        tls_connection: ssl.SSLSocket,
        admit_authenticated_request: Callable[[str], None] | None = None,
    ) -> dict[str, Any]:
        """Ingest only from the verified client certificate on a server TLS socket."""
        if not isinstance(tls_connection, ssl.SSLSocket) or not tls_connection.server_side:
            raise TypeError("ingestion requires the accepted server-side TLS connection")
        if tls_connection.context.verify_mode != ssl.CERT_REQUIRED:
            raise TypeError("TLS connection was not configured to require a client certificate")
        peer_certificate = tls_connection.getpeercert(binary_form=True)
        if not peer_certificate:
            raise ValueError("TLS connection has no verified client certificate")

        received_at = datetime.now(timezone.utc)
        fingerprint = hashlib.sha256(peer_certificate).hexdigest()
        machine_id = self.__registry._authorize_tls_fingerprint(
            fingerprint,
            at=received_at,
        )
        if admit_authenticated_request is not None:
            admit_authenticated_request(fingerprint)
        try:
            validated = parse_event(event_data)
        except ProtocolError as error:
            raise ValueError(f"invalid telemetry event: {error}") from error
        if validated["machine_id"] != machine_id:
            raise IdentityAuthorizationError(
                "event machine_id does not match the TLS certificate identity"
            )
        return self.__store._ingest_with_signed_receipt(
            validated,
            authenticated_machine_id=machine_id,
            received_at=received_at,
            signer=self.__receipt_signer,
        )
