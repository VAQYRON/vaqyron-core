"""Bounded retry sender for durable Genesis Monitor spool events."""

from __future__ import annotations

import http.client
import ipaddress
import math
import random
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Callable

from .receipts import CommittedReceiptVerifier
from .spool import EventSpool, SpoolError, _SenderOwnershipToken
from .transport import (
    TransportError,
    _send_spooled_event_owned,
    create_client_tls_context,
)


_MAX_BATCH_SIZE = 100
_MAX_TIMEOUT_SECONDS = 30.0
_MAX_BACKOFF_SECONDS = 300.0
_MAX_RETRY_AFTER_SECONDS = 300.0
_REMOTE_ENDPOINT_SEAL = object()


@dataclass(frozen=True)
class SenderRunResult:
    attempted: int
    delivered: int
    deferred: int


@dataclass(frozen=True, init=False)
class RemoteSenderEndpoint:
    """Explicit mTLS endpoint configuration; loading it never opens a connection."""

    host: str
    port: int
    tls_context: ssl.SSLContext
    _validation_seal: object | None = None

    def __new__(cls, *args: object, **kwargs: object) -> "RemoteSenderEndpoint":
        raise TypeError("use RemoteSenderEndpoint.load() to construct an endpoint")

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("use RemoteSenderEndpoint.load() to construct an endpoint")

    @classmethod
    def load(
        cls,
        *,
        host: str,
        port: int,
        server_ca_file: str,
        client_certificate_file: str,
        client_private_key_file: str,
    ) -> "RemoteSenderEndpoint":
        if not isinstance(host, str) or not host or host != host.strip():
            raise ValueError("remote server host must be an explicit DNS name or IP address")
        try:
            normalized_host = ipaddress.ip_address(host).compressed
        except ValueError:
            if (
                len(host) > 253
                or host.endswith(".")
                or "*" in host
                or "/" in host
                or ":" in host
            ):
                raise ValueError("remote server host must be a DNS name or IP address")
            labels = host.split(".")
            if len(labels) < 2 or any(
                not label
                or len(label) > 63
                or not label.isascii()
                or not label[0].isalnum()
                or not label[-1].isalnum()
                or any(not (character.isalnum() or character == "-") for character in label)
                for label in labels
            ):
                raise ValueError("remote server host must be a valid fully-qualified DNS name")
            normalized_host = host.lower()
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("remote server port must be an integer in 1..65535")
        tls_context = create_client_tls_context(
            server_ca_file=server_ca_file,
            certificate_file=client_certificate_file,
            private_key_file=client_private_key_file,
        )
        if (
            tls_context.verify_mode != ssl.CERT_REQUIRED
            or not tls_context.check_hostname
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise ValueError("remote endpoint requires verified TLS 1.2+ with hostname checking")
        instance = object.__new__(cls)
        object.__setattr__(instance, "host", normalized_host)
        object.__setattr__(instance, "port", port)
        object.__setattr__(instance, "tls_context", tls_context)
        object.__setattr__(instance, "_validation_seal", _REMOTE_ENDPOINT_SEAL)
        return instance

    def require_validated(self) -> None:
        if (
            self._validation_seal is not _REMOTE_ENDPOINT_SEAL
            or not isinstance(self.tls_context, ssl.SSLContext)
            or self.tls_context.verify_mode != ssl.CERT_REQUIRED
            or not self.tls_context.check_hostname
            or self.tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise ValueError("remote sender requires a validated mTLS endpoint")


class DurableEventSender:
    """Attempt one bounded due batch; failures remain durably queued."""

    def __init__(
        self,
        spool: EventSpool,
        *,
        port: int | None = None,
        tls_context: ssl.SSLContext | None = None,
        endpoint: RemoteSenderEndpoint | None = None,
        receipt_verifier: CommittedReceiptVerifier,
        batch_size: int = 20,
        timeout_seconds: float = 5.0,
        base_backoff_seconds: float = 5.0,
        max_backoff_seconds: float = _MAX_BACKOFF_SECONDS,
        jitter_fraction: float = 0.2,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] | None = None,
        random_value: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(spool, EventSpool):
            raise TypeError("spool must be an EventSpool")
        if endpoint is not None:
            if port is not None or tls_context is not None:
                raise ValueError("remote endpoint cannot be combined with legacy port/TLS options")
            if not isinstance(endpoint, RemoteSenderEndpoint):
                raise TypeError("endpoint must be a RemoteSenderEndpoint")
            endpoint.require_validated()
            port = endpoint.port
            tls_context = endpoint.tls_context
        elif port is None or tls_context is None:
            raise ValueError("either a validated remote endpoint or loopback port/TLS context is required")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer in 1..65535")
        if not isinstance(tls_context, ssl.SSLContext):
            raise TypeError("tls_context must be an SSLContext")
        if (
            tls_context.verify_mode != ssl.CERT_REQUIRED
            or not tls_context.check_hostname
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
        ):
            raise ValueError("client TLS context must verify server certificates and hostname")
        if not isinstance(receipt_verifier, CommittedReceiptVerifier):
            raise TypeError("receipt_verifier must be a CommittedReceiptVerifier")
        if isinstance(batch_size, bool) or not isinstance(batch_size, int) or not 1 <= batch_size <= _MAX_BATCH_SIZE:
            raise ValueError(f"batch_size must be in 1..{_MAX_BATCH_SIZE}")
        self.timeout_seconds = self._bounded_number(
            timeout_seconds, "timeout_seconds", 0.1, _MAX_TIMEOUT_SECONDS
        )
        self.base_backoff_seconds = self._bounded_number(
            base_backoff_seconds, "base_backoff_seconds", 0.1, _MAX_BACKOFF_SECONDS
        )
        self.max_backoff_seconds = self._bounded_number(
            max_backoff_seconds, "max_backoff_seconds", self.base_backoff_seconds,
            _MAX_BACKOFF_SECONDS,
        )
        self.jitter_fraction = self._bounded_number(
            jitter_fraction, "jitter_fraction", 0, 0.5
        )
        if wall_clock is not None and not callable(wall_clock):
            raise TypeError("wall_clock must be callable")
        if monotonic_clock is not None and not callable(monotonic_clock):
            raise TypeError("monotonic_clock must be callable")
        if random_value is not None and not callable(random_value):
            raise TypeError("random_value must be callable")
        self.spool = spool
        self.port = port
        self.tls_context = tls_context
        self.endpoint = endpoint
        self.receipt_verifier = receipt_verifier
        self.batch_size = batch_size
        self.wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self.monotonic_clock = monotonic_clock or time.monotonic
        self.random_value = random_value or random.SystemRandom().random
        anchor_wall = self.wall_clock()
        if (
            not isinstance(anchor_wall, datetime)
            or anchor_wall.tzinfo is None
            or anchor_wall.utcoffset() is None
        ):
            raise ValueError("wall_clock must return a timezone-aware datetime")
        self._wall_anchor = anchor_wall.astimezone(timezone.utc)
        self._monotonic_anchor = self._read_monotonic()

    @staticmethod
    def _bounded_number(value: float, name: str, minimum: float, maximum: float) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not minimum <= value <= maximum
        ):
            raise ValueError(f"{name} must be in {minimum}..{maximum}")
        return float(value)

    def run_once(self) -> SenderRunResult:
        with self.spool.sender_run_lock() as owner_token:
            return self._run_once_owned(owner_token)

    def _run_once_owned(self, owner_token: _SenderOwnershipToken) -> SenderRunResult:
        """Send at most one bounded batch of currently eligible spool events."""
        now = self._effective_utc_now()
        due = self.spool.due_pending(self.batch_size, now=now)
        attempted = 0
        delivered = 0
        deferred = 0
        for item in due:
            event = item["event"]
            attempts = item["attempt_count"]
            attempted += 1
            try:
                _send_spooled_event_owned(
                    event,
                    port=self.port,
                    tls_context=self.tls_context,
                    receipt_verifier=self.receipt_verifier,
                    spool=self.spool,
                    timeout=self.timeout_seconds,
                    owner_token=owner_token,
                    host=self.endpoint.host if self.endpoint is not None else "127.0.0.1",
                )
            except TransportError as error:
                failed_at = self._effective_utc_now()
                delay = self._retry_delay(attempts + 1, error.retry_after, failed_at)
                self.spool.schedule_retry(
                    event["event_id"],
                    delay_seconds=delay,
                    now=failed_at,
                    error=str(error),
                    _owner_token=owner_token,
                )
                deferred += 1
            except (OSError, http.client.HTTPException, ssl.SSLError, SpoolError) as error:
                failed_at = self._effective_utc_now()
                delay = self._retry_delay(attempts + 1, None, failed_at)
                self.spool.schedule_retry(
                    event["event_id"],
                    delay_seconds=delay,
                    now=failed_at,
                    error=f"{type(error).__name__}: {error}",
                    _owner_token=owner_token,
                )
                deferred += 1
            else:
                delivered += 1
        return SenderRunResult(attempted, delivered, deferred)

    def _read_monotonic(self) -> float:
        value = self.monotonic_clock()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value < 0
        ):
            raise ValueError("monotonic_clock must return a finite non-negative number")
        return float(value)

    def _effective_utc_now(self) -> datetime:
        elapsed = self._read_monotonic() - self._monotonic_anchor
        if elapsed < 0:
            raise ValueError("monotonic_clock moved backwards")
        return self._wall_anchor + timedelta(seconds=elapsed)

    def _retry_delay(
        self,
        attempt: int,
        retry_after: str | None,
        now: datetime,
    ) -> float:
        if retry_after is not None:
            try:
                requested = int(retry_after, 10)
            except ValueError:
                try:
                    retry_at = parsedate_to_datetime(retry_after)
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=timezone.utc)
                    requested = max(0, math.ceil((retry_at - now).total_seconds()))
                except (TypeError, ValueError, OverflowError):
                    requested = -1
            if requested > 0:
                return min(float(requested), _MAX_RETRY_AFTER_SECONDS)
        exponent = min(max(attempt - 1, 0), 30)
        delay = min(self.max_backoff_seconds, self.base_backoff_seconds * (2 ** exponent))
        jitter = self.random_value()
        if (
            isinstance(jitter, bool)
            or not isinstance(jitter, (int, float))
            or not math.isfinite(jitter)
            or not 0 <= jitter <= 1
        ):
            raise ValueError("random_value must return a finite number in 0..1")
        return min(self.max_backoff_seconds, delay * (1 + self.jitter_fraction * jitter))
