"""Loopback-only mTLS prototype for authenticated telemetry ingestion."""

from __future__ import annotations

import http.client
import http.server
import ipaddress
import json
import math
import select
import socket
import ssl
import threading
import time
from collections import deque
from typing import Any

from .ingestion import GenesisIngestionService
from .protocol import MAX_EVENT_BYTES, ProtocolError, canonical_json
from .receipts import (
    MAX_RECEIPT_BYTES,
    CommittedReceiptVerifier,
    ReceiptError,
    parse_committed_receipt,
)
from .spool import EventSpool, _SenderOwnershipToken
from .store import EventConflictError, StoreError
from .identity import IdentityAuthorizationError
from .private_ingress import (
    PrivateIngressConfig,
    PrivateIngressConfigurationError,
    windows_interface_inventory,
)


_LOOPBACK_HOST = "127.0.0.1"
_EVENT_PATH = "/v1/events"
_MAX_REQUEST_LINE_BYTES = 4096
_MAX_HEADER_LINE_BYTES = 4096
_MAX_HEADER_BYTES = 16 * 1024
_MAX_HEADER_LINES = 32
_MAX_CONNECTIONS = 8
_CONNECTION_TIMEOUT_SECONDS = 5
_REQUEST_DEADLINE_SECONDS = 5
_MAX_REQUEST_DEADLINE_SECONDS = 30
_GLOBAL_REQUEST_LIMIT = 60
_CERTIFICATE_REQUEST_LIMIT = 10
_RATE_WINDOW_SECONDS = 60.0
_MAX_TRACKED_CERTIFICATES = 1024
_MAX_GLOBAL_RATE_LIMIT = 10_000
_MAX_PER_CERTIFICATE_RATE_LIMIT = 1_000
_MAX_RATE_WINDOW_SECONDS = 3600.0


class TransportError(RuntimeError):
    """The authenticated telemetry transport rejected an operation."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class RateLimitExceeded(TransportError):
    """An authenticated request exceeded a fixed-window admission limit."""

    def __init__(self, retry_after: float) -> None:
        super().__init__("authenticated request rate limit exceeded")
        self.retry_after = max(1, math.ceil(retry_after))


class _RequestRateLimiter:
    """Thread-safe sliding-window limiter keyed by verified certificate hash."""

    def __init__(
        self,
        *,
        global_limit: int = _GLOBAL_REQUEST_LIMIT,
        per_certificate_limit: int = _CERTIFICATE_REQUEST_LIMIT,
        window_seconds: float = _RATE_WINDOW_SECONDS,
        max_tracked_certificates: int = _MAX_TRACKED_CERTIFICATES,
        clock: Any = time.monotonic,
    ) -> None:
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in (global_limit, per_certificate_limit, max_tracked_certificates)
        ):
            raise ValueError("rate limits and tracked-certificate bound must be positive integers")
        if (
            global_limit > _MAX_GLOBAL_RATE_LIMIT
            or per_certificate_limit > _MAX_PER_CERTIFICATE_RATE_LIMIT
            or max_tracked_certificates > _MAX_TRACKED_CERTIFICATES
        ):
            raise ValueError("rate-limit configuration exceeds its hard memory bound")
        if (
            isinstance(window_seconds, bool)
            or not isinstance(window_seconds, (int, float))
            or not math.isfinite(window_seconds)
            or not 0 < window_seconds <= _MAX_RATE_WINDOW_SECONDS
        ):
            raise ValueError(
                f"rate window must be in 0..{_MAX_RATE_WINDOW_SECONDS} seconds"
            )
        if not callable(clock):
            raise TypeError("rate-limit clock must be callable")
        self.global_limit = global_limit
        self.per_certificate_limit = per_certificate_limit
        self.window_seconds = float(window_seconds)
        self.max_tracked_certificates = max_tracked_certificates
        self._clock = clock
        self._global: deque[float] = deque()
        self._certificates: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def admit(self, fingerprint_sha256: str) -> None:
        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            self._prune(self._global, cutoff)
            for fingerprint, timestamps in list(self._certificates.items()):
                self._prune(timestamps, cutoff)
                if not timestamps:
                    del self._certificates[fingerprint]

            certificate_requests = self._certificates.get(fingerprint_sha256)
            if len(self._global) >= self.global_limit:
                raise RateLimitExceeded(self._global[0] + self.window_seconds - now)
            if (
                certificate_requests is not None
                and len(certificate_requests) >= self.per_certificate_limit
            ):
                raise RateLimitExceeded(
                    certificate_requests[0] + self.window_seconds - now
                )
            if certificate_requests is None:
                if len(self._certificates) >= self.max_tracked_certificates:
                    raise RateLimitExceeded(self.window_seconds)
                certificate_requests = deque()
                self._certificates[fingerprint_sha256] = certificate_requests
            self._global.append(now)
            certificate_requests.append(now)

    @staticmethod
    def _prune(timestamps: deque[float], cutoff: float) -> None:
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()


class _HeaderLimitError(Exception):
    pass


class _DeadlineSocketReader:
    def __init__(self, connection: ssl.SSLSocket, deadline: float) -> None:
        self._connection = connection
        self._deadline = deadline
        self._buffer = bytearray()
        self._total = 0
        self._lines = 0
        self._partial_header_line = bytearray()
        self._headers_started = False
        self._headers_finished = False

    def readline(self, size: int = -1) -> bytes:
        self.check_deadline()
        result = bytearray()
        while size < 0 or len(result) < size:
            newline = self._buffer.find(b"\n")
            available = newline + 1 if newline >= 0 else len(self._buffer)
            if available:
                take = available
                if size >= 0:
                    take = min(take, size - len(result))
                piece = bytes(self._buffer[:take])
                result.extend(piece)
                del self._buffer[:take]
                if self._headers_started and not self._headers_finished:
                    self._count_header_bytes(piece, complete=piece.endswith(b"\n"))
                if piece.endswith(b"\n") or (size >= 0 and len(result) >= size):
                    self.check_deadline()
                    return bytes(result)
            chunk = self._recv()
            if not chunk:
                self.check_deadline()
                return bytes(result)
            self._buffer.extend(chunk)

        return bytes(result)

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise ValueError("unbounded reads are not supported")
        self.check_deadline()
        result = bytearray()
        if self._buffer:
            take = min(size, len(self._buffer))
            result.extend(self._buffer[:take])
            del self._buffer[:take]
        while len(result) < size:
            chunk = self._recv(size - len(result))
            if not chunk:
                break
            result.extend(chunk)
        self.check_deadline()
        return bytes(result)

    def begin_headers(self) -> None:
        self._headers_started = True
        self._headers_finished = False
        self._total = 0
        self._lines = 0
        self._partial_header_line.clear()

    def _count_header_bytes(self, chunk: bytes, *, complete: bool) -> None:
        if not chunk or self._headers_finished:
            return
        self._total += len(chunk)
        self._partial_header_line.extend(chunk)
        if (
            len(self._partial_header_line) > _MAX_HEADER_LINE_BYTES
            or self._total > _MAX_HEADER_BYTES
        ):
            raise _HeaderLimitError
        if complete:
            self._lines += 1
            if self._lines > _MAX_HEADER_LINES:
                raise _HeaderLimitError
            if self._partial_header_line in (b"\r\n", b"\n"):
                self._headers_finished = True
            self._partial_header_line.clear()

    def _recv(self, size: int = 8192) -> bytes:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("absolute request deadline exceeded")
        self._connection.settimeout(remaining)
        return self._connection.recv(size)

    def set_write_timeout(self) -> None:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("absolute request deadline exceeded")
        self._connection.settimeout(remaining)

    def check_deadline(self) -> None:
        if time.monotonic() >= self._deadline:
            raise socket.timeout("absolute request deadline exceeded")

    def close(self) -> None:
        return


def create_server_tls_context(
    *,
    certificate_file: str,
    private_key_file: str,
    client_ca_file: str,
) -> ssl.SSLContext:
    """Create a server context that validates client certificates."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certificate_file, private_key_file)
    context.load_verify_locations(cafile=client_ca_file)
    return context


def create_client_tls_context(
    *,
    server_ca_file: str,
    certificate_file: str,
    private_key_file: str,
) -> ssl.SSLContext:
    """Create a client context with server-chain and hostname verification."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=server_ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.load_cert_chain(certificate_file, private_key_file)
    return context


class _IngestionHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "VAQYRON-Genesis-Monitor"
    sys_version = ""

    def setup(self) -> None:
        self.connection = self.request
        self.rfile = _DeadlineSocketReader(
            self.connection,
            self.server.request_deadline(),  # type: ignore[attr-defined]
        )
        self.wfile = self.connection.makefile("wb")

    def parse_request(self) -> bool:
        if len(self.raw_requestline) > _MAX_REQUEST_LINE_BYTES:
            self.send_error(414)
            return False
        self.rfile.begin_headers()
        try:
            return super().parse_request()
        except _HeaderLimitError:
            self.send_error(431)
            self.close_connection = True
            return False

    def _send_json(
        self,
        status: int,
        value: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        self.rfile.set_write_timeout()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        for name, header_value in (headers or {}).items():
            self.send_header(name, header_value)
        self.end_headers()
        self.wfile.write(encoded)
        self.close_connection = True

    def _method_not_allowed(self) -> None:
        self.send_response(405)
        self.send_header("Allow", "POST")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    def do_GET(self) -> None:
        self._method_not_allowed()

    def do_HEAD(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_POST(self) -> None:
        if not isinstance(self.server, _BoundedTLSHTTPServer):
            self._send_json(500, {"error": "ingestion server configuration is invalid"})
            return
        if self.path != _EVENT_PATH:
            self._send_json(404, {"error": "not found"})
            return
        header_names = ("Content-Length", "Content-Type", "Transfer-Encoding")
        if any(len(self.headers.get_all(name, [])) > 1 for name in header_names):
            self._send_json(400, {"error": "ambiguous request headers"})
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._send_json(400, {"error": "transfer encoding is not supported"})
            return
        if self.headers.get("Content-Type", "").lower() != "application/json":
            self._send_json(415, {"error": "application/json is required"})
            return
        raw_length = self.headers.get("Content-Length")
        if (
            raw_length is None
            or not raw_length.isascii()
            or not raw_length.isdecimal()
        ):
            self._send_json(400, {"error": "one decimal Content-Length is required"})
            return
        if len(raw_length) > 5:
            self._send_json(413, {"error": "request body exceeds 64 KiB"})
            return
        length = int(raw_length)
        if length > MAX_EVENT_BYTES:
            self._send_json(413, {"error": "request body exceeds 64 KiB"})
            return
        if length == 0:
            self._send_json(400, {"error": "request body is empty"})
            return
        body = self.rfile.read(length)
        if len(body) != length:
            self._send_json(400, {"error": "request body is incomplete"})
            return
        self.rfile.check_deadline()
        try:
            receipt = self.server.ingestion_service.ingest_verified_tls_connection(
                body,
                tls_connection=self.connection,
                admit_authenticated_request=self.server.rate_limiter.admit,
            )
        except RateLimitExceeded as error:
            self._send_json(
                429,
                {"error": "request rate limit exceeded"},
                headers={"Retry-After": str(error.retry_after)},
            )
            return
        except IdentityAuthorizationError:
            self._send_json(403, {"error": "client identity is not authorized"})
            return
        except ReceiptError:
            self._send_json(503, {"error": "committed receipt could not be issued"})
            return
        except (ProtocolError, ValueError):
            self._send_json(400, {"error": "telemetry event is invalid"})
            return
        except EventConflictError:
            self._send_json(409, {"error": "telemetry event conflicts with stored history"})
            return
        except StoreError:
            self._send_json(503, {"error": "telemetry could not be committed"})
            return
        self._send_json(200, receipt)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def handle(self) -> None:
        try:
            super().handle()
        except (socket.timeout, ssl.SSLError, OSError):
            self.close_connection = True


class _BoundedTLSHTTPServer:
    daemon_threads = True
    request_queue_size = 16

    def _initialize_tls_server(
        self,
        *,
        tls_context: ssl.SSLContext,
        ingestion_service: GenesisIngestionService,
        request_deadline_seconds: float = _REQUEST_DEADLINE_SECONDS,
        rate_limiter: _RequestRateLimiter | None = None,
    ) -> None:
        if not isinstance(tls_context, ssl.SSLContext):
            raise TypeError("tls_context must be an SSLContext")
        if tls_context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("server TLS context must require verified client certificates")
        if tls_context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise ValueError("server TLS context must require TLS 1.2 or newer")
        if not tls_context.get_ca_certs():
            raise ValueError("server TLS context must have explicit client trust roots")
        if (
            isinstance(request_deadline_seconds, bool)
            or not isinstance(request_deadline_seconds, (int, float))
            or not math.isfinite(request_deadline_seconds)
            or not 0.1 <= request_deadline_seconds <= _MAX_REQUEST_DEADLINE_SECONDS
        ):
            raise ValueError(
                f"request_deadline_seconds must be in 0.1..{_MAX_REQUEST_DEADLINE_SECONDS}"
            )
        if not isinstance(ingestion_service, GenesisIngestionService):
            raise TypeError("ingestion_service must be a GenesisIngestionService")
        self.ingestion_service = ingestion_service
        if rate_limiter is not None and not isinstance(rate_limiter, _RequestRateLimiter):
            raise TypeError("rate_limiter must be a _RequestRateLimiter")
        self.rate_limiter = rate_limiter or _RequestRateLimiter()
        self._connection_slots = threading.BoundedSemaphore(_MAX_CONNECTIONS)
        self._tls_context = tls_context
        self._request_deadline_seconds = float(request_deadline_seconds)
        self._admission_deadlines: dict[socket.socket, float] = {}
        self._admission_lock = threading.Lock()
        self._thread_state = threading.local()
        self._rejected_connections = 0

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._connection_slots.acquire(blocking=False):
            self._rejected_connections += 1
            self.shutdown_request(request)
            return
        with self._admission_lock:
            self._admission_deadlines[request] = (
                time.monotonic() + self._request_deadline_seconds
            )
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._admission_lock:
                self._admission_deadlines.pop(request, None)
            try:
                self.shutdown_request(request)
            finally:
                self._connection_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        tls_socket: ssl.SSLSocket | None = None
        with self._admission_lock:
            deadline = self._admission_deadlines.pop(request)
        self._thread_state.deadline = deadline
        try:
            tls_socket = self._wrap_and_handshake(request, deadline)
            tls_socket.setblocking(True)
            self.finish_request(tls_socket, client_address)
        except (socket.timeout, ssl.SSLError, OSError):
            pass
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self._thread_state.deadline = None
            try:
                self.shutdown_request(tls_socket or request)
            finally:
                self._connection_slots.release()

    def request_deadline(self) -> float:
        deadline = getattr(self._thread_state, "deadline", None)
        if deadline is None:
            raise RuntimeError("request has no admitted absolute deadline")
        return deadline

    def _wrap_and_handshake(
        self,
        raw_socket: socket.socket,
        deadline: float,
    ) -> ssl.SSLSocket:
        raw_socket.setblocking(False)
        tls_socket = self._tls_context.wrap_socket(
            raw_socket,
            server_side=True,
            do_handshake_on_connect=False,
        )
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise socket.timeout("absolute TLS handshake deadline exceeded")
                try:
                    tls_socket.do_handshake()
                    return tls_socket
                except ssl.SSLWantReadError:
                    readable, _, _ = select.select([tls_socket], [], [], remaining)
                    if not readable:
                        raise socket.timeout("absolute TLS handshake deadline exceeded")
                except ssl.SSLWantWriteError:
                    _, writable, _ = select.select([], [tls_socket], [], remaining)
                    if not writable:
                        raise socket.timeout("absolute TLS handshake deadline exceeded")
        except BaseException:
            tls_socket.close()
            raise


class LoopbackMTLSServer(_BoundedTLSHTTPServer, http.server.ThreadingHTTPServer):
    """Ephemeral IPv4-loopback listener with bounded TLS HTTP concurrency."""

    def __init__(
        self,
        *,
        tls_context: ssl.SSLContext,
        ingestion_service: GenesisIngestionService,
        request_deadline_seconds: float = _REQUEST_DEADLINE_SECONDS,
        rate_limiter: _RequestRateLimiter | None = None,
    ) -> None:
        self._initialize_tls_server(
            tls_context=tls_context,
            ingestion_service=ingestion_service,
            request_deadline_seconds=request_deadline_seconds,
            rate_limiter=rate_limiter,
        )
        http.server.ThreadingHTTPServer.__init__(
            self,
            (_LOOPBACK_HOST, 0),
            _IngestionHandler,
            bind_and_activate=True,
        )
        if self.server_address[0] != _LOOPBACK_HOST:
            self.server_close()
            raise OSError("ingestion prototype must bind exclusively to 127.0.0.1")

    def get_request(self) -> tuple[socket.socket, Any]:
        raw_socket, address = http.server.ThreadingHTTPServer.get_request(self)
        if address[0] != _LOOPBACK_HOST:
            raw_socket.close()
            raise OSError("ingestion prototype accepts loopback connections only")
        return raw_socket, address


class RemoteMTLSServer(_BoundedTLSHTTPServer, http.server.ThreadingHTTPServer):
    """Explicitly started private-interface mTLS telemetry receiver."""

    @staticmethod
    def validate_startup_configuration(
        configuration: PrivateIngressConfig,
        *,
        interface_inventory: Any,
    ) -> tuple[str, int, ssl.SSLContext]:
        if not isinstance(configuration, PrivateIngressConfig):
            raise TypeError("configuration must be a PrivateIngressConfig")
        configuration.require_validated_enabled_configuration()
        configuration.validate_current_interface_inventory(interface_inventory)
        if (
            configuration.bind_address is None
            or configuration.port is None
            or configuration.tls_context is None
        ):
            raise PrivateIngressConfigurationError(
                "validated receiver configuration is missing required settings"
            )
        if (
            configuration.tls_context.verify_mode != ssl.CERT_REQUIRED
            or configuration.tls_context.minimum_version < ssl.TLSVersion.TLSv1_2
            or not configuration.tls_context.get_ca_certs()
        ):
            raise PrivateIngressConfigurationError(
                "receiver configuration does not require trusted mutual TLS"
            )
        return (
            configuration.bind_address,
            configuration.port,
            configuration.tls_context,
        )

    def __init__(
        self,
        *,
        configuration: PrivateIngressConfig,
        ingestion_service: GenesisIngestionService,
        request_deadline_seconds: float = _REQUEST_DEADLINE_SECONDS,
        rate_limiter: _RequestRateLimiter | None = None,
    ) -> None:
        if not isinstance(configuration, PrivateIngressConfig):
            raise TypeError("configuration must be a PrivateIngressConfig")
        configuration.require_validated_enabled_configuration()
        bind_address, port, tls_context = self.validate_startup_configuration(
            configuration,
            interface_inventory=windows_interface_inventory(),
        )
        self.configuration = configuration
        address = ipaddress.ip_address(bind_address)
        self.address_family = (
            socket.AF_INET6 if address.version == 6 else socket.AF_INET
        )
        self._initialize_tls_server(
            tls_context=tls_context,
            ingestion_service=ingestion_service,
            request_deadline_seconds=request_deadline_seconds,
            rate_limiter=rate_limiter,
        )
        http.server.ThreadingHTTPServer.__init__(
            self,
            (bind_address, port, 0, 0)
            if address.version == 6
            else (bind_address, port),
            _IngestionHandler,
            bind_and_activate=False,
        )
        try:
            self.validate_startup_configuration(
                configuration,
                interface_inventory=windows_interface_inventory(),
            )
            self.server_bind()
            bound_address = ipaddress.ip_address(self.server_address[0])
            if bound_address != address or self.server_address[1] != port:
                raise OSError("receiver socket did not bind to the approved interface address")
            self.validate_startup_configuration(
                configuration,
                interface_inventory=windows_interface_inventory(),
            )
            self.server_activate()
        except BaseException:
            self.server_close()
            raise

    @classmethod
    def start(
        cls,
        *,
        configuration: PrivateIngressConfig,
        ingestion_service: GenesisIngestionService,
        request_deadline_seconds: float = _REQUEST_DEADLINE_SECONDS,
        rate_limiter: _RequestRateLimiter | None = None,
    ) -> "RemoteMTLSServer":
        """Explicitly bind and begin serving; never called automatically."""
        server = cls(
            configuration=configuration,
            ingestion_service=ingestion_service,
            request_deadline_seconds=request_deadline_seconds,
            rate_limiter=rate_limiter,
        )
        try:
            server._serve_thread = threading.Thread(
                target=server.serve_forever,
                kwargs={"poll_interval": 0.1},
                name="vaqyron-remote-telemetry",
                daemon=True,
            )
            server._serve_thread.start()
        except BaseException:
            server.server_close()
            raise
        return server

    def stop(self, *, timeout_seconds: float = 10.0) -> None:
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0.1 <= timeout_seconds <= 60
        ):
            raise ValueError("timeout_seconds must be in 0.1..60")
        thread = getattr(self, "_serve_thread", None)
        if thread is not None and thread.is_alive():
            self.shutdown()
            thread.join(timeout=timeout_seconds)
        self.server_close()
        if thread is not None and thread.is_alive():
            raise RuntimeError("remote telemetry receiver did not stop before timeout")


def send_spooled_event(
    event: dict[str, Any],
    *,
    port: int,
    tls_context: ssl.SSLContext,
    receipt_verifier: CommittedReceiptVerifier,
    spool: EventSpool,
    timeout: float = _CONNECTION_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Send one event while holding exclusive spool ownership through its ACK."""
    if not isinstance(spool, EventSpool):
        raise TypeError("spool must be an EventSpool")
    with spool.sender_run_lock() as owner_token:
        return _send_spooled_event_owned(
            event,
            port=port,
            tls_context=tls_context,
            receipt_verifier=receipt_verifier,
            spool=spool,
            timeout=timeout,
            owner_token=owner_token,
        )


def _send_spooled_event_owned(
    event: dict[str, Any],
    *,
    port: int,
    tls_context: ssl.SSLContext,
    receipt_verifier: CommittedReceiptVerifier,
    spool: EventSpool,
    timeout: float,
    owner_token: _SenderOwnershipToken,
    host: str = _LOOPBACK_HOST,
) -> dict[str, Any]:
    """Send over verified mTLS and ACK only a valid signed receipt."""
    spool._require_sender_owner(owner_token)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer in 1..65535")
    if not isinstance(tls_context, ssl.SSLContext):
        raise TypeError("tls_context must be an SSLContext")
    if tls_context.verify_mode != ssl.CERT_REQUIRED or not tls_context.check_hostname:
        raise ValueError("client TLS context must verify server certificates and hostname")
    if tls_context.minimum_version < ssl.TLSVersion.TLSv1_2:
        raise ValueError("client TLS context must require TLS 1.2 or newer")
    if not isinstance(receipt_verifier, CommittedReceiptVerifier):
        raise TypeError("receipt_verifier must be a CommittedReceiptVerifier")
    if not isinstance(spool, EventSpool):
        raise TypeError("spool must be an EventSpool")
    body = canonical_json(event).encode("utf-8")
    if len(body) > MAX_EVENT_BYTES:
        raise TransportError("event exceeds the 64 KiB transport limit")

    connection = http.client.HTTPSConnection(
        host,
        port,
        timeout=timeout,
        context=tls_context,
    )
    try:
        connection.request(
            "POST",
            _EVENT_PATH,
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        response_data = response.read(MAX_RECEIPT_BYTES + 1)
        if response.status != 200:
            raise TransportError(
                f"ingestion endpoint returned HTTP {response.status}",
                status=response.status,
                retry_after=response.getheader("Retry-After"),
            )
        if len(response_data) > MAX_RECEIPT_BYTES:
            raise TransportError("committed receipt exceeds the transport size limit")
        try:
            receipt = parse_committed_receipt(response_data, event, receipt_verifier)
        except ReceiptError as error:
            raise TransportError(f"server returned an invalid committed receipt: {error}") from error
        spool._acknowledge_owned(
            event["event_id"],
            receipt=receipt,
            owner_token=owner_token,
        )
        return receipt
    finally:
        connection.close()
