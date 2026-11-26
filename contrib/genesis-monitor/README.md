# VAQYRON Genesis Monitor — Offline telemetry and Phase 2A

Phase 1 supplies a versioned telemetry protocol, an offline read-only log and
checkpoint collector, and a bounded local SQLite event spool. It does not
start a collector service, open a network listener, enroll machines, or control
Genesis Search processes. The Ed25519 receipt implementation depends on the
maintained `cryptography` package declared in `requirements.txt`.

## Offline tests

Ensure the dependency in `requirements.txt` is already available from an
approved package source. Do not fetch packages as part of an offline test run.
From this directory, run only the synthetic unit tests:

```powershell
$env:PYTHONDONTWRITEBYTECODE = "1"
$env:PYTHONPATH = (Get-Location).Path
python -B -m unittest discover -s tests -v
```

The tests create temporary logs/checkpoints and SQLite databases only. They do
not access Dell, Acer, a VPS, a live search process, or the network.

## Event protocol version 1

An event has exactly these top-level fields:

```json
{
  "protocol_version": 1,
  "event_id": "machine-id:sequence",
  "sequence": 1,
  "machine_id": "machine-id",
  "observed_at": "2026-10-14T07:00:00.000000Z",
  "payload": {
    "log": {},
    "checkpoint": {}
  }
}
```

Validation rejects unknown/missing fields, duplicate JSON keys, invalid or
naive timestamps, invalid nonce/count ranges, duplicate worker indices,
non-finite speeds, invalid hashes, oversized events, and unsupported protocol
versions. `payload.log` reports parsed search time/range, worker allocation,
latest aggregate count/rate, terminal result, source mtime, parse-error count,
and observed workers. Each log worker contains its range/current observed
nonce, callback timestamp if present, and fields explicitly named
`shared_candidates_at_observation` and `aggregate_candidates_per_second`.
Those values originate from a shared callback counter/rate; they are not
per-worker totals or rates.

`payload.checkpoint` is separate from log-observed progress. A valid checkpoint
includes configuration and each worker's durable `last_completed_nonce`.
FOUND claims include nonce, conventional display-order block hash, raw
serialized digest bytes, and `independent_verification_status`. The collector
always labels a checkpoint FOUND as `not_performed`: parsing/integrity checking
is not independent PoW verification.

## Real-pilot preparation boundary (STEP 294–299)

`config/main-receiver.example.json`, `config/dell-agent.example.json`, and
`config/acer-agent.example.json` are deliberately disabled, placeholder-only
templates. `load_disabled_pilot_config(path, expected_role=...)` checks their
closed JSON schema, exact role, duplicate keys, false `enabled` and
`automatic_start`, zero port, and placeholder-only operational fields. It
rejects real addresses, paths, credentials, allowlists, unknown fields, and
attempts to enable operation. This disabled-template loader has no listener,
network, interface inventory, sender, credential, or search-process calls. It
is not a production configuration loader and its output cannot be passed as a
validated receiver or sender configuration. The separate
`load_operational_config()` loader validates explicit operational configs but
does not construct runtime objects or inspect referenced credential files.

The existing low-level receiver/sender classes remain separate, explicit APIs.
Calling `RemoteMTLSServer` startup binds the configured address, and calling a
sender's run method may connect to its configured endpoint; template validation
does neither. Do not invoke those APIs for a real pilot without the approvals
and acceptance evidence in [PILOT_ACCEPTANCE.md](./PILOT_ACCEPTANCE.md).

`PassiveAgentRunner.run_once()` composes one call to `LogCollector.collect`,
durable snapshot enqueue, and one bounded `DurableEventSender.run_once` batch.
The explicit CLI constructs these existing APIs; it adds no background loop,
scheduler, service, or automatic startup. The receiver still requires
deliberate operator provisioning of the identity registry, central store,
receipt signer, trust bundles, and enrolled machine fingerprints. No private
bind, credential issuance, or machine access is authorized by these commands.

The credential plan, least-privilege Windows key ACLs, rotation/revocation
requirements, manual recovery sequence, and PASS/FAIL operator gates are in
[PILOT_ACCEPTANCE.md](./PILOT_ACCEPTANCE.md). Dell's existing search was
started without checkpoint support: its log can provide observed progress only;
the Dell template deliberately sets `checkpoint_file` to `null`. No durable
resume position or liveness can be inferred. Acer readiness and any checkpoint
support remain unverified until separately approved access.

## Operational CLI (manual use only)

`python -m genesis_monitor.cli` exposes four explicit commands. Importing the
module and running `validate` only reads the named UTF-8 JSON config; validation
does not open referenced credentials/databases, enumerate interfaces, create
files, connect, or bind. Runtime commands are separate opt-in invocations.
Run from this directory after package dependencies are installed.

Receiver configuration has exactly these top-level fields:

- Common: `schema_version` (1), `role` (`receiver`), `enabled` (`true`),
  `automatic_start` (`false`).
- Bind: `bind_address`, canonical `interface_guid`, `port`, and non-empty
  `approved_interface_addresses`. The selected address must be a specific
  RFC1918 IPv4 or IPv6 ULA address and must appear in that array.
- TLS/identity: `server_identity`, `server_certificate_file`,
  `server_private_key_file`, `client_ca_file`, `identity_registry_file`,
  `receipt_signing_key_file`, `receipt_signing_key_id`, and
  `receipt_trust_bundle_file`.
- Data/output: `central_store_file`, `dashboard_output`, and `machines`, a
  non-empty array of unique `{ "machine_id", "display_name" }` objects.

Agent configuration has exactly these top-level fields:

- Common: `schema_version` (1), `role` (`agent`), `enabled` (`true`),
  `automatic_start` (`false`), and `machine_id`.
- `collection` with absolute `log_file` and nullable `checkpoint_file` paths.
- Absolute `spool_file`, separate from monitored inputs and TLS files.
- `receiver` with a numeric private `host` and `port`.
- `tls` with `server_ca_file`, `client_certificate_file`,
  `client_private_key_file`, and `receipt_trust_bundle_file`.

All operational paths must be absolute and contain no placeholders, environment
variables, parent traversal, or symlink components. `validate` checks schema
and path relationships only; it does not establish file permissions, inspect
key material, prove machine enrollment, or prove operator approval. Runtime
commands fail closed when required files/directories are absent. Private keys
must be protected with OS ACLs; encrypted PEM key files are not supported by
these file-based TLS/signing APIs.

Example command forms (use only approved, separately provisioned config files):

```powershell
python -m genesis_monitor.cli validate --config C:\VAQYRON\config\main-receiver.json
python -m genesis_monitor.cli receiver-start --config C:\VAQYRON\config\main-receiver.json
python -m genesis_monitor.cli agent-once --config C:\VAQYRON\config\dell-agent.json
python -m genesis_monitor.cli dashboard-render --config C:\VAQYRON\config\main-receiver.json
```

`receiver-start` binds the configured private interface in the foreground. Use
Ctrl+C to request stop; shutdown is bounded to 10 seconds. It does not close or
delete the identity registry, central store, or agent spool. `agent-once`
returns after one collection and one bounded send batch; deferred events remain
in the durable spool. `dashboard-render` writes a static HTML snapshot from the
central store and must be invoked again to refresh it. These are operator
commands, not authorization for deployment or live machine access.

## Log collection and compatibility

`LogCollector.collect(log_path, checkpoint_path=None)` reads an existing log
incrementally, retains an unterminated final line until its newline arrives,
and resets its in-memory generation on file replacement or observed
truncation. UTF-8, UTF-8 BOM, UTF-16LE, and UTF-16BE (with or without a BOM
when detectable) are supported. Invalid encoded lines and malformed matching
progress records increment `parse_errors`; out-of-range progress is not
accepted. Log read errors are raised as `CollectorError`.

The parser recognizes the current CLI's `WORKER RANGE`, `Progress: worker=`,
search time/range/worker headers, and final result/hash/digest output. A log
does not establish durable progress. The current CLI reports a shared
aggregate candidate count in each worker callback; the collector preserves
that provenance and never treats it as a worker-local count. Progress lines
usually have no absolute timestamp; in that case `progress_timestamp` is null
and the event's collection time is not misrepresented as the line's timestamp.

The currently running Dell search is **not** retrofitted by this phase. If an
operator later supplies an already-accessible log, the collector may parse
its existing output without interacting with the process. If its output is
unavailable, progress stays unavailable. A process started without
`--checkpoint` cannot acquire durable checkpoints retroactively. Installing an
agent, exposing/copying logs, or upgrading a later search requires separate
approval.

## Checkpoint V2 validation

`read_checkpoint()` opens the selected file read-only, does not acquire or
create the `.lock` sidecar, and does not modify the checkpoint. It enforces
the 1 MiB bound, checks the trailing double-SHA256 checksum, validates magic,
version 2 and YESPOWER_1_0 algorithm, parses canonical CompactSize, rejects
truncation/trailing payload bytes, and validates the original balanced,
contiguous worker partition and each durable nonce boundary. A version,
algorithm, checksum, or structure problem is an explicit `CheckpointError`.
The collector reports that as `status: invalid`; a missing/inaccessible
checkpoint is unavailable. A reader racing an atomic replacement may read one
complete old/new snapshot or report a change/read/integrity error. It never
claims checkpoint freshness implies search liveness.

Checkpoint hashes use Bitcoin `uint256` serialization. Header hashes are
converted to display order; raw PoW digests and worker digests remain in
serialized byte order. Checkpoint validation does not independently verify a
FOUND candidate and does not compare it to a search configuration supplied
out-of-band.

## Local event spool

`EventSpool` assigns monotonic SQLite sequence IDs and `machine_id:sequence`
event IDs. `pending()` returns all unacknowledged events; `due_pending()` filters
by each event's durable retry eligibility. Idempotency keys reject replays with
changed payloads. Count/byte limits fail explicitly and never discard
unacknowledged events. Acknowledged payload rows are compacted while a bounded
recent deduplication window is retained. The runner atomically suppresses an
unchanged collected snapshot per machine, including after a spool reopen. The
spool itself has no network code.
Protect its directory with operating-system user permissions; it is not
encrypted at rest.

## Phase 4A offline identity authorization and receipts

`CertificateIdentityRegistry.bootstrap(path)` is the explicit first-time
creation operation. It creates the SQLite file exclusively and refuses to
overwrite any existing path. A failed bootstrap leaves its created file in
place for operator inspection; remove or recover it only through a deliberate
operator procedure. `CertificateIdentityRegistry.open(path)` and the
constructor are operational opens: a missing file, corrupt database,
unsupported schema version, missing table/index, or incompatible table
definition fails closed. Operational open does not create or migrate schema.
Future schema upgrades must use explicit, transactional migrations that
preserve credential and revocation rows; no migration is currently applied
automatically. Reopen preserves enrollment, rotation, and revocation.
Operators must protect the database directory and backups with restrictive OS
ACLs and include them in a deliberate recovery procedure.

Initial enrollment and `rotate()` compare validity against every non-revoked
credential registered to that machine. Any overlap is rejected unless the
operator explicitly sets `allow_overlap=True` and supplies one
`overlap_until` strictly inside the common validity intersection for all
overlapping credentials. Each affected existing credential is shortened to
that bound in the same `BEGIN IMMEDIATE` transaction as the new credential
insertion. A boundary that does not cover every intersecting credential is
rejected without partial updates. Revocation is persisted transactionally.
SQLite write transactions serialize concurrent enrollment, rotation, and
revocation across registry instances. Registry timestamps are supplied by the
trusted caller and UTC-normalized; a future transport adapter must use
server-side time and a trusted clock.

**Offline ingestion-service foundation:** `GenesisIngestionService` centralizes
event validation, registry policy checks, the SQLite commit, and signed
receipt issuance. Its only implemented entry point is
`ingest_offline_simulated()`, which explicitly requires
`OfflineSimulatedPeerEvidence`. That evidence is caller-constructible test
input, and its fingerprint and timestamp are simulated. This flow tests
registry policy and commit/receipt sequencing only; it is **not authenticated
ingestion and is not evidence of TLS security**. It must not be wired as a
network endpoint.

`FutureTLSAdapter` remains a type-level contract for a future production
adapter. The loopback prototype below implements a separate narrow path that
derives peer identity from the exact accepted server-side `ssl.SSLSocket`;
neither HTTP headers, event fields, arbitrary Python identity objects, nor
caller-supplied fingerprints/timestamps establish identity. A Python
`Protocol` or object boundary cannot defend against hostile code in the same
process. The prototype's loopback integration tests demonstrate TLS
connection-to-request binding only for its controlled test configuration;
they do not establish a production TLS deployment or private-network security.

## Loopback mTLS prototype

`genesis_monitor.transport` contains a minimal HTTPS ingestion adapter and
single-attempt transport helper. `genesis_monitor.sender.DurableEventSender`
provides the bounded retry loop. The server binds internally to `127.0.0.1` on an OS-selected
ephemeral port only; it has no host/port override and refuses non-loopback
peers. It requires a server TLS context with TLS 1.2 or newer, explicit client
trust roots, and `CERT_REQUIRED`. The request handler reads the peer
certificate DER from the exact accepted server-side `SSLSocket`, hashes those
bytes with SHA256, and resolves that fingerprint against the persistent
identity registry using server UTC time before comparing it with the event's
machine ID. Client identity fields and request headers are never used as
authentication.

Only `POST /v1/events` with one `Content-Length`, JSON content type, and a
body no larger than 64 KiB is accepted. Transfer encoding is rejected;
request lines are limited to 4096 bytes, header lines to 4096 bytes, aggregate
headers to 16 KiB, and headers to 32 lines. The listen backlog is 16; admission
is nonblocking and limited to eight connections. The admission slot is
acquired before TLS wrapping, and TLS handshakes execute only in admitted
worker threads, so stalled handshakes cannot block the accept loop.

Each admitted request has one absolute monotonic deadline, five seconds by
default (test override is bounded to 0.1..30 seconds), beginning at admission.
It covers TLS handshake, request line, headers, and body; deadline-aware reads
recompute the remaining budget on every receive, preventing slow-drip traffic
from extending the deadline. Expiry closes the connection and releases its
slot. The deadline is checked again before ingestion and before response
writes. Synchronous SQLite work itself cannot be interrupted mid-transaction:
if it completes after the deadline or its response is lost, the event may
already be committed and must be retried identically to obtain a signed
`duplicate` receipt. The spool acknowledges only after validating that receipt
against the pending event.

Authenticated ingestion attempts are additionally limited by a thread-safe
monotonic sliding window: at most 60 requests globally and 10 per verified
certificate fingerprint per 60 seconds. At most 1024 certificate buckets are
retained; expired buckets are removed, and when that bound is full a new
authenticated fingerprint is rejected with HTTP 429 until a bucket expires.
The global/per-certificate limits and window have hard upper bounds so
configuration cannot make memory unbounded. `Retry-After` reports the next
eligible window time. Identity is the SHA256 fingerprint read from the
verified TLS connection, never a header or event field.

Unknown, revoked, expired, or otherwise unauthorized certificates receive
HTTP 403 and do not consume rate quota. Requests that reach the authenticated
ingestion boundary consume quota before telemetry parsing and before any
SQLite operation; consequently malformed events, machine-ID mismatches,
conflicts, and store failures count against the authenticated certificate and
global limits. Invalid HTTP method/path/framing/content type and oversized
bodies are rejected before that boundary and do not consume quota. Rate state
is in-memory and resets on process restart; these limits are defense-in-depth
for this single-process loopback prototype, not distributed or persistent
abuse controls.

Responses do not expose registry or store error details. The sender connects
only to `127.0.0.1`, requires server-chain and IP-hostname verification,
verifies the signed receipt against the exact event, and acknowledges the
local spool only after receipt verification. Lost responses, invalid receipts,
HTTP errors, and network failures leave the event pending and persist an
incremented attempt count, bounded error text, and next eligible UTC time in
the spool SQLite row. The schema upgrade adds retry columns without replacing
existing pending events. Scheduling advances against a monotonic clock while
the sender remains running; UTC eligibility is persisted so a restarted sender
can reconstruct the remaining delay. A restarted sender reuses this schedule;
events are eligible at most once per `run_once()` and each run processes no
more than 100 events (20 by default), with a connection timeout capped at 30
seconds (5 by default).

Every spooled delivery or acknowledgement acquires exclusive cross-process
ownership: `DurableEventSender.run_once()`, the public
`transport.send_spooled_event()` helper, and direct spool retry/acknowledgement
operations all use the same guard. Nested operations on the same file within
one thread are reentrant, so a sender holds ownership through delivery,
receipt verification, ACK, and retry-state update without deadlocking.

The guard identifies the underlying file using the filesystem's device and
file ID (`st_dev`/`st_ino`, following symlinks), then takes a SQLite
`BEGIN IMMEDIATE` transaction on a persistent lock database in the local
system temporary directory, named by that identity. This makes path
normalization, symlink aliases, and hard links to the same file converge on
one lock on Windows filesystems that expose a nonzero file ID. If the spool
cannot be given a reliable file identity, ownership fails closed before
delivery or acknowledgement. A competing operation fails explicitly without
changing event state. SQLite releases ownership on normal completion,
exceptions, and process termination; after a crash it rolls back the
transaction, allowing recovery without stale lease expiry. Do not remove or
replace the persistent lock database while a sender may be active. This
guarantee is for cooperating operations on the same local file identity; do
not rely on SQLite locking over network filesystems or across separate spool
copies. On Windows the lock directory comes from that account's temporary
directory, so processes using one shared spool must run under the same Windows
account; cross-account spool sharing is unsupported.

Retry delay uses capped exponential backoff (5 seconds base, 300 seconds
maximum by default) and bounded positive jitter (up to 20% by default).
Valid `Retry-After` delta-seconds and HTTP-date values are honored up to a
300-second cap. A zero delta or past HTTP date is not treated as a zero-delay
retry; zero, past, and malformed values fall back to positive exponential
backoff. The sender does not sleep or spin: the caller schedules a later
`run_once()`, while not-yet-due events remain queued. An identical retry after
a committed response loss receives a signed `duplicate` receipt and is
acknowledged only after exact event verification. Queue count/byte limits
still fail explicitly rather than discarding events.

Retry eligibility is monotonic-clock-derived while a sender instance is
running, but the persisted deadline is UTC for restart recovery. Therefore a
forward wall-clock jump while stopped can make an event eligible earlier than
the intended delay, and a backward jump can postpone it; this cannot be
eliminated while persisting portable absolute UTC deadlines without a trusted
external time source.

The integration tests create disposable CA, server, and client certificates
and keys in temporary directories and communicate over loopback only. No
certificate fixtures or production keys are committed. The dashboard remains a
static HTML snapshot and is not served by the ingestion adapter.

This is an integration prototype, not a production deployment configuration.
It does not provide private-network binding, VPN/firewall policy, certificate
enrollment, automated CRL/OCSP checking, multi-process rate limiting,
coordination across separate spool copies or network filesystems, or protected
production key storage.
The application deadline does not forcibly interrupt synchronous SQLite work
already in progress.
Registry fingerprint revocation is checked at ingestion time; certificate
chain and validity/purpose checks are delegated to Python/OpenSSL's TLS
verification against the configured trust roots. Deployment, exposure beyond
localhost, and production credentials require a separate security review.

## Remote mTLS receiver and sender (STEP 284–287 implementation)

`PrivateIngressConfig.load()` remains disabled by default; direct construction
is rejected. Enabled configurations require a numeric RFC1918 IPv4 or IPv6
ULA bind address, an exact approved-address tuple, a Windows adapter GUID,
explicit port, and validated TLS identity/trust material. Loopback, wildcard,
unspecified, link-local, multicast, reserved, and public addresses are
rejected. The server certificate must be current, match its IP/DNS SAN and
server-authentication EKU, match its private key, and use a client trust bundle
containing CA certificates. TLS requires client certificates and TLS 1.2+.

On Windows, loading an enabled configuration obtains the current adapter
GUID/IP inventory through a bounded, non-interactive PowerShell query.
`RemoteMTLSServer` re-queries ownership before binding, verifies the actual
bound address and port, and revalidates ownership before activating the
listener. It has an explicit `start()` API; constructing or starting it is an
operational action that binds the configured private address. This code is
implemented but was not invoked against a private interface for this batch.
`listener_available` remains false as a configuration flag; it does not mean
that the explicit remote receiver API is absent.

`RemoteSenderEndpoint.load()` validates an explicit DNS/IP server identity and
builds a TLS 1.2+ client context with CA verification, hostname checking, and
client certificate/key. `DurableEventSender` accepts this endpoint explicitly;
it does not choose a remote endpoint automatically. Receipt signature
verification, durable spool acknowledgement, retry, and duplicate handling
remain required. The loopback sender path remains available independently.

Both receivers use the bounded `/v1/events` ingestion handler with mutual TLS,
certificate-fingerprint authorization, request size/deadline and rate limits,
and signed committed receipts. The receiver has no dashboard or search-control
route. `LoopbackMTLSServer` remains restricted to `127.0.0.1`. Dashboard output
remains a separate static local file; no dashboard listener exists.

The address-approval tuple is a configuration assertion, not proof of operator
approval. These changes do not authorize or establish real multi-machine
readiness. No private-interface startup/bind, external connection, Windows
Firewall/VPN/DNS change, production enrollment, key provisioning,
trust-bundle distribution, service installation, or Dell/Acer access was
performed. Before deployment, obtain separate operator approval and security
review for interface assignment, source allowlisting, host/key protection,
identity enrollment and revocation distribution, certificate rotation,
firewall/network changes, startup supervision, recovery, and rollback.
Protect private keys with restrictive host ACLs and never place production
credentials in source control or telemetry. To roll back a separately
approved receiver, stop it using its bounded `stop()` method and remove its
explicit endpoint configuration; do not alter the existing loopback adapter.

Committed receipts use version 3 and contain exactly `receipt_version`,
`key_id`, `machine_id`, `event_id`, `sequence`, `canonical_event_hash`,
`outcome`, `issued_at`, and `signature`. The Ed25519 signature covers canonical
sorted-key UTF-8 JSON of all receipt fields except the signature itself. JSON
receipt parsing requires the exact canonical representation and rejects
duplicate keys. The event hash is lowercase SHA256 over canonical
protocol-v1 JSON.

The server-side `CommittedReceiptSigner` accepts Ed25519 private keys and
produces signatures only after the ingestion service's internal store path
returns from a successful SQLite commit. Clients receive only a
`CommittedReceiptVerifier` and a version-1 `ReceiptTrustBundle` containing
public keys, key IDs, validity windows, revocation state, and explicit bounded
rotation authorizations. Overlapping active key windows are rejected unless a
matching rotation entry authorizes the exact old-key expiry boundary. Receipt
verification rejects unknown, revoked, not-yet-valid, expired, or
out-of-window keys, malformed signatures, unsupported versions, and any
receipt that does not exactly match the pending event. The spool performs this
verification against its own stored pending event inside the acknowledgement
transaction.

Install the maintained `cryptography` dependency from `requirements.txt`.
Private signing keys must remain server-side and be provisioned through an
approved protected key-management process; never include them in client
installations, the trust bundle, SQLite telemetry/identity databases, test
fixtures, or source control. Test signing keys are ephemeral. Trust bundles
must be distributed to clients through an independently authenticated
provisioning/update channel, versioned and rolled forward deliberately. A
revoked key is rejected immediately once a client receives a bundle marking it
revoked; offline clients cannot learn revocations until their bundle is
updated. Retain old public keys only for their explicitly bounded overlap and
remove or mark them revoked in the next trust-bundle version.

Ed25519 receipt signatures establish that the holder of the configured server
private key signed the receipt; they do not replace TLS peer validation or
server authorization. The loopback prototype does not add production
deployment, key storage, automated trust-bundle distribution, or external
notifications. Direct `CentralStore` writes and its internal signed-receipt
path remain trusted-code interfaces, not network authorization boundaries.

## Phase 2A local central store and dashboard

`CentralStore` persists protocol-v1 events in a local SQLite database and
maintains event history plus a latest-state projection. Register each
`machine_id` locally before ingesting its telemetry. An ingestion call must
also supply an expected machine ID that matches the event and registration.
Despite the API parameter name `authenticated_machine_id`, it is only a
caller-supplied identity-binding check, **not authentication**. Phase 2A has no
transport, credential enrollment, or network listener.

Events are unique by event ID and by `(machine_id, sequence)`. Exact repeated
events are idempotent; reusing either identifier for changed content is an
explicit conflict. New events are retained in sequence history, including
late/out-of-order events. Only a sequence above the current high-water mark
replaces current telemetry. Sequence gaps are allowed because delayed delivery
can reorder events; arrival of a gap does not claim missing events were
received.

The dashboard labels recency as **local ingestion**, not agent connectivity.
The received timestamp is when this local store accepted an event (including
an accepted delayed event or exact replay); it cannot establish that a remote
agent is online or authenticated. Search activity is derived separately from
log observation and its age. A delayed event's old `observed_at` cannot
overwrite newer search state, and unknown/unavailable telemetry is not
presented as zero progress. Checkpoint age is computed from its observation
timestamp and reports clock skew rather than a negative age. Shared callback
candidate counts/rates remain aggregate values and are never rendered as
worker-local counts.

Log events include `worker_ranges_status`: `valid` means all configured worker
ranges were observed and collectively partition the full search range without
gaps or overlaps; `incomplete` means records are still missing; `inconsistent`
means observed ranges fail that check; `unavailable` means there is not enough
range metadata. Only `valid` partitions are rendered as trusted observed
progress and eligible for log-claim verification. Other observations remain
visible with an explicit warning, and cannot support a VERIFIED log claim.

`render_dashboard_html()` creates a self-contained static snapshot;
`write_dashboard_snapshot()` writes that HTML to a local file. The page has no
external assets, fetches, or listener and uses text-only DOM insertion for
telemetry values. Generate and open the file locally; it is not a live,
auto-refreshing dashboard. The SQLite store is writable, but dashboard
rendering only reads a snapshot. Protect the database and generated HTML using
the host operating system's file permissions.

Snapshot checkpoint age is classified as `available` through 15 seconds,
`stale` after 15 seconds by default, `clock_skew` when the timestamp is in the
future, or the collector's missing/invalid status when no valid checkpoint was
observed. Callers may override the threshold with
`CentralStore.snapshot(checkpoint_timeout_seconds=...)`. This is an age
indicator, not proof that a search process is live. The synthetic two-machine
pilot integration test is `python -B -m unittest tests.test_pilot_integration
-v`; it uses temporary files, disposable credentials, and loopback only.

## Phase 2B offline FOUND verification and local alerts

`FoundVerifier` reads a stored telemetry event and handles FOUND claims from
its log and/or valid Checkpoint V2 payload. It records a `PENDING` SQLite
verification record before attempting the verifier. A durable attempt counter
and lease prevent concurrent duplicate work and allow an explicit later
`verify_event()` call to recover a crash-left PENDING record after the lease
expires. Each claim receives at most three attempts; an expired PENDING record
at the limit is finalized as `ERROR`. Attempts are not automatic background
work. Outcomes are persisted as
`VERIFIED`, `REJECTED`, or `ERROR`. A duplicate claim from the same machine,
identified by nonce, block hash, and raw PoW digest, reuses its existing
record. Only `VERIFIED` records create a unique local alert; alerts are
displayed by the static dashboard and do not trigger external notification.

`FoundVerifier(store).verify_event(machine_id, event_id)` explicitly processes
an already stored event; the call is not performed automatically on ingestion.
The verifier invokes the existing
`contrib/genesis-verification/verify_candidate.py` with the explicit nonce and
reference yespower helper paths, using an argument array, `shell=False`,
captured UTF-8 stdout/stderr, and a bounded timeout. It does not invoke a
search. Before execution it requires a locally registered full search
configuration, checks that its frozen consensus fields match the independent
verifier's documented main-chain contract, and validates the candidate against
the registered nonce range and source worker ranges/configuration. The
independent output must report a valid target/PoW candidate and match the
telemetry's block hash and raw digest before an alert is created.

The registered search configuration is optional at machine registration for
Phase 2A compatibility, but a FOUND claim cannot be verified without it.
Updating an existing machine's registered configuration to a different value
is rejected. A configured verifier/helper that is missing, times out, exits
unexpectedly, or emits invalid output records `ERROR`; malformed or
configuration-incompatible claims are `REJECTED`. Crashes after `PENDING`
remain visible and are not treated as success. The verifier's known output is
small; pipe readers drain output while retaining at most the configured
stdout/stderr bounds. The child receives no stdin. On Windows, the verifier is
created suspended, assigned to a kill-on-close Job Object, and only then
resumed. Timeout/error cleanup terminates the job tree, including descendant
helper processes. The process is launched without a shell.

## Remaining boundaries

- This pipeline only verifies synthetic/offline supplied telemetry when
  explicitly called. No live FOUND candidate was verified for Phase 2B tests.
- Local identity binding does not authenticate an agent; Phase 2B adds no
  transport, remote credential, or network listener. Ingestion recency is
  not remote-agent presence.
- The verifier is intentionally fixed to its documented main-chain parameters
  and authorized nonce range. Other chains/configurations are rejected, not
  inferred or adapted.
- Local alerts are SQLite records and static dashboard content only. There are
  no external notifications or automatic verifier workers.

## Remaining limitations

- No production enrollment, credential distribution, private-network
  deployment, or real multi-machine pilot has been approved or performed.
- The implemented remote mTLS APIs do not start automatically. Calling the
  explicit remote receiver API binds a private interface and requires separate
  operator approval; acceptance tests did not invoke it.
- Log-derived worker progress is observed evidence only, not an atomic snapshot
  and not safe as a resume position.
- Checkpoint age comes from filesystem modification time and depends on a
  trustworthy local clock.
- Rotation/truncation detection uses file identity and size. Same-size
  in-place rewrites, filesystems with weak file identity, and a rotation race
  can require a rescan or explicit operator review.
- A valid checksum detects accidental corruption but does not authenticate
  who produced the file.
