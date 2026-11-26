# Real Multi-Laptop Pilot Acceptance Checklist (Preparation Only)

This checklist is a future operator gate, not authorization to run a pilot.
The example templates are disabled placeholders. A strict operational config
loader and explicit CLI now exist, but the examples remain unusable for runtime
and no production credentials/configuration are provisioned. Do not populate
operational values, bind a private interface, distribute credentials, or
contact another machine without the approvals below. `agent-once` is a manual
single-cycle command, not a resident supervisor or service.

## Preflight approvals

- [ ] **Scope and change approval:** named operator, approved time window,
  exact machines (MAIN, Dell, Acer), and a reviewed rollback owner.
- [ ] **Network approval:** MAIN private address/interface, source addresses,
  port, trusted network path, allowlisting, and firewall changes explicitly
  approved by the system/network owner. No wildcard/public/loopback receiver
  address.
- [ ] **Credential approval:** CA/operator, machine identity mapping, issuance,
  validity, revocation and rotation policy, protected key locations, and
  separately delivered receipt-verification public-key bundle approved.
- [ ] **Machine access approval:** read-only access to existing log/checkpoint
  files and permission to install/run a future passive agent. No search process
  control or modification.
- [ ] **Startup approval:** one-time manual MAIN receiver start and each agent
  launch individually approved. No service, scheduled task, or automatic
  startup.

The current operational config does not implement an application-level source
address allowlist. Require the network/firewall owner to approve and verify the
Dell-source restriction in the effective policy before starting the receiver.
If Windows reports `BlockInboundAlways` or local firewall rules are not honored,
do not assume a local allow rule will work and do not bypass that policy.

## Acceptance (record PASS/FAIL, evidence, operator and time)

The operational CLI commands are documented in `README.md`. Configuration
validation is read-only; `receiver-start`, `agent-once`, and
`dashboard-render` perform their named runtime action only when explicitly
invoked. `receiver-start` runs in the foreground and is stopped with Ctrl+C;
its bounded shutdown preserves the central store and agent spool files.

- [ ] **MAIN receiver:** approved interface GUID/address ownership revalidated;
  certificate SAN/validity/EKU/key/trust verified; mutual TLS required; identity
  registry contains only the approved machine certificate fingerprints;
  receiver binds only its approved address; `/v1/events` works and dashboard
  and search-control routes are unavailable.
- [ ] **Certificate identity:** each client certificate maps to exactly one
  machine ID; wrong, expired, revoked, and unregistered identities are
  rejected. Server identity and CA chain are verified by agents.
- [ ] **Dell telemetry:** existing log path is approved and read-only; progress
  is explicitly labelled log-observed. Dell was started without checkpoint
  support, so no durable checkpoint/resume position may be inferred or
  manufactured. Do not restart or alter the search to add checkpointing.
- [ ] **Acer telemetry:** readiness, supported log/checkpoint paths, worker
  configuration, identity enrollment, and non-interference are evidenced
  before collection.
- [ ] **Spool recovery:** force an approved test outage; pending events remain
  durable, retry after receiver recovery, verify signed receipts before ACK,
  and confirm duplicate delivery after lost ACK is idempotent.
- [ ] **Dashboard:** generated local static snapshot distinguishes local
  ingestion recency from machine/process liveness, shows missing/stale/valid
  checkpoint states, and does not claim remote process liveness.
- [ ] **Offline detection:** disconnect/outage does not discard events or
  report agents as live; record the last accepted ingestion time and recovery.
- [ ] **Shutdown and rollback:** manually stop receiver/senders; verify no
  listener remains, revert only approved pilot config/network changes, revoke
  pilot credentials when required, and confirm normal Genesis Search operation
  was untouched.

Any FAIL, unexpected listener, identity mismatch, telemetry loss, or observed
search impact stops the pilot. Preserve logs and spool state for operator
review; do not restart or alter Genesis Search as a recovery shortcut.

## Credential and key handling requirements

1. Issue distinct server and per-machine client certificates from the approved
   CA. Server certificates must identify the exact approved DNS name/IP in SAN
   and include server-auth EKU. Client certificates must include client-auth
   EKU and be fingerprint-enrolled to one machine ID in MAIN's registry.
2. Protect client private keys with Windows certificate-store non-exportable
   keys where supported, or restrictive NTFS ACLs granting read access only to
   the dedicated least-privilege agent account and SYSTEM/administrators.
   Protect MAIN server, CA/trust, receipt-signing key, registry and backups
   under separate least-privilege ACLs. Never place private keys in the spool,
   telemetry, templates, logs, or source control.
3. Deliver server CA roots and the Ed25519 receipt-verification public-key
   bundle to agents using an independently authenticated process. Receipt
   signatures are not a replacement for TLS server identity checking.
4. For rotation, issue and enroll a replacement credential before switching,
   use only an explicitly approved bounded overlap, confirm delivery under the
   replacement, then revoke/remove the old fingerprint and distribute updated
   trust. Revoke compromised credentials immediately; remember offline agents
   cannot learn updated revocation/trust until receiving the next approved
   bundle. Current TLS CA revocation checking has no automated CRL/OCSP
   integration.

## Manual recovery sequence

1. Prevent further transmissions by not invoking `agent-once` again. An
  in-progress one-shot completes or fails through its bounded sender call;
  keep local spool databases intact.
2. Stop MAIN receiver with Ctrl+C in the foreground `receiver-start` terminal;
  its bounded stop path closes the receiver socket. Do not kill unrelated
  processes.
3. Preserve error logs, identity-registry/receipt trust versions, spool
   databases and static dashboard snapshots under approved ACLs. Back up
   identity and receipt-key material before any authorized change.
4. Diagnose endpoint, certificate, identity, store, or interface ownership
   failure offline. Do not bypass TLS, clear pending spool events, or broaden
   bind/source access to recover.
5. Restore only a known-good, operator-approved configuration/trust backup.
   Revalidate the exact interface and certificates before a separately
   approved manual restart. If recovery cannot be proven safe, leave telemetry
   stopped and preserve Genesis Search untouched.
