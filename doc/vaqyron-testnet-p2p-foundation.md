# VAQYRON TESTNET P2P Foundation (Preparation Only)

Status: source/configuration preparation. This document does not authorize
node startup, peer connections, mining, DNS changes, firewall changes, or
public launch. The example files under
`contrib/vaqyron-testnet-p2p/` are inert and use reserved documentation IPs.

## Source-confirmed baseline

The current `VAQYRON_TESTNET` chain parameters in
`src/kernel/chainparams.cpp` set message magic `56 51 54 31` (`VQT1`), P2P
port `39733`, RPC port `39732`, and Bech32 prefix `tvqrn`. The TESTNET chain
parameters clear both DNS and fixed seed lists. Generic Core networking
supports manual `-addnode`, outbound peer selection, and inbound P2P; the
configured chain's message magic and consensus rules still determine which
peers can communicate and which blocks are accepted.

This means:

- Manual peer configuration is currently the only configured VAQYRON
  bootstrap mechanism. Provide the peer's public address to each tester out
  of band.
- Peers are untrusted sources of addresses, transactions, and candidate
  blocks. Each full node validates data locally; seeds do not establish
  consensus or certify peer honesty.
- A node behind NAT may make outbound connections without accepting inbound
  connections. At least one side of a two-node test must accept inbound TCP
  on `39733`.
- Do not expose RPC `39732` to the Internet. The examples bind RPC to
  `127.0.0.1`; the automatically generated cookie remains local to the node
  datadir.
- The two example peer IPs (`198.51.100.10` and `198.51.100.20`) are reserved
  documentation addresses, not reachable peers. Replace them only in a
  separately approved test configuration.

The recorded local TESTNET checkpoints establish genesis, block production,
and a transaction only. The handoff records P2P listening disabled during
the first node/RPC checkpoint and does not establish two-node connectivity,
public synchronization, or public-network security.

## Configuration example safety

`node-a.conf.example` and `node-b.conf.example` show explicit TESTNET-only
selection, the existing P2P port, disabled (currently empty) DNS/fixed-seed
discovery, and an `addnode` peer. They also keep optional diagnostic RPC
loopback-only. They contain no credentials, datadir, startup command, or
network action.

Before any separately approved local test:

1. Use two independently built/operated nodes, each with its own clean,
   explicitly identified datadir and its own `vaqyron.conf`. Never point both
   nodes at the existing accepted TESTNET wallet/datadir.
2. Verify the selected chain is `vaqyron-testnet`, both nodes report the same
   configured genesis, and neither node is MAIN.
3. Replace the sample peer address with the other node's reachable address.
   Permit only inbound TCP `39733` on the chosen inbound test node. Do not
   create an RPC firewall rule. If the second node is behind NAT, it can
   initiate the outbound `addnode` connection.
4. Start only after a specific runtime test is approved. Do not put wallet
   credentials or RPC passwords in configs; if RPC is enabled locally, use
   the node's cookie authentication.

## Future two-node acceptance procedure

This is a runbook for a future approved, isolated acceptance. It has not been
executed. Record software revision, OS, datadir identifiers (not secrets),
network identity, UTC timestamps, both node IDs, and outputs with private
addresses/cookies redacted. Do not reuse the accepted mining wallet.

### A. Separate nodes and initial state

1. Provision two isolated TESTNET nodes on distinct datadirs and preferably
   distinct machines or network namespaces. Keep wallet loading disabled if
   not required. Do not clone chainstate or wallet data between them.
2. Start the inbound test node with P2P listening on `39733`, loopback-only
   RPC if needed, and firewall TCP `39733` only. Start the second node with
   a manual `addnode` entry for the first node. Leave DNS seeding disabled.
3. Verify `getblockchaininfo` reports `chain=vaqyron-testnet`; compare both
   `getblockhash 0` values with the accepted TESTNET genesis hash
   `e4bccdb17adaa76a26e23f67f21062674d30f4476493dfb5f8cf297dc523ef97`.
   Confirm distinct datadirs and no RPC listener on a public interface.

### B. Peer handshake

1. On both nodes, inspect `getpeerinfo` and `getnetworkinfo`. Require one
   established VAQYRON P2P peer, completed version/verack handshake, no
   repeated disconnect loop, and matching software/network identity.
2. Confirm the connection uses P2P port `39733`, not RPC port `39732`.
   Preserve relevant logs. A configured `addnode` entry alone is not a
   handshake PASS.

### C. Block propagation and initial synchronization

1. Only after separate approval for TESTNET mining, produce the minimum
   controlled block(s) required on node A using an authorized TESTNET
   procedure. This is not a public network security test.
2. Require node B to receive and independently accept the block: its height
   increases, `getblockhash <height>` matches node A, and its block data and
   validation log show no rejection. Compare hashes, not just heights.
3. For sync acceptance, use a fresh, empty node B datadir in a later
   separately approved run. Let B synchronize from A and require the same
   height and best-block hash. Do not copy A's chainstate into B.
4. A two-node sync PASS proves only this controlled pair. It is not evidence
   of adversarial security, long-term availability, or public scale.

### D. Reconnection

1. With both test nodes otherwise healthy, deliberately disconnect the peer
   using the local node's peer-management interface; do not stop either
   machine or daemon.
2. Require peer count to drop, then require the configured manual peer to
   reconnect without changing chain identity or datadir. Verify handshake
   completes again and best-block hashes remain equal.
3. Repeat once with a brief, controlled inbound firewall interruption only
   if separately approved. Restore the test firewall rule immediately.
4. Fail acceptance if reconnection requires a company endpoint, DNS seed,
   shared wallet, or manual copying of blockchain state.

## Public bootstrap roadmap (not active)

### Stage 1: manual peer list

Publish a short, versioned list of community-operated TESTNET full-node
addresses through more than one distribution channel (for example, release
documentation plus an independently mirrored community post). Tell operators
to verify the genesis hash and connect with `-addnode=<address>:39733`.
Manual bootstrap must remain usable if every VAQYRON-operated service is
unavailable. Avoid a single privileged peer or a mandatory gateway.

### Stage 2: optional DNS seeds

Only after at least two-node acceptance and security review:

- Recruit multiple seed operators in distinct providers/regions. Seed
  machines should run ordinary validating nodes, not privileged consensus
  services.
- Register chain-specific seed hostnames only with operator consent and
  after testing the Core DNS-seed response format, uptime, rate limits, and
  abuse handling. DNS returns candidate peer addresses; nodes still establish
  direct P2P sessions and validate blocks locally.
- Add reviewed seed hostnames to the VAQYRON TESTNET parameters in a separately
  reviewed source change and release. This step is intentionally not done
  here. Do not point VAQYRON at Bitcoin seed hostnames.
- Keep manual peers as fallback. Fixed seeds are an optional compiled
  fallback of reviewed public peer addresses; they are not a trust list and
  should not be compiled from stale, unconsented, or private addresses.
- Monitor whether seed infrastructure is serving only discovery. Never put
  RPC, wallet, transaction-signing, or consensus authority on a seed host.

DNS can be unavailable, censored, or manipulated to return stale/malicious
addresses. This should affect reachability, not validation rules. A release
must retain manual-peer instructions and seed-operator independence.

## Capacity and monthly cost model

These are planning estimates in USD, not vendor quotes. Assumptions:

- Low-cost VPS budget range: **$6–$20/month per modest full-node VM** (roughly
  1–2 vCPU, 2–4 GiB RAM, SSD, and a plan with stated transfer allowance).
  Region, storage growth, backups, taxes, IPv4 fees, and overage can change it.
- Minimum project bootstrap: **three independently operated seed/full nodes**
  across at least two providers/regions; budget one small monitoring/alerting
  allowance of **$0–$15/month**. The project should seek community operators;
  three seeds are a resilience goal, not a protocol requirement.
- For participant-cost illustration only, assume 1% of registered users
  choose to host a full node, with each using $6–$20/month incremental hosting.
  Assume miners are a subset of node operators and use their own hardware;
  electricity, hardware purchase, broadband, and reward income are excluded.
  The other 99% can use lightweight wallet/application services; actual client
  design is not yet accepted.
- Optional hosted Explorer/API: budget **$25–$150/month at low traffic** for
  one small app/API tier plus limited transfer. This is a placeholder, not a
  capacity guarantee. Large traffic, block indexing/storage, backups, and
  egress require separate workload measurement and could multiply this cost.

| Users | Illustrative user-operated full nodes (1%) | Illustrative miners (subset; planning assumption) | Participant node hosting total | Minimum project bootstrap (3 nodes + monitoring) | Optional Explorer/API | Project total with optional Explorer/API |
|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 100 | 10 (assumed 0.1% of users) | $600–$2,000/mo | $18–$75/mo | $25–$150/mo | $43–$225/mo |
| 20,000 | 200 | 20 | $1,200–$4,000/mo | $18–$75/mo | $25–$150/mo | $43–$225/mo |
| 50,000 | 500 | 50 | $3,000–$10,000/mo | $18–$75/mo | $25–$150/mo | $43–$225/mo |

The participant totals are spread across the assumed node operators and are
**not** a VAQYRON company bill. Company-run infrastructure is intentionally
nearly flat with user count in this model; node count and miner count scale
through independent operators. Bandwidth for P2P is included only within the
assumed VM transfer allowance. Sustained block relay, high churn, or Explorer
traffic above the placeholder needs measured egress and revised estimates.
The 10,000–50,000-user capacity target is not established by this arithmetic.

## Acceptance gates and known blockers

- **Source readiness:** custom TESTNET identity and generic manual P2P support
  are present; no VAQYRON TESTNET DNS/fixed seeds are configured.
- **Offline preparation:** example configs are checked by the focused test
  beside them. This does not start a process or validate a live connection.
- **Local P2P acceptance:** pending the future two-node procedure above.
- **Public TESTNET acceptance:** pending peer discovery/operations review,
  independent operators, difficulty/security review, monitoring/abuse plan,
  and controlled public synchronization.
- **MAINNET:** genesis remains pending and startup guarded; nothing here
  finalizes it or enables MAINNET.
- **Scale:** no 10,000–50,000 user, node, or miner load test is claimed.

## Focused offline check

From the `vaqyron-core` source root, run:

```powershell
python .\contrib\vaqyron-testnet-p2p\test_examples.py
```

The checks only read the two inert examples and the TESTNET source parameter
block. They do not start a node, access runtime data, connect to peers, use
RPC, mine, or contact DNS.
