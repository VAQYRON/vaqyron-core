# VAQYRON genesis candidate verifier

This isolated tool reconstructs and checks a reported genesis nonce from the
frozen inputs. It does not search, alter consensus parameters, or install a
genesis block.

## Independence boundary

`verify_candidate.py` constructs the transaction and header bytes itself and
uses Python's standard-library SHA-256 for TXID, merkle root, and SHA256d
BLOCK_ID. It does not import production VAQYRON code. The yespower digest is
computed by `yespower_ref_cli.c`, separately linked to the repository's
reference `yespower-ref.c` and `sha256.c`, not to production consensus code.
The generator's reported hashes are not inputs to reconstruction.

The reference source is reused in place from
`../pow-prototype/deps/yespower/`; its source-file copyright notices and
redistribution terms are retained. The adapter contains no copied yespower
implementation.

## Frozen parameters

- Message: `VAQYRON - Independent Proof-of-Work Network - 2026`
- OP_RETURN marker: `VAQYRON genesis marker v1`; output value is zero.
- Version `1`; `nTime=1791363600` (`2026-10-07 09:00:00 UTC`);
  `nBits=0x1d00ffff`.
- PoW: `YESPOWER_1_0`, `N=2048`, `r=16`,
  personalization `VAQYRON:pow:yespower:v1`.
- Candidate-A is the little-endian integer of the raw digest bytes.
- BLOCK_ID is SHA256d of the canonical 80-byte header.

## Build and run

From the repository root, compile the adapter with the reference sources. For
example, using GCC or Clang:

```sh
cc -std=c11 -O2 -Wall -Wextra -pthread \
  -Icontrib/pow-prototype/deps/yespower \
  contrib/genesis-verification/yespower_ref_cli.c \
  contrib/pow-prototype/deps/yespower/yespower-ref.c \
  contrib/pow-prototype/deps/yespower/sha256.c \
  -o contrib/genesis-verification/yespower-ref-cli
```

With an MSVC developer environment initialized, build from the repository root
in PowerShell:

```powershell
cl /nologo /O2 /W4 /I contrib\pow-prototype\deps\yespower `
  contrib\genesis-verification\yespower_ref_cli.c `
  contrib\pow-prototype\deps\yespower\yespower-ref.c `
  contrib\pow-prototype\deps\yespower\sha256.c `
  /Fe:contrib\genesis-verification\yespower-ref-cli.exe
```

The helper accepts exactly one 160-character hexadecimal header argument and
prints one `POW_DIGEST=<hex>` line.

Verify the authorized search result by nonce; the nonce must be in the search
range `541696..4294967295` and must pass the frozen proof-of-work target:

```sh
python contrib/genesis-verification/verify_candidate.py \
  --nonce <reported-nonce> \
  --yespower-cli contrib/genesis-verification/yespower-ref-cli
```

Exit status 0 and `"candidate_valid": true` are required. The verifier prints
the independently reconstructed transaction, TXID, merkle root, canonical
header, BLOCK_ID, raw yespower digest, Candidate-A integer, decoded target,
and validity checks. A nonce outside the authorized range or a failed
proof-of-work check is reported as `NOT_A_VALID_CANDIDATE` with a nonzero
status.

## Tests

With the helper built, run:

```sh
YESPOWER_REF_CLI=contrib/genesis-verification/yespower-ref-cli \
  python contrib/genesis-verification/test_verify_candidate.py
```

On Windows PowerShell, set `$env:YESPOWER_REF_CLI` to the helper executable's
path and run:

```powershell
$env:YESPOWER_REF_CLI = 'contrib\genesis-verification\yespower-ref-cli.exe'
python contrib\genesis-verification\test_verify_candidate.py
```

Nonce zero is reserved here only for the explicitly non-candidate reconstruction
test; it is below the authorized search range and fails the target. A real
candidate must come from the separately authorized search. A verifier PASS
confirms the supplied candidate's reconstruction and proof of work only; it
does **not** install or finalize genesis, authorize Step 35D-E, or replace
further review.

## VAQYRON TESTNET candidate tooling (isolated)

The `vaqyron-testnet-genesis-search` executable and
`verify_testnet_candidate.py` are separate from the MAIN search inputs and
verifier. Do not use `verify_candidate.py` for a testnet candidate.

Testnet candidate inputs are fixed to:

- Chain identity: `vaqyron-testnet`
- Message: `VAQYRON TESTNET - Independent Proof-of-Work Network - 2026-10-08`
- OP_RETURN marker: `VAQYRON TESTNET genesis marker v1`; zero output value.
- Version `1`; `nTime=1791460800` (`2026-10-08 12:00:00 UTC`);
  `nBits=0x207fffff`.
- Testnet PoW limit: `7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`.
- PoW: `YESPOWER_1_0`, `N=2048`, `r=16`,
  personalization `VAQYRON:pow:yespower:v1`.
- Candidate-A is the little-endian integer of the raw digest bytes.
- The canonical block identity is SHA256d of the 80-byte header.

Build the search executable without running it:

```powershell
cmake --build build --config Debug --target vaqyron-testnet-genesis-search
```

When an authorized search is requested separately, it accepts an inclusive
nonce range and never changes the timestamp:

```powershell
build\bin\Debug\vaqyron-testnet-genesis-search.exe --start-nonce 0 --end-nonce 4294967295
```

The verifier reconstructs the transaction, Merkle root and header itself; its
only generator-related input is the reported nonce. Build the reference helper
using the C or MSVC instructions earlier in this README, then verify with:

```powershell
python contrib\genesis-verification\verify_testnet_candidate.py `
  --chain vaqyron-testnet `
  --nonce <reported-nonce> `
  --yespower-cli contrib\genesis-verification\yespower-ref-cli.exe
```

The expected PASS output requires the exact testnet chain identity and frozen
header fields, a canonical compact target within the testnet PoW limit, and a
Yespower digest meeting that target. The helper and verifier are not part of
genesis installation. Focused offline verifier tests can run without the
reference helper:

```powershell
python contrib\genesis-verification\test_verify_testnet_candidate.py
```

This tooling only searches and verifies a candidate. It does not install a
genesis, authorize startup, or alter the separate pending-genesis guard.
