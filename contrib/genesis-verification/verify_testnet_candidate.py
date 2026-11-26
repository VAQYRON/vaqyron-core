#!/usr/bin/env python3
"""Independently reconstruct and verify a VAQYRON TESTNET genesis candidate."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


CHAIN = "vaqyron-testnet"
MESSAGE = b"VAQYRON TESTNET - Independent Proof-of-Work Network - 2026-10-08"
MARKER = b"VAQYRON TESTNET genesis marker v1"
VERSION = 1
TIME = 1791460800
BITS = 0x207FFFFF
UINT32_MAX = 0xFFFFFFFF
POW_LIMIT = int("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(value):
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= UINT32_MAX:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def push_data(data):
    if len(data) < 0x4C:
        return bytes((len(data),)) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes((len(data),)) + data
    if len(data) <= 0xFFFF:
        return b"\x4d" + len(data).to_bytes(2, "little") + data
    return b"\x4e" + len(data).to_bytes(4, "little") + data


def reconstruct_transaction():
    script_sig = push_data(MESSAGE)
    script_pubkey = b"\x6a" + push_data(MARKER)
    tx = bytearray()
    tx.extend(VERSION.to_bytes(4, "little", signed=True))
    tx.extend(b"\x01")
    tx.extend(b"\x00" * 32)
    tx.extend(b"\xff" * 4)
    tx.extend(compact_size(len(script_sig)))
    tx.extend(script_sig)
    tx.extend(b"\xff" * 4)
    tx.extend(b"\x01")
    tx.extend((0).to_bytes(8, "little", signed=True))
    tx.extend(compact_size(len(script_pubkey)))
    tx.extend(script_pubkey)
    tx.extend((0).to_bytes(4, "little"))
    return bytes(tx)


def decode_compact_target(bits):
    size = bits >> 24
    word = bits & 0x007FFFFF
    negative = word != 0 and (bits & 0x00800000) != 0
    overflow = word != 0 and (
        size > 34
        or (word > 0xFF and size > 33)
        or (word > 0xFFFF and size > 32)
    )
    if size <= 3:
        target = word >> (8 * (3 - size))
    else:
        target = word << (8 * (size - 3))
    valid = not negative and not overflow and target != 0 and target <= POW_LIMIT
    return target, valid


def reconstruct_header(nonce):
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 <= nonce <= UINT32_MAX:
        raise ValueError("nonce must be an unsigned 32-bit integer")
    transaction = reconstruct_transaction()
    txid_raw = sha256d(transaction)
    header = (
        VERSION.to_bytes(4, "little", signed=True)
        + b"\x00" * 32
        + txid_raw
        + TIME.to_bytes(4, "little")
        + BITS.to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )
    if len(header) != 80:
        raise ValueError(f"canonical header is {len(header)} bytes, expected 80")
    return transaction, txid_raw, header


def verify_candidate(nonce, pow_digest, chain=CHAIN, header=None):
    transaction, txid_raw, expected_header = reconstruct_header(nonce)
    supplied_header = expected_header if header is None else bytes(header)
    chain_valid = chain == CHAIN
    header_valid = supplied_header == expected_header
    bits = int.from_bytes(supplied_header[72:76], "little") if len(supplied_header) == 80 else 0
    target, target_valid = decode_compact_target(bits)
    digest = bytes(pow_digest)
    digest_valid = len(digest) == 32
    pow_integer = int.from_bytes(digest, "little") if digest_valid else (1 << 256) - 1
    pow_valid = digest_valid and target_valid and pow_integer <= target
    return {
        "chain": chain,
        "chain_identity_valid": chain_valid,
        "nonce": nonce,
        "transaction_hex": transaction.hex(),
        "txid": txid_raw[::-1].hex(),
        "merkle_root": txid_raw[::-1].hex(),
        "header_hex": supplied_header.hex(),
        "header_length": len(supplied_header),
        "block_id": sha256d(expected_header)[::-1].hex(),
        "version": VERSION,
        "previous_block": "00" * 32,
        "time": TIME,
        "bits": f"{bits:08x}",
        "header_matches_reconstruction": header_valid,
        "pow_digest_raw": digest.hex(),
        "pow_integer": f"{pow_integer:064x}",
        "target": f"{target:064x}",
        "target_valid": target_valid and bits == BITS,
        "pow_integer_le_target": pow_valid,
        "candidate_valid": chain_valid and header_valid and bits == BITS and pow_valid,
    }


def compute_pow_digest(header, helper_path):
    result = subprocess.run(
        [str(helper_path), header.hex()],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or f"helper exited with {result.returncode}"
        raise RuntimeError(f"reference yespower helper failed: {detail}")
    match = re.fullmatch(r"POW_DIGEST=([0-9a-f]{64})\r?\n?", result.stdout)
    if match is None:
        raise RuntimeError("reference yespower helper returned malformed output")
    return bytes.fromhex(match.group(1))


def parse_nonce(value):
    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError("nonce must be unsigned decimal")
    nonce = int(value, 10)
    if nonce > UINT32_MAX:
        raise argparse.ArgumentTypeError("nonce must be in the uint32 range")
    return nonce


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chain", required=True)
    parser.add_argument("--nonce", required=True, type=parse_nonce)
    parser.add_argument("--yespower-cli", required=True, type=Path)
    args = parser.parse_args()

    if args.chain != CHAIN:
        print(f"verification error: expected chain identity {CHAIN}", file=sys.stderr)
        return 2
    try:
        _, _, header = reconstruct_header(args.nonce)
        digest = compute_pow_digest(header, args.yespower_cli)
        result = verify_candidate(args.nonce, digest, chain=args.chain)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"verification error: {error}", file=sys.stderr)
        return 2

    result["result"] = "PASS" if result["candidate_valid"] else "NOT_A_VALID_CANDIDATE"
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["candidate_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
