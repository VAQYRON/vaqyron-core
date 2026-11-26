#!/usr/bin/env python3
"""Independently reconstruct and verify a VAQYRON genesis candidate."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


MESSAGE = b"VAQYRON - Independent Proof-of-Work Network - 2026"
MARKER = b"VAQYRON genesis marker v1"
VERSION = 1
TIME = 1791363600
BITS = 0x1D00FFFF
AUTHORIZED_NONCE_START = 541696
UINT32_MAX = 0xFFFFFFFF
POW_LIMIT = int(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16
)
EXPECTED_TARGET = int(
    "00000000ffff0000000000000000000000000000000000000000000000000000", 16
)


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def compact_size(value):
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
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

    if len(script_sig) == 0 or script_sig[0] != len(MESSAGE):
        raise ValueError("genesis coinbase script is not the frozen message push")
    if script_pubkey != b"\x6a" + push_data(MARKER):
        raise ValueError("genesis output is not the frozen OP_RETURN marker")

    tx = bytearray()
    tx.extend(VERSION.to_bytes(4, "little", signed=True))
    tx.extend(compact_size(1))
    tx.extend(b"\x00" * 32)
    tx.extend(b"\xff" * 4)
    tx.extend(compact_size(len(script_sig)))
    tx.extend(script_sig)
    tx.extend(b"\xff" * 4)
    tx.extend(compact_size(1))
    tx.extend((0).to_bytes(8, "little", signed=True))
    tx.extend(compact_size(len(script_pubkey)))
    tx.extend(script_pubkey)
    tx.extend((0).to_bytes(4, "little"))

    # The encoding above has exactly one null-prevout coinbase input and one
    # zero-value OP_RETURN output, so no spendable/founder allocation exists.
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


def reconstruct_candidate(nonce, helper_path):
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 <= nonce <= UINT32_MAX:
        raise ValueError("nonce must be an unsigned 32-bit integer")

    transaction = reconstruct_transaction()
    txid_raw = sha256d(transaction)
    merkle_root_raw = txid_raw
    header = (
        VERSION.to_bytes(4, "little", signed=True)
        + b"\x00" * 32
        + merkle_root_raw
        + TIME.to_bytes(4, "little")
        + BITS.to_bytes(4, "little")
        + nonce.to_bytes(4, "little")
    )
    if len(header) != 80:
        raise ValueError(f"canonical header is {len(header)} bytes, expected 80")

    block_id_raw = sha256d(header)
    pow_digest_raw = compute_pow_digest(header, helper_path)
    pow_integer = int.from_bytes(pow_digest_raw, "little")
    target, target_valid = decode_compact_target(BITS)
    authorized_nonce = AUTHORIZED_NONCE_START <= nonce <= UINT32_MAX
    pow_valid = target_valid and pow_integer <= target

    return {
        "nonce": nonce,
        "nonce_in_authorized_search_range": authorized_nonce,
        "transaction_hex": transaction.hex(),
        "coinbase_input_count": 1,
        "output_count": 1,
        "output_value": 0,
        "output_script_hex": (b"\x6a" + push_data(MARKER)).hex(),
        "output_unspendable": True,
        "founder_allocation": False,
        "txid": txid_raw[::-1].hex(),
        "merkle_root": merkle_root_raw[::-1].hex(),
        "header_hex": header.hex(),
        "header_length": len(header),
        "version": VERSION,
        "previous_block": "00" * 32,
        "time": TIME,
        "bits": f"{BITS:08x}",
        "block_id": block_id_raw[::-1].hex(),
        "pow_digest_raw": pow_digest_raw.hex(),
        "pow_integer": f"{pow_integer:064x}",
        "target": f"{target:064x}",
        "target_valid": target_valid,
        "pow_integer_le_target": pow_integer <= target,
        "pow_valid": pow_valid,
        "candidate_valid": authorized_nonce and pow_valid,
    }


def parse_nonce(value):
    if re.fullmatch(r"[0-9]+", value) is None:
        raise argparse.ArgumentTypeError("nonce must be unsigned decimal")
    nonce = int(value, 10)
    if nonce > UINT32_MAX:
        raise argparse.ArgumentTypeError("nonce must be in the uint32 range")
    return nonce


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nonce", required=True, type=parse_nonce)
    parser.add_argument("--yespower-cli", required=True, type=Path)
    args = parser.parse_args()

    try:
        result = reconstruct_candidate(args.nonce, args.yespower_cli)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"verification error: {error}", file=sys.stderr)
        return 2

    result["result"] = "PASS" if result["candidate_valid"] else "NOT_A_VALID_CANDIDATE"
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["candidate_valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
