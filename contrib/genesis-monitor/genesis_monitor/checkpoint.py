"""Read-only parser for VAQYRON Genesis Search Checkpoint V2."""

from __future__ import annotations

import hashlib
import os
import struct
from pathlib import Path
from typing import Any

MAGIC = 0x56514743
VERSION = 2
ALGORITHM_YESPOWER_1_0 = 1
MAX_CHECKPOINT_BYTES = 1024 * 1024
MAX_WORKERS = 4


class CheckpointError(ValueError):
    """Checkpoint is unreadable, corrupt, malformed, or incompatible."""


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise CheckpointError("checkpoint payload is truncated")
        result = self.data[self.offset : self.offset + size]
        self.offset += size
        return result

    def u8(self) -> int:
        return self.read(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.read(4))[0]

    def compact_size(self) -> int:
        marker = self.u8()
        if marker < 253:
            return marker
        if marker == 253:
            value = struct.unpack("<H", self.read(2))[0]
            if value < 253:
                raise CheckpointError("checkpoint has non-canonical CompactSize")
            return value
        if marker == 254:
            value = self.u32()
            if value <= 0xFFFF:
                raise CheckpointError("checkpoint has non-canonical CompactSize")
            return value
        value = struct.unpack("<Q", self.read(8))[0]
        if value <= 0xFFFFFFFF:
            raise CheckpointError("checkpoint has non-canonical CompactSize")
        return value


def _hex_display(serialized_uint256: bytes) -> str:
    """Match uint256::GetHex(): reverse the serialized internal byte order."""
    return serialized_uint256[::-1].hex()


def parse_checkpoint_bytes(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes):
        raise TypeError("checkpoint data must be bytes")
    if len(data) > MAX_CHECKPOINT_BYTES:
        raise CheckpointError("checkpoint exceeds the 1 MiB size limit")
    if len(data) < 33:
        raise CheckpointError("checkpoint is truncated")
    payload, saved_checksum = data[:-32], data[-32:]
    expected_checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if saved_checksum != expected_checksum:
        raise CheckpointError("checkpoint integrity check failed")

    reader = _Reader(payload)
    magic = reader.u32()
    version = reader.u32()
    algorithm = reader.u32()
    if magic != MAGIC:
        raise CheckpointError("checkpoint magic is invalid")
    if version != VERSION:
        raise CheckpointError(f"unsupported checkpoint version: {version}")
    if algorithm != ALGORITHM_YESPOWER_1_0:
        raise CheckpointError(f"unsupported checkpoint algorithm: {algorithm}")

    search_time = reader.u32()
    start_nonce = reader.u32()
    end_nonce = reader.u32()
    requested_workers = reader.u32()
    nbits = reader.u32()
    block_version = reader.i32()
    pow_limit_raw = reader.read(32)
    found_flag = reader.u8()
    found_nonce = reader.u32()
    found_header_raw = reader.read(32)
    found_digest_raw = reader.read(32)
    worker_count = reader.compact_size()

    if start_nonce > end_nonce:
        raise CheckpointError("checkpoint search range start exceeds its end")
    if requested_workers == 0 or requested_workers > MAX_WORKERS:
        raise CheckpointError("checkpoint requested worker count is outside supported limits")
    expected_workers = min(end_nonce - start_nonce + 1, requested_workers)
    if worker_count != expected_workers:
        raise CheckpointError("checkpoint worker count is inconsistent with its configuration")
    if found_flag not in (0, 1):
        raise CheckpointError("checkpoint FOUND status is invalid")

    workers: list[dict[str, Any]] = []
    next_nonce = start_nonce
    nonce_count = end_nonce - start_nonce + 1
    base_size, remainder = divmod(nonce_count, worker_count)
    for index in range(worker_count):
        worker_index = reader.u32()
        worker_start = reader.u32()
        worker_end = reader.u32()
        has_progress = reader.u8()
        last_completed = reader.u32()
        last_digest = reader.read(32)
        range_size = base_size + (1 if index < remainder else 0)
        expected_end = next_nonce + range_size - 1
        if worker_index != index or worker_start != next_nonce or worker_end != expected_end:
            raise CheckpointError("checkpoint worker ranges are not the original contiguous partition")
        if has_progress not in (0, 1):
            raise CheckpointError(f"checkpoint worker {index} progress flag is invalid")
        if has_progress:
            if not worker_start <= last_completed <= worker_end:
                raise CheckpointError(f"checkpoint worker {index} progress is outside its range")
            digest_value: str | None = last_digest.hex()
            completed_value: int | None = last_completed
        else:
            if last_completed != 0 or any(last_digest):
                raise CheckpointError(f"checkpoint worker {index} has data without progress")
            digest_value = None
            completed_value = None
        workers.append({
            "worker_index": worker_index,
            "start_nonce": worker_start,
            "end_nonce": worker_end,
            "last_completed_nonce": completed_value,
            "last_pow_digest_raw": digest_value,
        })
        next_nonce = expected_end + 1

    if reader.offset != len(payload):
        raise CheckpointError("checkpoint contains trailing or unparsed payload data")

    if found_flag:
        if not any(worker["start_nonce"] <= found_nonce <= worker["end_nonce"] for worker in workers):
            raise CheckpointError("checkpoint FOUND nonce is outside its worker ranges")
        found: dict[str, Any] | None = {
            "nonce": found_nonce,
            "header_hash": _hex_display(found_header_raw),
            "pow_digest_raw": found_digest_raw.hex(),
            "independent_verification_status": "not_performed",
        }
    else:
        if found_nonce != 0 or any(found_header_raw) or any(found_digest_raw):
            raise CheckpointError("checkpoint contains winner data without FOUND status")
        found = None

    return {
        "format_version": version,
        "configuration": {
            "time": search_time,
            "start_nonce": start_nonce,
            "end_nonce": end_nonce,
            "requested_worker_count": requested_workers,
            "nbits": nbits,
            "block_version": block_version,
            "pow_limit": _hex_display(pow_limit_raw),
        },
        "workers": workers,
        "found": found,
        "checksum_valid": True,
    }


def read_checkpoint(path: str | os.PathLike[str]) -> tuple[dict[str, Any], str]:
    """Read a single checkpoint snapshot without locking or changing any file."""
    checkpoint_path = Path(path)
    try:
        with checkpoint_path.open("rb") as stream:
            initial = os.fstat(stream.fileno())
            if initial.st_size > MAX_CHECKPOINT_BYTES:
                raise CheckpointError("checkpoint exceeds the 1 MiB size limit")
            data = stream.read(MAX_CHECKPOINT_BYTES + 1)
            if len(data) > MAX_CHECKPOINT_BYTES:
                raise CheckpointError("checkpoint exceeds the 1 MiB size limit")
            final = os.fstat(stream.fileno())
            if (initial.st_size, initial.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
                raise CheckpointError("checkpoint changed while it was being read")
    except OSError as error:
        raise CheckpointError(f"cannot read checkpoint: {error}") from error
    return parse_checkpoint_bytes(data), _iso_utc_ns(final.st_mtime_ns)


def _iso_utc_ns(timestamp_ns: int) -> str:
    from datetime import datetime, timezone

    value = datetime.fromtimestamp(timestamp_ns / 1_000_000_000, timezone.utc)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
