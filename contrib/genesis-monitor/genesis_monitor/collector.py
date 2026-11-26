"""Offline read-only collector for existing Genesis Search output and checkpoints."""

from __future__ import annotations

import os
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .checkpoint import CheckpointError, read_checkpoint

_U32 = r"(0|[1-9][0-9]{0,9})"
_U64 = r"(0|[1-9][0-9]{0,19})"
_RANGE_RE = re.compile(r"WORKER RANGE\s+(\d+):\s*(\d+)\.\.(\d+)")
_PROGRESS_RE = re.compile(
    r"Progress:\s*worker=(\d+)\s+range=(\d+)\.\.(\d+)\s+"
    r"nonce=(\d+)\s+candidates=(\d+)\s+elapsed_seconds=([0-9]+(?:\.[0-9]+)?)\s+"
    r"candidates_per_second=([0-9]+(?:\.[0-9]+)?)"
)
_TIMESTAMP_RE = re.compile(
    r"^\s*(?:\[)?(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d))\]?\s+"
)
_SEARCH_TIME_RE = re.compile(r"\bnTime:\s*(\d+)")
_SEARCH_START_RE = re.compile(r"SEARCH START NONCE:\s*(\d+)")
_SEARCH_END_RE = re.compile(r"SEARCH END NONCE:\s*(\d+)")
_WORKER_COUNT_RE = re.compile(r"SEARCH WORKERS:\s*(\d+)")
_RESULT_RE = re.compile(r"\bRESULT:\s*(FOUND|NOT FOUND)\b")
_NONCE_RE = re.compile(r"^NONCE:\s*(\d+)\s*$")
_BLOCK_HASH_RE = re.compile(r"^SHA256d BLOCK_ID:\s*([0-9a-fA-F]{64})\s*$")
_POW_DIGEST_RE = re.compile(r"^POW_DIGEST \(raw\):\s*([0-9a-fA-F]{64})\s*$")
_CANDIDATE_COUNT_RE = re.compile(r"^CANDIDATES EVALUATED:\s*(\d+)\s*$")
_RATE_RE = re.compile(r"^CANDIDATES PER SECOND:\s*([0-9]+(?:\.[0-9]+)?)\s*$")
_MAX_LOG_READ = 128 * 1024 * 1024


class CollectorError(ValueError):
    """The log cannot be safely read or its structure is inconsistent."""


def _utc_now(value: datetime | None = None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("observed_at must be timezone-aware")
    return current.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp_on_line(line: str) -> tuple[str | None, str]:
    match = _TIMESTAMP_RE.match(line)
    if match is None:
        return None, line
    raw = match.group(1).replace(" ", "T")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None, line
    if parsed.tzinfo is None:
        return None, line
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"), line[match.end():]


def _number(value: str, maximum: int, label: str) -> int:
    if len(value) > 20:
        raise ValueError(f"{label} is too large")
    result = int(value, 10)
    if result > maximum:
        raise ValueError(f"{label} is outside the supported range")
    return result


def _empty_log(status: str) -> dict[str, Any]:
    return {
        "status": status,
        "worker_ranges_status": "unavailable",
        "source_mtime": None,
        "search_time": None,
        "range_start": None,
        "range_end": None,
        "worker_count": None,
        "aggregate_candidates": None,
        "aggregate_candidates_per_second": None,
        "result": None,
        "found_candidate": None,
        "workers": [],
        "parse_errors": 0,
    }


@dataclass
class _LogState:
    identity: tuple[int, int] | None = None
    offset: int = 0
    pending: bytearray = field(default_factory=bytearray)
    encoding: str | None = None
    bom_length: int = 0
    log: dict[str, Any] = field(default_factory=lambda: _empty_log("available"))
    workers: dict[int, dict[str, Any]] = field(default_factory=dict)
    found_parts: dict[str, Any] = field(default_factory=dict)
    source_path: str = ""

    def reset(self) -> None:
        self.offset = 0
        self.pending.clear()
        self.encoding = None
        self.bom_length = 0
        self.log = _empty_log("available")
        self.workers.clear()
        self.found_parts.clear()


class LogCollector:
    """Incremental log reader. It never writes to, locks, or controls a worker."""

    def __init__(self) -> None:
        self._states: dict[str, _LogState] = {}

    def _lines(self, path: Path, state: _LogState, stat: os.stat_result) -> list[str]:
        identity = (stat.st_dev, stat.st_ino)
        if state.identity is None:
            state.identity = identity
            state.source_path = str(path.resolve())
        elif identity != state.identity or stat.st_size < state.offset:
            state.reset()
            state.identity = identity
            state.source_path = str(path.resolve())
        if stat.st_size > _MAX_LOG_READ:
            raise CollectorError("log exceeds the 128 MiB scan limit")
        try:
            with path.open("rb") as stream:
                stream.seek(state.offset)
                chunk = stream.read(_MAX_LOG_READ + 1)
                after = os.fstat(stream.fileno())
        except OSError as error:
            raise CollectorError(f"cannot read log: {error}") from error
        if len(chunk) > _MAX_LOG_READ:
            raise CollectorError("log update exceeds the 128 MiB read limit")
        if (after.st_dev, after.st_ino) != state.identity or after.st_size < state.offset + len(chunk):
            state.reset()
            state.identity = (after.st_dev, after.st_ino)
            raise CollectorError("log rotated or truncated while it was being read; retry collection")
        state.offset += len(chunk)
        state.pending.extend(chunk)

        if state.encoding is None:
            prefix = bytes(state.pending[:256])
            if prefix.startswith(b"\xef\xbb\xbf"):
                state.encoding, state.bom_length = "utf-8", 3
            elif prefix.startswith(b"\xff\xfe"):
                state.encoding, state.bom_length = "utf-16-le", 2
            elif prefix.startswith(b"\xfe\xff"):
                state.encoding, state.bom_length = "utf-16-be", 2
            elif len(prefix) >= 4:
                even_nuls = sum(prefix[index] == 0 for index in range(0, len(prefix), 2))
                odd_nuls = sum(prefix[index] == 0 for index in range(1, len(prefix), 2))
                if odd_nuls > max(1, len(prefix) // 8):
                    state.encoding = "utf-16-le"
                elif even_nuls > max(1, len(prefix) // 8):
                    state.encoding = "utf-16-be"
                else:
                    state.encoding = "utf-8"
            else:
                return []

        if state.bom_length:
            del state.pending[:state.bom_length]
            state.bom_length = 0
        if state.encoding == "utf-16-le":
            delimiter = b"\n\x00"
        elif state.encoding == "utf-16-be":
            delimiter = b"\x00\n"
        else:
            delimiter = b"\n"
        complete: list[str] = []
        while True:
            index = state.pending.find(delimiter)
            if index < 0:
                break
            raw_line = bytes(state.pending[:index])
            del state.pending[: index + len(delimiter)]
            if state.encoding.startswith("utf-16") and len(raw_line) % 2:
                state.log["parse_errors"] += 1
                continue
            try:
                line = raw_line.decode(state.encoding, errors="strict")
            except UnicodeDecodeError:
                state.log["parse_errors"] += 1
                continue
            complete.append(line.removesuffix("\r"))
        return complete

    def _consume(self, state: _LogState, line: str) -> None:
        timestamp, body = _timestamp_on_line(line)
        try:
            match = _SEARCH_TIME_RE.search(body)
            if match:
                state.log["search_time"] = _number(match.group(1), 0xFFFFFFFF, "nTime")
            match = _SEARCH_START_RE.search(body)
            if match:
                state.log["range_start"] = _number(match.group(1), 0xFFFFFFFF, "search start nonce")
            match = _SEARCH_END_RE.search(body)
            if match:
                state.log["range_end"] = _number(match.group(1), 0xFFFFFFFF, "search end nonce")
            match = _WORKER_COUNT_RE.search(body)
            if match:
                state.log["worker_count"] = _number(match.group(1), 1024, "worker count")

            match = _RANGE_RE.search(body)
            if match:
                index, start, end = (_number(value, 0xFFFFFFFF, "worker range") for value in match.groups())
                if start > end:
                    raise ValueError("worker range start exceeds end")
                worker = self._worker(state, index)
                if worker["range_start"] not in (None, start) or worker["range_end"] not in (None, end):
                    raise ValueError("worker range changed within one log generation")
                worker["range_start"], worker["range_end"] = start, end
            elif "WORKER RANGE" in body:
                raise ValueError("malformed worker range line")

            match = _PROGRESS_RE.search(body)
            if match:
                index, start, end, nonce = (_number(value, 0xFFFFFFFF, "progress nonce") for value in match.groups()[:4])
                candidates = _number(match.group(5), 0xFFFFFFFFFFFFFFFF, "aggregate candidate count")
                speed = float(match.group(7))
                if not math.isfinite(speed):
                    raise ValueError("aggregate rate is not finite")
                if start > end or not start <= nonce <= end:
                    raise ValueError("progress nonce or range is inconsistent")
                worker = self._worker(state, index)
                if worker["range_start"] not in (None, start) or worker["range_end"] not in (None, end):
                    raise ValueError("progress range differs from declared worker range")
                worker["range_start"], worker["range_end"] = start, end
                worker["current_nonce"] = nonce
                worker["shared_candidates_at_observation"] = candidates
                worker["aggregate_candidates_per_second"] = speed
                worker["progress_timestamp"] = timestamp
                state.log["aggregate_candidates"] = candidates
                state.log["aggregate_candidates_per_second"] = speed
            elif "Progress:" in body:
                raise ValueError("malformed progress line")

            match = _RESULT_RE.search(body)
            if match:
                state.log["result"] = match.group(1)
            for pattern, key, maximum in (
                (_NONCE_RE, "nonce", 0xFFFFFFFF),
                (_BLOCK_HASH_RE, "block_hash", None),
                (_POW_DIGEST_RE, "pow_digest_raw", None),
                (_CANDIDATE_COUNT_RE, "candidates_evaluated", 0xFFFFFFFFFFFFFFFF),
                (_RATE_RE, "candidates_per_second", None),
            ):
                match = pattern.search(body)
                if match:
                    raw = match.group(1)
                    if maximum is None:
                        parsed_value = float(raw) if key == "candidates_per_second" else raw.lower()
                        if key == "candidates_per_second" and not math.isfinite(parsed_value):
                            raise ValueError("aggregate rate is not finite")
                        state.found_parts[key] = parsed_value
                    else:
                        state.found_parts[key] = _number(raw, maximum, key)
            if state.log["result"] == "FOUND":
                nonce = state.found_parts.get("nonce")
                block_hash = state.found_parts.get("block_hash")
                digest = state.found_parts.get("pow_digest_raw")
                if nonce is not None and block_hash is not None and digest is not None:
                    state.log["found_candidate"] = {
                        "nonce": nonce,
                        "block_hash": block_hash,
                        "pow_digest_raw": digest,
                        "timestamp": timestamp,
                    }
            if state.found_parts.get("candidates_evaluated") is not None:
                state.log["aggregate_candidates"] = state.found_parts["candidates_evaluated"]
            if state.found_parts.get("candidates_per_second") is not None:
                state.log["aggregate_candidates_per_second"] = state.found_parts["candidates_per_second"]
        except (ValueError, OverflowError):
            state.log["parse_errors"] += 1

    @staticmethod
    def _worker(state: _LogState, index: int) -> dict[str, Any]:
        if index not in state.workers:
            state.workers[index] = {
                "worker_index": index,
                "range_start": None,
                "range_end": None,
                "current_nonce": None,
                "shared_candidates_at_observation": None,
                "aggregate_candidates_per_second": None,
                "progress_timestamp": None,
            }
        return state.workers[index]

    @staticmethod
    def _worker_ranges_status(log: dict[str, Any]) -> str:
        worker_count = log["worker_count"]
        range_start, range_end = log["range_start"], log["range_end"]
        workers = log["workers"]
        if worker_count is None or range_start is None or range_end is None:
            return "incomplete" if workers or worker_count is not None else "unavailable"
        if worker_count == 0 or len(workers) > worker_count:
            return "inconsistent"
        by_index = {worker["worker_index"]: worker for worker in workers}
        if any(index >= worker_count for index in by_index):
            return "inconsistent"
        if len(workers) < worker_count:
            return "incomplete"
        if set(by_index) != set(range(worker_count)):
            return "inconsistent"
        next_nonce = range_start
        for index in range(worker_count):
            worker = by_index[index]
            start, end = worker["range_start"], worker["range_end"]
            if (start is None) != (end is None):
                return "inconsistent"
            if start is None:
                return "incomplete"
            if start != next_nonce or start > end or end > range_end:
                return "inconsistent"
            next_nonce = end + 1
        return "valid" if next_nonce == range_end + 1 else "inconsistent"

    def collect(
        self,
        log_path: str | os.PathLike[str] | None,
        checkpoint_path: str | os.PathLike[str] | None = None,
        *,
        observed_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Return separate observed-log and durable-checkpoint telemetry."""
        collected_at = _utc_now(observed_at)
        if log_path is None:
            log_observation = _empty_log("not_configured")
        else:
            path = Path(log_path)
            key = str(path.absolute())
            state = self._states.setdefault(key, _LogState())
            try:
                stat = path.stat()
                lines = self._lines(path, state, stat)
            except OSError as error:
                raise CollectorError(f"cannot inspect log: {error}") from error
            for line in lines:
                self._consume(state, line)
            state.log["status"] = "available"
            state.log["source_mtime"] = datetime.fromtimestamp(
                stat.st_mtime, timezone.utc
            ).isoformat(timespec="microseconds").replace("+00:00", "Z")
            state.log["workers"] = [state.workers[index] for index in sorted(state.workers)]
            state.log["worker_ranges_status"] = self._worker_ranges_status(state.log)
            log_observation = state.log

        if checkpoint_path is None:
            checkpoint_observation = {
                "status": "not_configured",
                "observed_at": None,
                "format_version": None,
                "configuration": None,
                "workers": [],
                "found": None,
                "error": None,
            }
        else:
            try:
                checkpoint, checkpoint_mtime = read_checkpoint(checkpoint_path)
            except CheckpointError as error:
                checkpoint_observation = {
                    "status": "invalid" if Path(checkpoint_path).exists() else "unavailable",
                    "observed_at": None,
                    "format_version": None,
                    "configuration": None,
                    "workers": [],
                    "found": None,
                    "error": str(error)[:256],
                }
            else:
                checkpoint_observation = {
                    "status": "valid",
                    "observed_at": checkpoint_mtime,
                    "format_version": checkpoint["format_version"],
                    "configuration": checkpoint["configuration"],
                    "workers": checkpoint["workers"],
                    "found": checkpoint["found"],
                    "error": None,
                }
        return {
            "log": log_observation,
            "checkpoint": checkpoint_observation,
        }


def parse_complete_log_text(text: str) -> dict[str, Any]:
    """Deterministic convenience parser for complete synthetic/archived log text."""
    collector = LogCollector()
    import tempfile

    with tempfile.TemporaryDirectory(prefix="vaqyron-genesis-monitor-") as directory:
        path = Path(directory) / "synthetic.log"
        path.write_text(text, encoding="utf-8", newline="")
        result = collector.collect(path)
    return result["log"]
