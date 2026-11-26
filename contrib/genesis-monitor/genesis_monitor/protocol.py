"""Strict versioned telemetry event schema for the Genesis Monitor."""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from typing import Any, Mapping

PROTOCOL_VERSION = 1
MAX_EVENT_BYTES = 64 * 1024
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class ProtocolError(ValueError):
    """Telemetry input is malformed or incompatible."""


def _object(value: Any, name: str, keys: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProtocolError(f"{name} must contain exactly: {', '.join(sorted(keys))}")
    return value


def _uint(value: Any, name: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ProtocolError(f"{name} must be an integer in 0..{maximum}")


def _nullable_uint(value: Any, name: str, maximum: int) -> None:
    if value is not None:
        _uint(value, name, maximum)


def _nullable_text(value: Any, name: str) -> None:
    if value is not None and (not isinstance(value, str) or len(value) > 256):
        raise ProtocolError(f"{name} must be null or a string of at most 256 characters")


def _timestamp(value: Any, name: str, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProtocolError(f"{name} must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProtocolError(f"{name} is not a valid ISO-8601 timestamp") from error
    if parsed.utcoffset() is None:
        raise ProtocolError(f"{name} must include UTC")


def _hash(value: Any, name: str, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise ProtocolError(f"{name} must be 64 lowercase hexadecimal characters")


def _finite_number(value: Any, name: str, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ProtocolError(f"{name} must be a finite non-negative number")


def _validate_log(log: Any) -> dict[str, Any]:
    fields = {
        "status", "worker_ranges_status", "source_mtime", "search_time", "range_start", "range_end",
        "worker_count", "aggregate_candidates", "aggregate_candidates_per_second",
        "result", "found_candidate", "workers", "parse_errors",
    }
    legacy_fields = fields - {"worker_ranges_status"}
    if isinstance(log, dict) and set(log) == legacy_fields:
        item = dict(log)
        item["worker_ranges_status"] = "incomplete"
    else:
        item = dict(_object(log, "payload.log", fields))
    if not isinstance(item["status"], str) or item["status"] not in ("available", "unavailable", "not_configured"):
        raise ProtocolError("payload.log.status is invalid")
    if item["worker_ranges_status"] not in ("unavailable", "incomplete", "valid", "inconsistent"):
        raise ProtocolError("payload.log.worker_ranges_status is invalid")
    _timestamp(item["source_mtime"], "payload.log.source_mtime", nullable=True)
    _nullable_uint(item["search_time"], "payload.log.search_time", 0xFFFFFFFF)
    _nullable_uint(item["range_start"], "payload.log.range_start", 0xFFFFFFFF)
    _nullable_uint(item["range_end"], "payload.log.range_end", 0xFFFFFFFF)
    if item["range_start"] is not None and item["range_end"] is not None:
        if item["range_start"] > item["range_end"]:
            raise ProtocolError("payload.log range start exceeds its end")
    elif (item["range_start"] is None) != (item["range_end"] is None):
        raise ProtocolError("payload.log range boundaries must both be present or null")
    _nullable_uint(item["worker_count"], "payload.log.worker_count", 1024)
    _nullable_uint(item["aggregate_candidates"], "payload.log.aggregate_candidates", 0xFFFFFFFFFFFFFFFF)
    _finite_number(item["aggregate_candidates_per_second"], "payload.log.aggregate_candidates_per_second", nullable=True)
    if item["result"] is not None and (
        not isinstance(item["result"], str) or item["result"] not in ("FOUND", "NOT FOUND")
    ):
        raise ProtocolError("payload.log.result is invalid")
    candidate = item["found_candidate"]
    if candidate is not None:
        candidate = _object(candidate, "payload.log.found_candidate", {
            "nonce", "block_hash", "pow_digest_raw", "timestamp",
        })
        _uint(candidate["nonce"], "payload.log.found_candidate.nonce", 0xFFFFFFFF)
        _hash(candidate["block_hash"], "payload.log.found_candidate.block_hash")
        _hash(candidate["pow_digest_raw"], "payload.log.found_candidate.pow_digest_raw")
        _timestamp(candidate["timestamp"], "payload.log.found_candidate.timestamp", nullable=True)
    if not isinstance(item["workers"], list) or len(item["workers"]) > 1024:
        raise ProtocolError("payload.log.workers must be a bounded array")
    seen_workers: set[int] = set()
    for worker in item["workers"]:
        worker = _object(worker, "payload.log.worker", {
            "worker_index", "range_start", "range_end", "current_nonce",
            "shared_candidates_at_observation", "aggregate_candidates_per_second",
            "progress_timestamp",
        })
        _uint(worker["worker_index"], "payload.log.worker.worker_index", 1023)
        if worker["worker_index"] in seen_workers:
            raise ProtocolError("payload.log contains duplicate worker indices")
        seen_workers.add(worker["worker_index"])
        _nullable_uint(worker["range_start"], "payload.log.worker.range_start", 0xFFFFFFFF)
        _nullable_uint(worker["range_end"], "payload.log.worker.range_end", 0xFFFFFFFF)
        if worker["range_start"] is not None and worker["range_end"] is not None:
            if worker["range_start"] > worker["range_end"]:
                raise ProtocolError("payload.log.worker range start exceeds its end")
        elif (worker["range_start"] is None) != (worker["range_end"] is None):
            raise ProtocolError("payload.log.worker range boundaries must both be present or null")
        _nullable_uint(worker["current_nonce"], "payload.log.worker.current_nonce", 0xFFFFFFFF)
        _nullable_uint(
            worker["shared_candidates_at_observation"],
            "payload.log.worker.shared_candidates_at_observation",
            0xFFFFFFFFFFFFFFFF,
        )
        _finite_number(
            worker["aggregate_candidates_per_second"],
            "payload.log.worker.aggregate_candidates_per_second",
            nullable=True,
        )
        _timestamp(worker["progress_timestamp"], "payload.log.worker.progress_timestamp", nullable=True)
        if worker["current_nonce"] is not None and worker["range_start"] is not None:
            if not worker["range_start"] <= worker["current_nonce"] <= worker["range_end"]:
                raise ProtocolError("payload.log.worker.current_nonce is outside its range")
        elif worker["current_nonce"] is not None:
            raise ProtocolError("payload.log.worker.current_nonce requires a complete worker range")
    _uint(item["parse_errors"], "payload.log.parse_errors", 0xFFFFFFFF)
    if item["status"] == "not_configured" and (
        item["workers"] or item["range_start"] is not None or item["range_end"] is not None
        or item["aggregate_candidates"] is not None
    ):
        raise ProtocolError("unconfigured log observation cannot contain search progress")
    if item["found_candidate"] is not None and item["result"] != "FOUND":
        raise ProtocolError("a log candidate claim requires RESULT: FOUND")
    if item["worker_count"] is not None:
        if len(item["workers"]) > item["worker_count"]:
            raise ProtocolError("payload.log has more worker records than configured workers")
        for worker in item["workers"]:
            if worker["worker_index"] >= item["worker_count"]:
                raise ProtocolError("payload.log worker index exceeds configured worker count")
            if (
                item["worker_ranges_status"] == "valid"
                and item["range_start"] is not None
                and worker["range_start"] is not None
            ):
                if worker["range_start"] < item["range_start"] or worker["range_end"] > item["range_end"]:
                    raise ProtocolError("payload.log worker range exceeds the search range")
    if item["worker_ranges_status"] == "valid":
        if (
            item["status"] != "available"
            or item["range_start"] is None
            or item["range_end"] is None
            or item["worker_count"] is None
            or len(item["workers"]) != item["worker_count"]
        ):
            raise ProtocolError("valid worker range status requires a complete log observation")
        by_index = {worker["worker_index"]: worker for worker in item["workers"]}
        if set(by_index) != set(range(item["worker_count"])):
            raise ProtocolError("valid worker ranges must include every configured worker index")
        next_nonce = item["range_start"]
        for index in range(item["worker_count"]):
            worker = by_index[index]
            if worker["range_start"] is None or worker["range_end"] is None:
                raise ProtocolError("valid worker ranges must provide both boundaries")
            if worker["range_start"] != next_nonce:
                raise ProtocolError("valid worker ranges must be contiguous and non-overlapping")
            next_nonce = worker["range_end"] + 1
        if next_nonce != item["range_end"] + 1:
            raise ProtocolError("valid worker ranges must cover the complete search range")
    return item


def _validate_checkpoint(checkpoint: Any) -> None:
    item = _object(checkpoint, "payload.checkpoint", {
        "status", "observed_at", "format_version", "configuration", "workers", "found", "error",
    })
    if not isinstance(item["status"], str) or item["status"] not in ("valid", "invalid", "unavailable", "not_configured"):
        raise ProtocolError("payload.checkpoint.status is invalid")
    _timestamp(item["observed_at"], "payload.checkpoint.observed_at", nullable=True)
    _nullable_uint(item["format_version"], "payload.checkpoint.format_version", 0xFFFFFFFF)
    _nullable_text(item["error"], "payload.checkpoint.error")
    configuration = item["configuration"]
    if configuration is not None:
        configuration = _object(configuration, "payload.checkpoint.configuration", {
            "time", "start_nonce", "end_nonce", "requested_worker_count",
            "nbits", "block_version", "pow_limit",
        })
        for name in ("time", "start_nonce", "end_nonce", "requested_worker_count", "nbits"):
            _uint(configuration[name], f"payload.checkpoint.configuration.{name}", 0xFFFFFFFF)
        block_version = configuration["block_version"]
        if isinstance(block_version, bool) or not isinstance(block_version, int) or not -(1 << 31) <= block_version < (1 << 31):
            raise ProtocolError("payload.checkpoint.configuration.block_version must be int32")
        _hash(configuration["pow_limit"], "payload.checkpoint.configuration.pow_limit")
        if configuration["start_nonce"] > configuration["end_nonce"]:
            raise ProtocolError("checkpoint range start exceeds its end")
    if not isinstance(item["workers"], list) or len(item["workers"]) > 1024:
        raise ProtocolError("payload.checkpoint.workers must be a bounded array")
    seen_workers: set[int] = set()
    for worker in item["workers"]:
        worker = _object(worker, "payload.checkpoint.worker", {
            "worker_index", "start_nonce", "end_nonce", "last_completed_nonce", "last_pow_digest_raw",
        })
        _uint(worker["worker_index"], "payload.checkpoint.worker.worker_index", 1023)
        if worker["worker_index"] in seen_workers:
            raise ProtocolError("payload.checkpoint contains duplicate worker indices")
        seen_workers.add(worker["worker_index"])
        _uint(worker["start_nonce"], "payload.checkpoint.worker.start_nonce", 0xFFFFFFFF)
        _uint(worker["end_nonce"], "payload.checkpoint.worker.end_nonce", 0xFFFFFFFF)
        if worker["start_nonce"] > worker["end_nonce"]:
            raise ProtocolError("checkpoint worker range start exceeds its end")
        _nullable_uint(worker["last_completed_nonce"], "payload.checkpoint.worker.last_completed_nonce", 0xFFFFFFFF)
        _hash(worker["last_pow_digest_raw"], "payload.checkpoint.worker.last_pow_digest_raw", nullable=True)
        if worker["last_completed_nonce"] is not None and not worker["start_nonce"] <= worker["last_completed_nonce"] <= worker["end_nonce"]:
            raise ProtocolError("checkpoint worker progress is outside its original range")
    found = item["found"]
    if found is not None:
        found = _object(found, "payload.checkpoint.found", {
            "nonce", "header_hash", "pow_digest_raw", "independent_verification_status",
        })
        _uint(found["nonce"], "payload.checkpoint.found.nonce", 0xFFFFFFFF)
        _hash(found["header_hash"], "payload.checkpoint.found.header_hash")
        _hash(found["pow_digest_raw"], "payload.checkpoint.found.pow_digest_raw")
        if not isinstance(found["independent_verification_status"], str) or found["independent_verification_status"] not in (
            "not_performed", "valid", "invalid", "error"
        ):
            raise ProtocolError("checkpoint FOUND verification status is invalid")
        if not any(worker["start_nonce"] <= found["nonce"] <= worker["end_nonce"] for worker in item["workers"]):
            raise ProtocolError("checkpoint FOUND nonce is outside its worker ranges")
    if item["status"] == "valid":
        if item["format_version"] != 2 or item["observed_at"] is None or configuration is None or item["error"] is not None:
            raise ProtocolError("valid checkpoint observation has incomplete metadata")
        nonce_count = configuration["end_nonce"] - configuration["start_nonce"] + 1
        expected_workers = min(nonce_count, configuration["requested_worker_count"])
        if configuration["requested_worker_count"] == 0 or len(item["workers"]) != expected_workers:
            raise ProtocolError("valid checkpoint worker count does not match its configuration")
        base_size, remainder = divmod(nonce_count, expected_workers)
        next_nonce = configuration["start_nonce"]
        for index, worker in enumerate(item["workers"]):
            expected_end = next_nonce + base_size + (1 if index < remainder else 0) - 1
            if worker["worker_index"] != index or worker["start_nonce"] != next_nonce or worker["end_nonce"] != expected_end:
                raise ProtocolError("valid checkpoint worker ranges are not a contiguous partition")
            next_nonce = expected_end + 1
    elif item["status"] == "not_configured":
        if (
            item["observed_at"] is not None or item["format_version"] is not None
            or configuration is not None or item["workers"] or found is not None or item["error"] is not None
        ):
            raise ProtocolError("unconfigured checkpoint observation cannot contain checkpoint data")
    else:
        if item["format_version"] is not None or configuration is not None or item["workers"] or found is not None:
            raise ProtocolError("invalid/unavailable checkpoint observation cannot contain parsed data")
        if item["status"] == "invalid" and item["error"] is None:
            raise ProtocolError("invalid checkpoint observation must include an error")


def validate_event(event: Any) -> dict[str, Any]:
    """Validate and return a plain JSON-compatible event with exact schema keys."""
    item = _object(event, "event", {
        "protocol_version", "event_id", "sequence", "machine_id", "observed_at", "payload",
    })
    if isinstance(item["protocol_version"], bool) or item["protocol_version"] != PROTOCOL_VERSION:
        raise ProtocolError(f"unsupported telemetry protocol version: {item['protocol_version']!r}")
    for field in ("event_id", "machine_id"):
        value = item[field]
        if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
            raise ProtocolError(f"{field} has invalid syntax")
    _uint(item["sequence"], "sequence", 0x7FFFFFFFFFFFFFFF)
    if item["sequence"] == 0:
        raise ProtocolError("sequence must be positive")
    _timestamp(item["observed_at"], "observed_at")
    payload = _object(item["payload"], "payload", {"log", "checkpoint"})
    validated_log = _validate_log(payload["log"])
    _validate_checkpoint(payload["checkpoint"])
    validated = json.loads(json.dumps(item, allow_nan=False))
    validated["payload"]["log"] = validated_log
    return validated


def canonical_json(value: Any) -> str:
    """Serialize deterministic UTF-8-compatible JSON after strict validation."""
    validated = validate_event(value)
    return json.dumps(validated, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def parse_event(data: str | bytes) -> dict[str, Any]:
    if isinstance(data, bytes):
        if len(data) > MAX_EVENT_BYTES:
            raise ProtocolError("event exceeds the maximum encoded size")
        try:
            data = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ProtocolError("event is not valid UTF-8") from error
    if not isinstance(data, str) or len(data.encode("utf-8")) > MAX_EVENT_BYTES:
        raise ProtocolError("event exceeds the maximum encoded size")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        parsed = json.loads(data, object_pairs_hook=reject_duplicate_keys, parse_constant=lambda value: (_ for _ in ()).throw(ProtocolError(f"invalid JSON constant: {value}")))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ProtocolError("event is not valid JSON") from error
    return validate_event(parsed)
