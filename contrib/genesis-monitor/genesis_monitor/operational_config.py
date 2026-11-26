"""Strict operational configuration validation without runtime side effects."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any
from uuid import UUID


_MAX_CONFIG_BYTES = 64 * 1024
_MACHINE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_COMMON_FIELDS = {"schema_version", "role", "enabled", "automatic_start"}
_RECEIVER_FIELDS = {
    "bind_address", "interface_guid", "port", "approved_interface_addresses",
    "server_identity", "server_certificate_file", "server_private_key_file",
    "client_ca_file", "identity_registry_file", "central_store_file",
    "receipt_signing_key_file", "receipt_signing_key_id",
    "receipt_trust_bundle_file", "dashboard_output", "machines",
}
_AGENT_FIELDS = {
    "machine_id", "collection", "spool_file", "receiver", "tls",
}


class OperationalConfigurationError(ValueError):
    """Operational configuration is incomplete, unsafe, or inconsistent."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OperationalConfigurationError(f"duplicate configuration key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise OperationalConfigurationError(f"invalid JSON constant: {value}")


def load_operational_config(
    path: str | os.PathLike[str],
    *,
    expected_role: str | None = None,
) -> dict[str, Any]:
    """Read and validate one config file; do not inspect paths it references."""
    config_path = Path(path)
    if not config_path.is_absolute():
        raise OperationalConfigurationError("configuration path must be absolute")
    if any(candidate.is_symlink() for candidate in (config_path, *config_path.parents)):
        raise OperationalConfigurationError("configuration path cannot contain a symlink")
    try:
        with config_path.open("rb") as stream:
            raw = stream.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            raise OperationalConfigurationError("configuration exceeds the 64 KiB limit")
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except OperationalConfigurationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OperationalConfigurationError(
            f"cannot read operational configuration: {type(error).__name__}"
        ) from error

    _validate_config(value, expected_role=expected_role, source_path=config_path)
    return value


def _validate_config(
    value: Any,
    *,
    expected_role: str | None,
    source_path: Path,
) -> None:
    if not isinstance(value, dict):
        raise OperationalConfigurationError("configuration must be a JSON object")
    role = value.get("role")
    if role not in ("receiver", "agent"):
        raise OperationalConfigurationError("role must be 'receiver' or 'agent'")
    if expected_role is not None and role != expected_role:
        raise OperationalConfigurationError("configuration role does not match this command")
    role_fields = _RECEIVER_FIELDS if role == "receiver" else _AGENT_FIELDS
    if set(value) != _COMMON_FIELDS | role_fields:
        raise OperationalConfigurationError("configuration has missing or unknown fields")
    if (
        isinstance(value["schema_version"], bool)
        or value["schema_version"] != 1
    ):
        raise OperationalConfigurationError("schema_version must be integer 1")
    if value["enabled"] is not True:
        raise OperationalConfigurationError("operational configuration must be explicitly enabled")
    if value["automatic_start"] is not False:
        raise OperationalConfigurationError("automatic_start must remain false")
    if role == "receiver":
        _validate_receiver(value, source_path=source_path)
    else:
        _validate_agent(value, source_path=source_path)


def _validate_receiver(value: dict[str, Any], *, source_path: Path) -> None:
    bind_address = _private_address(value["bind_address"], "bind_address")
    try:
        normalized_guid = str(UUID(value["interface_guid"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise OperationalConfigurationError("interface_guid must be a Windows adapter GUID") from error
    if not isinstance(value["interface_guid"], str) or normalized_guid != value["interface_guid"].lower().strip("{}"):
        raise OperationalConfigurationError("interface_guid must use canonical UUID syntax")
    _port(value["port"], "port")
    addresses = value["approved_interface_addresses"]
    if not isinstance(addresses, list) or not addresses:
        raise OperationalConfigurationError("approved_interface_addresses must be a non-empty array")
    normalized_addresses = [_private_address(item, "approved interface address") for item in addresses]
    if len(set(normalized_addresses)) != len(normalized_addresses):
        raise OperationalConfigurationError("approved interface addresses must be unique")
    if _normalize_ip(value["bind_address"]) not in normalized_addresses:
        raise OperationalConfigurationError("bind_address must be in approved_interface_addresses")
    if _server_identity(value["server_identity"]) != bind_address:
        raise OperationalConfigurationError("server_identity must match bind_address for IP-SAN verification")
    _key_id(value["receipt_signing_key_id"])

    paths = {
        name: _absolute_path(value[name], name)
        for name in (
            "server_certificate_file", "server_private_key_file", "client_ca_file",
            "identity_registry_file", "central_store_file", "receipt_signing_key_file",
            "receipt_trust_bundle_file", "dashboard_output",
        )
    }
    _require_distinct_paths(paths)
    config_identity = _path_identity(source_path)
    for name in ("central_store_file", "dashboard_output"):
        if paths[name] == config_identity:
            raise OperationalConfigurationError(f"{name} cannot overwrite the configuration file")
    machines = value["machines"]
    if not isinstance(machines, list) or not machines or len(machines) > 1024:
        raise OperationalConfigurationError("machines must contain 1..1024 entries")
    seen_ids: set[str] = set()
    for machine in machines:
        if not isinstance(machine, dict) or set(machine) != {"machine_id", "display_name"}:
            raise OperationalConfigurationError("each machine must contain machine_id and display_name")
        machine_id = _machine_id(machine["machine_id"])
        if machine_id in seen_ids:
            raise OperationalConfigurationError("machine_id entries must be unique")
        seen_ids.add(machine_id)
        if (
            not isinstance(machine["display_name"], str)
            or not machine["display_name"].strip()
            or len(machine["display_name"]) > 128
        ):
            raise OperationalConfigurationError("display_name must contain 1..128 characters")


def _validate_agent(value: dict[str, Any], *, source_path: Path) -> None:
    _machine_id(value["machine_id"])
    collection = value["collection"]
    if not isinstance(collection, dict) or set(collection) != {"log_file", "checkpoint_file"}:
        raise OperationalConfigurationError("collection must contain log_file and checkpoint_file")
    log_path = _absolute_path(collection["log_file"], "collection.log_file")
    checkpoint_path = (
        _absolute_path(collection["checkpoint_file"], "collection.checkpoint_file")
        if collection["checkpoint_file"] is not None
        else None
    )
    if checkpoint_path == log_path:
        raise OperationalConfigurationError("log_file and checkpoint_file must be separate inputs")
    spool_path = _absolute_path(value["spool_file"], "spool_file")
    if spool_path == log_path or spool_path == checkpoint_path:
        raise OperationalConfigurationError("spool_file must be separate from monitored inputs")
    if spool_path == _path_identity(source_path):
        raise OperationalConfigurationError("spool_file cannot overwrite the configuration file")

    receiver = value["receiver"]
    if not isinstance(receiver, dict) or set(receiver) != {"host", "port"}:
        raise OperationalConfigurationError("receiver must contain host and port")
    _private_address(receiver["host"], "receiver.host")
    _port(receiver["port"], "receiver.port")
    tls = value["tls"]
    tls_fields = {
        "server_ca_file", "client_certificate_file", "client_private_key_file",
        "receipt_trust_bundle_file",
    }
    if not isinstance(tls, dict) or set(tls) != tls_fields:
        raise OperationalConfigurationError("tls has missing or unknown fields")
    tls_paths = {name: _absolute_path(tls[name], f"tls.{name}") for name in tls_fields}
    _require_distinct_paths(tls_paths)
    if spool_path in tls_paths.values():
        raise OperationalConfigurationError("spool_file must be separate from TLS files")


def _machine_id(value: Any) -> str:
    if not isinstance(value, str) or _MACHINE_ID_RE.fullmatch(value) is None:
        raise OperationalConfigurationError("machine_id has invalid syntax")
    return value


def _key_id(value: Any) -> str:
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise OperationalConfigurationError("receipt_signing_key_id has invalid syntax")
    return value


def _port(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise OperationalConfigurationError(f"{name} must be an integer in 1..65535")
    return value


def _normalize_ip(value: str) -> str:
    return ipaddress.ip_address(value).compressed


def _private_address(value: Any, name: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise OperationalConfigurationError(f"{name} must be a numeric private IP address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise OperationalConfigurationError(f"{name} must be a numeric private IP address") from error
    networks = (
        (ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16"))
        if address.version == 4
        else (ipaddress.ip_network("fc00::/7"),)
    )
    if (
        address.is_unspecified or address.is_loopback or address.is_multicast
        or address.is_link_local or address.is_reserved
        or not any(address in network for network in networks)
    ):
        raise OperationalConfigurationError(f"{name} must be a specific RFC1918 or IPv6 ULA address")
    if any(address == network.network_address for network in networks) or (
        address.version == 4 and any(address == network.broadcast_address for network in networks)
    ):
        raise OperationalConfigurationError(f"{name} cannot be a network or broadcast address")
    return address.compressed


def _server_identity(value: Any) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "*" in value:
        raise OperationalConfigurationError("server identity must be an explicit DNS name or IP address")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    if len(value) > 253 or value.endswith("."):
        raise OperationalConfigurationError("server identity must be a valid DNS name or IP address")
    labels = value.split(".")
    if len(labels) < 2 or any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
        raise OperationalConfigurationError("server identity must be a valid DNS name or IP address")
    return value.lower()


def _absolute_path(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise OperationalConfigurationError(f"{name} must be an explicit absolute path")
    if "<" in value or ">" in value or "%" in value:
        raise OperationalConfigurationError(f"{name} cannot contain placeholders or environment variables")
    if ".." in re.split(r"[\\/]+", value):
        raise OperationalConfigurationError(f"{name} cannot contain parent-directory traversal")
    path = Path(value)
    if not path.is_absolute():
        raise OperationalConfigurationError(f"{name} must be absolute")
    return _path_identity(Path(value))


def _path_identity(path: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.abspath(os.path.normpath(str(path))))


def _require_distinct_paths(paths: dict[str, str]) -> None:
    values = list(paths.values())
    if len(set(values)) != len(values):
        raise OperationalConfigurationError("configuration paths must not overlap by exact path")


__all__ = ["OperationalConfigurationError", "load_operational_config"]