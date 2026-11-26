"""Validation-only disabled templates for a future Genesis Monitor pilot."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


_PLACEHOLDER_RE = re.compile(r"^<[A-Z][A-Z0-9_]*>$")


class PilotConfigurationError(ValueError):
    """A pilot template is malformed, unsafe, or attempts activation."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PilotConfigurationError(f"duplicate configuration key: {key}")
        result[key] = value
    return result


def load_disabled_pilot_config(
    path: str | Path,
    *,
    expected_role: str,
) -> dict[str, Any]:
    """Load a placeholder-only template; this API never enables an endpoint."""
    if not isinstance(expected_role, str) or expected_role not in {
        "main_receiver",
        "dell_agent",
        "acer_agent",
    }:
        raise PilotConfigurationError("unsupported pilot configuration role")
    try:
        text = Path(path).read_text(encoding="utf-8")
        configuration = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PilotConfigurationError(
            f"cannot read pilot configuration: {error}"
        ) from error

    _validate_disabled_config(configuration, expected_role)
    return configuration


def _validate_disabled_config(configuration: Any, expected_role: str) -> None:
    if not isinstance(configuration, dict):
        raise PilotConfigurationError("pilot configuration must be a JSON object")
    common = {"schema_version", "role", "enabled", "automatic_start"}
    role_fields = {
        "main_receiver": {
            "bind",
            "tls",
            "identity_registry_file",
            "receipt_signing_key_file",
            "source_allowlist",
        },
        "dell_agent": {"machine_id", "collection", "spool_file", "receiver", "tls"},
        "acer_agent": {"machine_id", "collection", "spool_file", "receiver", "tls"},
    }
    if set(configuration) != common | role_fields[expected_role]:
        raise PilotConfigurationError("pilot configuration has missing or unknown fields")
    if (
        isinstance(configuration["schema_version"], bool)
        or configuration["schema_version"] != 1
    ):
        raise PilotConfigurationError("schema_version must be integer 1")
    if configuration["role"] != expected_role:
        raise PilotConfigurationError("pilot configuration role does not match its file")
    if configuration["enabled"] is not False:
        raise PilotConfigurationError("pilot configuration must remain disabled")
    if configuration["automatic_start"] is not False:
        raise PilotConfigurationError("automatic startup is prohibited")

    if expected_role == "main_receiver":
        _require_object_fields(configuration["bind"], {"interface_guid", "address", "port"})
        bind = configuration["bind"]
        _require_placeholder(bind["interface_guid"], "bind.interface_guid")
        _require_placeholder(bind["address"], "bind.address")
        if isinstance(bind["port"], bool) or bind["port"] != 0:
            raise PilotConfigurationError("disabled receiver template port must be 0")
        _require_object_fields(
            configuration["tls"],
            {
                "server_identity",
                "certificate_file",
                "private_key_file",
                "client_ca_file",
            },
        )
        _require_placeholders(configuration["tls"], "tls")
        _require_placeholder(configuration["identity_registry_file"], "identity_registry_file")
        _require_placeholder(
            configuration["receipt_signing_key_file"],
            "receipt_signing_key_file",
        )
        if configuration["source_allowlist"] != []:
            raise PilotConfigurationError("source_allowlist must be empty while disabled")
        return

    expected_machine_placeholder = (
        "<DELL_ENROLLED_MACHINE_ID>"
        if expected_role == "dell_agent"
        else "<ACER_ENROLLED_MACHINE_ID>"
    )
    if configuration["machine_id"] != expected_machine_placeholder:
        raise PilotConfigurationError(
            f"machine_id must remain {expected_machine_placeholder}"
        )
    _require_object_fields(configuration["collection"], {"log_file", "checkpoint_file"})
    collection = configuration["collection"]
    _require_placeholder(collection["log_file"], "collection.log_file")
    checkpoint = collection["checkpoint_file"]
    if checkpoint is not None:
        _require_placeholder(checkpoint, "collection.checkpoint_file")
    _require_placeholder(configuration["spool_file"], "spool_file")
    _require_object_fields(configuration["receiver"], {"host", "port"})
    _require_placeholder(configuration["receiver"]["host"], "receiver.host")
    if (
        isinstance(configuration["receiver"]["port"], bool)
        or configuration["receiver"]["port"] != 0
    ):
        raise PilotConfigurationError("disabled agent template port must be 0")
    _require_object_fields(
        configuration["tls"],
        {
            "server_ca_file",
            "client_certificate_file",
            "client_private_key_file",
            "receipt_trust_bundle_file",
        },
    )
    _require_placeholders(configuration["tls"], "tls")


def _require_object_fields(value: Any, expected_fields: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise PilotConfigurationError("configuration section has missing or unknown fields")


def _require_placeholders(value: Mapping[str, Any], prefix: str) -> None:
    for key, item in value.items():
        _require_placeholder(item, f"{prefix}.{key}")


def _require_placeholder(value: Any, name: str) -> None:
    if not isinstance(value, str) or _PLACEHOLDER_RE.fullmatch(value) is None:
        raise PilotConfigurationError(f"{name} must remain an uppercase placeholder")
