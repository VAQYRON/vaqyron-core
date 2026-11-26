"""Validation-only boundary for a future private telemetry ingress."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import ClassVar
from uuid import UUID

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


_PRIVATE_V4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_PRIVATE_V6_NETWORKS = (ipaddress.ip_network("fc00::/7"),)
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_PEM_CERTIFICATE_RE = re.compile(
    br"-----BEGIN CERTIFICATE-----\s+.+?-----END CERTIFICATE-----",
    re.DOTALL,
)
_TLS_MINIMUM = ssl.TLSVersion.TLSv1_2
_WINDOWS_INVENTORY_TIMEOUT_SECONDS = 5
_CONFIGURATION_SEAL = object()
_WINDOWS_INVENTORY_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "$adapters = @{}; "
    "Get-NetAdapter -IncludeHidden | ForEach-Object { "
    "$adapters[[int]$_.ifIndex] = [string]$_.InterfaceGuid "
    "}; "
    "$entries = @(Get-NetIPAddress | ForEach-Object { "
    "$guid = $adapters[[int]$_.InterfaceIndex]; "
    "if ($guid) { [PSCustomObject]@{ InterfaceIdentity=$guid; "
    "Address=[string]$_.IPAddress } } "
    "}); "
    "ConvertTo-Json -InputObject $entries -Compress"
)


def windows_interface_inventory() -> Mapping[str, tuple[str, ...]]:
    """Read current Windows adapter GUIDs and assigned IP addresses."""
    if sys.platform != "win32":
        raise PrivateIngressConfigurationError(
            "Windows interface inventory is unavailable on this platform"
        )
    try:
        system_root = os.environ.get("SystemRoot")
        if not system_root:
            raise OSError("SystemRoot is unavailable")
        powershell = (
            Path(system_root)
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )
        completed = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _WINDOWS_INVENTORY_SCRIPT,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=_WINDOWS_INVENTORY_TIMEOUT_SECONDS,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PrivateIngressConfigurationError(
            f"cannot obtain current Windows interface inventory: {error}"
        ) from error
    if completed.returncode != 0:
        raise PrivateIngressConfigurationError(
            "Windows interface inventory query failed"
        )
    try:
        entries = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise PrivateIngressConfigurationError(
            "Windows interface inventory returned invalid JSON"
        ) from error
    if isinstance(entries, dict):
        entries = [entries]
    if not isinstance(entries, list) or not entries:
        raise PrivateIngressConfigurationError(
            "Windows interface inventory is empty or has an invalid shape"
        )

    inventory: dict[str, set[str]] = {}
    try:
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "InterfaceIdentity",
                "Address",
            }:
                raise ValueError("invalid interface inventory entry")
            identity = str(UUID(entry["InterfaceIdentity"]))
            address_value = entry["Address"]
            if not isinstance(address_value, str):
                raise ValueError("interface address must be a string")
            if "%" in address_value:
                address_value = address_value.split("%", 1)[0]
            address = ipaddress.ip_address(address_value).compressed
            inventory.setdefault(identity, set()).add(address)
    except (ValueError, TypeError, AttributeError) as error:
        raise PrivateIngressConfigurationError(
            "Windows interface inventory contains malformed identifiers or addresses"
        ) from error
    if not inventory:
        raise PrivateIngressConfigurationError(
            "Windows interface inventory contains no usable adapters"
        )
    return MappingProxyType(
        {identity: tuple(sorted(addresses)) for identity, addresses in inventory.items()}
    )


class PrivateIngressConfigurationError(ValueError):
    """Private-ingress settings are absent, unsafe, or incompatible."""


@dataclass(frozen=True, init=False)
class PrivateIngressConfig:
    """Validated settings only; this type deliberately cannot create a listener."""

    enabled: bool
    bind_address: str | None = None
    interface_identity: str | None = None
    port: int | None = None
    approved_interface_addresses: tuple[str, ...] = ()
    server_identity: str | None = None
    server_certificate_file: Path | None = None
    server_private_key_file: Path | None = None
    client_trust_file: Path | None = None
    tls_context: ssl.SSLContext | None = None
    _validation_seal: object | None = None
    listener_available: ClassVar[bool] = False

    def __new__(cls, *args: object, **kwargs: object) -> "PrivateIngressConfig":
        raise TypeError("use PrivateIngressConfig.load() to construct configuration")

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("use PrivateIngressConfig.load() to construct configuration")

    @classmethod
    def load(
        cls,
        *,
        enabled: bool = False,
        bind_address: str | None = None,
        interface_identity: str | None = None,
        port: int | None = None,
        approved_interface_addresses: tuple[str, ...] = (),
        interface_inventory: Mapping[str, tuple[str, ...]] | None = None,
        server_identity: str | None = None,
        server_certificate_file: str | Path | None = None,
        server_private_key_file: str | Path | None = None,
        client_trust_file: str | Path | None = None,
    ) -> "PrivateIngressConfig":
        if not isinstance(enabled, bool):
            raise PrivateIngressConfigurationError("enabled must be an explicit boolean")
        options = (
            bind_address,
            interface_identity,
            port,
            approved_interface_addresses,
            interface_inventory,
            server_identity,
            server_certificate_file,
            server_private_key_file,
            client_trust_file,
        )
        if not enabled:
            if any(value not in (None, ()) for value in options):
                raise PrivateIngressConfigurationError(
                    "disabled private ingress cannot accept listener configuration"
                )
            instance = object.__new__(cls)
            object.__setattr__(instance, "enabled", False)
            object.__setattr__(instance, "bind_address", None)
            object.__setattr__(instance, "interface_identity", None)
            object.__setattr__(instance, "port", None)
            object.__setattr__(instance, "approved_interface_addresses", ())
            object.__setattr__(instance, "server_identity", None)
            object.__setattr__(instance, "server_certificate_file", None)
            object.__setattr__(instance, "server_private_key_file", None)
            object.__setattr__(instance, "client_trust_file", None)
            object.__setattr__(instance, "tls_context", None)
            object.__setattr__(instance, "_validation_seal", _CONFIGURATION_SEAL)
            return instance

        address = cls._private_address(bind_address, "bind_address")
        identity = cls._interface_identity(interface_identity)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise PrivateIngressConfigurationError("port must be an explicit integer in 1..65535")
        if (
            not isinstance(approved_interface_addresses, tuple)
            or not approved_interface_addresses
        ):
            raise PrivateIngressConfigurationError(
                "an explicit approved interface-address tuple is required"
            )
        cls._validate_interface_ownership(
            identity,
            address,
            interface_inventory
            if interface_inventory is not None
            else windows_interface_inventory(),
        )
        approved = tuple(
            cls._private_address(item, "approved interface address")
            for item in approved_interface_addresses
        )
        if len(set(approved)) != len(approved) or address not in approved:
            raise PrivateIngressConfigurationError(
                "bind_address must exactly match one unique approved private interface address"
            )
        server_identity_value = cls._server_identity(server_identity)

        certificate_path = cls._required_file(
            server_certificate_file, "server certificate"
        )
        key_path = cls._required_file(server_private_key_file, "server private key")
        trust_path = cls._required_file(client_trust_file, "client trust bundle")
        cls._validate_server_certificate(certificate_path, server_identity_value)
        cls._validate_client_trust(trust_path)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = _TLS_MINIMUM
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            context.load_cert_chain(str(certificate_path), str(key_path))
            context.load_verify_locations(cafile=str(trust_path))
        except (OSError, ssl.SSLError, ValueError) as error:
            raise PrivateIngressConfigurationError(
                f"TLS certificate, key, or client trust configuration is invalid: {error}"
            ) from error
        if not context.get_ca_certs():
            raise PrivateIngressConfigurationError(
                "client trust bundle contains no usable CA certificates"
            )

        instance = object.__new__(cls)
        object.__setattr__(instance, "enabled", True)
        object.__setattr__(instance, "bind_address", address)
        object.__setattr__(instance, "interface_identity", identity)
        object.__setattr__(instance, "port", port)
        object.__setattr__(instance, "approved_interface_addresses", approved)
        object.__setattr__(instance, "server_identity", server_identity_value)
        object.__setattr__(instance, "server_certificate_file", certificate_path)
        object.__setattr__(instance, "server_private_key_file", key_path)
        object.__setattr__(instance, "client_trust_file", trust_path)
        object.__setattr__(instance, "tls_context", context)
        object.__setattr__(instance, "_validation_seal", _CONFIGURATION_SEAL)
        return instance

    def require_validated_enabled_configuration(self) -> None:
        if (
            getattr(self, "_validation_seal", None) is not _CONFIGURATION_SEAL
            or getattr(self, "enabled", False) is not True
            or getattr(self, "bind_address", None) is None
            or getattr(self, "interface_identity", None) is None
            or getattr(self, "port", None) is None
            or getattr(self, "tls_context", None) is None
        ):
            raise PrivateIngressConfigurationError(
                "remote receiver requires a validated enabled configuration"
            )

    @staticmethod
    def _interface_identity(value: str | None) -> str:
        if not isinstance(value, str) or value != value.strip():
            raise PrivateIngressConfigurationError(
                "interface_identity must be an explicit Windows adapter GUID"
            )
        try:
            return str(UUID(value))
        except (ValueError, TypeError, AttributeError) as error:
            raise PrivateIngressConfigurationError(
                "interface_identity must be an explicit Windows adapter GUID"
            ) from error

    @classmethod
    def _validate_interface_ownership(
        cls,
        interface_identity: str,
        bind_address: str,
        interface_inventory: Mapping[str, tuple[str, ...]] | None,
    ) -> None:
        if not isinstance(interface_inventory, Mapping) or not interface_inventory:
            raise PrivateIngressConfigurationError(
                "an explicit interface inventory is required to verify address ownership"
            )
        owners: dict[str, list[str]] = {}
        seen_identities: set[str] = set()
        for identity, addresses in interface_inventory.items():
            if not isinstance(addresses, tuple):
                raise PrivateIngressConfigurationError(
                    "interface inventory contains an invalid interface entry"
                )
            try:
                normalized_identity = str(UUID(identity))
            except (ValueError, TypeError, AttributeError) as error:
                raise PrivateIngressConfigurationError(
                    "interface inventory contains an invalid Windows adapter GUID"
                ) from error
            if normalized_identity in seen_identities:
                raise PrivateIngressConfigurationError(
                    "interface inventory contains duplicate normalized interface identity"
                )
            seen_identities.add(normalized_identity)
            for value in addresses:
                if not isinstance(value, str):
                    raise PrivateIngressConfigurationError(
                        "interface inventory addresses must be numeric IP addresses"
                    )
                if "%" in value:
                    value = value.split("%", 1)[0]
                try:
                    normalized = ipaddress.ip_address(value).compressed
                except ValueError as error:
                    raise PrivateIngressConfigurationError(
                        "interface inventory contains a non-numeric IP address"
                    ) from error
                owners.setdefault(normalized, []).append(normalized_identity)

        matching_interfaces = owners.get(bind_address, [])
        if identity not in {
            str(UUID(item))
            for item in interface_inventory
            if isinstance(item, str)
        }:
            raise PrivateIngressConfigurationError(
                "selected interface identity is not present in the current inventory"
            )
        if matching_interfaces != [interface_identity]:
            raise PrivateIngressConfigurationError(
                "bind address must be uniquely assigned to the selected interface"
            )

    def validate_current_interface_inventory(
        self,
        interface_inventory: Mapping[str, tuple[str, ...]],
    ) -> None:
        """Recheck the selected address against a fresh, caller-supplied inventory."""
        if not self.enabled or self.bind_address is None or self.interface_identity is None:
            raise PrivateIngressConfigurationError(
                "disabled private ingress has no interface selection to validate"
            )
        self._validate_interface_ownership(
            self.interface_identity,
            self.bind_address,
            interface_inventory,
        )

    @staticmethod
    def _private_address(value: str | None, name: str) -> str:
        if not isinstance(value, str):
            raise PrivateIngressConfigurationError(f"{name} must be an explicit IP address")
        if "%" in value:
            raise PrivateIngressConfigurationError(
                f"{name} cannot contain an IPv6 scope identifier"
            )
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise PrivateIngressConfigurationError(
                f"{name} must be a numeric private IP address"
            ) from error
        networks = _PRIVATE_V4_NETWORKS if address.version == 4 else _PRIVATE_V6_NETWORKS
        if (
            address.is_unspecified
            or address.is_loopback
            or address.is_multicast
            or address.is_link_local
            or address.is_reserved
            or not any(address in network for network in networks)
        ):
            raise PrivateIngressConfigurationError(
                f"{name} must be a specific RFC1918 or IPv6 ULA interface address"
            )
        network = next(network for network in networks if address in network)
        if address == network.network_address or (
            address.version == 4 and address == network.broadcast_address
        ):
            raise PrivateIngressConfigurationError(
                f"{name} cannot be a private-network or broadcast address"
            )
        return address.compressed

    @staticmethod
    def _server_identity(value: str | None) -> str:
        if not isinstance(value, str) or not value or value != value.strip():
            raise PrivateIngressConfigurationError(
                "server_identity must be an explicit DNS name or IP address"
            )
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            pass
        if len(value) > 253 or value.endswith(".") or "*" in value:
            raise PrivateIngressConfigurationError(
                "server_identity must be a non-wildcard DNS name or IP address"
            )
        labels = value.split(".")
        if len(labels) < 2 or any(_DNS_LABEL_RE.fullmatch(label) is None for label in labels):
            raise PrivateIngressConfigurationError(
                "server_identity must be a valid fully-qualified DNS name or IP address"
            )
        return value.lower()

    @staticmethod
    def _required_file(value: str | Path | None, name: str) -> Path:
        if value is None:
            raise PrivateIngressConfigurationError(f"{name} path is required")
        path = Path(value)
        if not path.is_file():
            raise PrivateIngressConfigurationError(f"{name} file is missing or not a file")
        return path.resolve()

    @staticmethod
    def _validate_server_certificate(certificate_path: Path, identity: str) -> None:
        try:
            certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
            extended_usage = certificate.extensions.get_extension_for_class(
                x509.ExtendedKeyUsage
            ).value
            subject_alt_names = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value
        except (OSError, ValueError, x509.ExtensionNotFound) as error:
            raise PrivateIngressConfigurationError(
                f"server certificate is malformed or lacks required extensions: {error}"
            ) from error
        if ExtendedKeyUsageOID.SERVER_AUTH not in extended_usage:
            raise PrivateIngressConfigurationError(
                "server certificate must include the TLS server-authentication EKU"
            )
        not_before = getattr(certificate, "not_valid_before_utc", None)
        not_after = getattr(certificate, "not_valid_after_utc", None)
        if not_before is None:
            not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        if not_after is None:
            not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if now < not_before or now >= not_after:
            raise PrivateIngressConfigurationError(
                "server certificate is not currently within its validity period"
            )
        try:
            address = ipaddress.ip_address(identity)
        except ValueError:
            dns_names = {
                name.lower()
                for name in subject_alt_names.get_values_for_type(x509.DNSName)
            }
            if identity.lower() not in dns_names:
                raise PrivateIngressConfigurationError(
                    "server certificate SAN does not match server_identity"
                )
        else:
            ip_addresses = subject_alt_names.get_values_for_type(x509.IPAddress)
            if address not in ip_addresses:
                raise PrivateIngressConfigurationError(
                    "server certificate IP SAN does not match server_identity"
                )

    @staticmethod
    def _validate_client_trust(trust_path: Path) -> None:
        try:
            pem_data = trust_path.read_bytes()
            certificates = _PEM_CERTIFICATE_RE.findall(pem_data)
            if not certificates:
                raise ValueError("no PEM certificates found")
            for encoded in certificates:
                certificate = x509.load_pem_x509_certificate(encoded)
                constraints = certificate.extensions.get_extension_for_class(
                    x509.BasicConstraints
                ).value
                if not constraints.ca:
                    raise ValueError("trust bundle contains a certificate that is not a CA")
        except (OSError, ValueError, x509.ExtensionNotFound) as error:
            raise PrivateIngressConfigurationError(
                f"client trust bundle is invalid: {error}"
            ) from error
