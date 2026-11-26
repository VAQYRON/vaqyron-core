"""Explicit operational commands for Genesis Monitor."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .agent_runner import PassiveAgentRunner
from .collector import LogCollector
from .dashboard import write_dashboard_snapshot
from .identity import CertificateIdentityRegistry
from .ingestion import GenesisIngestionService
from .operational_config import (
    OperationalConfigurationError,
    load_operational_config,
)
from .private_ingress import PrivateIngressConfig
from .receipts import (
    CommittedReceiptSigner,
    CommittedReceiptVerifier,
    ReceiptTrustBundle,
)
from .sender import DurableEventSender, RemoteSenderEndpoint
from .spool import EventSpool
from .store import CentralStore
from .transport import RemoteMTLSServer


_MAX_TRUST_BUNDLE_BYTES = 64 * 1024


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("trust bundle contains a duplicate JSON key")
        result[key] = value
    return result


def _read_trust_bundle(path: str) -> ReceiptTrustBundle:
    trust_path = _require_regular_file(path, "receipt trust bundle")
    with trust_path.open("rb") as stream:
        raw = stream.read(_MAX_TRUST_BUNDLE_BYTES + 1)
    if len(raw) > _MAX_TRUST_BUNDLE_BYTES:
        raise ValueError("receipt trust bundle exceeds the 64 KiB limit")
    value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_pairs_without_duplicates)
    return ReceiptTrustBundle.from_mapping(value)


def _require_regular_file(value: str, name: str) -> Path:
    path = Path(value)
    _reject_symlink_path(path, name)
    if not path.is_file():
        raise ValueError(f"{name} is missing or is not a regular file")
    return path


def _reject_symlink_path(path: Path, name: str) -> None:
    if any(candidate.is_symlink() for candidate in (path, *path.parents)):
        raise ValueError(f"{name} path cannot contain a symlink")


def _require_output_parent(value: str, name: str) -> Path:
    path = Path(value)
    parent = path.parent
    _reject_symlink_path(path, name)
    if not parent.is_dir():
        raise ValueError(f"{name} parent directory does not exist")
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise ValueError(f"{name} must be a regular file path")
    return path


def _run_receiver(config: dict[str, Any]) -> int:
    for field in (
        "server_certificate_file", "server_private_key_file", "client_ca_file",
        "receipt_signing_key_file", "receipt_trust_bundle_file",
    ):
        _require_regular_file(config[field], field)
    _require_output_parent(config["central_store_file"], "central store")
    _require_output_parent(config["dashboard_output"], "dashboard output")

    trust_bundle = _read_trust_bundle(config["receipt_trust_bundle_file"])
    key_path = _require_regular_file(config["receipt_signing_key_file"], "receipt signing key")
    with key_path.open("rb") as stream:
        signing_key = serialization.load_pem_private_key(stream.read(), password=None)
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise ValueError("receipt signing key must be an Ed25519 private key")
    signer = CommittedReceiptSigner(
        {config["receipt_signing_key_id"]: signing_key},
        active_key_id=config["receipt_signing_key_id"],
        trust_bundle=trust_bundle,
    )
    registry = CertificateIdentityRegistry.open(config["identity_registry_file"])
    store = CentralStore(config["central_store_file"])
    for machine in config["machines"]:
        store.register_machine(machine["machine_id"], machine["display_name"])
    service = GenesisIngestionService(registry, store, signer)
    ingress = PrivateIngressConfig.load(
        enabled=True,
        bind_address=config["bind_address"],
        interface_identity=config["interface_guid"],
        port=config["port"],
        approved_interface_addresses=tuple(config["approved_interface_addresses"]),
        server_identity=config["server_identity"],
        server_certificate_file=config["server_certificate_file"],
        server_private_key_file=config["server_private_key_file"],
        client_trust_file=config["client_ca_file"],
    )
    server = RemoteMTLSServer(
        configuration=ingress,
        ingestion_service=service,
    )
    print("Receiver started in foreground. Press Ctrl+C to stop.")
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        print("Receiver stop requested.")
    finally:
        server.stop(timeout_seconds=10.0)
    print("Receiver stopped; central data and pending agent spools were preserved.")
    return 0


def _run_agent_once(config: dict[str, Any]) -> int:
    collection = config["collection"]
    _require_regular_file(collection["log_file"], "collection log")
    if collection["checkpoint_file"] is not None:
        checkpoint = Path(collection["checkpoint_file"])
        _reject_symlink_path(checkpoint, "collection checkpoint")
        if checkpoint.exists():
            _require_regular_file(str(checkpoint), "collection checkpoint")
    tls = config["tls"]
    for field in ("server_ca_file", "client_certificate_file", "client_private_key_file", "receipt_trust_bundle_file"):
        _require_regular_file(tls[field], f"tls.{field}")
    _require_output_parent(config["spool_file"], "spool")
    spool_path = Path(config["spool_file"])
    if spool_path.exists():
        _require_regular_file(str(spool_path), "spool")

    trust_bundle = _read_trust_bundle(tls["receipt_trust_bundle_file"])
    verifier = CommittedReceiptVerifier(trust_bundle)
    endpoint = RemoteSenderEndpoint.load(
        host=config["receiver"]["host"],
        port=config["receiver"]["port"],
        server_ca_file=tls["server_ca_file"],
        client_certificate_file=tls["client_certificate_file"],
        client_private_key_file=tls["client_private_key_file"],
    )
    spool = EventSpool(config["spool_file"], receipt_verifier=verifier)
    sender = DurableEventSender(
        spool,
        endpoint=endpoint,
        receipt_verifier=verifier,
    )
    runner = PassiveAgentRunner(
        machine_id=config["machine_id"],
        log_path=collection["log_file"],
        checkpoint_path=collection["checkpoint_file"],
        collector=LogCollector(),
        spool=spool,
        sender=sender,
    )
    result = runner.run_once()
    print(
        "Agent run complete: "
        f"event_id={result.event_id or 'unchanged'} "
        f"attempted={result.delivery.attempted} "
        f"delivered={result.delivery.delivered} "
        f"deferred={result.delivery.deferred}"
    )
    return 0 if result.delivery.deferred == 0 else 1


def _render_dashboard(config: dict[str, Any]) -> int:
    _require_regular_file(config["central_store_file"], "central store")
    output = _require_output_parent(config["dashboard_output"], "dashboard output")
    store = CentralStore(config["central_store_file"])
    snapshot = store.snapshot(now=datetime.now(timezone.utc))
    write_dashboard_snapshot(snapshot, str(output))
    print("Static dashboard snapshot written.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="genesis-monitor")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "receiver-start", "agent-once", "dashboard-render"):
        command = commands.add_parser(name)
        command.add_argument("--config", required=True, help="absolute operational JSON configuration path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    expected_role = (
        "agent" if args.command == "agent-once"
        else "receiver" if args.command in {"receiver-start", "dashboard-render"}
        else None
    )
    try:
        config = load_operational_config(args.config, expected_role=expected_role)
        if args.command == "validate":
            print(f"Operational configuration valid (role={config['role']}).")
            return 0
        if args.command == "receiver-start":
            return _run_receiver(config)
        if args.command == "agent-once":
            return _run_agent_once(config)
        return _render_dashboard(config)
    except OperationalConfigurationError as error:
        print(f"Configuration rejected: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Operation interrupted; persistent spool data was preserved.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Genesis Monitor operation failed ({type(error).__name__}).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())