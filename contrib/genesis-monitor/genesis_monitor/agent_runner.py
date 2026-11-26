"""Explicit one-shot orchestration for passive Genesis Search telemetry."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path

from .collector import LogCollector
from .sender import DurableEventSender, SenderRunResult
from .spool import EventSpool


@dataclass(frozen=True)
class AgentRunResult:
    event_id: str | None
    observation_unchanged: bool
    delivery: SenderRunResult


class PassiveAgentRunner:
    """Collect one explicit snapshot, persist it, then attempt one bounded send."""

    def __init__(
        self,
        *,
        machine_id: str,
        log_path: str | os.PathLike[str],
        checkpoint_path: str | os.PathLike[str] | None,
        collector: LogCollector,
        spool: EventSpool,
        sender: DurableEventSender,
    ) -> None:
        if not isinstance(collector, LogCollector):
            raise TypeError("collector must be a LogCollector")
        if not isinstance(spool, EventSpool):
            raise TypeError("spool must be an EventSpool")
        if not isinstance(sender, DurableEventSender):
            raise TypeError("sender must be a DurableEventSender")
        if sender.spool is not spool:
            raise ValueError("sender and runner must use the same event spool")
        self.machine_id = machine_id
        self.log_path = Path(log_path)
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path is not None else None
        self.collector = collector
        self.spool = spool
        self.sender = sender

    def run_once(self, *, observed_at: datetime | None = None) -> AgentRunResult:
        """Perform one read-only collection and at most one sender batch."""
        timestamp = observed_at or datetime.now(timezone.utc)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        observed_text = timestamp.astimezone(timezone.utc).isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z")
        payload = self.collector.collect(
            self.log_path,
            self.checkpoint_path,
            observed_at=timestamp,
        )
        event, unchanged = self.spool.enqueue_observation(
            self.machine_id,
            observed_text,
            payload,
        )
        delivery = self.sender.run_once()
        return AgentRunResult(
            event_id=event["event_id"] if event is not None else None,
            observation_unchanged=unchanged,
            delivery=delivery,
        )