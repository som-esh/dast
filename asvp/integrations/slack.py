"""Slack notification seam (FR-DX-5, FR-FND-5 escalations).

Batched: max one digest per day per team outside SLA escalations. The
transport is injectable; the default records outbound messages to the
event journal (and is what tests assert against).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional

from asvp.storage import Store


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


class SlackNotifier:
    def __init__(self, store: Store, transport: Optional[Callable[[str, str], None]] = None):
        self._store = store
        self._transport = transport or (
            lambda channel, text: self._store.append_event(
                "slack.outbound", "slack", channel, {"text": text}
            )
        )
        self._digest_sent: dict[str, str] = {}  # team -> date

    def sla_escalation(self, channel: str, finding_title: str, sla_due: str) -> None:
        # SLA escalations are never batched (FR-DX-5 exception)
        self._transport(
            channel,
            f":rotating_light: SLA breach — '{finding_title}' was due {sla_due}.",
        )

    def bypass_alert(self, channel: str, service: str, approver: str, reason: str) -> None:
        self._transport(
            channel,
            f":unlock: Gate bypass approved on {service} by {approver}: {reason}",
        )

    def daily_digest(self, team: str, channel: str, summary: str) -> bool:
        if self._digest_sent.get(team) == _today():
            return False  # max 1 digest/day per team
        self._digest_sent[team] = _today()
        self._transport(channel, f"ASVP daily digest for {team}:\n{summary}")
        return True
