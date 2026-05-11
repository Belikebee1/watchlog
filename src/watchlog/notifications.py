"""Per-device push history — defeats repeat-notification fatigue.

The FCM reporter sends one push per `watchlog run` that finds anything
actionable. With the 4h timer that means six pushes a day for a single
unresolved alert — most of which the user has already seen and is
already trying to fix.

This module remembers what each device was last pushed about. The FCM
reporter consults it and suppresses any push where:
  * the same check is at the same severity (no new information), AND
  * the device's per-check cooldown hasn't elapsed yet.

Escalation always punches through: if disk_space was WARN earlier and
is now CRITICAL, we push. Same for "first ever push for this check".

State lives in /var/lib/watchlog/notifications.json. The schema is
versioned so we can evolve the format without losing data.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

STATE_PATH = Path("/var/lib/watchlog/notifications.json")
SCHEMA_VERSION = 1

_SEV_RANK = {"OK": 0, "INFO": 1, "WARN": 2, "CRITICAL": 3}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclasses.dataclass
class PushDecision:
    """Outcome of consulting the state store for one device + alert.

    deliver:    True if the FCM reporter should send the push.
    new_or_escalated: subset of checks for which this is "new
                     information" — first push or severity escalation
                     since last push. The reporter could use this to
                     rewrite the message body in the future; for now
                     we just keep the standard combined message.
    reason:     short string for the audit / debug log.
    """

    deliver: bool
    new_or_escalated: list[str]
    reason: str


class NotificationStateStore:
    """Thread-safe JSON-backed store for per-device push history.

    All operations atomic-rename through a tmp file so readers never
    see a half-written state. The lock is process-wide; in practice
    only the API/timer daemons write here, and they don't share the
    process anyway."""

    _lock = threading.Lock()

    def __init__(self, path: Path | str = STATE_PATH) -> None:
        self.path = path if isinstance(path, Path) else Path(path)

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return {"schema_version": SCHEMA_VERSION, "last_pushed": {}}
        try:
            return json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            log.error("notifications state corrupt, starting fresh: %s", exc)
            return {"schema_version": SCHEMA_VERSION, "last_pushed": {}}

    def _save(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def decide(
        self,
        token_id: str,
        actionable: list[tuple[str, str]],
        *,
        cooldown_hours: int,
        now: datetime | None = None,
    ) -> PushDecision:
        """Evaluate whether to push for this device given the current
        actionable list.

        actionable is a list of (check_name, severity) tuples — every
        check that fired in this run with severity ≥ the global push
        threshold. The store treats a check as "new information" iff:

          * we've never pushed about it for this device, OR
          * its current severity is strictly higher than the recorded
            one (escalation), OR
          * the device's per-check cooldown has elapsed since the last
            push.

        Returns a [PushDecision] describing the verdict. Caller is
        expected to record the push outcome via [record_push] after
        actually sending — that way a failed delivery doesn't poison
        the cooldown.
        """
        if not actionable:
            return PushDecision(deliver=False, new_or_escalated=[], reason="empty")
        if cooldown_hours <= 0:
            # Cooldown disabled → behave like the legacy "push on every
            # run" reporter for this device.
            return PushDecision(
                deliver=True,
                new_or_escalated=[name for name, _ in actionable],
                reason="cooldown_disabled",
            )

        now = now or _utcnow()
        threshold = now - timedelta(hours=cooldown_hours)

        with self._lock:
            data = self._load()
            history = data.get("last_pushed", {}).get(token_id, {})

        new_or_escalated: list[str] = []
        for name, sev in actionable:
            prev = history.get(name)
            if prev is None:
                new_or_escalated.append(name)
                continue
            prev_rank = _SEV_RANK.get(prev.get("severity", "OK"), 0)
            cur_rank = _SEV_RANK.get(sev, 0)
            if cur_rank > prev_rank:
                new_or_escalated.append(name)
                continue
            prev_ts = _parse_iso(prev.get("ts"))
            if prev_ts is None or prev_ts < threshold:
                new_or_escalated.append(name)
                continue
            # else: same-or-lower severity within cooldown — suppress.

        if new_or_escalated:
            return PushDecision(
                deliver=True,
                new_or_escalated=new_or_escalated,
                reason="new_or_escalated",
            )
        return PushDecision(
            deliver=False,
            new_or_escalated=[],
            reason="in_cooldown",
        )

    def record_push(
        self,
        token_id: str,
        actionable: list[tuple[str, str]],
        *,
        now: datetime | None = None,
    ) -> None:
        """Stamp every actionable check as having been just pushed to
        this device. Called by the reporter AFTER a successful send so
        a failed delivery doesn't suppress future tries."""
        if not actionable:
            return
        ts = _iso(now or _utcnow())
        with self._lock:
            data = self._load()
            data.setdefault("schema_version", SCHEMA_VERSION)
            book = data.setdefault("last_pushed", {})
            device = book.setdefault(token_id, {})
            for name, sev in actionable:
                device[name] = {"severity": sev, "ts": ts}
            self._save(data)

    def forget_device(self, token_id: str) -> None:
        """Drop everything we know about a device. Called when the
        operator revokes its token so stale state doesn't linger."""
        with self._lock:
            data = self._load()
            book = data.get("last_pushed", {})
            if token_id in book:
                del book[token_id]
                self._save(data)
