"""Persistent state — snooze / ignore tracking shared by reporter and bot daemon.

Stored as a single JSON file. Tiny enough to read+write atomically on every change.
The file is updated by the daemon (on button clicks) and read by reporters
(to suppress alerts that are snoozed or ignored).

Schema:
{
  "version": 1,
  "snoozes": {
    "<check_name>": {"until": "ISO8601 UTC", "by": "telegram"}
  },
  "ignores": {
    "<check_name>": {"since": "ISO8601 UTC", "by": "telegram"}
  }
}
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PATH = Path("/var/lib/watchlog/state.json")


class State:
    """Snooze + ignore registry. Persisted as JSON."""

    def __init__(self, data: dict, path: Path):
        self._data = data
        self._path = path

    # ----------- factories -----------

    @classmethod
    def load(cls, path: Path | None = None) -> "State":
        path = path or DEFAULT_PATH
        if not path.is_file():
            return cls({"version": 1, "snoozes": {}, "ignores": {}}, path)
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return cls({"version": 1, "snoozes": {}, "ignores": {}}, path)
        # Normalize missing keys
        data.setdefault("version", 1)
        data.setdefault("snoozes", {})
        data.setdefault("ignores", {})
        return cls(data, path)

    # ----------- queries -----------

    def is_silenced(self, check_name: str) -> bool:
        """True if alerts for this check should be suppressed right now."""
        return self.is_ignored(check_name) or self.is_snoozed(check_name)

    def is_snoozed(self, check_name: str) -> bool:
        snooze = self._data.get("snoozes", {}).get(check_name)
        if not snooze:
            return False
        try:
            until = datetime.fromisoformat(snooze["until"])
        except (KeyError, ValueError):
            return False
        return datetime.now(timezone.utc) < until

    def is_ignored(self, check_name: str) -> bool:
        return check_name in self._data.get("ignores", {})

    # ----------- mutations -----------

    def snooze(self, check_name: str, until: datetime, by: str = "telegram") -> None:
        self._data.setdefault("snoozes", {})[check_name] = {
            "until": until.isoformat(),
            "by": by,
        }
        self._save()

    def ignore(self, check_name: str, by: str = "telegram") -> None:
        self._data.setdefault("ignores", {})[check_name] = {
            "since": datetime.now(timezone.utc).isoformat(),
            "by": by,
        }
        # Ignoring also clears any active snooze
        self._data.get("snoozes", {}).pop(check_name, None)
        self._save()

    def unsnooze(self, check_name: str) -> None:
        self._data.get("snoozes", {}).pop(check_name, None)
        self._save()

    def unignore(self, check_name: str) -> None:
        self._data.get("ignores", {}).pop(check_name, None)
        self._save()

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self._path)
        # Make it readable by both root (reporter) and the bot user (daemon)
        try:
            self._path.chmod(0o644)
        except OSError:
            pass

    def to_dict(self) -> dict:
        return dict(self._data)
