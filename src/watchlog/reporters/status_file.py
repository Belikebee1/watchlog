"""Status file reporter — writes a tiny JSON heartbeat that a remote monitor can poll.

The output is a single, small JSON document at a configured path (e.g. served by
Nginx as /status.json on a public domain). Use case: external uptime checks
that want to confirm "watchlog itself is still running daily" without SSH access.

Schema (stable):
{
  "schema_version": 1,
  "ran_at": "2026-05-02T07:45:00+00:00",   # UTC ISO 8601
  "host": "myserver",                       # hostname
  "watchlog_version": "0.1.0",
  "worst_severity": "WARN",                 # OK | INFO | WARN | CRITICAL
  "checks_total": 9,
  "counts": {"OK": 7, "INFO": 1, "WARN": 1, "CRITICAL": 0},
  "actionable": [
    {"check": "ssl_certs", "severity": "WARN", "title": "..."}
  ]
}
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

from watchlog import __version__
from watchlog.core.check import CheckResult
from watchlog.core.runner import register_reporter
from watchlog.core.severity import Severity
from watchlog.reporters.base import Reporter


@register_reporter("status_file")
class StatusFileReporter(Reporter):
    name = "status_file"

    def emit(self, results: list[CheckResult]) -> None:
        if not self.config.get("enabled", False):
            return

        path_str = self.config.get("path")
        if not path_str:
            return

        worst = max((r.severity for r in results), default=Severity.OK)
        counts = {s.name: 0 for s in Severity}
        for r in results:
            counts[r.severity.name] += 1

        actionable = [
            {
                "check": r.check_name,
                "severity": r.severity.name,
                "title": r.title,
            }
            for r in results
            if r.severity > Severity.OK
        ]

        payload = {
            "schema_version": 1,
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "host": socket.gethostname(),
            "watchlog_version": __version__,
            "worst_severity": worst.name,
            "checks_total": len(results),
            "counts": counts,
            "actionable": actionable,
        }

        path = Path(path_str)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write via tmp + rename, so consumers never see a half-written file.
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
