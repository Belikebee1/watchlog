"""JSON reporter — write results to a file (for archiving / piping)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from watchlog.core.check import CheckResult
from watchlog.core.runner import register_reporter
from watchlog.reporters.base import Reporter


@register_reporter("json")
class JsonReporter(Reporter):
    name = "json"

    def emit(self, results: list[CheckResult]) -> None:
        log_dir = Path(self.config.get("log_dir") or "/var/log/watchlog")
        log_dir.mkdir(parents=True, exist_ok=True)
        date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        path = log_dir / f"{date}.json"

        existing: list[dict] = []
        if path.is_file():
            try:
                existing = json.loads(path.read_text())
            except json.JSONDecodeError:
                existing = []

        existing.append({
            "ran_at": datetime.now(timezone.utc).isoformat(),
            "results": [r.to_dict() for r in results],
        })
        path.write_text(json.dumps(existing, indent=2, ensure_ascii=False))
