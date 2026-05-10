"""Base class and result type for individual checks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from watchlog.core.severity import Severity


@dataclass
class CheckResult:
    """Outcome of a single check run.

    title:    one-line summary shown in alerts
    summary:  short body (1-3 lines) explaining what was found
    details:  structured per-item details (e.g. list of outdated packages)
    actions:  suggested commands to fix it (e.g. "apt upgrade openssl")
    metrics:  numeric facts the mobile UI renders as bars/sparklines —
              e.g. {"used_pct": 35, "total_gb": 75}. Free-form per check;
              the consumer matches on `check_name` to know what keys to
              expect. Always JSON-safe (numbers, strings, booleans).
    """

    check_name: str
    severity: Severity
    title: str
    summary: str = ""
    details: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_actionable(self) -> bool:
        """True if severity warrants notification."""
        return self.severity >= Severity.WARN

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check_name,
            "severity": self.severity.name,
            "title": self.title,
            "summary": self.summary,
            "details": self.details,
            "actions": self.actions,
            "metrics": self.metrics,
            "timestamp": self.timestamp.isoformat(),
        }


class Check(ABC):
    """Base class for all checks.

    Subclasses must define `name` and implement `run`.
    """

    name: str = ""

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @abstractmethod
    def run(self) -> CheckResult:
        """Execute the check and return its result."""
        raise NotImplementedError

    def _ok(self, title: str, summary: str = "", **kwargs: Any) -> CheckResult:
        return CheckResult(self.name, Severity.OK, title, summary, **kwargs)

    def _info(self, title: str, summary: str = "", **kwargs: Any) -> CheckResult:
        return CheckResult(self.name, Severity.INFO, title, summary, **kwargs)

    def _warn(self, title: str, summary: str = "", **kwargs: Any) -> CheckResult:
        return CheckResult(self.name, Severity.WARN, title, summary, **kwargs)

    def _critical(self, title: str, summary: str = "", **kwargs: Any) -> CheckResult:
        return CheckResult(self.name, Severity.CRITICAL, title, summary, **kwargs)
