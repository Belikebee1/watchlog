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
    """

    check_name: str
    severity: Severity
    title: str
    summary: str = ""
    details: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
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
