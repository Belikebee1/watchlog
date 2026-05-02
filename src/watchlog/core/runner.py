"""Runner — orchestrates checks and emits results to reporters."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from watchlog.core.check import Check, CheckResult
from watchlog.core.severity import Severity

if TYPE_CHECKING:
    from watchlog.core.config import Config
    from watchlog.reporters.base import Reporter

log = logging.getLogger(__name__)


# Registry — populated by checks/__init__.py
CHECK_REGISTRY: dict[str, type[Check]] = {}
REPORTER_REGISTRY: dict[str, type] = {}


def register_check(cls: type[Check]) -> type[Check]:
    """Decorator to register a check class."""
    if not cls.name:
        raise ValueError(f"Check {cls.__name__} has empty name attribute")
    CHECK_REGISTRY[cls.name] = cls
    return cls


def register_reporter(name: str):
    """Decorator factory to register a reporter under a name."""

    def decorator(cls):
        REPORTER_REGISTRY[name] = cls
        return cls

    return decorator


class Runner:
    """Run all enabled checks, return their results."""

    def __init__(self, config: Config):
        self.config = config

    def list_available_checks(self) -> list[str]:
        return sorted(CHECK_REGISTRY.keys())

    def list_enabled_checks(self) -> list[str]:
        return [name for name in CHECK_REGISTRY if self.config.check_enabled(name)]

    def run_check(self, name: str) -> CheckResult:
        if name not in CHECK_REGISTRY:
            raise KeyError(f"Unknown check: {name}. Available: {sorted(CHECK_REGISTRY)}")
        cls = CHECK_REGISTRY[name]
        check = cls(self.config.check_config(name))
        try:
            return check.run()
        except Exception as exc:  # noqa: BLE001 - we want any failure surfaced as a result
            log.exception("Check %s crashed", name)
            return CheckResult(
                check_name=name,
                severity=Severity.CRITICAL,
                title=f"Check {name} crashed",
                summary=f"{type(exc).__name__}: {exc}",
            )

    def run_all(self, only: list[str] | None = None) -> list[CheckResult]:
        names = only if only else self.list_enabled_checks()
        results = []
        for name in names:
            result = self.run_check(name)
            log.info("[%s] %s: %s", name, result.severity.name, result.title)
            results.append(result)
        return results

    @staticmethod
    def worst_severity(results: list[CheckResult]) -> Severity:
        if not results:
            return Severity.OK
        return max(r.severity for r in results)
