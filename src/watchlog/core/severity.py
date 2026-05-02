"""Severity levels for check results."""

from enum import IntEnum


class Severity(IntEnum):
    """Check result severity. Higher integer = more severe.

    OK       — everything is fine, nothing to report
    INFO     — informational, not actionable (e.g. minor packages outdated)
    WARN     — needs attention soon (e.g. cert expires in 20 days)
    CRITICAL — needs attention NOW (e.g. service is down, security update available)
    """

    OK = 0
    INFO = 1
    WARN = 2
    CRITICAL = 3

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Parse from string (case-insensitive)."""
        return cls[value.upper()]

    def emoji(self) -> str:
        """Emoji marker for this severity."""
        return {
            Severity.OK: "✅",
            Severity.INFO: "ℹ️",
            Severity.WARN: "⚠️",
            Severity.CRITICAL: "🔴",
        }[self]

    def color(self) -> str:
        """Rich color tag."""
        return {
            Severity.OK: "green",
            Severity.INFO: "cyan",
            Severity.WARN: "yellow",
            Severity.CRITICAL: "red bold",
        }[self]
