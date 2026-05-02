"""Systemd services check — must_be_active list."""

from __future__ import annotations

import subprocess

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


def _is_active(service: str) -> tuple[bool, str]:
    """Return (active?, status_word) using systemctl is-active."""
    try:
        proc = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        status = proc.stdout.strip() or "unknown"
        return status == "active", status
    except (subprocess.SubprocessError, OSError) as exc:
        return False, f"error: {exc}"


@register_check
class ServicesCheck(Check):
    name = "services"

    def run(self) -> CheckResult:
        wanted = list(self.config.get("must_be_active") or [])
        if not wanted:
            return self._info("No services configured", "Set checks.services.must_be_active")

        statuses: list[tuple[str, bool, str]] = []
        for svc in wanted:
            active, status = _is_active(svc)
            statuses.append((svc, active, status))

        broken = [(s, st) for s, ok, st in statuses if not ok]
        details = [f"{'✅' if ok else '❌'} {s}: {st}" for s, ok, st in statuses]

        if not broken:
            return self._ok(f"All {len(wanted)} services active", details=details)

        names = ", ".join(s for s, _ in broken)
        return CheckResult(
            check_name=self.name,
            severity=Severity.CRITICAL,
            title=f"{len(broken)} service(s) not active: {names}",
            summary="Critical services are not running. Investigate immediately.",
            details=details,
            actions=[f"systemctl status {s}" for s, _ in broken]
            + [f"journalctl -u {s} -n 50 --no-pager" for s, _ in broken],
        )
