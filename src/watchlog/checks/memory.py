"""Free RAM check from /proc/meminfo."""

from __future__ import annotations

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


def _meminfo() -> dict[str, int]:
    """Parse /proc/meminfo into kB ints."""
    data: dict[str, int] = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, _, rest = line.partition(":")
            value = rest.strip().split()
            if not value:
                continue
            try:
                data[key] = int(value[0])
            except ValueError:
                pass
    return data


@register_check
class MemoryCheck(Check):
    name = "memory"

    def run(self) -> CheckResult:
        warn_mb = int(self.config.get("warn_mb_free", 500))
        crit_mb = int(self.config.get("critical_mb_free", 100))

        info = _meminfo()
        # MemAvailable is the realistic "free" — accounts for reclaimable cache.
        avail_kb = info.get("MemAvailable") or info.get("MemFree", 0)
        total_kb = info.get("MemTotal", 0)
        avail_mb = avail_kb // 1024
        total_mb = total_kb // 1024
        used_pct = 100 * (1 - avail_kb / total_kb) if total_kb else 0

        details = [
            f"Total: {total_mb} MB",
            f"Available: {avail_mb} MB",
            f"Used: {used_pct:.1f}%",
        ]

        if avail_mb < crit_mb:
            return CheckResult(
                self.name,
                Severity.CRITICAL,
                f"Only {avail_mb} MB RAM available",
                summary="Server is critically low on memory. OOM killer may strike.",
                details=details,
                actions=["ps aux --sort=-%mem | head -10", "free -h"],
            )
        if avail_mb < warn_mb:
            return CheckResult(
                self.name,
                Severity.WARN,
                f"Low RAM: {avail_mb} MB available",
                summary="Consider closing/restarting services with leaks.",
                details=details,
                actions=["ps aux --sort=-%mem | head -10"],
            )
        return self._ok(f"RAM OK ({avail_mb} MB / {total_mb} MB available)", details=details)
