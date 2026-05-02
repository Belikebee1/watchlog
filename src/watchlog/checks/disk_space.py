"""Disk space check using shutil.disk_usage."""

from __future__ import annotations

import shutil

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


def _read_mounts() -> list[str]:
    """Return list of mountpoints from /proc/mounts (filtering out virtual/snap)."""
    mounts: list[str] = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                _device, mountpoint, fstype = parts[0], parts[1], parts[2]
                # Skip virtual filesystems
                if fstype in {
                    "proc",
                    "sysfs",
                    "tmpfs",
                    "devtmpfs",
                    "devpts",
                    "cgroup",
                    "cgroup2",
                    "overlay",
                    "squashfs",
                    "fuse.snapfuse",
                    "fusectl",
                    "pstore",
                    "bpf",
                    "tracefs",
                    "debugfs",
                    "configfs",
                    "ramfs",
                    "rpc_pipefs",
                    "binfmt_misc",
                    "autofs",
                    "mqueue",
                    "hugetlbfs",
                    "fuse.lxcfs",
                    "nsfs",
                }:
                    continue
                mounts.append(mountpoint)
    except OSError:
        return ["/"]
    return mounts or ["/"]


@register_check
class DiskSpaceCheck(Check):
    name = "disk_space"

    def run(self) -> CheckResult:
        warn_pct = int(self.config.get("warn_pct", 80))
        crit_pct = int(self.config.get("critical_pct", 90))
        ignore = set(self.config.get("ignore") or [])

        rows: list[tuple[str, int, int, float]] = []
        for mp in _read_mounts():
            if any(mp.startswith(i) for i in ignore):
                continue
            try:
                total, used, _free = shutil.disk_usage(mp)
            except OSError:
                continue
            if total == 0:
                continue
            pct = used / total * 100
            rows.append((mp, total, used, pct))

        if not rows:
            return self._info("No mountpoints to inspect")

        rows.sort(key=lambda r: -r[3])  # most-full first
        worst = rows[0]
        worst_mp, _t, _u, worst_pct = worst

        if worst_pct >= crit_pct:
            severity = Severity.CRITICAL
        elif worst_pct >= warn_pct:
            severity = Severity.WARN
        else:
            severity = Severity.OK

        details = [
            f"{mp}: {pct:.1f}% used ({used / 1e9:.1f} GB / {total / 1e9:.1f} GB)"
            for mp, total, used, pct in rows
        ]

        if severity == Severity.OK:
            return self._ok(
                f"Disk usage OK (worst: {worst_mp} at {worst_pct:.0f}%)", details=details
            )

        return CheckResult(
            check_name=self.name,
            severity=severity,
            title=f"Disk {worst_mp} is {worst_pct:.0f}% full",
            summary=f"Free up space on {worst_mp} or expand the volume.",
            details=details,
            actions=[
                f"du -sh {worst_mp}/* 2>/dev/null | sort -h | tail -20",
                "docker system prune -af  # if Docker fills disk",
                "journalctl --vacuum-time=14d  # if journal fills disk",
            ],
        )
