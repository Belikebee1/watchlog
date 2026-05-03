"""fail2ban statistics — verify fail2ban is alive and report ban activity.

This check answers: "Is the brute-force defender working, and is anything
unusual happening?" If fail2ban silently dies (crash, config error), brute-force
attempts go through. We want to know.

Reports:
- Active jails (sshd, postfix, dovecot, etc.)
- Currently banned IPs per jail
- Total banned in the last "interval" (uptime since fail2ban started)
- WARN if a jail expected to be active is missing
- WARN if currently banned count exceeds threshold (suggests sustained attack)
- CRITICAL if fail2ban service is down
- INFO if fail2ban not installed
"""

from __future__ import annotations

import re
import shutil
import subprocess

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


def _fail2ban(*args: str) -> tuple[int, str]:
    """Run fail2ban-client. Returns (returncode, output)."""
    try:
        proc = subprocess.run(
            ["fail2ban-client", *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        return -1, f"{type(exc).__name__}: {exc}"
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _list_jails() -> list[str]:
    rc, out = _fail2ban("status")
    if rc != 0:
        return []
    # Output line: "`- Jail list:	sshd, postfix-sasl, ..."
    match = re.search(r"Jail list:\s*(.*)", out)
    if not match:
        return []
    return [j.strip() for j in match.group(1).split(",") if j.strip()]


def _jail_status(name: str) -> dict[str, int]:
    """Parse `fail2ban-client status <jail>` into counts."""
    rc, out = _fail2ban("status", name)
    if rc != 0:
        return {}
    stats: dict[str, int] = {}
    for line in out.splitlines():
        m = re.match(r"\s*[`|]-\s*(?:\|-\s*)?([^:]+):\s+(\d+)", line)
        if not m:
            continue
        key = m.group(1).strip().lower().replace(" ", "_")
        try:
            stats[key] = int(m.group(2))
        except ValueError:
            continue
    return stats


@register_check
class Fail2banStatsCheck(Check):
    name = "fail2ban_stats"

    def run(self) -> CheckResult:
        if shutil.which("fail2ban-client") is None:
            return self._info(
                "fail2ban not installed",
                "Install with `apt install fail2ban` to protect SSH and mail from brute-force.",
                actions=["apt install fail2ban"],
            )

        # Service alive?
        rc, _out = _fail2ban("ping")
        if rc != 0:
            return self._critical(
                "fail2ban not responding",
                summary="The service may be down. Brute-force protection is OFFLINE.",
                actions=[
                    "systemctl status fail2ban",
                    "systemctl restart fail2ban",
                    "journalctl -u fail2ban -n 50 --no-pager",
                ],
            )

        jails = _list_jails()
        if not jails:
            return self._warn(
                "fail2ban running but no active jails",
                summary="No protection rules active. Configure jails in /etc/fail2ban/jail.local.",
            )

        warn_currently = int(self.config.get("warn_currently_banned", 50))
        crit_currently = int(self.config.get("critical_currently_banned", 200))
        required: list[str] = list(self.config.get("required_jails") or [])

        details: list[str] = []
        total_currently = 0
        total_ever = 0
        worst = Severity.OK

        for jail in jails:
            stats = _jail_status(jail)
            cur = stats.get("currently_banned", 0)
            tot = stats.get("total_banned", 0)
            total_currently += cur
            total_ever += tot
            details.append(
                f"{jail}: currently_banned={cur}, total_banned={tot}, "
                f"failed={stats.get('total_failed', 0)}"
            )

        # Required jails missing?
        missing = [j for j in required if j not in jails]
        if missing:
            details.append(f"⚠️ Missing required jails: {', '.join(missing)}")
            worst = max(worst, Severity.WARN)

        # Sustained attack?
        if total_currently >= crit_currently:
            worst = max(worst, Severity.CRITICAL)
        elif total_currently >= warn_currently:
            worst = max(worst, Severity.WARN)

        title = (
            f"fail2ban OK — {len(jails)} jails, "
            f"{total_currently} currently banned, {total_ever} total"
        )
        if worst == Severity.CRITICAL:
            title = f"fail2ban — {total_currently} currently banned (sustained attack?)"
        elif worst == Severity.WARN and missing:
            title = f"fail2ban — required jail(s) missing: {', '.join(missing)}"
        elif worst == Severity.WARN:
            title = f"fail2ban — {total_currently} currently banned (high)"

        return CheckResult(
            check_name=self.name,
            severity=worst,
            title=title,
            summary="" if worst == Severity.OK
            else "Investigate the source IPs and consider adjusting bantime/findtime.",
            details=details,
            actions=[
                "fail2ban-client status",
                "fail2ban-client status <jail>",
            ] if worst > Severity.OK else [],
        )
