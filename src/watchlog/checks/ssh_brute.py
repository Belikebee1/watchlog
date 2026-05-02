"""SSH brute-force detection — count failed logins in last 24h."""

from __future__ import annotations

import datetime as dt
import re
import subprocess

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity

FAILED_RE = re.compile(r"Failed password|Invalid user|Connection closed by authenticating user")


@register_check
class SshBruteCheck(Check):
    name = "ssh_brute"

    def run(self) -> CheckResult:
        threshold = int(self.config.get("threshold_24h", 1000))
        # Read from journalctl (ubuntu 24.04 uses journal not /var/log/auth.log by default)
        since = (dt.datetime.now() - dt.timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        try:
            proc = subprocess.run(
                ["journalctl", "_SYSTEMD_UNIT=ssh.service", "--since", since, "--no-pager"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return self._info("Cannot read SSH log", f"{exc}")

        if proc.returncode != 0:
            return self._info(
                "journalctl failed", proc.stderr.strip()[:300] or "no output"
            )

        lines = proc.stdout.splitlines()
        failed = [line for line in lines if FAILED_RE.search(line)]

        # Count unique source IPs
        ip_re = re.compile(r"from (\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)")
        ips: dict[str, int] = {}
        for line in failed:
            m = ip_re.search(line)
            if m:
                ips[m.group(1)] = ips.get(m.group(1), 0) + 1

        top = sorted(ips.items(), key=lambda kv: -kv[1])[:10]
        details = [f"{ip}: {count} attempts" for ip, count in top]

        if len(failed) >= threshold * 2:
            severity = Severity.CRITICAL
        elif len(failed) >= threshold:
            severity = Severity.WARN
        else:
            return self._ok(
                f"SSH brute-force normal ({len(failed)} failed attempts in 24h, "
                f"{len(ips)} unique IPs)",
                details=details,
            )

        return CheckResult(
            check_name=self.name,
            severity=severity,
            title=f"{len(failed)} failed SSH logins in 24h from {len(ips)} IPs",
            summary="Verify fail2ban is working. Consider tightening SSH config.",
            details=details,
            actions=[
                "fail2ban-client status sshd",
                "# Disable password auth in /etc/ssh/sshd_config (PasswordAuthentication no)",
                "# Move SSH to non-standard port",
            ],
        )
