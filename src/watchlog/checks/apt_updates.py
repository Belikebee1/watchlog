"""APT updates check — counts upgradable packages and flags security ones."""

from __future__ import annotations

import re
import subprocess

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity

# Output line format: "package/jammy-security 1.2.3-1ubuntu1 amd64 [upgradable from: 1.2.0-1]"
UPGRADABLE_RE = re.compile(r"^(?P<pkg>[^/]+)/(?P<suite>\S+)\s+(?P<version>\S+)\s+(?P<arch>\S+)")


@register_check
class AptUpdatesCheck(Check):
    name = "apt_updates"

    def run(self) -> CheckResult:
        # Refresh lists silently. Don't fail the check if apt-get update fails — we still
        # want to report on stale info rather than nothing.
        subprocess.run(
            ["apt-get", "update", "-qq"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )

        proc = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode != 0:
            return self._critical(
                "Cannot list APT upgradables",
                summary=proc.stderr.strip()[:500] or "apt list failed",
            )

        all_pkgs: list[str] = []
        security_pkgs: list[str] = []

        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Listing"):
                continue
            match = UPGRADABLE_RE.match(line)
            if not match:
                continue
            pkg = match.group("pkg")
            suite = match.group("suite")
            all_pkgs.append(pkg)
            if "security" in suite.lower():
                security_pkgs.append(pkg)

        if not all_pkgs:
            return self._ok("System is up to date", "No upgradable packages.")

        # Severity: any security update -> critical
        sev_security = self.config.get("security_severity", "critical")
        sev_normal = self.config.get("normal_severity", "info")
        title = f"{len(all_pkgs)} packages can be upgraded ({len(security_pkgs)} security)"

        if security_pkgs:
            severity = Severity.from_str(sev_security)
            details = [f"SECURITY: {p}" for p in security_pkgs] + [
                f"  other: {p}" for p in all_pkgs if p not in security_pkgs
            ]
        else:
            severity = Severity.from_str(sev_normal)
            details = [f"  {p}" for p in all_pkgs]

        return CheckResult(
            check_name=self.name,
            severity=severity,
            title=title,
            summary=(
                f"Run `apt upgrade` to apply. "
                f"For security only: `unattended-upgrade -d`."
            ),
            details=details,
            actions=[
                "apt update && apt upgrade",
                "unattended-upgrade -v",
            ],
        )
