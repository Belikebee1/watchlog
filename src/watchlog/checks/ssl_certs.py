"""SSL/TLS certificate expiry check (Let's Encrypt or any PEM)."""

from __future__ import annotations

import datetime as dt
import subprocess
from pathlib import Path

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


@register_check
class SslCertsCheck(Check):
    name = "ssl_certs"

    def run(self) -> CheckResult:
        paths = [Path(p) for p in self.config.get("paths", ["/etc/letsencrypt/live"])]
        warn_days = int(self.config.get("warn_days", 30))
        crit_days = int(self.config.get("critical_days", 7))

        certs: list[tuple[Path, dt.datetime, int]] = []
        for base in paths:
            if not base.exists():
                continue
            # /etc/letsencrypt/live/<domain>/fullchain.pem layout
            for fullchain in base.rglob("fullchain.pem"):
                expires = self._cert_expiry(fullchain)
                if expires is None:
                    continue
                days_left = (expires - dt.datetime.now(dt.timezone.utc)).days
                certs.append((fullchain, expires, days_left))

        if not certs:
            return self._info("No SSL certs found", f"Searched: {', '.join(str(p) for p in paths)}")

        certs.sort(key=lambda x: x[2])  # soonest expiring first
        worst_days = certs[0][2]

        if worst_days <= crit_days:
            severity = Severity.CRITICAL
        elif worst_days <= warn_days:
            severity = Severity.WARN
        else:
            severity = Severity.OK

        details = [
            f"{cert.parent.name}: expires in {days} days ({expires:%Y-%m-%d})"
            for cert, expires, days in certs
        ]

        if severity == Severity.OK:
            return self._ok(
                f"All {len(certs)} certs healthy (soonest in {worst_days} days)",
                details=details,
            )

        return CheckResult(
            check_name=self.name,
            severity=severity,
            title=f"Cert expires in {worst_days} days: {certs[0][0].parent.name}",
            summary="Run certbot renew if auto-renewal hasn't triggered.",
            details=details,
            actions=["certbot renew", "systemctl status certbot.timer"],
        )

    @staticmethod
    def _cert_expiry(path: Path) -> dt.datetime | None:
        """Return UTC datetime when cert expires, or None if can't read."""
        try:
            proc = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", str(path)],
                capture_output=True,
                text=True,
                timeout=5,
                check=True,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        # Format: "notAfter=Jul 30 18:25:33 2026 GMT"
        line = proc.stdout.strip()
        if "=" not in line:
            return None
        try:
            return dt.datetime.strptime(line.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=dt.timezone.utc
            )
        except ValueError:
            return None
