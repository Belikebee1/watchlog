"""DNS records sanity — verify SPF/DMARC/MX/A still exist."""

from __future__ import annotations

import subprocess

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


def _dig(record_type: str, name: str) -> list[str]:
    """Run dig +short and return list of result lines."""
    try:
        proc = subprocess.run(
            ["dig", "+short", "+timeout=3", record_type, name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    except (subprocess.SubprocessError, OSError):
        return []


@register_check
class DnsRecordsCheck(Check):
    name = "dns_records"

    def run(self) -> CheckResult:
        domains = list(self.config.get("domains") or [])
        if not domains:
            return self._info("No domains configured", "Set checks.dns_records.domains")

        require: set[str] = set(self.config.get("require") or ["mx", "spf", "dmarc"])

        problems: list[str] = []
        ok_lines: list[str] = []

        for domain in domains:
            if "a" in require:
                a = _dig("A", domain)
                (ok_lines if a else problems).append(
                    f"{domain} A: {', '.join(a) if a else 'MISSING'}"
                )

            if "mx" in require:
                mx = _dig("MX", domain)
                (ok_lines if mx else problems).append(
                    f"{domain} MX: {', '.join(mx) if mx else 'MISSING'}"
                )

            if "spf" in require:
                txt = _dig("TXT", domain)
                spf = [t for t in txt if "v=spf1" in t]
                (ok_lines if spf else problems).append(
                    f"{domain} SPF: {spf[0][:80] if spf else 'MISSING'}"
                )

            if "dmarc" in require:
                txt = _dig("TXT", f"_dmarc.{domain}")
                dmarc = [t for t in txt if "v=DMARC1" in t]
                (ok_lines if dmarc else problems).append(
                    f"{domain} DMARC: {dmarc[0][:80] if dmarc else 'MISSING'}"
                )

        details = problems + ok_lines

        if problems:
            return CheckResult(
                check_name=self.name,
                severity=Severity.CRITICAL,
                title=f"{len(problems)} DNS records missing or broken",
                summary="Fix in your DNS provider's panel.",
                details=details,
                actions=[f"dig +short ANY {d}" for d in domains],
            )

        return self._ok(f"All required DNS records present for {len(domains)} domain(s)",
                        details=details)
