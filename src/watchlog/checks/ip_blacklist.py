"""IP blacklist check — DNS-based RBL lookup."""

from __future__ import annotations

import socket
import subprocess

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


def _detect_public_ip() -> str | None:
    """Best-effort public IPv4 detection via ifconfig.me."""
    for cmd in (
        ["curl", "-s", "-4", "--max-time", "5", "ifconfig.me"],
        ["curl", "-s", "-4", "--max-time", "5", "https://api.ipify.org"],
    ):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True)
            ip = proc.stdout.strip()
            if ip and len(ip.split(".")) == 4:
                return ip
        except (subprocess.SubprocessError, OSError):
            continue
    return None


def _reverse_octets(ip: str) -> str:
    """1.2.3.4 -> 4.3.2.1"""
    return ".".join(reversed(ip.split(".")))


def _on_blacklist(ip: str, rbl: str) -> tuple[bool, str | None]:
    """Returns (listed, reply) — DNS A lookup for reverse_ip.rbl."""
    query = f"{_reverse_octets(ip)}.{rbl}"
    try:
        result = socket.gethostbyname(query)
        return True, result
    except socket.gaierror:
        return False, None


@register_check
class IpBlacklistCheck(Check):
    name = "ip_blacklist"

    def run(self) -> CheckResult:
        ip = self.config.get("ip") or _detect_public_ip()
        if not ip:
            return self._warn(
                "Cannot determine public IP",
                "Set checks.ip_blacklist.ip in config or check internet connection.",
            )
        rbls = list(self.config.get("lists") or ["zen.spamhaus.org", "b.barracudacentral.org"])

        listed: list[tuple[str, str]] = []
        clean: list[str] = []
        rate_limited: list[str] = []

        for rbl in rbls:
            ok, reply = _on_blacklist(ip, rbl)
            if not ok:
                clean.append(rbl)
            elif reply and reply.startswith("127.255."):
                # Spamhaus rate-limit indicator (not actually listed)
                rate_limited.append(f"{rbl} (rate-limited, not authoritative)")
            else:
                listed.append((rbl, reply or "?"))

        details = (
            [f"❌ LISTED on {rbl} → {reply}" for rbl, reply in listed]
            + [f"✅ Clean on {rbl}" for rbl in clean]
            + [f"⚠️ {info}" for info in rate_limited]
        )

        if listed:
            return CheckResult(
                check_name=self.name,
                severity=Severity.CRITICAL,
                title=f"IP {ip} on {len(listed)} blacklist(s)",
                summary="Mail deliverability impaired. Submit delisting requests.",
                details=details,
                actions=[
                    f"# Open removal request for each listed RBL",
                    f"# Spamhaus: https://check.spamhaus.org/listed/?searchterm={ip}",
                    f"# Barracuda: https://barracudacentral.org/rbl/removal-request",
                ],
            )

        return self._ok(f"IP {ip} not on any blacklist", details=details)
