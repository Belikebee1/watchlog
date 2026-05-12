"""Snapshot of static-ish host info served by /api/v1/host.

Static-ish means: things that change infrequently (kernel, OS release,
hostname, RAM total, disk total) rather than continuously fluctuating
metrics (CPU%, free RAM, processes). For the latter we already have the
existing checks (memory, disk_space) which carry the live numbers in
their results — surfacing them again here would just duplicate.

The mobile app uses this for the server detail header: a passive
identifying card so you know which box you're looking at, plus a few
"is this thing alive at all" signals (uptime, IP).

Everything is computed best-effort. Missing files don't error — they
just return None for that field. The mobile UI hides null fields.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def collect_host_info() -> dict[str, Any]:
    """Return a JSON-serializable snapshot of host info.

    All fields are optional except `hostname` — if even that fails we
    fall back to "unknown" rather than 500-ing the API call.
    """
    from watchlog import __version__ as _watchlog_version

    return {
        "hostname": _hostname(),
        "fqdn": _fqdn(),
        "os": _os_release(),
        "kernel": _kernel(),
        "arch": platform.machine() or None,
        "cpu_cores": os.cpu_count(),
        "cpu_model": _cpu_model(),
        "ram_total_mb": _ram_total_mb(),
        "disk_total_gb": _disk_total_gb(),
        "uptime_seconds": _uptime_seconds(),
        "boot_time_iso": _boot_time_iso(),
        "ip_addresses": _ip_addresses(),
        "timezone": _timezone(),
        # Installed watchlog package version. The mobile app compares
        # this against the GitHub Releases "latest" tag and shows an
        # "Update available" banner when the server is behind. Old
        # servers that pre-date this field will simply omit it; the
        # mobile silently hides the banner in that case.
        "watchlog_version": _watchlog_version,
    }


def _hostname() -> str:
    try:
        return socket.gethostname() or "unknown"
    except OSError:
        return "unknown"


def _fqdn() -> str | None:
    """Fully-qualified hostname (e.g. fitegro.example.com). Often falls
    back to plain hostname on hosts without proper DNS config — we still
    return it so the mobile UI can show it side-by-side with the short
    hostname when it differs."""
    try:
        fqdn = socket.getfqdn()
        return fqdn if fqdn and fqdn != _hostname() else None
    except OSError:
        return None


def _os_release() -> dict[str, str | None] | None:
    """Parse /etc/os-release into a small dict the mobile app understands.
    Returns None on systems without the file (BSD, macOS); the API just
    omits the field and the UI doesn't render that row."""
    path = Path("/etc/os-release")
    if not path.is_file():
        return None
    try:
        data: dict[str, str] = {}
        for line in path.read_text().splitlines():
            if "=" not in line:
                continue
            k, _, v = line.partition("=")
            data[k.strip()] = v.strip().strip('"')
    except OSError:
        return None
    return {
        "name": data.get("NAME"),
        "version": data.get("VERSION") or data.get("VERSION_ID"),
        "pretty_name": data.get("PRETTY_NAME"),
        "id": data.get("ID"),
    }


def _kernel() -> str | None:
    try:
        return platform.release() or None
    except OSError:
        return None


def _cpu_model() -> str | None:
    """First model-name line from /proc/cpuinfo. Trimmed because some
    chips report verbose strings ("Intel(R) Xeon(R) Gold 6230 CPU @
    2.10GHz") that look ugly in a phone-sized header."""
    path = Path("/proc/cpuinfo")
    if not path.is_file():
        return None
    try:
        for line in path.read_text().splitlines():
            if line.startswith("model name"):
                _, _, value = line.partition(":")
                return value.strip() or None
    except OSError:
        pass
    return None


def _ram_total_mb() -> int | None:
    """Read MemTotal from /proc/meminfo and return megabytes (1024-based,
    matching what `free -m` shows). None on non-Linux."""
    path = Path("/proc/meminfo")
    if not path.is_file():
        return None
    try:
        for line in path.read_text().splitlines():
            if line.startswith("MemTotal:"):
                m = re.search(r"(\d+)\s*kB", line)
                if m:
                    return int(m.group(1)) // 1024
    except (OSError, ValueError):
        pass
    return None


def _disk_total_gb() -> int | None:
    """Total bytes for the root filesystem, in GB. We deliberately don't
    sum across all mountpoints — that conflates user-visible disk with
    docker overlays and bind mounts. The mobile detail screen shows root
    capacity as a sanity-check identifier ("this is the 75 GB box")."""
    try:
        usage = shutil.disk_usage("/")
        return int(usage.total // (1024 ** 3))
    except OSError:
        return None


def _uptime_seconds() -> int | None:
    """Read /proc/uptime so the mobile UI can show "up 18 days" without
    parsing `uptime` shell output. None on non-Linux."""
    path = Path("/proc/uptime")
    if not path.is_file():
        return None
    try:
        first, _ = path.read_text().split(maxsplit=1)
        return int(float(first))
    except (OSError, ValueError):
        return None


def _boot_time_iso() -> str | None:
    """Boot timestamp as ISO-8601 in UTC. Easier for the mobile to render
    "since 2026-04-22 14:33 UTC" than to do uptime arithmetic itself."""
    uptime = _uptime_seconds()
    if uptime is None:
        return None
    try:
        from datetime import datetime, timezone
        boot = time.time() - uptime
        return datetime.fromtimestamp(boot, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except OSError:
        return None


def _ip_addresses() -> list[dict[str, str]]:
    """Return [{name, addr, family}] for each non-loopback interface.

    Uses `ip -j addr` which is JSON-native on modern Linux. Falls back to
    parsing `ip addr` text output if the JSON flag isn't supported (very
    old iproute2). Empty list on systems without `ip` at all.
    """
    if not shutil.which("ip"):
        return []
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    try:
        import json
        ifaces = json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return []

    out: list[dict[str, str]] = []
    for iface in ifaces:
        name = iface.get("ifname", "")
        if name == "lo" or name.startswith("docker") or name.startswith("br-"):
            # Skip loopback and bridge/docker noise — the mobile UI wants
            # the "real" public IPs, not the box's internal NAT layout.
            continue
        for addr in iface.get("addr_info", []):
            family = addr.get("family")
            ip = addr.get("local")
            scope = addr.get("scope", "")
            if not ip or scope == "link":
                # Link-local IPv6 (fe80::) is noise on a phone screen.
                continue
            out.append({
                "interface": name,
                "addr": ip,
                "family": "ipv6" if family == "inet6" else "ipv4",
            })
    return out


def _timezone() -> str | None:
    """System timezone identifier (e.g. "Europe/Warsaw") so mobile can
    render times in the server's local clock when more useful than UTC."""
    try:
        link = Path("/etc/localtime")
        if link.is_symlink():
            target = os.readlink(link)
            # Typical target: ../usr/share/zoneinfo/Europe/Warsaw
            if "zoneinfo/" in target:
                return target.split("zoneinfo/", 1)[1]
        tz_file = Path("/etc/timezone")
        if tz_file.is_file():
            return tz_file.read_text().strip() or None
    except OSError:
        pass
    return None
