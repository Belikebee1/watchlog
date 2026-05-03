"""Open ports baseline diff — detect new listening ports.

This is a simple intrusion-detection signal: if a process starts listening on
a port that wasn't on the baseline, something is different. Could be:
  - A new service you legitimately installed (then update the baseline)
  - A leftover dev server you forgot to stop
  - Malware (rare but possible) opening a backdoor

The baseline is captured automatically on first run. Subsequent runs diff the
current `ss -tlnp` output against it. If new ports appear:
  - Flagged WARN (or CRITICAL with config)
  - Closed ports are reported as INFO (a service stopped)

To accept the current state as the new baseline:
    sudo rm /var/lib/watchlog/ports-baseline.txt
    sudo watchlog run --check open_ports
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


# Match ss -tlnp output, capturing protocol, address:port and process info.
# Example line (after header):
#   LISTEN 0  100   0.0.0.0:587  0.0.0.0:*  users:(("master",pid=99240,fd=17))
SS_LINE = re.compile(
    r"^\s*LISTEN\s+\d+\s+\d+\s+(?P<addr>\S+)\s+\S+\s*(?:users:\((?P<users>.+)\))?",
)
PROC_RE = re.compile(r'"([^"]+)"')


def _is_ephemeral_localhost(addr: str) -> bool:
    """High random ports bound to localhost — runtime-internal stuff that varies
    between restarts (containerd, vscode-server, dev runtimes). Not security-relevant."""
    if not addr.startswith(("127.", "[::1]:")):
        return False
    try:
        port = int(addr.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return False
    # Linux ephemeral port range starts at 32768 by default.
    return port >= 32768


def _snapshot_ports() -> set[str]:
    """Return a set of ``addr|process`` strings — one per listening socket.

    Filters out ephemeral high ports bound to localhost (containerd, IDE servers,
    etc.) since they vary between restarts and aren't security-relevant.
    """
    try:
        proc = subprocess.run(
            ["ss", "-tlnpH"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return set()

    snapshot: set[str] = set()
    for line in proc.stdout.splitlines():
        m = SS_LINE.match(line)
        if not m:
            continue
        addr = m.group("addr")
        if _is_ephemeral_localhost(addr):
            continue
        users = m.group("users") or ""
        # Use only the first (parent) process name. Daemons like Postfix spawn
        # children (smtpd) that share the listening socket; their presence
        # varies with traffic. Tracking only the parent gives a stable signal.
        names = sorted(set(PROC_RE.findall(users)))
        proc_str = names[0] if names else "?"
        snapshot.add(f"{addr}|{proc_str}")
    return snapshot


@register_check
class OpenPortsCheck(Check):
    name = "open_ports"

    def run(self) -> CheckResult:
        baseline_path = Path(
            self.config.get("baseline") or "/var/lib/watchlog/ports-baseline.txt"
        )
        new_severity = Severity.from_str(self.config.get("new_port_severity", "warn"))
        closed_severity = Severity.from_str(self.config.get("closed_port_severity", "info"))

        current = _snapshot_ports()
        if not current:
            return self._info(
                "Cannot read listening sockets",
                "Is `ss` available? Try `apt install iproute2`.",
            )

        # First run — establish baseline
        if not baseline_path.is_file():
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            baseline_path.write_text("\n".join(sorted(current)) + "\n", encoding="utf-8")
            return self._info(
                f"Port baseline established ({len(current)} sockets)",
                summary=f"Saved to {baseline_path}. Future runs will diff against this.",
                details=sorted(current),
            )

        baseline = {
            line.strip()
            for line in baseline_path.read_text().splitlines()
            if line.strip()
        }
        added = current - baseline
        removed = baseline - current

        if not added and not removed:
            return self._ok(
                f"Port baseline matches current state ({len(current)} sockets)",
                details=sorted(current)[:20],
            )

        details: list[str] = []
        if added:
            details.append(f"NEW (open since baseline) — {len(added)}:")
            for entry in sorted(added):
                details.append(f"  + {entry}")
        if removed:
            details.append(f"CLOSED (in baseline but not now) — {len(removed)}:")
            for entry in sorted(removed):
                details.append(f"  - {entry}")

        if added:
            severity = new_severity
            title = f"{len(added)} new listening port(s) since baseline"
        else:
            severity = closed_severity
            title = f"{len(removed)} port(s) closed since baseline (services stopped)"

        return CheckResult(
            check_name=self.name,
            severity=severity,
            title=title,
            summary=(
                "If the change is expected, re-baseline: "
                f"sudo rm {baseline_path} && sudo watchlog run --check open_ports"
            ),
            details=details,
            actions=[
                "ss -tlnp",
                f"# Re-baseline: rm {baseline_path}",
            ],
        )
