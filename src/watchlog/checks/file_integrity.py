"""File integrity check via AIDE (Advanced Intrusion Detection Environment).

AIDE stores cryptographic hashes of system files and detects tampering.
This check shells out to `aide --check --config /etc/aide/aide.conf` and
parses the result.

Setup (once, after installing AIDE):
    sudo apt install aide
    sudo aideinit                    # build initial database (slow, ~5-15 min)
    sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

When you intentionally change something AIDE tracks (e.g. install a package),
re-baseline:
    sudo aideinit
    sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

If AIDE isn't installed, this check returns INFO and points to setup commands.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from watchlog.core.check import Check, CheckResult
from watchlog.core.runner import register_check
from watchlog.core.severity import Severity


@register_check
class FileIntegrityCheck(Check):
    name = "file_integrity"

    def run(self) -> CheckResult:
        if shutil.which("aide") is None:
            return self._info(
                "AIDE not installed",
                summary="File-integrity monitoring optional but recommended for security.",
                details=[
                    "Install:  apt install aide",
                    "Init DB:  aideinit  (slow, builds checksums of /usr, /etc, /bin, ...)",
                    "Confirm:  cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
                ],
                actions=[
                    "apt install aide",
                    "aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
                ],
            )

        # AIDE database must be initialised
        db = Path("/var/lib/aide/aide.db")
        if not db.is_file():
            return self._warn(
                "AIDE database not initialised",
                summary="Run `aideinit` to build the baseline before AIDE can detect changes.",
                actions=["aideinit", "cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"],
            )

        timeout_s = int(self.config.get("timeout_s", 600))
        try:
            proc = subprocess.run(
                ["aide", "--check"],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._warn(
                f"AIDE check timed out after {timeout_s}s",
                summary="Increase `timeout_s` in config if needed (default 600s).",
            )
        except (subprocess.SubprocessError, OSError) as exc:
            return self._info(f"AIDE error: {type(exc).__name__}: {exc}")

        # AIDE exit codes:
        # 0   = no differences
        # 1   = new file added
        # 2   = removed file
        # 4   = changed file
        # bits OR'd together
        out = proc.stdout + proc.stderr
        rc = proc.returncode

        if rc == 0:
            return self._ok(
                "File integrity OK — no changes since baseline",
                details=["AIDE: 0 added, 0 removed, 0 changed"],
            )

        # Parse summary section if present
        summary_lines: list[str] = []
        for line in out.splitlines():
            stripped = line.strip()
            if any(
                stripped.startswith(prefix)
                for prefix in (
                    "Added entries", "Removed entries", "Changed entries",
                    "Total number of", "Number of entries", "added :",
                    "removed :", "changed :",
                )
            ):
                summary_lines.append(stripped)

        # Severity mapping
        added = bool(rc & 1)
        removed = bool(rc & 2)
        changed = bool(rc & 4)

        # CRITICAL on any binary/config change in /usr, /bin, /sbin, /etc
        # WARN otherwise. Conservative: any difference is at least WARN.
        if changed or removed:
            severity = Severity.from_str(self.config.get("change_severity", "critical"))
            title = "AIDE detected file changes — possible tampering"
        elif added:
            severity = Severity.from_str(self.config.get("add_severity", "warn"))
            title = "AIDE detected new files since baseline"
        else:
            severity = Severity.WARN
            title = f"AIDE returned exit code {rc}"

        # Take first 30 changed/added lines from output for context
        diff_lines: list[str] = []
        in_diff = False
        for line in out.splitlines():
            if "added entries:" in line.lower() or "changed entries:" in line.lower() or "removed entries:" in line.lower():
                in_diff = True
                diff_lines.append(line)
                continue
            if in_diff and line.strip():
                diff_lines.append(line)
                if len(diff_lines) > 30:
                    diff_lines.append("(... truncated ...)")
                    break

        return CheckResult(
            check_name=self.name,
            severity=severity,
            title=title,
            summary=(
                "Investigate the changes below. If they are expected (e.g. you installed "
                "a package), re-baseline: `aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db`."
            ),
            details=summary_lines + diff_lines,
            actions=[
                "aide --check | less",
                "aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db",
            ],
        )
