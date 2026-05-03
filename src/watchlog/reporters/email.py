"""Email reporter — sends a summary via SMTP."""

from __future__ import annotations

import smtplib
import socket
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from watchlog.core.check import CheckResult
from watchlog.core.runner import register_reporter
from watchlog.core.severity import Severity
from watchlog.reporters.base import Reporter
from watchlog.state import State


@register_reporter("email")
class EmailReporter(Reporter):
    name = "email"

    def emit(self, results: list[CheckResult]) -> None:
        if not self.config.get("enabled", False):
            return

        # Filter by only_when threshold AND respect snooze/ignore state
        # (so a user who hits "Snooze" on Telegram also stops getting emails)
        threshold_str = self.config.get("only_when", "warn")
        threshold = Severity.from_str(threshold_str)
        state = State.load()
        actionable = [
            r for r in results
            if r.severity >= threshold and not state.is_silenced(r.check_name)
        ]
        if not actionable:
            return  # nothing to report (or everything silenced)
        # The body builder still uses the full results list for the OK count.
        worst = max(r.severity for r in actionable)

        to_addr = self.config.get("to")
        from_addr = self.config.get("from") or f"watchlog@{socket.getfqdn()}"
        host = self.config.get("smtp_host", "127.0.0.1")
        port = int(self.config.get("smtp_port", 25))
        user = self.config.get("smtp_user") or None
        password = self.config.get("smtp_password") or None
        starttls = bool(self.config.get("smtp_starttls", False))

        if not to_addr:
            return

        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Subject"] = self._subject(results, worst)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=socket.getfqdn())
        msg.set_content(self._body_text(results), charset="utf-8")
        msg.add_alternative(self._body_html(results), subtype="html")

        with smtplib.SMTP(host, port, timeout=30) as smtp:
            if starttls:
                smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)

    @staticmethod
    def _subject(results: list[CheckResult], worst: Severity) -> str:
        host = socket.gethostname()
        emoji = worst.emoji()
        critical = sum(1 for r in results if r.severity == Severity.CRITICAL)
        warn = sum(1 for r in results if r.severity == Severity.WARN)
        if critical:
            return f"{emoji} [watchlog/{host}] {critical} CRITICAL, {warn} WARN"
        if warn:
            return f"{emoji} [watchlog/{host}] {warn} WARN"
        return f"{emoji} [watchlog/{host}] all clear"

    @staticmethod
    def _body_text(results: list[CheckResult]) -> str:
        lines = [f"watchlog report from {socket.gethostname()}", ""]
        actionable = [r for r in results if r.severity > Severity.OK]
        ok_count = len(results) - len(actionable)

        if actionable:
            lines.append(f"{len(actionable)} check(s) need attention:")
            lines.append("")
            for r in actionable:
                lines.append(f"{r.severity.emoji()}  {r.check_name}: {r.title}")
                if r.summary:
                    lines.append(f"     {r.summary}")
                for d in r.details:
                    lines.append(f"     · {d}")
                if r.actions:
                    lines.append("     Suggested actions:")
                    for a in r.actions:
                        lines.append(f"       $ {a}")
                lines.append("")
        if ok_count:
            lines.append(f"({ok_count} other check(s) OK)")
        return "\n".join(lines)

    @staticmethod
    def _body_html(results: list[CheckResult]) -> str:
        rows = []
        actionable = [r for r in results if r.severity > Severity.OK]
        ok_count = len(results) - len(actionable)

        for r in actionable:
            rows.append(
                f"<tr style='vertical-align:top'>"
                f"<td><strong>{r.severity.emoji()} {r.check_name}</strong></td>"
                f"<td>"
                f"<strong>{r.title}</strong><br/>"
                f"{r.summary}"
                f"<ul>{''.join(f'<li><code>{d}</code></li>' for d in r.details)}</ul>"
                + (
                    "<details><summary>Suggested actions</summary><pre>"
                    + "\n".join(r.actions)
                    + "</pre></details>"
                    if r.actions
                    else ""
                )
                + "</td></tr>"
            )

        body = (
            f"<h2>watchlog report — {socket.gethostname()}</h2>"
            f"<p>{len(actionable)} check(s) need attention. ({ok_count} OK)</p>"
            f"<table cellpadding='6' cellspacing='0' border='1' style='border-collapse:collapse'>"
            f"{''.join(rows)}"
            f"</table>"
        )
        return body
