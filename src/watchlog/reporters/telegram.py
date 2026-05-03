"""Telegram reporter — sends watchlog alerts to a Telegram chat with inline action buttons.

The reporter only SENDS messages (one HTTP request per emit). The interactive part
— receiving button clicks — is handled by the separate `watchlog telegram bot`
daemon (see watchlog.bot). Together they form the v0.2 interactive notification
loop:

    watchlog run  →  emits alert with buttons  →  Telegram delivers
                                                       │
    user clicks "Apply security updates"  ──────────► daemon receives callback
                                                            │
    daemon runs unattended-upgrade  ────────────────► posts result to chat

Button callback_data uses a compact format (Telegram limit: 64 bytes):

    apply_security              → run unattended-upgrade
    run_now                     → trigger fresh `watchlog run`
    snooze:<check>:<hours>      → silence one check for N hours
    ignore:<check>              → ignore one check until manually un-ignored
    show_log:<check>            → show last 30 lines of relevant log

This reporter uses urllib (stdlib), so it has zero extra dependencies.
"""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from urllib import error as urlerror
from urllib import request as urlreq

from watchlog.core.check import CheckResult
from watchlog.core.runner import register_reporter
from watchlog.core.severity import Severity
from watchlog.reporters.base import Reporter
from watchlog.state import State

log = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org"
MAX_MESSAGE_LEN = 3800  # Telegram limit is 4096; leave headroom for HTML markup


@register_reporter("telegram")
class TelegramReporter(Reporter):
    name = "telegram"

    def emit(self, results: list[CheckResult]) -> None:
        if not self.config.get("enabled", False):
            return

        token = self.config.get("bot_token") or ""
        chat_id = self.config.get("chat_id") or ""
        if not token or not chat_id:
            log.warning("Telegram reporter enabled but bot_token/chat_id missing")
            return

        threshold = Severity.from_str(self.config.get("only_when", "warn"))
        worst = max((r.severity for r in results), default=Severity.OK)
        if worst < threshold:
            return  # nothing actionable

        # Filter by snooze/ignore state — same as in-app silencing
        state = State.load()
        actionable = [
            r
            for r in results
            if r.severity >= threshold and not state.is_silenced(r.check_name)
        ]
        if not actionable:
            return

        text = self._build_message(actionable, results)
        keyboard = self._build_keyboard(actionable)

        self._send(token, chat_id, text, keyboard)

    # --------------- formatting ---------------

    @staticmethod
    def _build_message(actionable: list[CheckResult], all_results: list[CheckResult]) -> str:
        host = socket.gethostname()
        worst = max(r.severity for r in actionable)
        lines: list[str] = []

        lines.append(f"{worst.emoji()} <b>watchlog @ {host}</b>")
        lines.append("")

        critical = [r for r in actionable if r.severity == Severity.CRITICAL]
        warn = [r for r in actionable if r.severity == Severity.WARN]

        for r in critical + warn:
            lines.append(f"{r.severity.emoji()} <b>{_html_escape(r.check_name)}</b>")
            lines.append(f"   {_html_escape(r.title)}")
            if r.summary:
                lines.append(f"   <i>{_html_escape(r.summary[:300])}</i>")
            # Show first 5 details inline, hide the rest
            if r.details:
                preview = r.details[:5]
                for d in preview:
                    lines.append(f"     • <code>{_html_escape(str(d)[:120])}</code>")
                if len(r.details) > 5:
                    lines.append(f"     <i>… +{len(r.details) - 5} more</i>")
            lines.append("")

        ok_count = len([r for r in all_results if r.severity == Severity.OK])
        info_count = len([r for r in all_results if r.severity == Severity.INFO])
        if ok_count or info_count:
            lines.append(f"<i>({ok_count} OK · {info_count} INFO not shown)</i>")

        text = "\n".join(lines)
        if len(text) > MAX_MESSAGE_LEN:
            text = text[: MAX_MESSAGE_LEN - 100] + "\n\n<i>… truncated.</i>"
        return text

    @staticmethod
    def _build_keyboard(actionable: list[CheckResult]) -> list[list[dict]]:
        """Build inline keyboard. Buttons depend on what's actionable."""
        rows: list[list[dict]] = []

        # Big "Apply security" button if there's a security update pending
        if any(
            r.check_name == "apt_updates"
            and r.severity == Severity.CRITICAL
            and any("security" in d.lower() for d in r.details)
            for r in actionable
        ):
            rows.append(
                [
                    {"text": "✅ Apply security updates", "callback_data": "apply_security"},
                ]
            )

        # Per-check snooze/ignore — group by check_name
        seen: set[str] = set()
        for r in actionable:
            if r.check_name in seen:
                continue
            seen.add(r.check_name)
            rows.append(
                [
                    {
                        "text": f"⏰ Snooze {r.check_name} 4h",
                        "callback_data": f"snooze:{r.check_name}:4",
                    },
                    {
                        "text": f"🚫 Ignore {r.check_name}",
                        "callback_data": f"ignore:{r.check_name}",
                    },
                ]
            )

        # Final row — utility actions
        rows.append(
            [
                {"text": "🔄 Run watchlog now", "callback_data": "run_now"},
            ]
        )

        return rows

    # --------------- transport ---------------

    @staticmethod
    def _send(token: str, chat_id: str, text: str, keyboard: list[list[dict]]) -> None:
        url = f"{TELEGRAM_API}/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            "reply_markup": {"inline_keyboard": keyboard},
        }
        body = json.dumps(payload).encode("utf-8")
        req = urlreq.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlreq.urlopen(req, timeout=15) as resp:
                resp.read()
        except urlerror.HTTPError as exc:
            try:
                err_body = exc.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                err_body = ""
            log.error("Telegram sendMessage failed: HTTP %s — %s", exc.code, err_body[:300])
        except urlerror.URLError as exc:
            log.error("Telegram sendMessage URL error: %s", exc)


def _html_escape(s: str) -> str:
    """Minimal HTML escape for Telegram parse_mode=HTML."""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
