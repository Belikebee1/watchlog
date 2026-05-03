"""Telegram bot daemon — handles button clicks (callback queries).

Uses Telegram's `getUpdates` long-polling endpoint with stdlib urllib only.
This keeps watchlog dependency-free at runtime; the only thing you need is
a bot token from @BotFather and the chat_id you want to talk to.

Run via:
    sudo watchlog telegram bot

Or as a systemd service (created by `watchlog telegram install-service`).

Authorization: the bot accepts callback queries ONLY from the configured chat_id.
Any other chat is silently ignored (and logged).

Actions handled:
    apply_security              → sudo unattended-upgrade -v
    run_now                     → sudo watchlog run
    snooze:<check>:<hours>      → write state file, send confirmation
    ignore:<check>              → write state file, send confirmation
"""

from __future__ import annotations

import json
import logging
import re
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlreq

from watchlog.core.config import Config
from watchlog.state import State

log = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org"
LONG_POLL_TIMEOUT = 30  # seconds

# Whitelist of safe shell commands — daemon never runs anything not in this list
ACTION_HANDLERS: dict[str, list[str]] = {
    "apply_security": ["unattended-upgrade", "-v"],
    "run_now": ["watchlog", "run"],
}

CALLBACK_RE = re.compile(
    r"^("
    r"apply_security"
    r"|run_now"
    r"|snooze:[A-Za-z0-9_]+:\d+"
    r"|ignore:[A-Za-z0-9_]+"
    r")$"
)


class TelegramBot:
    """Long-polling daemon. One instance per process, blocking run loop."""

    def __init__(self, config: Config):
        tg = config.reporter_config("telegram")
        self.token: str = tg.get("bot_token") or ""
        self.allowed_chat_id: str = str(tg.get("chat_id") or "")
        if not self.token:
            raise RuntimeError("telegram.bot_token not set in config")
        if not self.allowed_chat_id:
            raise RuntimeError("telegram.chat_id not set in config")
        self._stop = False
        self._offset: int | None = None

    # --------------- public ---------------

    def run(self) -> None:
        signal.signal(signal.SIGTERM, self._handle_stop)
        signal.signal(signal.SIGINT, self._handle_stop)
        log.info("Telegram bot started (chat_id=%s)", self.allowed_chat_id)
        self._notify("watchlog bot started ✅")
        while not self._stop:
            try:
                updates = self._get_updates()
            except urlerror.URLError as exc:
                log.warning("getUpdates failed (network): %s", exc)
                time.sleep(5)
                continue
            except Exception as exc:  # noqa: BLE001
                log.exception("getUpdates crashed: %s", exc)
                time.sleep(10)
                continue
            for update in updates:
                self._handle_update(update)
        log.info("Telegram bot stopped")

    # --------------- internals ---------------

    def _handle_stop(self, *_args: object) -> None:
        log.info("Stop signal received")
        self._stop = True

    def _api(self, method: str, params: dict | None = None) -> dict:
        url = f"{TELEGRAM_API}/bot{self.token}/{method}"
        if params:
            data = json.dumps(params).encode("utf-8")
            req = urlreq.Request(
                url, data=data, headers={"Content-Type": "application/json"}, method="POST"
            )
        else:
            req = urlreq.Request(url)
        with urlreq.urlopen(req, timeout=LONG_POLL_TIMEOUT + 5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        if not payload.get("ok"):
            raise RuntimeError(f"Telegram API {method} returned: {payload}")
        return payload.get("result")

    def _get_updates(self) -> list[dict]:
        params = {
            "timeout": LONG_POLL_TIMEOUT,
            "allowed_updates": ["callback_query", "message"],
        }
        if self._offset is not None:
            params["offset"] = self._offset
        result = self._api("getUpdates", params)
        if not result:
            return []
        # Advance offset past the last update we saw
        self._offset = result[-1]["update_id"] + 1
        return result

    def _handle_update(self, update: dict) -> None:
        if "callback_query" in update:
            self._handle_callback(update["callback_query"])
        elif "message" in update:
            self._handle_message(update["message"])

    def _handle_callback(self, cq: dict) -> None:
        from_chat = str(cq.get("from", {}).get("id") or "")
        if from_chat != self.allowed_chat_id:
            log.warning("Rejecting callback from unauthorized chat_id=%s", from_chat)
            self._answer_callback(cq["id"], "Unauthorized.")
            return

        data = cq.get("data") or ""
        if not CALLBACK_RE.match(data):
            log.warning("Rejecting callback with malformed data: %r", data)
            self._answer_callback(cq["id"], "Invalid action.")
            return

        # Always acknowledge the click first so user sees the spinner stop
        self._answer_callback(cq["id"], "Working…")

        try:
            response_text = self._dispatch(data)
        except Exception as exc:  # noqa: BLE001
            log.exception("Action %s crashed: %s", data, exc)
            response_text = f"❌ Error running {data}:\n<code>{type(exc).__name__}: {exc}</code>"

        self._notify(response_text)

    def _handle_message(self, msg: dict) -> None:
        from_chat = str(msg.get("chat", {}).get("id") or "")
        if from_chat != self.allowed_chat_id:
            log.info("Ignoring message from unauthorized chat_id=%s", from_chat)
            return
        text = (msg.get("text") or "").strip().lower()
        if text in {"/start", "/help"}:
            self._notify(
                "👁️ <b>watchlog bot</b>\n\n"
                "I send security & health alerts here, with action buttons.\n\n"
                "Commands:\n"
                "  <code>/status</code> — show current snoozes/ignores\n"
                "  <code>/runnow</code> — run watchlog now and post the report\n"
                "  <code>/clearignores</code> — un-ignore all checks\n"
            )
        elif text == "/status":
            state = State.load()
            d = state.to_dict()
            snz = d.get("snoozes", {})
            ign = d.get("ignores", {})
            lines = [f"<b>Snoozed:</b> {len(snz)}", f"<b>Ignored:</b> {len(ign)}"]
            for name, info in snz.items():
                lines.append(f"  ⏰ {name} until <code>{info.get('until')}</code>")
            for name, info in ign.items():
                lines.append(f"  🚫 {name} since <code>{info.get('since')}</code>")
            self._notify("\n".join(lines))
        elif text == "/runnow":
            self._notify("Running watchlog…")
            output = self._run_command(["watchlog", "run"])
            self._notify(f"<pre>{_html_escape(output[-2000:])}</pre>")
        elif text == "/clearignores":
            state = State.load()
            cleared = list(state.to_dict().get("ignores", {}).keys())
            for name in cleared:
                state.unignore(name)
            self._notify(f"Cleared {len(cleared)} ignore(s).")

    # --------------- dispatch ---------------

    def _dispatch(self, data: str) -> str:
        if data == "apply_security":
            output = self._run_command(["unattended-upgrade", "-v"])
            return f"✅ <b>Security updates</b>\n<pre>{_html_escape(output[-2000:])}</pre>"

        if data == "run_now":
            output = self._run_command(["watchlog", "run"])
            return f"🔄 <b>watchlog run</b>\n<pre>{_html_escape(output[-2000:])}</pre>"

        if data.startswith("snooze:"):
            _, check_name, hours_str = data.split(":")
            hours = int(hours_str)
            until = datetime.now(timezone.utc) + timedelta(hours=hours)
            State.load().snooze(check_name, until)
            return f"⏰ Snoozed <b>{_html_escape(check_name)}</b> for {hours}h (until {until:%H:%M UTC})."

        if data.startswith("ignore:"):
            _, check_name = data.split(":", 1)
            State.load().ignore(check_name)
            return (
                f"🚫 Ignoring <b>{_html_escape(check_name)}</b> until "
                f"<code>/clearignores</code>."
            )

        return f"Unknown action: <code>{_html_escape(data)}</code>"

    @staticmethod
    def _run_command(argv: list[str]) -> str:
        """Execute a whitelisted command with capped output."""
        log.info("Running: %s", shlex.join(argv))
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
        except subprocess.SubprocessError as exc:
            return f"Subprocess error: {exc}"
        out = (proc.stdout or "") + (proc.stderr or "")
        return f"$ {shlex.join(argv)}\n(exit {proc.returncode})\n{out}"

    # --------------- helpers ---------------

    def _answer_callback(self, callback_id: str, text: str) -> None:
        try:
            self._api(
                "answerCallbackQuery",
                {"callback_query_id": callback_id, "text": text, "show_alert": False},
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("answerCallbackQuery failed: %s", exc)

    def _notify(self, text: str) -> None:
        try:
            self._api(
                "sendMessage",
                {
                    "chat_id": self.allowed_chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("sendMessage failed: %s", exc)


def _html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def main(config: Config) -> int:
    """Entry point used by the CLI."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    bot = TelegramBot(config)
    try:
        bot.run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    from watchlog.core.config import load_config

    sys.exit(main(load_config()))
