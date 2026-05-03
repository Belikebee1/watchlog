"""Command-line interface."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click

# Trigger registration of all checks and reporters
from watchlog import __version__
from watchlog.checks import *  # noqa: F401, F403
from watchlog.core.config import load_config
from watchlog.core.runner import CHECK_REGISTRY, REPORTER_REGISTRY, Runner
from watchlog.core.severity import Severity
from watchlog.reporters import *  # noqa: F401, F403


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


@click.group(help="watchlog — server health and security monitor.")
@click.version_option(version=__version__, prog_name="watchlog")
@click.option("--config", "-c", type=click.Path(path_type=Path), help="Path to config.yaml")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.pass_context
def main(ctx: click.Context, config: Path | None, verbose: bool) -> None:
    _configure_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config


@main.command(help="Run all enabled checks and emit reports.")
@click.option("--check", "checks", multiple=True, help="Run only these check(s) by name.")
@click.option(
    "--reporter",
    "reporters_only",
    multiple=True,
    help="Override reporters: only emit to these (default: all enabled).",
)
@click.option(
    "--exit-code",
    is_flag=True,
    help="Exit with non-zero status if any WARN/CRITICAL (useful in CI).",
)
@click.pass_context
def run(
    ctx: click.Context,
    checks: tuple[str, ...],
    reporters_only: tuple[str, ...],
    exit_code: bool,
) -> None:
    cfg = load_config(ctx.obj.get("config_path"))
    runner = Runner(cfg)

    only = list(checks) if checks else None
    results = runner.run_all(only=only)

    # Always print to stdout
    stdout_cls = REPORTER_REGISTRY.get("stdout")
    if stdout_cls:
        stdout_cls({}).emit(results)

    # Other reporters from config
    for name, cls in REPORTER_REGISTRY.items():
        if name == "stdout":
            continue
        if reporters_only and name not in reporters_only:
            continue
        rcfg = cfg.reporter_config(name)
        if not rcfg.get("enabled", False):
            continue
        try:
            cls(rcfg).emit(results)
        except Exception as exc:  # noqa: BLE001
            click.echo(f"Reporter {name} failed: {exc}", err=True)

    # Also write JSON archive (uses state config, not notifications)
    json_cls = REPORTER_REGISTRY.get("json")
    if json_cls:
        state = cfg.get("state", default={}) or {}
        json_cls(state).emit(results)

    worst = runner.worst_severity(results)
    if exit_code and worst >= Severity.WARN:
        sys.exit(2 if worst == Severity.CRITICAL else 1)


@main.command(help="List available checks and which are enabled.")
@click.pass_context
def list_checks(ctx: click.Context) -> None:
    try:
        cfg = load_config(ctx.obj.get("config_path"))
    except FileNotFoundError:
        cfg = None

    click.echo("Available checks:")
    for name in sorted(CHECK_REGISTRY):
        enabled = cfg.check_enabled(name) if cfg else False
        marker = "✅" if enabled else "  "
        click.echo(f"  {marker} {name}")


@main.command(help="Install systemd service + timer for daily runs at 08:00.")
@click.option(
    "--time",
    "schedule",
    default="08:00",
    show_default=True,
    help="Time of day (HH:MM) to run.",
)
def install(schedule: str) -> None:
    """Write systemd unit + timer to /etc/systemd/system and enable."""
    import shutil
    import textwrap

    if shutil.which("systemctl") is None:
        click.echo("systemctl not found — this command is for systemd hosts only.", err=True)
        sys.exit(1)

    bin_path = shutil.which("watchlog") or "/usr/local/bin/watchlog"

    service = textwrap.dedent(
        f"""\
        [Unit]
        Description=watchlog — server health and security monitor
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart={bin_path} run
        # Don't kill on timeout — checks may include slow apt update
        TimeoutStartSec=300
        """
    )

    timer = textwrap.dedent(
        f"""\
        [Unit]
        Description=watchlog daily run

        [Timer]
        OnCalendar=*-*-* {schedule}:00
        Persistent=true
        # Randomize +/- 15 min to avoid thundering herd if many servers
        RandomizedDelaySec=900

        [Install]
        WantedBy=timers.target
        """
    )

    Path("/etc/systemd/system/watchlog.service").write_text(service)
    Path("/etc/systemd/system/watchlog.timer").write_text(timer)

    import subprocess

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "watchlog.timer"], check=True)

    click.echo(f"✅ Installed. Will run daily at {schedule}.")
    click.echo("   Status: systemctl status watchlog.timer")
    click.echo("   Run now: systemctl start watchlog.service")


@main.group(help="Email reporter management.")
def email() -> None:
    pass


@email.command(name="setup", help="Interactive walkthrough: choose local / external SMTP / disabled.")
@click.pass_context
def email_setup(ctx: click.Context) -> None:
    """Walk the user through configuring the email reporter."""
    cfg = load_config(ctx.obj.get("config_path"))
    if not cfg.path:
        click.echo("Cannot determine config path.", err=True)
        sys.exit(1)

    click.echo("=" * 60)
    click.echo("watchlog email setup")
    click.echo("=" * 60)
    click.echo()
    click.echo("Pick how watchlog should send email alerts:")
    click.echo()
    click.echo("  [1] Disable email entirely (use Telegram only)")
    click.echo("  [2] Local mail server (Postfix/Exim already on this box)")
    click.echo("  [3] External SMTP relay (Gmail, Mailgun, SES, ...)")
    click.echo()
    choice = click.prompt("Choice", type=click.Choice(["1", "2", "3"]), default="1")
    click.echo()

    if choice == "1":
        click.echo("Disabling email reporter.")
        click.echo()
        click.echo("Edit /etc/watchlog/config.yaml and set:")
        click.echo("    notifications.email.enabled: false")
        click.echo()
        click.echo("Then for alerts, set up Telegram instead:")
        click.echo("    sudo watchlog telegram setup")
        return

    to_addr = click.prompt("Notify email address (where alerts arrive)", type=str).strip()
    from_addr = click.prompt(
        "Sender address (From: header)", type=str, default=f"watchlog@{to_addr.split('@', 1)[1]}"
    ).strip()

    if choice == "2":
        click.echo()
        click.echo("Using local mail server on 127.0.0.1:25.")
        click.echo("Make sure Postfix/Exim is running and accepts mail from localhost.")
        smtp_host = "127.0.0.1"
        smtp_port = 25
        smtp_user = ""
        smtp_password = ""
        smtp_starttls = False

    else:  # choice 3
        click.echo()
        click.echo("Common external SMTP relays:")
        click.echo("  Gmail:    smtp.gmail.com:587 (use Google App Password, not your real password)")
        click.echo("  Mailgun:  smtp.mailgun.org:587")
        click.echo("  SendGrid: smtp.sendgrid.net:587")
        click.echo("  AWS SES:  email-smtp.<region>.amazonaws.com:587")
        click.echo()
        smtp_host = click.prompt("SMTP host", type=str, default="smtp.gmail.com").strip()
        smtp_port = int(click.prompt("SMTP port", type=int, default=587))
        smtp_user = click.prompt("SMTP username", type=str).strip()
        smtp_password = click.prompt("SMTP password / app password", hide_input=True, type=str)
        smtp_starttls = click.confirm("Use STARTTLS?", default=True)

    click.echo()
    click.echo("Sending a test email...")
    import smtplib  # noqa: PLC0415
    from email.message import EmailMessage  # noqa: PLC0415
    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = "watchlog test email"
    msg.set_content(
        "This is a test email from `watchlog email setup`.\n"
        "If you received this, your SMTP config is working.\n"
    )
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as smtp:
            if smtp_starttls:
                smtp.starttls()
            if smtp_user and smtp_password:
                smtp.login(smtp_user, smtp_password)
            smtp.send_message(msg)
        click.secho(f"✅ Test email sent to {to_addr}.", fg="green")
    except Exception as exc:  # noqa: BLE001
        click.secho(f"❌ SMTP test failed: {exc}", fg="red")
        if not click.confirm("Continue and write the config anyway?", default=False):
            click.echo("Aborted.")
            sys.exit(1)

    click.echo()
    click.echo("Add this to /etc/watchlog/config.yaml under `notifications:`")
    click.echo()
    click.secho(f"  email:", fg="cyan")
    click.secho(f"    enabled: true", fg="cyan")
    click.secho(f"    to: \"{to_addr}\"", fg="cyan")
    click.secho(f"    from: \"{from_addr}\"", fg="cyan")
    click.secho(f"    smtp_host: \"{smtp_host}\"", fg="cyan")
    click.secho(f"    smtp_port: {smtp_port}", fg="cyan")
    if smtp_user:
        click.secho(f"    smtp_user: \"{smtp_user}\"", fg="cyan")
        click.secho(f"    smtp_password: \"<see your password manager>\"", fg="cyan")
    click.secho(f"    smtp_starttls: {str(smtp_starttls).lower()}", fg="cyan")
    click.secho(f"    only_when: warn", fg="cyan")
    click.echo()
    click.echo("(I'm not auto-writing the config to avoid clobbering your other settings.)")


@main.group(help="FCM push notification management (mobile app).")
def push() -> None:
    pass


@push.command(name="list", help="List devices registered for push notifications.")
def push_list() -> None:
    from watchlog.fcm import TokenRegistry  # noqa: PLC0415

    entries = TokenRegistry().all_entries()
    if not entries:
        click.echo("No devices registered.")
        return
    click.echo(f"{len(entries)} device(s) registered:")
    for e in entries:
        token_short = e["token"][:16] + "..."
        platform = e.get("platform", "?")
        label = e.get("device_label") or "(no label)"
        registered = e.get("registered_at", "?")
        click.echo(f"  [{platform}] {token_short}  {label}  ({registered})")


@push.command(name="test", help="Send a test push notification to all registered devices.")
@click.option("--title", default="watchlog test", help="Notification title")
@click.option(
    "--body",
    default="If you see this, push notifications are working!",
    help="Notification body",
)
@click.pass_context
def push_test(ctx: click.Context, title: str, body: str) -> None:
    from watchlog.fcm import FcmSender, TokenRegistry  # noqa: PLC0415

    cfg = load_config(ctx.obj.get("config_path"))
    fcm_cfg = cfg.reporter_config("fcm_push")
    sa_path = fcm_cfg.get("service_account_path")
    if not sa_path:
        click.echo(
            "notifications.fcm_push.service_account_path not set in config.",
            err=True,
        )
        ctx.exit(1)

    registry = TokenRegistry()
    tokens = registry.all_tokens()
    if not tokens:
        click.echo("No devices registered. Open the mobile app and sign in first.")
        return

    click.echo(f"Sending to {len(tokens)} device(s)...")
    sender = FcmSender(sa_path)
    successes, invalid = sender.send_to_tokens(tokens, title=title, body=body)
    click.secho(f"✅ Sent: {successes}/{len(tokens)}", fg="green")
    if invalid:
        click.secho(
            f"⚠️ {len(invalid)} invalid token(s) — removing from registry",
            fg="yellow",
        )
        registry.remove_invalid(invalid)


@main.group(help="Telegram bot management.")
def telegram() -> None:
    pass


@telegram.command(name="setup", help="Interactive walkthrough to configure Telegram bot.")
@click.pass_context
def telegram_setup(ctx: click.Context) -> None:
    """Walk the user through getting a bot token and chat_id."""
    click.echo("=" * 60)
    click.echo("watchlog Telegram bot setup")
    click.echo("=" * 60)
    click.echo()
    click.echo("Step 1: Create a bot")
    click.echo("  Open Telegram → search '@BotFather' → send /newbot")
    click.echo("  Pick a name (e.g. 'My server watchlog') and a username")
    click.echo("  ending in 'bot' (e.g. 'myserver_watchlog_bot').")
    click.echo("  BotFather will reply with a token like:")
    click.echo("    123456789:ABCdef-GhIJkl...")
    click.echo()
    token = click.prompt("Paste the bot token", type=str).strip()

    click.echo()
    click.echo("Step 2: Find your chat_id")
    click.echo("  Open Telegram → search '@userinfobot' → send /start")
    click.echo("  It will reply with your numeric ID.")
    click.echo()
    chat_id = click.prompt("Paste your chat_id (number)", type=str).strip()

    click.echo()
    click.echo("Step 3: Test it")
    click.echo("  I'll send a test message to confirm the bot can reach you.")
    if click.confirm("Continue?", default=True):
        from urllib import error as urlerror  # noqa: PLC0415
        from urllib import request as urlreq  # noqa: PLC0415

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        body = json.dumps({
            "chat_id": chat_id,
            "text": "👁️ watchlog test — if you see this, your bot is working!",
        }).encode("utf-8")
        req = urlreq.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urlreq.urlopen(req, timeout=15) as resp:
                resp.read()
            click.secho("✅ Test message sent. Check Telegram.", fg="green")
        except urlerror.HTTPError as exc:
            click.secho(f"❌ HTTP {exc.code}: {exc.read().decode()[:300]}", fg="red")
            ctx.exit(1)
        except urlerror.URLError as exc:
            click.secho(f"❌ Network error: {exc}", fg="red")
            ctx.exit(1)

    click.echo()
    click.echo("Step 4: Save to config")
    click.echo(f"  Add to your /etc/watchlog/config.yaml under notifications.telegram:")
    click.echo(f"")
    click.echo(f"  notifications:")
    click.echo(f"    telegram:")
    click.echo(f"      enabled: true")
    click.echo(f"      bot_token: \"{token}\"")
    click.echo(f"      chat_id: \"{chat_id}\"")
    click.echo(f"      only_when: warn")
    click.echo()
    click.echo("Step 5: Start the bot daemon")
    click.echo("  sudo watchlog telegram install-service")
    click.echo("  sudo systemctl start watchlog-bot")
    click.echo()
    click.secho("Done.", fg="green")


@telegram.command(name="bot", help="Run the Telegram bot daemon (long-polling).")
@click.pass_context
def telegram_bot(ctx: click.Context) -> None:
    cfg = load_config(ctx.obj.get("config_path"))
    from watchlog.bot import main as bot_main  # noqa: PLC0415

    sys.exit(bot_main(cfg))


@telegram.command(
    name="install-service",
    help="Install systemd service for the bot daemon (auto-start, restart on crash).",
)
def telegram_install_service() -> None:
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415
    import textwrap  # noqa: PLC0415

    if shutil.which("systemctl") is None:
        click.echo("systemctl not found.", err=True)
        sys.exit(1)

    bin_path = shutil.which("watchlog") or "/usr/local/bin/watchlog"

    service = textwrap.dedent(
        f"""\
        [Unit]
        Description=watchlog Telegram bot daemon
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStart={bin_path} telegram bot
        Restart=on-failure
        RestartSec=10s
        # Run as root so the bot can `unattended-upgrade` and `watchlog run`.
        # If you want to drop privileges, set User= and ensure that user can sudo
        # the specific commands without password (more complex setup).
        User=root

        [Install]
        WantedBy=multi-user.target
        """
    )

    Path("/etc/systemd/system/watchlog-bot.service").write_text(service)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "watchlog-bot.service"], check=True)
    click.echo("✅ Installed watchlog-bot.service.")
    click.echo("   Start: sudo systemctl start watchlog-bot")
    click.echo("   Status: systemctl status watchlog-bot")
    click.echo("   Logs: journalctl -u watchlog-bot -f")


@main.group(help="REST API + dashboard daemon (v0.3+).")
def api() -> None:
    pass


@api.command(name="setup", help="Generate API token and write to /etc/watchlog/config.yaml.")
@click.pass_context
def api_setup(ctx: click.Context) -> None:
    import secrets  # noqa: PLC0415
    cfg = load_config(ctx.obj.get("config_path"))
    if not cfg.path:
        click.echo("Cannot determine config path.", err=True)
        sys.exit(1)
    existing = (cfg.get("api", default={}) or {}).get("token")
    if existing:
        if not click.confirm(f"API token already set. Regenerate? Current: {existing[:8]}…", default=False):
            click.echo("Keeping existing token.")
            click.echo(f"Token: {existing}")
            return
    new_token = secrets.token_urlsafe(32)
    # Append api: section if not present, or update if present.
    text = cfg.path.read_text()
    if "\napi:" in text or text.startswith("api:"):
        # Replace existing token line under api:
        import re  # noqa: PLC0415
        text = re.sub(
            r"(\napi:\s*\n(?:[^\n]*\n)*?\s*token:\s*)\"[^\"]*\"",
            r"\1\"" + new_token + "\"",
            text,
            count=1,
        )
        if "token:" not in text.split("\napi:")[1].split("\n\n")[0]:
            # token field missing under api:
            text = text.replace("\napi:", f"\napi:\n  token: \"{new_token}\"", 1)
    else:
        text += f"\n# REST API + dashboard\napi:\n  token: \"{new_token}\"\n  bind_host: \"127.0.0.1\"\n  bind_port: 8765\n"
    cfg.path.write_text(text)
    click.secho(f"✅ Token saved to {cfg.path}", fg="green")
    click.echo()
    click.echo("Token (give this to the dashboard login or curl -H 'Authorization: Bearer ...'):")
    click.secho(f"  {new_token}", fg="yellow")
    click.echo()
    click.echo("Next steps:")
    click.echo("  sudo watchlog api install-service")
    click.echo("  sudo systemctl start watchlog-api")


@api.command(name="serve", help="Run the API server in foreground (blocks).")
@click.option("--host", default=None, help="Bind host (default: from config or 127.0.0.1)")
@click.option("--port", default=None, type=int, help="Bind port (default: from config or 8765)")
@click.pass_context
def api_serve(ctx: click.Context, host: str | None, port: int | None) -> None:
    cfg = load_config(ctx.obj.get("config_path"))
    api_cfg = cfg.get("api", default={}) or {}
    h = host or api_cfg.get("bind_host", "127.0.0.1")
    p = int(port or api_cfg.get("bind_port", 8765))
    from watchlog.api import serve as api_serve_main  # noqa: PLC0415
    api_serve_main(cfg, host=h, port=p)


@api.command(
    name="install-service",
    help="Install systemd service for the API daemon.",
)
def api_install_service() -> None:
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415
    import textwrap  # noqa: PLC0415

    if shutil.which("systemctl") is None:
        click.echo("systemctl not found.", err=True)
        sys.exit(1)
    bin_path = shutil.which("watchlog") or "/usr/local/bin/watchlog"
    service = textwrap.dedent(
        f"""\
        [Unit]
        Description=watchlog REST API + dashboard daemon
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        ExecStart={bin_path} api serve
        Restart=on-failure
        RestartSec=10s
        # Run as root so the API can `unattended-upgrade` and `watchlog run`.
        User=root

        [Install]
        WantedBy=multi-user.target
        """
    )
    Path("/etc/systemd/system/watchlog-api.service").write_text(service)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "watchlog-api.service"], check=True)
    click.echo("✅ Installed watchlog-api.service.")
    click.echo("   Start: sudo systemctl start watchlog-api")
    click.echo("   Logs: journalctl -u watchlog-api -f")


if __name__ == "__main__":
    main()
