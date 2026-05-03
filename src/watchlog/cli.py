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


if __name__ == "__main__":
    main()
