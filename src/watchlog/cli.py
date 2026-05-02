"""Command-line interface."""

from __future__ import annotations

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


if __name__ == "__main__":
    main()
