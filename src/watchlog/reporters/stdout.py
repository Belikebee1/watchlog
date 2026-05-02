"""Stdout reporter — colored output via Rich, with table summary."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from watchlog.core.check import CheckResult
from watchlog.core.runner import register_reporter
from watchlog.core.severity import Severity
from watchlog.reporters.base import Reporter


@register_reporter("stdout")
class StdoutReporter(Reporter):
    name = "stdout"

    def emit(self, results: list[CheckResult]) -> None:
        console = Console()

        table = Table(
            title=f"watchlog — {len(results)} checks", show_header=True, header_style="bold"
        )
        table.add_column("", justify="center", width=3)
        table.add_column("Check", style="cyan", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Title")

        for r in results:
            color = r.severity.color()
            table.add_row(
                r.severity.emoji(),
                r.check_name,
                f"[{color}]{r.severity.name}[/{color}]",
                r.title,
            )

        console.print(table)

        # Show details for any non-OK
        actionable = [r for r in results if r.severity > Severity.OK]
        for r in actionable:
            color = r.severity.color()
            body_lines = []
            if r.summary:
                body_lines.append(r.summary)
            if r.details:
                body_lines.append("")
                body_lines.extend(r.details)
            if r.actions:
                body_lines.append("")
                body_lines.append("[bold]Suggested actions:[/bold]")
                body_lines.extend(f"  $ {cmd}" for cmd in r.actions)
            console.print(
                Panel(
                    "\n".join(body_lines) or "(no details)",
                    title=f"{r.severity.emoji()} [{color}]{r.check_name}[/{color}] — {r.title}",
                    border_style=color,
                )
            )
