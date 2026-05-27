# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
``dns-aid doctor`` — non-interactive environment diagnostics.

Thin Rich renderer over :func:`dns_aid.doctor.run_checks`.
"""

from __future__ import annotations

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from dns_aid.doctor import DiagnosticReport, run_checks

console = Console()

# ── formatting helpers ─────────────────────────────────────────────

_ICON = {
    "pass": "[green]✓[/green]",  # nosec B105 — Rich markup, not a credential
    "fail": "[red]✗[/red]",
    "warn": "[yellow]○[/yellow]",
}


def _render_report(report: DiagnosticReport) -> None:
    """Render a DiagnosticReport to the console with Rich."""
    console.print(
        Panel(
            f"[bold]dns-aid doctor[/bold]  v{report.version}",
            subtitle="[dim]IETF draft-mozleywilliams-dnsop-dnsaid-02[/dim]",
            width=56,
        )
    )

    for section, checks in report.sections.items():
        console.print(f"\n[bold]{section}[/bold]")
        for check in checks:
            icon = _ICON[check.status]
            suffix = f"  [dim]{escape(check.detail)}[/dim]" if check.detail else ""
            console.print(f"  {icon} {check.label}{suffix}")

    # Summary footer
    total = report.pass_count + report.fail_count
    console.print()

    summary = Table.grid(padding=(0, 1))
    summary.add_column(style="bold")
    summary.add_column()

    if report.fail_count:
        summary.add_row(
            "Result:",
            f"[green]{report.pass_count}[/green]/{total} passed, "
            f"[red]{report.fail_count} failed[/red]",
        )
    else:
        summary.add_row(
            "Result:",
            f"[green]{report.pass_count}/{total} passed — all good![/green]",
        )

    legend = "[green]✓[/green] pass  [red]✗[/red] fail  [yellow]○[/yellow] optional/unconfigured"
    summary.add_row("Legend:", f"[dim]{legend}[/dim]")

    console.print(Panel(summary, width=56))
    console.print()


# ── main command ───────────────────────────────────────────────────


def doctor(
    domain: str | None = None,
) -> None:
    """
    Diagnose your DNS-AID environment.

    Checks Python, dependencies, DNS resolution, backend credentials,
    optional features, and .env configuration.

    The --domain flag sets the domain used for the agent discovery check.
    Falls back to DNS_AID_DOCTOR_DOMAIN env var. Skipped if neither is set.

    Example:
        dns-aid doctor
        dns-aid doctor --domain example.com
    """
    report = run_checks(domain=domain)
    _render_report(report)
