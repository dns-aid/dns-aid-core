# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
``dns-aid init`` — interactive setup wizard.

Guides users through backend selection, shows required env vars,
generates a ``.env`` snippet, and offers a quick verification.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
error_console = Console(stderr=True)


def _discover_quickstart() -> None:
    """Show quickstart examples for discover-only usage."""
    console.print("\n[bold green]Discover-only mode — no backend needed![/bold green]\n")
    console.print("You can discover agents without any credentials:\n")
    console.print("  [bold]dns-aid discover example.com[/bold]")
    console.print("  [bold]dns-aid discover example.com --json[/bold]")
    console.print("  [bold]dns-aid verify network.example.com[/bold]")
    console.print(
        "\nTo [bold]publish[/bold] agents, re-run [bold]dns-aid init[/bold] and choose a backend.\n"
    )


def _show_backend_setup(name: str) -> None:
    """Show detailed setup for the chosen backend."""
    from dns_aid.cli.backends import BACKEND_REGISTRY

    info = BACKEND_REGISTRY[name]
    console.print(f"\n[bold]{info.display_name} setup[/bold]\n")

    # Required env vars
    if info.required_env:
        console.print("[bold]Required environment variables:[/bold]")
        for var, desc in info.required_env.items():
            console.print(f"  {var}  — {desc}")

    # Optional env vars
    if info.optional_env:
        console.print("\n[bold]Optional:[/bold]")
        for var, desc in info.optional_env.items():
            console.print(f"  {var}  — {desc}")

    # Setup steps
    if info.setup_steps:
        console.print("\n[bold]Steps:[/bold]")
        for i, step in enumerate(info.setup_steps, 1):
            console.print(f"  {i}. {step}")

    if info.setup_url:
        console.print(f"\n  Docs: {info.setup_url}")

    # Generate .env snippet
    console.print("\n[bold].env snippet:[/bold]")
    snippet_lines = [f"DNS_AID_BACKEND={name}"]
    for var in info.required_env:
        snippet_lines.append(f"{var}=")
    for var in info.optional_env:
        snippet_lines.append(f"# {var}=")
    snippet = "\n".join(snippet_lines)

    console.print(Panel(snippet, title=".env", border_style="dim"))

    # Offer to write .env
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        if typer.confirm("Create .env file with this template?", default=True):
            env_path.write_text(snippet + "\n")
            console.print(f"[green]✓ Created {env_path}[/green]")
            console.print("[yellow]Fill in the values, then run:[/yellow]")
        else:
            console.print("\nCopy the snippet above to your .env file, then run:")
    else:
        console.print(f"\n[yellow].env already exists at {env_path}[/yellow]")
        console.print("Add the variables above, then run:")

    console.print("  [bold]dns-aid doctor[/bold]  — verify configuration")


def init():
    """
    Interactive setup wizard for DNS-AID.

    Guides you through choosing a DNS backend, configuring
    credentials, and verifying your setup.

    Example:
        dns-aid init
    """
    from dns_aid import __version__
    from dns_aid.cli.backends import BACKEND_REGISTRY, REAL_BACKEND_NAMES

    console.print(f"\n[bold]dns-aid init[/bold]  v{__version__}\n")

    # Check .env
    env_path = Path.cwd() / ".env"
    if env_path.exists():
        console.print(f"[dim]Found .env at {env_path}[/dim]")

    # Backend menu
    console.print("[bold]What would you like to do?[/bold]\n")
    choices = [("discover", "Discover agents only (no backend needed)")]
    for name in REAL_BACKEND_NAMES:
        info = BACKEND_REGISTRY[name]
        choices.append((name, f"Publish via {info.display_name}"))

    table = Table(show_header=False, box=None, padding=(0, 2))
    for i, (_key, label) in enumerate(choices):
        table.add_row(f"  [bold]{i}[/bold]", label)
    console.print(table)

    # Get choice
    raw = typer.prompt("\nChoose", default="0")
    try:
        idx = int(raw)
        if idx < 0 or idx >= len(choices):
            raise ValueError
    except ValueError:
        # Try matching by name
        idx = next(
            (i for i, (k, _) in enumerate(choices) if k == raw.lower()),
            None,
        )
        if idx is None:
            error_console.print(f"[red]Invalid choice: {raw}[/red]")
            raise typer.Exit(1) from None

    chosen_key = choices[idx][0]

    if chosen_key == "discover":
        _discover_quickstart()
    else:
        _show_backend_setup(chosen_key)

    # Offer to run doctor
    console.print()
    if typer.confirm("Run dns-aid doctor to verify?", default=True):
        from dns_aid.cli.doctor import doctor as run_doctor

        run_doctor()
