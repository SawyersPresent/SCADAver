"""Rich-based TUI for Rockwell Logix PLC monitoring and editing."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table

from scadaver.vendors.rockwell.driver import RockwellError, RockwellPLC

console = Console()


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _parse_value(raw: str) -> Any:
    """Try to parse a string as JSON, fall back to plain string.

    Args:
        raw: User-entered value string.

    Returns:
        Parsed Python value.
    """
    import json
    try:
        return json.loads(raw)
    except Exception:
        return raw


def _tag_table(values: dict[str, Any], changes: list[dict] | None = None) -> Table:
    """Build a Rich Table from tag values, highlighting changes.

    Args:
        values: Current tag values dict.
        changes: Optional list of change dicts to highlight yellow.

    Returns:
        Configured Rich Table.
    """
    changed_tags = {c["tag"] for c in changes} if changes else set()
    table = Table(header_style="bold cyan", expand=True, highlight=True)
    table.add_column("#", style="dim", width=6)
    table.add_column("Tag", style="white", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_column("Status", width=10)

    for idx, (tag, value) in enumerate(values.items(), start=1):
        row_str = str(value)
        if row_str.startswith("ERROR"):
            tag_style = "red"
            status = "[red]ERROR[/red]"
        elif tag in changed_tags:
            tag_style = "yellow"
            status = "[yellow]CHANGED[/yellow]"
        else:
            tag_style = "green"
            status = "[green]OK[/green]"
        table.add_row(str(idx), f"[{tag_style}]{tag}[/{tag_style}]", row_str, status)

    return table


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_monitor(plc_ip: str, interval: float = 1.0) -> None:
    """Live-updating monitor view for all PLC tags.

    Polls the PLC at *interval* seconds and refreshes a Rich table in-place.
    Changed tags are highlighted yellow. Press Ctrl-C to exit.

    Args:
        plc_ip: PLC IP address.
        interval: Poll interval in seconds.
    """
    plc = RockwellPLC(plc_ip)
    console.print(f"[cyan]Connecting to {plc_ip}…[/cyan]")
    try:
        plc.load_tags()
    except RockwellError as exc:
        console.print(f"[red][!] {exc}[/red]")
        return
    console.print(f"[green]Loaded {len(plc.tags)} tags. Starting monitor (Ctrl-C to stop).[/green]\n")

    layout = Layout()
    try:
        with Live(layout, refresh_per_second=4, screen=True) as live:
            for current, changes in plc.monitor(interval=interval):
                layout.update(_tag_table(current, changes))
                live.refresh()
    except RockwellError as exc:
        console.print(f"\n[red][!] Connection lost: {exc}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/yellow]")


def run_editor(plc_ip: str) -> None:
    """Interactive tag value editor.

    Displays a numbered table of current tag values. The user enters
    a tag number to select it, types a new value, then ``w`` to write
    all pending changes to the PLC at once.

    Args:
        plc_ip: PLC IP address.
    """
    plc = RockwellPLC(plc_ip)
    console.print(f"[cyan]Connecting to {plc_ip}\u2026[/cyan]")
    try:
        plc.load_tags()
    except RockwellError as exc:
        console.print(f"[red][!] {exc}[/red]")
        return
    pending: dict[str, Any] = {}

    while True:
        try:
            current = plc.read_all()
        except RockwellError as exc:
            console.print(f"[red][!] Read failed: {exc}[/red]")
            return
        # Show current values merged with pending edits
        merged = {**current, **pending}
        console.print(_tag_table(merged))

        if pending:
            console.print(f"[yellow]Pending writes ({len(pending)}):[/yellow] {list(pending.keys())}")

        action = Prompt.ask(
            "[bold]Enter tag # to edit, [w] to write pending, [r] to refresh, [q] to quit[/bold]"
        )

        if action.lower() == "q":
            break
        elif action.lower() == "r":
            pending.clear()
            continue
        elif action.lower() == "w":
            if not pending:
                console.print("[yellow]Nothing pending.[/yellow]")
                continue
            try:
                results = plc.write_many(pending)
            except RockwellError as exc:
                console.print(f"[red][!] Write failed: {exc}[/red]")
                continue
            for tag, ok in results.items():
                status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
                console.print(f"  {tag}: {status}")
            pending.clear()
        else:
            try:
                idx = int(action) - 1
                tag = list(current.keys())[idx]
            except (ValueError, IndexError):
                console.print("[red]Invalid selection.[/red]")
                continue
            raw = Prompt.ask(f"New value for [cyan]{tag}[/cyan] (current: {current[tag]})")
            pending[tag] = _parse_value(raw)


def run_history(plc_ip: str, limit: int = 30) -> None:
    """Display the last *limit* tag change events.

    Args:
        plc_ip: PLC IP address.
        limit: Maximum number of history entries to show.
    """
    plc = RockwellPLC(plc_ip)
    history = plc.load_history()

    if not history:
        console.print("[yellow]No change history recorded yet.[/yellow]")
        return

    recent = history[-limit:]
    table = Table(title=f"Last {len(recent)} changes for {plc_ip}", header_style="bold cyan")
    table.add_column("Timestamp", style="dim")
    table.add_column("Tag", style="white")
    table.add_column("Old Value", style="red")
    table.add_column("New Value", style="green")

    for entry in reversed(recent):
        table.add_row(
            entry.get("timestamp", ""),
            entry.get("tag", ""),
            str(entry.get("old_value", "")),
            str(entry.get("new_value", "")),
        )
    console.print(table)
