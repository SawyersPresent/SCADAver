"""Rich-based TUI for Rockwell Logix PLC monitoring and editing."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table

from scadaver.vendors.rockwell.driver import RockwellError, RockwellPLC

console = Console(stderr=False)


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
    cached = plc._tags_file.exists()
    status_msg = (
        f"[cyan]Loading {plc_ip} tag cache…"
        if cached
        else f"[yellow]Discovering tags on {plc_ip} (first run — may take 30-60 s)…"
    )
    with console.status(status_msg):
        try:
            plc.load_tags()
        except RockwellError as exc:
            console.print(f"[red][!] {exc}[/red]")
            return

    console.print(
        f"[green]✓ {len(plc.tags)} tags loaded{'from cache' if cached else ''}. "
        f"Starting monitor (Ctrl-C to stop).[/green]\n"
    )

    try:
        with Live(
            console=console,
            refresh_per_second=2,
            vertical_overflow="visible",
            auto_refresh=False,
        ) as live:
            for current, changes in plc.monitor(interval=interval):
                live.update(_tag_table(current, changes))
                live.refresh()
    except RockwellError as exc:
        console.print(f"\n[red][!] Connection lost: {exc}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/yellow]")


def run_editor(plc_ip: str) -> None:
    """Interactive tag value editor.

    Holds a single persistent LogixDriver connection open for the whole session
    to avoid per-refresh TCP + CIP handshake overhead.
    The user selects a tag by number, types a new value, then presses ``w``
    to write all staged changes at once.

    Args:
        plc_ip: PLC IP address.
    """
    from pycomm3 import LogixDriver
    from pycomm3.exceptions import CommError, ResponseError

    plc = RockwellPLC(plc_ip)
    cached = plc._tags_file.exists()
    status_msg = (
        f"[cyan]Loading {plc_ip} tag cache…"
        if cached
        else f"[yellow]Discovering tags on {plc_ip} (first run — may take 30-60 s)…"
    )
    with console.status(status_msg):
        try:
            plc.load_tags()
        except RockwellError as exc:
            console.print(f"[red][!] {exc}[/red]")
            return

    console.print(f"[green]✓ {len(plc.tags)} tags loaded. Opening persistent session…[/green]")
    pending: dict[str, Any] = {}

    try:
        with LogixDriver(plc_ip) as driver:
            console.print(f"[green]✓ Connected. Fetching initial values…[/green]")
            while True:
                with console.status("[cyan]Reading tags…"):
                    try:
                        current = plc.read_all_open(driver)
                    except Exception as exc:
                        raise RockwellError(str(exc)) from exc

                merged = {**current, **pending}
                console.print(_tag_table(merged))

                if pending:
                    console.print(
                        f"[yellow]Pending writes ({len(pending)}):[/yellow] {list(pending.keys())}"
                    )

                action = Prompt.ask(
                    "[bold]Tag # to edit | [w] write | [r] refresh | [q] quit[/bold]"
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
                    with console.status("[cyan]Writing tags…"):
                        try:
                            write_results: dict[str, bool] = {}
                            for tag, value in pending.items():
                                res = driver.write(tag, value)
                                if isinstance(res, list):
                                    res = res[0]
                                write_results[tag] = res.error is None
                        except (ResponseError, CommError) as exc:
                            console.print(f"[red][!] Write failed: {exc}[/red]")
                            continue
                    for tag, ok in write_results.items():
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
                    raw = Prompt.ask(
                        f"New value for [cyan]{tag}[/cyan] (current: {current[tag]})"
                    )
                    pending[tag] = _parse_value(raw)
    except (ResponseError, CommError, RockwellError) as exc:
        console.print(f"[red][!] Session error: {exc}[/red]")


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
