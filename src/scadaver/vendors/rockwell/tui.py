"""Rich-based TUI for Rockwell Logix PLC monitoring and editing."""

from __future__ import annotations

import os
import shutil
import threading
import time
from typing import Any

from rich.console import Console, Group as RichGroup
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

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


def _tag_table(
    values: dict[str, Any],
    changes: list[dict] | None = None,
    scroll: int = 0,
    visible: int | None = None,
) -> RichGroup:
    """Build a Rich table from tag values, with optional viewport slicing.

    When *visible* is supplied only *visible* rows starting at *scroll* are
    rendered and a navigation footer is appended.  When *visible* is ``None``
    the full table is returned (used by editor and history).

    Args:
        values: Current tag values dict.
        changes: Optional list of change dicts to highlight yellow.
        scroll: First row to display (0-based absolute index).
        visible: Number of rows to show; ``None`` means show all.

    Returns:
        RichGroup containing the table and (optionally) a footer line.
    """
    changed_tags = {c["tag"] for c in changes} if changes else set()
    total = len(values)

    if visible is not None:
        scroll = max(0, min(scroll, max(0, total - visible)))
        items = list(values.items())[scroll : scroll + visible]
        start_idx = scroll
    else:
        items = list(values.items())
        start_idx = 0

    table = Table(header_style="bold cyan", expand=True, highlight=True)
    table.add_column("#", style="dim", width=6)
    table.add_column("Tag", style="white", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_column("Status", width=10)

    for abs_idx, (tag, value) in enumerate(items, start=start_idx + 1):
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
        table.add_row(str(abs_idx), f"[{tag_style}]{tag}[/{tag_style}]", row_str, status)

    renderables: list[Any] = [table]
    if visible is not None:
        end = min(scroll + visible, total)
        renderables.append(
            Text(
                f"  rows {scroll + 1}\u2013{end} of {total}  "
                "\u2502  \u2191\u2193 one row  "
                "\u2502  PgUp/PgDn page  "
                "\u2502  [q] quit",
                style="dim",
            )
        )
    return RichGroup(*renderables)


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_monitor(plc_ip: str, interval: float = 1.0) -> None:
    """Full-screen live monitor for all PLC tags with keyboard scrolling.

    Takes over the terminal (alternate screen buffer) so the display updates
    in-place without flooding the scroll buffer.  Changed tags are highlighted
    yellow.  Use arrow keys / PgUp / PgDn to scroll; press ``q`` or Ctrl-C to
    exit.

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

    # ── shared state ──────────────────────────────────────────────
    _scroll = 0
    _lock = threading.Lock()
    _current: dict[str, Any] = {}
    _changes: list[dict] = []
    _stop = threading.Event()
    _error: list[str] = []  # at most one element; list avoids nonlocal assignment

    # ── keyboard input thread ─────────────────────────────────────
    def _input_loop() -> None:
        nonlocal _scroll
        page_size = max(5, shutil.get_terminal_size().lines - 6)

        if os.name == "nt":
            import msvcrt  # type: ignore[import-untyped]
            while not _stop.is_set():
                if msvcrt.kbhit():
                    ch = msvcrt.getch()
                    if ch == b"\xe0":
                        ch2 = msvcrt.getch()
                        if   ch2 == b"H": _scroll = max(0, _scroll - 1)           # ↑
                        elif ch2 == b"P": _scroll += 1                             # ↓
                        elif ch2 == b"I": _scroll = max(0, _scroll - page_size)   # PgUp
                        elif ch2 == b"Q": _scroll += page_size                    # PgDn
                    elif ch in (b"q", b"Q"):
                        _stop.set()
                time.sleep(0.05)
        else:
            import select  # noqa: PLC0415
            import sys
            import termios  # type: ignore[import-untyped]
            import tty      # type: ignore[import-untyped]
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while not _stop.is_set():
                    r, _, _ = select.select([sys.stdin], [], [], 0.05)
                    if not r:
                        continue
                    ch = sys.stdin.buffer.read(1)
                    if ch == b"\x1b":
                        r2, _, _ = select.select([sys.stdin], [], [], 0.05)
                        if r2:
                            ch += sys.stdin.buffer.read(1)
                            r3, _, _ = select.select([sys.stdin], [], [], 0.05)
                            if r3:
                                ch += sys.stdin.buffer.read(1)
                    if   ch == b"\x1b[A":  _scroll = max(0, _scroll - 1)          # ↑
                    elif ch == b"\x1b[B":  _scroll += 1                            # ↓
                    elif ch == b"\x1b[5~": _scroll = max(0, _scroll - page_size)  # PgUp
                    elif ch == b"\x1b[6~": _scroll += page_size                   # PgDn
                    elif ch in (b"q", b"Q", b"\x03", b"\x04"):
                        _stop.set()
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    # ── data poll thread ──────────────────────────────────────────
    def _poll_loop() -> None:
        nonlocal _current, _changes
        try:
            for vals, chgs in plc.monitor(interval=interval):
                if _stop.is_set():
                    break
                with _lock:
                    _current = vals
                    _changes = chgs
        except RockwellError as exc:
            _error.append(str(exc))
            _stop.set()

    # ── renderable builder ────────────────────────────────────────
    def _renderable() -> Any:
        term_h = shutil.get_terminal_size().lines
        visible = max(5, term_h - 6)  # leave room for table borders + footer
        with _lock:
            vals = dict(_current)
            chgs = list(_changes)
        if not vals:
            return Text(f"  Connecting to {plc_ip}… waiting for first poll", style="dim")
        return _tag_table(vals, chgs, scroll=_scroll, visible=visible)

    t_input = threading.Thread(target=_input_loop, daemon=True)
    t_poll = threading.Thread(target=_poll_loop, daemon=True)
    t_input.start()
    t_poll.start()

    try:
        with Live(
            console=console,
            screen=True,
            auto_refresh=True,
            refresh_per_second=4,
        ) as live:
            while not _stop.is_set():
                live.update(_renderable())
                time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        _stop.set()

    if _error:
        console.print(f"[red][!] Connection lost: {_error[0]}[/red]")
    else:
        console.print("[yellow]Monitor stopped.[/yellow]")


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
