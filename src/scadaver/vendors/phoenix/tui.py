"""Rich-based TUI for Phoenix Contact WebVisit HMI monitoring and editing.

Wraps CVE-2016-8380 tag read/write (unauthenticated) with a TUI that matches
the Rockwell module: live monitor, interactive editor, and change history.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table

console = Console(stderr=False)

DATA_DIR = Path("data")


# ------------------------------------------------------------------
# Driver wrapper
# ------------------------------------------------------------------

class PhoenixPLC:
    """Thin wrapper around webvisit helpers with caching and history.

    Tag names are discovered from the HMI project file and cached locally
    so subsequent runs load instantly.
    """

    def __init__(self, ip: str) -> None:
        self.ip = ip
        DATA_DIR.mkdir(exist_ok=True)
        safe = ip.replace(".", "_")
        self._tags_file = DATA_DIR / f"tags_phoenix_{safe}.json"
        self._changes_file = DATA_DIR / f"changes_phoenix_{safe}.json"
        self.tags: list[str] = []
        self.project: str = ""
        self._previous: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Tag discovery
    # ------------------------------------------------------------------

    def discover_tags(self) -> list[str]:
        """Fetch project tags from the HMI and cache them to disk.

        Returns:
            Sorted list of tag names.

        Raises:
            RuntimeError: If the HMI is unreachable or has no project.
        """
        from scadaver.vendors.phoenix.webvisit import get_tags
        result = get_tags(self.ip)
        if result is None:
            raise RuntimeError(f"Could not retrieve tags from {self.ip}")
        self.project, self.tags = result[0], sorted(result[1])
        cache = {"project": self.project, "tags": self.tags}
        self._tags_file.write_text(json.dumps(cache, indent=2))
        return self.tags

    def load_tags(self) -> list[str]:
        """Load tag list from cache, discovering from HMI if not present."""
        if self._tags_file.exists():
            try:
                data = json.loads(self._tags_file.read_text())
                self.project = data.get("project", "")
                self.tags = data.get("tags", [])
                return self.tags
            except Exception:
                pass
        return self.discover_tags()

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    def read_all(self) -> dict[str, str]:
        """Read the current value of all known tags.

        Returns:
            Dict mapping tag name → value string.

        Raises:
            RuntimeError: If the HMI is unreachable.
        """
        if not self.tags:
            self.load_tags()
        from scadaver.vendors.phoenix.webvisit import read_tag_values
        try:
            pairs = read_tag_values(self.ip, self.tags)
            return dict(pairs)
        except Exception as exc:
            raise RuntimeError(f"Read failed: {exc}") from exc

    def write_tag(self, tag: str, value: str) -> bool:
        """Write a single tag value.

        Args:
            tag: Tag name.
            value: New value (as string).

        Returns:
            True on success.
        """
        from scadaver.vendors.phoenix.webvisit import write_tag_value
        return write_tag_value(self.ip, tag, value)

    # ------------------------------------------------------------------
    # Change detection / history
    # ------------------------------------------------------------------

    def detect_changes(self, current: dict[str, str]) -> list[dict]:
        """Compare current tag values against the previous snapshot."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        changes: list[dict] = []
        for tag, val in current.items():
            if tag in self._previous and self._previous[tag] != val:
                changes.append({
                    "timestamp": ts,
                    "tag": tag,
                    "old_value": self._previous[tag],
                    "new_value": val,
                    "plc_ip": self.ip,
                })
        return changes

    def save_changes(self, changes: list[dict]) -> None:
        """Append changes to persistent log file, capped at 1000 entries."""
        if not changes:
            return
        history = self.load_history()
        history.extend(changes)
        self._changes_file.write_text(json.dumps(history[-1000:], indent=2))

    def load_history(self) -> list[dict]:
        """Load change history from disk."""
        if self._changes_file.exists():
            try:
                return json.loads(self._changes_file.read_text())
            except Exception:
                return []
        return []

    # ------------------------------------------------------------------
    # Monitor generator
    # ------------------------------------------------------------------

    def monitor(self, interval: float = 1.0):
        """Generator yielding (current_values, changes) at each poll interval.

        Args:
            interval: Poll interval in seconds.

        Yields:
            Tuple of (current_values dict, changes list).
        """
        if not self.tags:
            self.load_tags()
        first = True
        while True:
            current = self.read_all()
            changes = [] if first else self.detect_changes(current)
            if changes:
                self.save_changes(changes)
            self._previous = current.copy()
            first = False
            yield current, changes
            time.sleep(interval)


# ------------------------------------------------------------------
# Rich helpers
# ------------------------------------------------------------------

def _tag_table(values: dict[str, str], changes: list[dict] | None = None) -> Table:
    """Build a Rich Table from WebVisit tag values."""
    changed_tags = {c["tag"] for c in changes} if changes else set()
    table = Table(header_style="bold cyan", expand=True)
    table.add_column("#", style="dim", width=6)
    table.add_column("Tag", style="white", no_wrap=True)
    table.add_column("Value", style="white")
    table.add_column("Status", width=10)

    for idx, (tag, value) in enumerate(values.items(), start=1):
        if tag in changed_tags:
            tag_style = "yellow"
            status = "[yellow]CHANGED[/yellow]"
        else:
            tag_style = "green"
            status = "[green]OK[/green]"
        table.add_row(str(idx), f"[{tag_style}]{tag}[/{tag_style}]", str(value), status)

    return table


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_monitor(ip: str, interval: float = 1.0) -> None:
    """Live-updating tag value monitor for a Phoenix WebVisit HMI.

    Polls at *interval* seconds and highlights changed tags in yellow.
    Press Ctrl-C to exit.

    Args:
        ip: HMI IP address.
        interval: Poll interval in seconds.
    """
    plc = PhoenixPLC(ip)
    cached = plc._tags_file.exists()
    msg = (
        f"[cyan]Loading {ip} tag cache…"
        if cached
        else f"[yellow]Discovering tags on {ip} (fetching HMI project)…"
    )
    with console.status(msg):
        try:
            plc.load_tags()
        except RuntimeError as exc:
            console.print(f"[red][!] {exc}[/red]")
            return

    console.print(
        f"[green]✓ {len(plc.tags)} tags loaded "
        f"({'cached' if cached else 'discovered'}, project: {plc.project}). "
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
    except RuntimeError as exc:
        console.print(f"\n[red][!] Read error: {exc}[/red]")
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/yellow]")


def run_editor(ip: str) -> None:
    """Interactive tag value editor for a Phoenix WebVisit HMI.

    Select a tag by number, type a new value, then press 'w' to write.
    All writes are staged and committed in one pass.

    Args:
        ip: HMI IP address.
    """
    plc = PhoenixPLC(ip)
    cached = plc._tags_file.exists()
    msg = (
        f"[cyan]Loading {ip} tag cache…"
        if cached
        else f"[yellow]Discovering tags on {ip}…"
    )
    with console.status(msg):
        try:
            plc.load_tags()
        except RuntimeError as exc:
            console.print(f"[red][!] {exc}[/red]")
            return

    console.print(f"[green]✓ {len(plc.tags)} tags loaded. Fetching initial values…[/green]")
    pending: dict[str, str] = {}

    while True:
        with console.status("[cyan]Reading tags…"):
            try:
                current = plc.read_all()
            except RuntimeError as exc:
                console.print(f"[red][!] {exc}[/red]")
                break

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
                results: dict[str, bool] = {}
                for tag, value in pending.items():
                    results[tag] = plc.write_tag(tag, value)
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
            raw = Prompt.ask(
                f"New value for [cyan]{tag}[/cyan] (current: {current.get(tag, '?')})"
            )
            pending[tag] = raw


def run_history(ip: str, limit: int = 30) -> None:
    """Display the last *limit* tag change events for a Phoenix HMI.

    Args:
        ip: HMI IP address.
        limit: Maximum number of history entries to show.
    """
    plc = PhoenixPLC(ip)
    history = plc.load_history()
    if not history:
        console.print("[yellow]No change history recorded yet.[/yellow]")
        return

    recent = history[-limit:]
    table = Table(
        title=f"Last {len(recent)} changes for {ip}",
        header_style="bold cyan",
    )
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
