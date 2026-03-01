"""Rich-based TUI for Siemens S7 PLC monitoring and I/O editing."""

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
_AREAS = ("inputs", "outputs", "merkers")


# ------------------------------------------------------------------
# Small driver-level helpers
# ------------------------------------------------------------------

class SiemensPLC:
    """Thin wrapper around s7comm helpers with history/change tracking."""

    def __init__(self, ip: str, port: int = 102) -> None:
        self.ip = ip
        self.port = port
        DATA_DIR.mkdir(exist_ok=True)
        safe = ip.replace(".", "_")
        self._changes_file = DATA_DIR / f"changes_siemens_{safe}.json"
        self._previous: dict[str, dict[str, int]] = {}

    def read_io(self) -> dict[str, dict[str, int] | None]:
        """Read inputs, outputs, and merkers from the PLC."""
        from scadaver.vendors.siemens.control import read_io
        return read_io(self.ip, self.port)

    def write_outputs(self, bits: str) -> bool:
        """Write 8-bit binary string to outputs."""
        from scadaver.vendors.siemens.control import write_outputs
        return write_outputs(self.ip, bits, self.port)

    def write_merkers(self, bits: str, offset: int = 0) -> bool:
        """Write 8-bit binary string to merkers."""
        from scadaver.vendors.siemens.control import write_merkers
        return write_merkers(self.ip, bits, offset, self.port)

    def cpu_state(self) -> str:
        """Return the current CPU state string."""
        from scadaver.vendors.siemens.control import cpu_state
        return cpu_state(self.ip, self.port)

    def flip_cpu(self) -> bool:
        """Toggle CPU state between Running and Stopped."""
        from scadaver.vendors.siemens.control import flip_cpu
        return flip_cpu(self.ip, self.port)

    def detect_changes(self, current: dict[str, dict[str, int] | None]) -> list[dict]:
        """Compare current I/O snapshot against previous, return change list."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        changes: list[dict] = []
        for area in _AREAS:
            cur = current.get(area)
            prev = self._previous.get(area)
            if cur is None or prev is None:
                continue
            for bit, val in cur.items():
                if bit in prev and prev[bit] != val:
                    changes.append({
                        "timestamp": ts,
                        "area": area,
                        "bit": bit,
                        "old_value": prev[bit],
                        "new_value": val,
                        "plc_ip": self.ip,
                    })
        return changes

    def save_changes(self, changes: list[dict]) -> None:
        """Append changes to persistent log file, capped at 1000."""
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
# Rich helper
# ------------------------------------------------------------------

def _io_table(
    io: dict[str, dict[str, int] | None],
    changed_bits: set[tuple[str, str]] | None = None,
) -> Table:
    """Build a Rich table for I/O bit data."""
    changed = changed_bits or set()
    table = Table(header_style="bold cyan", expand=True)
    table.add_column("Bit", style="dim", width=6)
    for area in _AREAS:
        table.add_column(area.capitalize(), width=12)

    # Collect all bit addresses present
    all_bits: set[str] = set()
    for area in _AREAS:
        if io.get(area):
            all_bits.update(io[area].keys())  # type: ignore[union-attr]

    for bit in sorted(all_bits, key=lambda x: (int(x.split(".")[0]), int(x.split(".")[1]))):
        cells = [bit]
        for area in _AREAS:
            data = io.get(area)
            if data is None:
                cells.append("[red]ERR[/red]")
            else:
                val = data.get(bit)
                if val is None:
                    cells.append("[dim]—[/dim]")
                elif (area, bit) in changed:
                    cells.append(f"[yellow bold]{val}[/yellow bold]")
                else:
                    cells.append(f"[green]{val}[/green]" if val else f"[dim]{val}[/dim]")
        table.add_row(*cells)
    return table


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_io_monitor(ip: str, port: int = 102, interval: float = 1.0) -> None:
    """Live-updating I/O bit monitor for a Siemens S7 PLC.

    Polls inputs, outputs, and merkers at *interval* seconds.
    Changed bits are highlighted yellow. Press Ctrl-C to exit.

    Args:
        ip: Target PLC IP address.
        port: S7Comm port (default 102).
        interval: Poll interval in seconds.
    """
    plc = SiemensPLC(ip, port)
    with console.status(f"[cyan]Connecting to {ip}:{port}…"):
        initial = plc.read_io()

    if all(v is None for v in initial.values()):
        console.print(f"[red][!] No I/O data from {ip}. Check connectivity.[/red]")
        return

    console.print(f"[green]✓ Connected. Starting I/O monitor (Ctrl-C to stop).[/green]\n")
    plc._previous = {k: dict(v) for k, v in initial.items() if v is not None}
    first = True

    try:
        with Live(console=console, refresh_per_second=4, screen=True):
            while True:
                with console.status("[dim]…[/dim]"):
                    current = plc.read_io()
                changes = [] if first else plc.detect_changes(current)
                if changes:
                    plc.save_changes(changes)
                changed_set = {(c["area"], c["bit"]) for c in changes}
                plc._previous = {k: dict(v) for k, v in current.items() if v is not None}
                first = False
                console.print(_io_table(current, changed_set))
                time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitor stopped.[/yellow]")


def run_io_editor(ip: str, port: int = 102) -> None:
    """Interactive I/O editor — write outputs and merkers on a Siemens S7 PLC.

    Displays current I/O state, then prompts for binary strings to write.
    Press Ctrl-C or enter 'q' to exit.

    Args:
        ip: Target PLC IP address.
        port: S7Comm port (default 102).
    """
    plc = SiemensPLC(ip, port)

    while True:
        with console.status(f"[cyan]Reading I/O from {ip}…"):
            io = plc.read_io()
        console.print(_io_table(io))

        action = Prompt.ask(
            "[bold]Action: [o] write outputs | [m] write merkers | [r] refresh | [q] quit[/bold]",
            default="r",
        ).lower()

        if action == "q":
            break
        elif action == "r":
            continue
        elif action == "o":
            bits = Prompt.ask("[cyan]8-bit binary for outputs[/cyan]", default="00000000")
            if len(bits) != 8 or not all(c in "01" for c in bits):
                console.print("[red]Invalid — must be exactly 8 binary digits.[/red]")
                continue
            with console.status("[cyan]Writing outputs…"):
                ok = plc.write_outputs(bits)
            status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
            console.print(f"  Outputs write: {status}")
        elif action == "m":
            bits = Prompt.ask("[cyan]8-bit binary for merkers[/cyan]", default="00000000")
            if len(bits) != 8 or not all(c in "01" for c in bits):
                console.print("[red]Invalid — must be exactly 8 binary digits.[/red]")
                continue
            offset_str = Prompt.ask("[cyan]Byte offset[/cyan]", default="0")
            try:
                offset = int(offset_str)
            except ValueError:
                console.print("[red]Invalid offset.[/red]")
                continue
            with console.status("[cyan]Writing merkers…"):
                ok = plc.write_merkers(bits, offset)
            status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
            console.print(f"  Merkers write: {status}")


def run_cpu_panel(ip: str, port: int = 102) -> None:
    """Display and control the Siemens S7 CPU state.

    Shows the current run state and optionally toggles it.

    Args:
        ip: Target PLC IP address.
        port: S7Comm port (default 102).
    """
    plc = SiemensPLC(ip, port)

    with console.status(f"[cyan]Querying CPU state on {ip}…"):
        state = plc.cpu_state()

    colour = "green" if "run" in state.lower() else "yellow"
    console.print(f"  [{colour}]CPU state: {state}[/{colour}]")

    action = Prompt.ask(
        "[bold]Toggle CPU state (run↔stop)?[/bold]",
        choices=["y", "n"],
        default="n",
    )
    if action == "y":
        with console.status("[cyan]Sending state change…"):
            ok = plc.flip_cpu()
        if ok:
            with console.status("[cyan]Re-reading state…"):
                new_state = plc.cpu_state()
            console.print(f"  [green]State changed → {new_state}[/green]")
        else:
            console.print("[red]State change failed.[/red]")


def run_history(ip: str, limit: int = 30) -> None:
    """Display the last *limit* I/O change events for a Siemens PLC.

    Args:
        ip: PLC IP address.
        limit: Maximum number of history entries to show.
    """
    plc = SiemensPLC(ip)
    history = plc.load_history()
    if not history:
        console.print("[yellow]No change history recorded yet.[/yellow]")
        return

    recent = history[-limit:]
    table = Table(
        title=f"Last {len(recent)} I/O changes for {ip}",
        header_style="bold cyan",
    )
    table.add_column("Timestamp", style="dim")
    table.add_column("Area", style="white")
    table.add_column("Bit", style="white")
    table.add_column("Old", style="red")
    table.add_column("New", style="green")

    for entry in reversed(recent):
        table.add_row(
            entry.get("timestamp", ""),
            entry.get("area", ""),
            entry.get("bit", ""),
            str(entry.get("old_value", "")),
            str(entry.get("new_value", "")),
        )
    console.print(table)
