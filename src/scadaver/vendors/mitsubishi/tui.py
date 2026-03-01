"""Rich-based TUI for Mitsubishi MELSEC PLC control.

The Mitsubishi control protocol is UDP broadcast-based.
All operations require selecting a local network interface.
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

console = Console(stderr=False)


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_control(ip: str | None = None) -> None:
    """Interactive RUN/STOP/PAUSE control for a Mitsubishi MELSEC PLC.

    Selects the local network interface, then sends the chosen state
    command via UDP broadcast.

    Args:
        ip: Unused (broadcast-based — kept for interface consistency).
    """
    from scadaver.core.network import get_interfaces, select_interface
    from scadaver.vendors.mitsubishi.control import set_state

    ifaces = get_interfaces()
    if not ifaces:
        console.print("[red][!] No network interfaces found.[/red]")
        return

    iface = select_interface(ifaces)
    console.print(f"[dim]Using interface: {iface.ip}[/dim]")

    action = Prompt.ask(
        "[bold]State: [run] | [stop] | [pause] | [q] quit[/bold]",
        choices=["run", "stop", "pause", "q"],
        default="q",
    )
    if action == "q":
        return

    with console.status(f"[cyan]Sending {action.upper()} to Mitsubishi PLC…"):
        try:
            ok = set_state(iface, action)
        except Exception as exc:
            console.print(f"[red][!] {exc}[/red]")
            return

    status = "[green]OK — PLC acknowledged.[/green]" if ok else "[yellow]No acknowledgement.[/yellow]"
    console.print(status)


def run_scan_table(devices: list[dict]) -> None:
    """Display a list of discovered Mitsubishi MELSEC devices as a Rich table.

    Args:
        devices: List of device dicts from scan() or scan_ip().
    """
    if not devices:
        console.print("[yellow]No Mitsubishi devices found.[/yellow]")
        return

    table = Table(
        title=f"Mitsubishi MELSEC Devices ({len(devices)} found)",
        header_style="bold cyan",
    )
    table.add_column("IP", style="white")
    table.add_column("Type", style="green")
    table.add_column("Title", style="white")
    table.add_column("Comment", style="dim")

    for dev in devices:
        table.add_row(
            dev.get("ip", "?"),
            dev.get("type", "?"),
            dev.get("title", ""),
            dev.get("comment", ""),
        )
    console.print(table)
