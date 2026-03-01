"""Rich-based TUI for Beckhoff TwinCAT PLC monitoring and control.

Beckhoff ADS operations require a device dict (from discovery) plus
a local AMS Net ID, so this module wraps the discovery step before
any ADS call.
"""

from __future__ import annotations

import socket

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console(stderr=False)


# ------------------------------------------------------------------
# ADS prerequisite helpers
# ------------------------------------------------------------------

def _probe_local_ip(target_ip: str) -> str:
    """Determine the local IP address used to reach *target_ip*."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((target_ip, 80))
        local_ip = sock.getsockname()[0]
        sock.close()
        return local_ip
    except OSError:
        return "0.0.0.0"


def _resolve_device(ip: str) -> tuple[dict, str] | None:
    """Discover a Beckhoff device and build the local AMS Net ID.

    Args:
        ip: Target device IP address.

    Returns:
        Tuple of (device_dict, local_netid) or None if unreachable.
    """
    from scadaver.vendors.beckhoff.ads import build_local_netid
    from scadaver.vendors.beckhoff.scan import discover_ip

    devices = discover_ip(ip)
    if not devices:
        return None

    local_ip = _probe_local_ip(ip)
    local_netid = build_local_netid(local_ip)
    return devices[0], local_netid


# ------------------------------------------------------------------
# Rich helpers
# ------------------------------------------------------------------

def _device_table(info: dict) -> Table:
    """Build a Rich Table showing Beckhoff device details."""
    table = Table(header_style="bold cyan", show_header=False, expand=True)
    table.add_column("Field", style="dim", width=20)
    table.add_column("Value", style="white")

    for key, label in [
        ("ip", "IP Address"),
        ("name", "Device Name"),
        ("netid", "AMS Net ID"),
        ("tc_version", "TwinCAT Version"),
        ("kernel", "OS / Kernel"),
        ("serial", "Serial Number"),
        ("hardware_model", "Hardware Model"),
        ("os_name", "OS Name"),
        ("os_version", "OS Version"),
        ("ssl_thumbprint", "SSL Thumbprint"),
    ]:
        val = info.get(key)
        if val:
            table.add_row(label, str(val))

    return table


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_device_panel(ip: str) -> None:
    """Show device info and TwinCAT state for a Beckhoff device.

    Discovers the device via ADS, then displays hardware and OS details.

    Args:
        ip: Target device IP address.
    """
    with console.status(f"[cyan]Discovering {ip} via ADS…"):
        resolved = _resolve_device(ip)

    if resolved is None:
        console.print(f"[red][!] No Beckhoff device found at {ip}[/red]")
        return

    device, local_netid = resolved
    console.print(f"[green]✓ Found: {device['name']} ({device['netid_str']})[/green]")

    with console.status("[cyan]Querying device info…"):
        from scadaver.vendors.beckhoff.scan import get_device_info, get_state
        info = get_device_info(device, local_netid) or device
        state = get_state(device, local_netid)

    colour = "green" if state == "RUN" else "yellow"
    console.print(Panel(
        _device_table(info),
        title=f"[bold]{device['name']}[/bold] — [{colour}]{state}[/{colour}]",
        border_style=colour,
    ))


def run_control(ip: str) -> None:
    """Interactive control panel for a Beckhoff TwinCAT device.

    Discovers the device, shows the current state, then lets you
    change state or trigger a reboot/shutdown.

    Args:
        ip: Target device IP address.
    """
    with console.status(f"[cyan]Discovering {ip}…"):
        resolved = _resolve_device(ip)

    if resolved is None:
        console.print(f"[red][!] No Beckhoff device found at {ip}[/red]")
        return

    device, local_netid = resolved
    console.print(f"[green]✓ {device['name']} ({device['netid_str']})[/green]")

    with console.status("[cyan]Reading TwinCAT state…"):
        from scadaver.vendors.beckhoff.scan import (
            get_state,
            reboot_device,
            set_twincat_state,
            shutdown_device,
        )
        state = get_state(device, local_netid)

    colour = "green" if state == "RUN" else "yellow"
    console.print(f"  Current state: [{colour}]{state}[/{colour}]")

    action = Prompt.ask(
        "[bold]Action: [run/config/stop/reset] | [reboot] | [shutdown] | [q] quit[/bold]",
        default="q",
    ).lower()

    if action == "q":
        return
    elif action == "reboot":
        confirm = Prompt.ask("[red]Confirm reboot[/red]", choices=["y", "n"], default="n")
        if confirm == "y":
            with console.status("[cyan]Sending reboot…"):
                ok = reboot_device(device, local_netid)
            console.print("[green]Reboot sent.[/green]" if ok else "[red]Reboot failed.[/red]")
    elif action == "shutdown":
        confirm = Prompt.ask("[red]Confirm shutdown[/red]", choices=["y", "n"], default="n")
        if confirm == "y":
            with console.status("[cyan]Sending shutdown…"):
                ok = shutdown_device(device, local_netid)
            console.print("[green]Shutdown sent.[/green]" if ok else "[red]Shutdown failed.[/red]")
    elif action in ("run", "config", "stop", "reset"):
        with console.status(f"[cyan]Setting state → {action.upper()}…"):
            ok = set_twincat_state(device, local_netid, action)
        if ok:
            with console.status("[cyan]Re-reading state…"):
                new_state = get_state(device, local_netid)
            console.print(f"  [green]State → {new_state}[/green]")
        else:
            console.print("[red]State change failed.[/red]")
    else:
        console.print(f"[red]Unknown action: {action}[/red]")


def run_scan_table(devices: list[dict]) -> None:
    """Display a list of discovered Beckhoff devices as a Rich table.

    Args:
        devices: List of device dicts from discover() or discover_ip().
    """
    if not devices:
        console.print("[yellow]No Beckhoff devices found.[/yellow]")
        return

    table = Table(
        title=f"Beckhoff Devices ({len(devices)} found)",
        header_style="bold cyan",
    )
    table.add_column("IP", style="white")
    table.add_column("Name", style="green")
    table.add_column("AMS Net ID", style="dim")
    table.add_column("TwinCAT", style="cyan")
    table.add_column("OS / Kernel", style="dim")

    for dev in devices:
        table.add_row(
            dev.get("ip", "?"),
            dev.get("name", "?"),
            dev.get("netid_str", dev.get("netid", "?")),
            dev.get("tc_version", "?"),
            dev.get("kernel", "?"),
        )
    console.print(table)
