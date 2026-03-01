"""Rich-based TUI for eWON device scanning and credential extraction."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console(stderr=False)


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_scan_table(devices: list[dict]) -> None:
    """Display a list of discovered eWON devices as a Rich table.

    Args:
        devices: List of device dicts from scan() or scan_ip().
    """
    if not devices:
        console.print("[yellow]No eWON devices found.[/yellow]")
        return

    table = Table(
        title=f"eWON Devices ({len(devices)} found)",
        header_style="bold cyan",
    )
    table.add_column("IP", style="white")
    table.add_column("MAC", style="dim")
    table.add_column("Serial", style="white")
    table.add_column("Product Code", style="dim")
    table.add_column("Firmware", style="green")
    table.add_column("Netmask", style="dim")

    for dev in devices:
        table.add_row(
            dev.get("ip", "?"),
            dev.get("mac", ""),
            dev.get("serial", ""),
            dev.get("product_code", ""),
            dev.get("firmware", ""),
            dev.get("netmask", ""),
        )
    console.print(table)


def run_device_panel(ip: str) -> None:
    """Show device info for a specific eWON device.

    Args:
        ip: Target eWON device IP address.
    """
    from scadaver.vendors.ewon.scan import scan_ip

    with console.status(f"[cyan]Querying {ip}…"):
        devices = scan_ip(ip)

    if not devices:
        console.print(f"[red][!] No eWON device found at {ip}[/red]")
        return

    dev = devices[0]
    table = Table(show_header=False, expand=True)
    table.add_column("Field", style="dim", width=20)
    table.add_column("Value", style="white")

    for key, label in [
        ("ip", "IP Address"),
        ("netmask", "Netmask"),
        ("mac", "MAC Address"),
        ("serial", "Serial Number"),
        ("product_code", "Product Code"),
        ("firmware", "Firmware"),
        ("identifier", "Identifier"),
    ]:
        val = dev.get(key)
        if val:
            table.add_row(label, str(val))

    console.print(Panel(table, title=f"[bold]{ip}[/bold] — eWON", border_style="cyan"))


def run_credential_extract(ip: str) -> None:
    """Extract credentials from an eWON Flexy via auth bypass.

    Runs CVE-based unauthenticated credential retrieval.

    Args:
        ip: Target eWON Flexy IP address.
    """
    from scadaver.vendors.ewon.exploit import exploit

    confirm = Prompt.ask(
        f"[bold]Extract credentials from {ip}?[/bold]",
        choices=["y", "n"],
        default="n",
    )
    if confirm != "y":
        return

    with console.status(f"[cyan]Extracting credentials from {ip}…"):
        result = exploit(ip)

    if not result:
        console.print("[yellow]No credentials retrieved.[/yellow]")
        return

    table = Table(title="eWON Credentials", header_style="bold red")
    table.add_column("Username", style="white")
    table.add_column("Password", style="red bold")
    table.add_column("Level", style="dim")
    table.add_column("Group", style="dim")

    users = result if isinstance(result, list) else [result]
    for user in users:
        table.add_row(
            str(user.get("username", user.get("user", "?"))),
            str(user.get("password", user.get("pass", "?"))),
            str(user.get("level", "")),
            str(user.get("group", "")),
        )
    console.print(table)
