"""Rich-based TUI for EtherNet/IP (CIP) device scanning."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(stderr=False)


def _vendor_name(device: dict) -> str:
    """Resolve VendorID integer to human-readable name."""
    try:
        from scadaver.vendors.enip.enums import VENDOR_ID
        from scadaver.vendors.enip.scan import convert_to_int
        vid = convert_to_int(bytes.fromhex(device["VendorID"]), inverted=False)
        return VENDOR_ID.get(str(vid), f"Unknown ({device['VendorID']})")
    except Exception:
        return device.get("VendorID", "?")


def _device_type_name(device: dict) -> str:
    """Resolve DeviceType integer to human-readable name."""
    try:
        from scadaver.vendors.enip.enums import DEVICE_TYPE
        return DEVICE_TYPE.get(str(device["DeviceType"]), f"Unknown ({device['DeviceType']})")
    except Exception:
        return str(device.get("DeviceType", "?"))


# ------------------------------------------------------------------
# Public TUI entry points
# ------------------------------------------------------------------

def run_scan_table(devices: list[dict]) -> None:
    """Display a list of discovered EtherNet/IP devices as a Rich table.

    Args:
        devices: List of device dicts from scan() or scan_ip().
    """
    if not devices:
        console.print("[yellow]No EtherNet/IP devices found.[/yellow]")
        return

    table = Table(
        title=f"EtherNet/IP Devices ({len(devices)} found)",
        header_style="bold cyan",
    )
    table.add_column("IP", style="white")
    table.add_column("Product Name", style="green", no_wrap=True)
    table.add_column("Device Type", style="white")
    table.add_column("Vendor", style="cyan")
    table.add_column("Revision", style="dim")
    table.add_column("Serial", style="dim")

    for dev in devices:
        addr = dev.get("SocketAddr", {})
        ip = addr.get("sin_addr", dev.get("ip", "?"))
        table.add_row(
            ip,
            dev.get("ProductName", "?"),
            _device_type_name(dev),
            _vendor_name(dev),
            dev.get("Revision", "?"),
            dev.get("SerialNumber", ""),
        )
    console.print(table)


def run_device_panel(ip: str) -> None:
    """Show detailed info for a single EtherNet/IP device.

    Args:
        ip: Target device IP address.
    """
    from scadaver.vendors.enip.scan import scan_ip

    with console.status(f"[cyan]Querying {ip} via EtherNet/IP…"):
        devices = scan_ip(ip)

    if not devices:
        console.print(f"[red][!] No EtherNet/IP device at {ip}[/red]")
        return

    dev = devices[0]
    addr = dev.get("SocketAddr", {})

    detail = Table(show_header=False, expand=True)
    detail.add_column("Field", style="dim", width=22)
    detail.add_column("Value", style="white")

    detail.add_row("IP Address", addr.get("sin_addr", "?"))
    detail.add_row("Port", str(addr.get("sin_port", "?")))
    detail.add_row("Product Name", dev.get("ProductName", "?"))
    detail.add_row("Device Type", _device_type_name(dev))
    detail.add_row("Vendor", _vendor_name(dev))
    detail.add_row("Revision", dev.get("Revision", "?"))
    detail.add_row("Serial Number", dev.get("SerialNumber", ""))
    detail.add_row("Status", dev.get("Status", ""))
    detail.add_row("Encaps Version", dev.get("EncapsVersion", ""))
    detail.add_row("State", dev.get("State", ""))

    console.print(Panel(
        detail,
        title=f"[bold]{dev.get('ProductName', ip)}[/bold] — EtherNet/IP",
        border_style="cyan",
    ))
