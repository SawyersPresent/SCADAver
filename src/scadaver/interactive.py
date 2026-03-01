"""Interactive numbered-menu fallback for scadaver.

Launched when ``scadaver`` is invoked without a subcommand.
Presents a hierarchical menu for users who prefer guided
interaction over CLI flags.
"""

from __future__ import annotations

import sys


def _clear() -> None:
    import os
    os.system("cls" if os.name == "nt" else "clear")


BANNER = r"""
  ███████╗ ██████╗ █████╗ ██████╗  █████╗ ██╗   ██╗███████╗██████╗
  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝██╔══██╗
  ███████╗██║     ███████║██║  ██║███████║██║   ██║█████╗  ██████╔╝
  ╚════██║██║     ██╔══██║██║  ██║██╔══██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
  ███████║╚██████╗██║  ██║██████╔╝██║  ██║ ╚████╔╝ ███████╗██║  ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

               Unified ICS Red Team Multi-Tool v1.0
                       by sawyerspresent
[*****************************************************************************]
"""

# MAIN_MENU is defined at the bottom of the file after all handlers.

# ===================================================================
# Menu helpers
# ===================================================================

def _prompt(items: list[tuple[str, object]], title: str = "MAIN MENU") -> int:
    """Display a numbered menu and return the 0-based selection index."""
    _clear()
    print(BANNER)
    print(f"  ###--- {title} ---###\n")
    for i, (label, _) in enumerate(items, 1):
        print(f"  [{i}] {label}")
    print()
    while True:
        answer = input("Select option: ").strip()
        if answer.lower() in ("q", "quit"):
            return len(items) - 1  # last item = Quit
        if answer.isdigit() and 1 <= int(answer) <= len(items):
            return int(answer) - 1
        print("Invalid selection, try again.")


def _pause() -> None:
    input("\nPress [Enter] to continue")


def _ask_ip(prompt_text: str = "Target IP") -> str:
    ip = input(f"{prompt_text}: ").strip()
    if not ip:
        print("No IP provided.")
        return ""
    return ip


# ===================================================================
# Scan sub-menu
# ===================================================================

def _menu_scan() -> None:
    items = [
        ("EtherNet/IP (CIP) scan", _scan_enip),
        ("eWON scan", _scan_ewon),
        ("Schneider Electric scan", _scan_schneider),
        ("Mitsubishi MELSEC scan", _scan_mitsubishi),
        ("Beckhoff TwinCAT scan", _scan_beckhoff),
        ("Siemens (single IP)", _scan_siemens_ip),
        ("Rockwell Allen-Bradley Logix", _scan_rockwell),
        ("Back", None),
    ]
    while True:
        idx = _prompt(items, "SCAN MENU")
        if items[idx][1] is None:
            return
        items[idx][1]()
        _pause()


def _ask_scan_mode() -> str | None:
    """Ask whether to broadcast or target a specific IP.

    Returns:
        IP string if specific IP chosen, None for broadcast.
    """
    choice = input("Scan mode — (B)roadcast or specific (I)P? [B]: ").strip().lower() or "b"
    if choice.startswith("i"):
        return _ask_ip("Target IP")
    return None


def _scan_enip() -> None:
    from rich.console import Console as _Con
    from scadaver.vendors.enip.scan import scan, scan_ip
    _con = _Con()
    target = _ask_scan_mode()
    if target:
        with _con.status(f"[cyan]Querying {target}\u2026"):
            devices = scan_ip(target)
    else:
        from scadaver.core.network import get_interfaces, select_interface
        iface = select_interface(get_interfaces())
        with _con.status("[cyan]Broadcasting EtherNet/IP discovery\u2026"):
            devices = scan(interface=iface)
    _con.print(f"[green]Found {len(devices)} EtherNet/IP device(s).[/green]")


def _scan_ewon() -> None:
    from rich.console import Console as _Con
    from scadaver.vendors.ewon.scan import scan, scan_ip
    _con = _Con()
    target = _ask_scan_mode()
    if target:
        with _con.status(f"[cyan]Querying {target}\u2026"):
            devices = scan_ip(target)
    else:
        from scadaver.core.network import get_interfaces, select_interface
        iface = select_interface(get_interfaces())
        with _con.status("[cyan]Broadcasting eWON discovery\u2026"):
            devices = scan(interface=iface)
    _con.print(f"[green]Found {len(devices)} eWON device(s).[/green]")


def _scan_schneider() -> None:
    from rich.console import Console as _Con
    from scadaver.vendors.schneider.scan import scan, scan_ip
    _con = _Con()
    target = _ask_scan_mode()
    if target:
        with _con.status(f"[cyan]Querying {target}\u2026"):
            devices = scan_ip(target)
    else:
        from scadaver.core.network import get_interfaces, select_interface
        iface = select_interface(get_interfaces())
        with _con.status("[cyan]Broadcasting Schneider discovery\u2026"):
            devices = scan(interface=iface)
    _con.print(f"[green]Found {len(devices)} Schneider device(s).[/green]")


def _scan_mitsubishi() -> None:
    from rich.console import Console as _Con
    from scadaver.vendors.mitsubishi.scan import scan, scan_ip
    _con = _Con()
    target = _ask_scan_mode()
    if target:
        with _con.status(f"[cyan]Querying {target}\u2026"):
            devices = scan_ip(target)
    else:
        from scadaver.core.network import get_interfaces, select_interface
        iface = select_interface(get_interfaces())
        with _con.status("[cyan]Broadcasting Mitsubishi MELSEC discovery\u2026"):
            devices = scan(interface=iface)
    from scadaver.vendors.mitsubishi.tui import run_scan_table
    run_scan_table(devices)


def _scan_beckhoff() -> None:
    from rich.console import Console as _Con
    from scadaver.vendors.beckhoff.scan import discover, discover_ip
    _con = _Con()
    target = _ask_scan_mode()
    if target:
        with _con.status(f"[cyan]Querying {target}\u2026"):
            devices = discover_ip(target)
    else:
        from scadaver.core.network import get_interfaces, select_interface
        iface = select_interface(get_interfaces())
        with _con.status("[cyan]Broadcasting Beckhoff ADS discovery\u2026"):
            devices = discover(interface=iface)
    from scadaver.vendors.beckhoff.tui import run_scan_table
    run_scan_table(devices)


def _scan_siemens_ip() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from rich.console import Console as _Con
    from scadaver.vendors.siemens.scan import scan_ip
    _con = _Con()
    with _con.status(f"[cyan]Scanning {ip}\u2026"):
        d = scan_ip(ip)
    _con.print(f"\n  [green]{d.get('ip_address', '?')}[/green] \u2014 {d.get('type_of_station', '?')}")
    if d.get("hardware"):
        _con.print(f"    HW: {d['hardware']}, FW: {d.get('firmware', '?')}")
    if d.get("cpu_state"):
        _con.print(f"    CPU: [cyan]{d['cpu_state']}[/cyan]")


def _scan_rockwell() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from scadaver.vendors.rockwell.driver import RockwellError, RockwellPLC
    from rich.console import Console as _Con
    _con = _Con()
    plc = RockwellPLC(ip)
    cached = plc._tags_file.exists()
    _msg = "Loading tag cache\u2026" if cached else "Discovering tags (first run \u2014 may take 30-60 s)\u2026"
    try:
        with _con.status(f"[cyan]{_msg}"):
            tags = plc.discover_tags()
    except RockwellError as exc:
        print(f"\n[!] Rockwell error: {exc}")
        return
    preview = tags[:20]
    for t in preview:
        print(f"  {t}")
    if len(tags) > 20:
        print(f"  \u2026 and {len(tags) - 20} more (saved to {plc._tags_file})")
    print(f"\nTotal: {len(tags)} tag(s).")


# ===================================================================
# Control sub-menu
# ===================================================================

def _menu_control() -> None:
    items = [
        ("Mitsubishi RUN/STOP/PAUSE", _ctrl_mitsubishi),
        ("Phoenix ILC 150/390", _ctrl_phoenix),
        ("Siemens S7 I/O read/write", _ctrl_siemens_io),
        ("Siemens S7 CPU state", _ctrl_siemens_cpu),
        ("Beckhoff TwinCAT state", _ctrl_beckhoff),
        ("Rockwell Allen-Bradley Logix", _ctrl_rockwell),
        ("Back", None),
    ]
    while True:
        idx = _prompt(items, "CONTROL MENU")
        if items[idx][1] is None:
            return
        items[idx][1]()
        _pause()


def _ctrl_mitsubishi() -> None:
    from scadaver.vendors.mitsubishi.tui import run_control
    run_control()


def _ctrl_phoenix() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from rich.console import Console as _Con
    _con = _Con()
    mode = input(
        "Action: [(i)nfo / cold / warm / hot / stop] or [(t) tag monitor / (e) tag editor / (h) history] [i]: "
    ).strip().lower() or "i"
    if mode == "t":
        interval_str = input("Poll interval seconds [2.0]: ").strip() or "2.0"
        from scadaver.vendors.phoenix.tui import run_monitor
        run_monitor(ip, interval=float(interval_str))
        return
    elif mode == "e":
        from scadaver.vendors.phoenix.tui import run_editor
        run_editor(ip)
        return
    elif mode == "h":
        from scadaver.vendors.phoenix.tui import run_history
        run_history(ip)
        return
    action = "info" if mode in ("", "i") else mode
    model = input("Model (ilc150/ilc390) [ilc150]: ").strip().lower() or "ilc150"
    from scadaver.vendors.phoenix.control import (
        control_ilc150,
        control_ilc390,
        get_device_info,
    )
    if action == "info":
        with _con.status(f"[cyan]Querying {ip}\u2026"):
            info = get_device_info(ip)
        _con.print(f"  Device info: {info}")
    elif model == "ilc150":
        with _con.status(f"[cyan]Sending ILC 150 {action.upper()}\u2026"):
            ok = control_ilc150(ip, action)
        _con.print(f"  ILC 150 {action}: [green]OK[/green]" if ok else f"  ILC 150 {action}: [red]Failed[/red]")
    else:
        with _con.status(f"[cyan]Sending ILC 390 {action.upper()}\u2026"):
            ok = control_ilc390(ip, action)
        _con.print(f"  ILC 390 {action}: [green]OK[/green]" if ok else f"  ILC 390 {action}: [red]Failed[/red]")


def _ctrl_siemens_io() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from rich.console import Console as _Con
    _con = _Con()
    mode = input(
        "Action: [(r) read] | [(o) outputs] | [(m) merkers] | [(t) live monitor] | [(e) editor] | [(h) history] [r]: "
    ).strip().lower() or "r"
    if mode == "t":
        interval_str = input("Poll interval seconds [1.0]: ").strip() or "1.0"
        from scadaver.vendors.siemens.tui import run_io_monitor
        run_io_monitor(ip, interval=float(interval_str))
        return
    elif mode == "e":
        from scadaver.vendors.siemens.tui import run_io_editor
        run_io_editor(ip)
        return
    elif mode == "h":
        from scadaver.vendors.siemens.tui import run_history
        run_history(ip)
        return
    from scadaver.vendors.siemens.control import read_io, write_merkers, write_outputs
    if mode == "o":
        bits = input("Binary outputs [00000000]: ").strip() or "00000000"
        with _con.status("[cyan]Writing outputs\u2026"):
            ok = write_outputs(ip, bits)
        _con.print("  Outputs: [green]written[/green]" if ok else "  Outputs: [red]failed[/red]")
    elif mode == "m":
        bits = input("Binary merkers [00000000]: ").strip() or "00000000"
        offset = input("Byte offset [0]: ").strip() or "0"
        with _con.status("[cyan]Writing merkers\u2026"):
            ok = write_merkers(ip, bits, int(offset))
        _con.print("  Merkers: [green]written[/green]" if ok else "  Merkers: [red]failed[/red]")
    with _con.status(f"[cyan]Reading I/O from {ip}\u2026"):
        data = read_io(ip)
    for area in ("inputs", "outputs", "merkers"):
        bits_dict = data.get(area)
        if bits_dict is None:
            _con.print(f"  [red]{area}: error[/red]")
            continue
        _con.print(f"  [cyan]{area}:[/cyan]")
        for k in sorted(bits_dict, key=lambda x: (int(x.split(".")[0]), int(x.split(".")[1]))):
            val = bits_dict[k]
            style = "green" if val else "dim"
            _con.print(f"    {k}: [{style}]{val}[/{style}]")


def _ctrl_siemens_cpu() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from scadaver.vendors.siemens.tui import run_cpu_panel
    run_cpu_panel(ip)


def _ctrl_beckhoff() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from scadaver.vendors.beckhoff.tui import run_control
    run_control(ip)


def _ctrl_rockwell() -> None:
    ip = _ask_ip()
    if not ip:
        return
    actions = [
        ("Read all tags", None),
        ("Read single tag", None),
        ("Write tag(s)", None),
        ("Live monitor (TUI)", None),
        ("Interactive editor (TUI)", None),
        ("View change history", None),
        ("Back", None),
    ]
    idx = _prompt(actions, f"ROCKWELL {ip}")
    if idx == 6:  # Back
        return
    from scadaver.vendors.rockwell.driver import RockwellError, RockwellPLC
    plc = RockwellPLC(ip)
    try:
        if idx == 0:
            from rich.console import Console as _Con
            _con = _Con()
            with _con.status("[cyan]Reading all tags\u2026"):
                values = plc.read_all()
            for t, v in list(values.items())[:40]:
                print(f"  {t} = {v}")
            if len(values) > 40:
                print(f"  \u2026 and {len(values) - 40} more")
        elif idx == 1:
            tag = input("Tag name: ").strip()
            if tag:
                print(f"  {tag} = {plc.read_tag(tag)}")
        elif idx == 2:
            import json
            raw = input("Enter TAG=value pairs (comma-separated): ").strip()
            pairs: dict = {}
            for item in raw.split(","):
                item = item.strip()
                if "=" not in item:
                    continue
                t, v = item.split("=", 1)
                try:
                    pairs[t.strip()] = json.loads(v.strip())
                except Exception:
                    pairs[t.strip()] = v.strip()
            results = plc.write_many(pairs)
            for t, ok in results.items():
                print(f"  {t}: {'OK' if ok else 'FAIL'}")
        elif idx == 3:
            from scadaver.vendors.rockwell.tui import run_monitor
            interval_str = input("Poll interval seconds [1.0]: ").strip() or "1.0"
            run_monitor(ip, interval=float(interval_str))
        elif idx == 4:
            from scadaver.vendors.rockwell.tui import run_editor
            run_editor(ip)
        elif idx == 5:
            from scadaver.vendors.rockwell.tui import run_history
            run_history(ip)
    except RockwellError as exc:
        print(f"\n[!] Rockwell error: {exc}")


# ===================================================================
# Exploit sub-menu
# ===================================================================

def _menu_exploit() -> None:
    items = [
        ("eWON Flexy credential extraction", _expl_ewon),
        ("Schneider Flash LED", _expl_schneider_flash),
        ("Schneider Session Hijack (CVE-2017-6026)", _expl_schneider_hijack),
        ("Phoenix Password Retrieval (CVE-2016-8366)", _expl_phoenix_pass),
        ("Phoenix Tag Read/Write (CVE-2016-8380)", _expl_phoenix_tags),
        ("Beckhoff CX9020 Reboot (UPnP)", _expl_beckhoff_reboot),
        ("Beckhoff CX9020 Add User (UPnP)", _expl_beckhoff_user),
        ("Beckhoff Route Brute-Force (Linux)", _expl_beckhoff_route),
        ("Back", None),
    ]
    while True:
        idx = _prompt(items, "EXPLOIT MENU")
        if items[idx][1] is None:
            return
        items[idx][1]()
        _pause()


def _expl_ewon() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from scadaver.vendors.ewon.tui import run_credential_extract
    run_credential_extract(ip)


def _expl_schneider_flash() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from scadaver.vendors.schneider.tui import run_flash_led
    run_flash_led(ip)


def _expl_schneider_hijack() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from scadaver.vendors.schneider.tui import run_session_panel
    run_session_panel(ip)


def _expl_phoenix_pass() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from rich.console import Console as _Con
    from rich.table import Table
    from scadaver.vendors.phoenix.webvisit import retrieve_passwords
    _con = _Con()
    with _con.status(f"[cyan]Retrieving passwords from {ip}\u2026"):
        passwords = retrieve_passwords(ip)
    if not passwords:
        _con.print("[yellow]No passwords retrieved.[/yellow]")
        return
    table = Table(title="WebVisit Credentials", header_style="bold red")
    table.add_column("User Level", style="white")
    table.add_column("Password / Hash", style="red bold")
    table.add_column("Type", style="dim")
    for entry in passwords:
        table.add_row(
            str(entry.get("user_level", "?")),
            entry.get("password", entry.get("hash", "?")),
            entry.get("type", ""),
        )
    _con.print(table)


def _expl_phoenix_tags() -> None:
    ip = _ask_ip()
    if not ip:
        return
    # Delegate to the full interactive TUI editor for a richer experience
    from scadaver.vendors.phoenix.tui import run_editor
    run_editor(ip)


def _expl_beckhoff_reboot() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from rich.console import Console as _Con
    from scadaver.vendors.beckhoff.webcontrol import reboot
    _con = _Con()
    with _con.status(f"[cyan]Sending reboot to {ip}\u2026"):
        reboot(ip)
    _con.print("[green]Reboot command sent.[/green]")


def _expl_beckhoff_user() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from rich.console import Console as _Con
    _con = _Con()
    user = input("Username [scadaver_admin]: ").strip() or "scadaver_admin"
    pwd = input("Password [Sc4d4v3r!]: ").strip() or "Sc4d4v3r!"
    from scadaver.vendors.beckhoff.webcontrol import add_user
    with _con.status(f"[cyan]Adding user '{user}' on {ip}\u2026"):
        add_user(ip, username=user, password=pwd)
    _con.print(f"[green]User '{user}' creation command sent.[/green]")


def _expl_beckhoff_route() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from scadaver.core.network import get_interfaces, select_interface
    from scadaver.vendors.beckhoff.route_spoof import brute_force_routes
    ifaces = get_interfaces()
    iface = select_interface(ifaces)
    cidr = input(f"CIDR to scan [{iface.ip[:iface.ip.rfind('.')]}.0/24]: ").strip()
    if not cidr:
        cidr = f"{iface.ip[:iface.ip.rfind('.')]}.0/24"
    result = brute_force_routes(
        adapter_ip=iface.ip,
        adapter_mac=iface.mac.replace(":", ""),
        target_ip=ip,
        cidr=cidr,
    )
    if result:
        print(f"Working IP: {result}")


# ===================================================================
# Entry point
# ===================================================================

def interactive_menu() -> None:
    """Launch the top-level interactive menu."""
    main_menu = [
        ("Scan for devices", _menu_scan),
        ("Control PLC / device", _menu_control),
        ("Run exploits", _menu_exploit),
        ("Quit", None),
    ]
    while True:
        idx = _prompt(main_menu, "MAIN MENU")
        handler = main_menu[idx][1]
        if handler is None:
            print("Goodbye.")
            sys.exit(0)
        handler()
