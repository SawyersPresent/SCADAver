"""Schneider Electric PLC discovery via proprietary UDP protocol.

Scans the local subnet on UDP port 1740 for Schneider devices.
"""

from __future__ import annotations

import socket

from icstool.core.network import NetworkInterface, calculate_broadcast

DEST_PORT = 1740
SOURCE_PORT = 1740
DEFAULT_TIMEOUT = 3


def _build_discovery_packet(
    src_ip: str,
    subnet: str,
) -> str:
    """Build a Schneider discovery broadcast packet.

    Args:
        src_ip: Local source IP address.
        subnet: Local subnet mask.

    Returns:
        Hex string of the discovery packet.
    """
    b_parts = []
    for i in range(4):
        val = int(src_ip.split(".")[i]) & (
            255 - int(subnet.split(".")[i])
        )
        b_parts.append(hex(val)[2:].zfill(2))

    return (
        "c574400300003d7d"
        + "".join(b_parts)
        + "9000000002c203013b540000"
    ).replace(" ", "")


def scan(
    interface: NetworkInterface,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Broadcast-scan for Schneider Electric devices.

    Args:
        interface: Local network interface.
        timeout: Seconds to wait for responses.

    Returns:
        List of parsed device dictionaries.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    sock.bind((interface.ip, SOURCE_PORT))

    broadcast = calculate_broadcast(interface.ip, interface.netmask)
    packet = _build_discovery_packet(interface.ip, interface.netmask)

    print(
        f"Sending discovery packets, waiting {timeout}s for answers..."
    )
    sock.sendto(bytes.fromhex(packet), (broadcast, DEST_PORT))

    raw_responses: list[tuple[bytes, tuple[str, int]]] = []
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            raw_responses.append((data, addr))
        except (socket.timeout, OSError):
            break

    sock.close()

    devices: list[dict] = []
    for data, addr in raw_responses:
        if addr[0] == interface.ip:
            continue

        hexdata = data.hex()
        device: dict = {"ip": addr[0]}

        if len(hexdata) > 100:
            firmware = ".".join((
                str(int(hexdata[102:104], 16)),
                str(int(hexdata[100:102], 16)),
                str(int(hexdata[98:100], 16)),
                str(int(hexdata[96:98], 16)),
            ))
            raw_name = bytes.fromhex(hexdata[104:])
            name = (
                raw_name.replace(b"\x00\x00", b" ")
                .replace(b"\x00", b"")
                .decode(errors="replace")
            )
            device["firmware"] = firmware
            device["name"] = name
            print(f"  {addr[0]}: {name} (firmware {firmware})")
        else:
            print(f"  {addr[0]}: (short response)")

        devices.append(device)

    if not devices:
        print("No Schneider devices found.")
    else:
        print(f"Found {len(devices)} device(s).")

    return devices
