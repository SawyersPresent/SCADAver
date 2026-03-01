"""Mitsubishi MELSEC PLC discovery via GX Works broadcast protocol.

Scans for Mitsubishi PLCs using the same discovery packets as
GX Works V3 software. Broadcasts on UDP port 5561.
"""

from __future__ import annotations

import os
import socket

from icstool.core.network import NetworkInterface

DISCOVERY_PORT = 5561
DISCOVERY_PACKET = (
    "57010000001111070000ffff030000fe0300001e001c"
    "0a161400000000000000000000000000000000000000"
    "00000b2001000000"
)
DEFAULT_TIMEOUT = 2


def _parse_device(data: bytes, ip: str) -> dict:
    """Parse a GX Works discovery response.

    Args:
        data: Raw UDP response bytes.
        ip: Source IP of the response.

    Returns:
        Dictionary with device info.
    """
    optional_data = data.split(b"   ")[2] if len(data.split(b"   ")) > 2 else b""

    title = ""
    comment = ""
    try:
        len1 = optional_data[0]
        title = optional_data[6 : 6 + len1].decode("utf-16")
    except Exception:
        pass

    try:
        len2 = optional_data[2]
        comment = optional_data[6 + len1 : 6 + len1 + len2].decode("utf-16")
    except Exception:
        pass

    try:
        device_type = data.split(b"   ")[1].decode()
    except Exception:
        device_type = "Unknown"

    return {
        "ip": ip,
        "type": device_type,
        "title": title,
        "comment": comment,
    }


def scan(
    interface: NetworkInterface,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Broadcast-scan for Mitsubishi MELSEC PLCs.

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

    if os.name == "nt":
        sock.bind((interface.ip, 0))
    elif interface.raw_dev:
        raw = (
            interface.raw_dev.encode()
            if isinstance(interface.raw_dev, str)
            else interface.raw_dev
        )
        sock.setsockopt(socket.SOL_SOCKET, 25, raw)

    print(f"Scanning for Mitsubishi devices ({timeout}s timeout)...")
    sock.sendto(
        bytes.fromhex(DISCOVERY_PACKET.replace(" ", "")),
        ("255.255.255.255", DISCOVERY_PORT),
    )

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
        device = _parse_device(data, addr[0])
        devices.append(device)
        extra = ""
        if device["title"]:
            extra += f"CPU Title: {device['title']}"
        if device["comment"]:
            extra += f", Comment: {device['comment']}"
        print(
            f"  Found {device['type']} at {device['ip']}"
            + (f" ({extra})" if extra else "")
        )

    if not devices:
        print("No Mitsubishi devices found.")

    return devices
