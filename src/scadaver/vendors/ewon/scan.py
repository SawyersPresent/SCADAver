"""eWON device discovery via IPCONF broadcast protocol.

Sends broadcast packets on UDP port 1507 and listens on port 1506
for responses from eWON industrial routers.
"""

from __future__ import annotations

import os
import socket

from scadaver.core.network import NetworkInterface

DISCOVERY_PORT = 1507
RESPONSE_PORT = 1506
DEFAULT_TIMEOUT = 2

DISCOVERY_PACKETS = [
    "4950434f4e4600000000000000000000000000000000000000000000000000000000000000000000",
    "4950434f4e460000000000000000000a000000000000000000000000000000000000000000000000",
]


def parse_response(data: bytes) -> dict | None:
    """Parse an eWON IPCONF discovery response.

    Args:
        data: Raw UDP response bytes.

    Returns:
        Dictionary with device info or None.
    """
    response_type = str(data[15])
    if response_type == "2":
        return _parse_device_info(data)
    if response_type == "5":
        return _parse_firmware_info(data)
    return None


def _parse_device_info(data: bytes) -> dict:
    """Parse type-2 response containing IP, MAC, serial, product code."""
    def fromhex(b: int) -> str:
        return hex(b)[2:].zfill(2)

    ip = ".".join((
        str(data[23]), str(data[22]),
        str(data[21]), str(data[20]),
    ))
    netmask = ".".join((
        str(data[27]), str(data[26]),
        str(data[25]), str(data[24]),
    ))
    mac = ":".join((
        fromhex(data[32]), fromhex(data[33]),
        fromhex(data[34]), fromhex(data[35]),
        fromhex(data[36]), fromhex(data[37]),
    ))
    token = data[16:20].hex()
    pcode = str(data[16])

    serialp1 = str(data[19])
    serialp2 = str(
        int(int((data[18:19] + data[17:18]).hex(), 16) / 1000)
    )
    serialp3 = data[17]
    if int((data[18:19] + data[17:18]).hex(), 16) % 1000 >= 500:
        serialp3 += 0x100
    serialp4 = data[16]
    serial = f"{serialp1}{serialp2}-{str(serialp3).zfill(4)}-{serialp4}"

    return {
        "type": "device_info",
        "identifier": data[:4].decode(errors="replace"),
        "ip": ip,
        "netmask": netmask,
        "mac": mac,
        "token": token,
        "serial": serial,
        "product_code": pcode,
    }


def _parse_firmware_info(data: bytes) -> dict:
    """Parse type-5 response containing firmware version."""
    firmware = data[20:].strip(b"\x00").decode(errors="replace")
    return {
        "type": "firmware_info",
        "firmware": firmware,
    }


def scan(
    interface: NetworkInterface,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Broadcast-scan for eWON devices.

    Args:
        interface: Local network interface to send from.
        timeout: Seconds to wait for responses.

    Returns:
        List of parsed device dictionaries.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    sock.bind(("", RESPONSE_PORT))

    if os.name != "nt" and interface.raw_dev:
        sock.setsockopt(
            socket.SOL_SOCKET, 25,
            interface.raw_dev.encode()
            if isinstance(interface.raw_dev, str)
            else interface.raw_dev,
        )

    print(
        f"Sending discovery packets, waiting {timeout}s for answers..."
    )
    for pkt in DISCOVERY_PACKETS:
        sock.sendto(
            bytes.fromhex(pkt), ("255.255.255.255", DISCOVERY_PORT)
        )

    responses: list[bytes] = []
    while True:
        try:
            data, _addr = sock.recvfrom(1024)
            responses.append(data)
        except (socket.timeout, OSError):
            break

    sock.close()
    device_count = len(responses) // 2
    print(f"Got {device_count} response(s):")

    devices: list[dict] = []
    for data in responses:
        parsed = parse_response(data)
        if not parsed:
            continue
        devices.append(parsed)
        if parsed["type"] == "device_info":
            print(
                f"  - {parsed['identifier']}, {parsed['ip']}, "
                f"{parsed['netmask']}, {parsed['mac']}, "
                f"{parsed['serial']}, Pcode: {parsed['product_code']}"
            )
        elif parsed["type"] == "firmware_info":
            print(f"    Firmware: {parsed['firmware']}")

    return devices
