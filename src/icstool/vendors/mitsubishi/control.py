"""Mitsubishi MELSEC PLC state control via broadcast.

Sends RUN, STOP, or PAUSE commands to Mitsubishi PLCs
over UDP broadcast on port 5560. Verified on FX5U-32M.
"""

from __future__ import annotations

import os
import socket

from icstool.core.network import NetworkInterface

CONTROL_PORT = 5560
DEFAULT_TIMEOUT = 4

# Initialization handshake packets
_INIT_PACKETS = [
    ("5a000001", True),
    ("5a000001", True),
    ("5a000022", True),
    ("5a000001", True),
    ("5a000011", True),
    ("5a0000ff", True),
    (
        "57010000001111070000ffff030000fe03000020001c"
        "0a161400000000000000000000000000000000000000"
        "000001210100000000"
        "01",
        True,
    ),
    (
        "57010000001111070000ffff030000fe03000023001c"
        "0a161400000000000000000000000000000000000000"
        "000001a0020000000854067dc9",
        True,
    ),
]

# Control command packets
_CMD_STOP = (
    "57010000001111070000ffff030000fe03000020001c"
    "0a161400000000000000000000000000000000000000"
    "001002090000000100"
)
_CMD_PAUSE = (
    "57010000001111070000ffff030000fe03000020001c"
    "0a161400000000000000000000000000000000000000"
    "001003090000000100"
)
_CMD_RUN = (
    "57010000001111070000ffff030000fe03000022001c"
    "0a161400000000000000000000000000000000000000"
    "0010010900000001000000"
)


def _create_socket(
    interface: NetworkInterface,
) -> socket.socket:
    """Create and configure the broadcast UDP socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(DEFAULT_TIMEOUT)

    if os.name == "nt":
        sock.bind((interface.ip, 0))
    elif interface.raw_dev:
        raw = (
            interface.raw_dev.encode()
            if isinstance(interface.raw_dev, str)
            else interface.raw_dev
        )
        sock.setsockopt(socket.SOL_SOCKET, 25, raw)

    return sock


def _send_and_recv(
    sock: socket.socket,
    packet_hex: str,
) -> bytes:
    """Send a hex packet via broadcast and await a response."""
    data = bytes.fromhex(packet_hex.replace(" ", ""))
    sock.sendto(data, ("255.255.255.255", CONTROL_PORT))
    resp, _addr = sock.recvfrom(1024)
    return resp


def init_connection(interface: NetworkInterface) -> None:
    """Perform the initialization handshake with the PLC.

    This registers the source IP with the PLC. Only needed
    once per boot cycle or source IP change.

    Args:
        interface: Local network interface.
    """
    sock = _create_socket(interface)
    for pkt_hex, expect_resp in _INIT_PACKETS:
        clean = pkt_hex.replace(" ", "")
        data = bytes.fromhex(clean)
        sock.sendto(data, ("255.255.255.255", CONTROL_PORT))
        if expect_resp:
            try:
                _send_and_recv(sock, clean)
            except (socket.timeout, OSError):
                pass
    sock.close()


def set_state(
    interface: NetworkInterface,
    action: str = "run",
) -> bool:
    """Send a RUN, STOP, or PAUSE command to the PLC.

    Args:
        interface: Local network interface.
        action: One of "run", "stop", "pause".

    Returns:
        True if the device acknowledged the command.
    """
    cmd_map = {
        "stop": _CMD_STOP,
        "pause": _CMD_PAUSE,
        "run": _CMD_RUN,
    }
    packet = cmd_map.get(action.lower())
    if not packet:
        raise ValueError(
            f"Invalid action '{action}'. Use: run, stop, pause"
        )

    print("Initializing connection...")
    init_connection(interface)

    print(f"Sending {action.upper()} command...")
    sock = _create_socket(interface)
    try:
        resp = _send_and_recv(sock, packet)
        success = resp.hex()[-8:] == "09000000"
        if success:
            print("Command acknowledged by PLC.")
        else:
            print("Unexpected response from PLC.")
        return success
    except (socket.timeout, OSError) as exc:
        print(f"No response from PLC: {exc}")
        return False
    finally:
        sock.close()
