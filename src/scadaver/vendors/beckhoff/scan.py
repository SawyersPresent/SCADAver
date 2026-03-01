"""Beckhoff TwinCAT UDP device discovery and ADS management.

Broadcasts on UDP port 48899 to discover Beckhoff devices,
then provides TCP-based AMS/ADS operations: route management,
device info retrieval, state control, file browsing, and more.
"""

from __future__ import annotations

import datetime
import os
import random
import socket
import time
import xml.etree.ElementTree as ET

from scadaver.core.bytes import get_netid_as_string, ip_to_hex, reverse_bytes
from scadaver.core.network import NetworkInterface
from scadaver.vendors.beckhoff.ads import (
    build_local_netid,
    construct_ams_packet,
    parse_ads_response,
    parse_ams_response,
)

DISCOVERY_PORT = 48899
ADS_TCP_PORT = 48898
DEFAULT_TIMEOUT = 1


def _send_recv_tcp(sock: socket.socket, packet_hex: str) -> bytes:
    """Send hex packet over TCP and receive response."""
    sock.send(bytes.fromhex(packet_hex.replace(" ", "")))
    return sock.recv(4096)


def _send_udp(
    sock: socket.socket,
    ip: str,
    port: int,
    packet_hex: str,
) -> None:
    """Send hex packet via UDP."""
    sock.sendto(
        bytes.fromhex(packet_hex.replace(" ", "")),
        (ip, port),
    )


def _recv_udp(sock: socket.socket) -> tuple[bytes, tuple]:
    """Receive a UDP datagram."""
    return sock.recvfrom(1024)


def discover(
    interface: NetworkInterface,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Broadcast-discover Beckhoff TwinCAT devices.

    Args:
        interface: Local network interface.
        timeout: Seconds to wait for responses.

    Returns:
        List of device dictionaries.
    """
    local_netid = build_local_netid(interface.ip)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    sock.bind((interface.ip, 0))

    discovery_pkt = (
        "03661471 0000000001000000"
        + local_netid
        + "1027 00000000"
    )
    print(
        f"Scanning for Beckhoff devices ({timeout}s timeout)..."
    )
    _send_udp(sock, "255.255.255.255", DISCOVERY_PORT, discovery_pkt)

    raw_responses: list[tuple[bytes, tuple]] = []
    while True:
        try:
            raw_responses.append(_recv_udp(sock))
        except (socket.timeout, OSError):
            break
    sock.close()

    devices: list[dict] = []
    for data, addr in raw_responses:
        hexdata = data.hex().encode()
        netid = hexdata[24:36]
        name_len = int(hexdata[54:56] + hexdata[52:54], 16)
        name = data[28 : 27 + name_len].decode(errors="ignore")
        i = (27 + name_len) * 2 + 18

        kernel = "{}.{}.{}".format(
            int(reverse_bytes(hexdata[i : i + 8]), 16),
            int(reverse_bytes(hexdata[i + 8 : i + 16]), 16),
            int(reverse_bytes(hexdata[i + 16 : i + 24]), 16),
        )
        i = i + 24 + 528

        try:
            tc_ver = "{}.{}.{}".format(
                int(hexdata[i : i + 2], 16),
                int(hexdata[i + 2 : i + 4], 16),
                int(reverse_bytes(hexdata[i + 4 : i + 8]), 16),
            )
        except Exception:
            tc_ver = "Unknown"

        try:
            thumbprint = (
                data.split(b"\x12\x00\x41\x00")[1]
                .split(b"\x00")[0]
                .decode(errors="ignore")
                .upper()
            )
        except Exception:
            thumbprint = None

        if name:
            device = {
                "ip": addr[0],
                "name": name,
                "netid": netid.decode(),
                "netid_str": get_netid_as_string(netid.decode()),
                "tc_version": tc_ver,
                "kernel": kernel,
                "ssl_thumbprint": thumbprint,
            }
            devices.append(device)
            print(
                f"  {addr[0]}: {name} "
                f"(NetID: {device['netid_str']}, "
                f"TC: {tc_ver}, OS: {kernel})"
            )

    if not devices:
        print("No Beckhoff devices found.")

    return devices


def get_state(
    device: dict,
    local_netid: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Query the TwinCAT state of a device via ADS.

    Args:
        device: Device dictionary from discover().
        local_netid: Local AMS Net ID hex string.
        timeout: Connection timeout.

    Returns:
        State string: "RUN", "STOP", "CONFIG", or "ERROR".
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((device["ip"], ADS_TCP_PORT))
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "ERROR"

    packet = construct_ams_packet(device["netid"], local_netid, 4)
    try:
        resp = _send_recv_tcp(sock, packet).hex()
    except Exception:
        resp = ""
    sock.close()

    if len(resp) > 0:
        state_byte = resp[-8:-6]
        state_map = {"06": "STOP", "0f": "CONFIG"}
        return state_map.get(state_byte, "RUN")
    return "ERROR"


def add_route(
    device: dict,
    local_ip: str,
    local_netid: str,
    username: str = "Administrator",
    password: str = "1",
    route_name: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """Add a route on a remote Beckhoff device.

    Args:
        device: Device dictionary from discover().
        local_ip: Local IP address.
        local_netid: Local AMS Net ID hex string.
        username: Device login username.
        password: Device login password.
        route_name: Name for the route (defaults to hostname).
        timeout: Connection timeout.

    Returns:
        True if the route was added successfully.
    """
    if route_name is None:
        route_name = socket.gethostname()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.bind((local_ip, 0))

    name_len = hex(1 + len(route_name))[2:].zfill(2)
    name_hex = route_name.encode().hex()
    user_len = hex(1 + len(username))[2:].zfill(2)
    user_hex = username.encode().hex()
    pass_len = hex(1 + len(password))[2:].zfill(2)
    pass_hex = password.encode().hex()
    host_len = hex(1 + len(local_ip))[2:].zfill(2)
    host_hex = local_ip.encode().hex()

    packet = (
        "036614710000000006000000"
        + local_netid
        + "1027050000000c00"
        + name_len + "00" + name_hex + "00"
        + " 07000600" + local_netid
        + "0d00" + user_len + "00" + user_hex + "00"
        + " 0200" + pass_len + "00" + pass_hex + "00"
        + " 0500" + host_len + "00" + host_hex + "00"
    )

    print(
        f"Adding route '{route_name}' for {local_ip} "
        f"with {username}/<password>"
    )
    _send_udp(sock, device["ip"], DISCOVERY_PORT, packet)

    try:
        resp, _addr = _recv_udp(sock)
        sock.close()
        if resp[-4:] == b"\x00" * 4:
            print("Route added successfully.")
            return True
        print("Route add failed (wrong credentials?).")
        return False
    except (socket.timeout, OSError):
        sock.close()
        print("No response from device.")
        return False


def set_twincat_state(
    device: dict,
    local_netid: str,
    mode: str = "run",
    timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """Change the TwinCAT service state.

    Args:
        device: Device dictionary from discover().
        local_netid: Local AMS Net ID hex string.
        mode: "run", "stop", "config", or "reset".
        timeout: Connection timeout.

    Returns:
        True if the state change was successful.
    """
    mode_map = {
        "run": 2,
        "reset": 5,
        "stop": 6,
        "config": 16,
    }
    ads_state = mode_map.get(mode.lower())
    if ads_state is None:
        raise ValueError(
            f"Invalid mode '{mode}'. Use: run, stop, config, reset"
        )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2 * timeout)
    sock.connect((device["ip"], ADS_TCP_PORT))

    packet = construct_ams_packet(
        device["netid"], local_netid, 5, (ads_state, 0, b"")
    )
    resp = _send_recv_tcp(sock, packet)
    sock.close()

    error_code = parse_ams_response(resp)["ErrorCode"]
    if error_code != "00000000":
        print(f"State change failed (error: {error_code})")
        return False

    print(f"TwinCAT state changed to {mode.upper()}")
    return True


def get_device_info(
    device: dict,
    local_netid: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict | None:
    """Retrieve detailed device info via ADS Read.

    For TwinCAT 3 devices, reads XML containing hardware,
    OS image, and version details.

    Args:
        device: Device dictionary from discover().
        local_netid: Local AMS Net ID hex string.
        timeout: Connection timeout.

    Returns:
        Dictionary with detailed device info, or None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((device["ip"], ADS_TCP_PORT))
    except Exception:
        return None

    info: dict = {
        "ip": device["ip"],
        "name": device["name"],
        "netid": device.get("netid_str", ""),
        "tc_version": device["tc_version"],
        "kernel": device["kernel"],
    }

    if device["tc_version"].startswith("3"):
        try:
            pkt1 = construct_ams_packet(
                device["netid"], local_netid, 2, (700, 1, 4)
            )
            resp1 = _send_recv_tcp(sock, pkt1)
            resp_len = int(
                reverse_bytes(
                    parse_ads_response(
                        parse_ams_response(resp1)["ADSData"]
                    )["ADSData"]
                ),
                16,
            )

            pkt2 = construct_ams_packet(
                device["netid"], local_netid, 2,
                (700, 1, resp_len),
            )
            resp2 = _send_recv_tcp(sock, pkt2)
            xml_hex = parse_ads_response(
                parse_ams_response(resp2)["ADSData"]
            )["ADSData"]
            xml_bytes = bytes.fromhex(xml_hex).strip(b"\x00")
            root = ET.fromstring(xml_bytes)

            info["target_type"] = root[0].text
            info["target_version"] = (
                f"{root[1][0].text}.{root[1][1].text}"
                f".{root[1][2].text}"
            )
            info["hardware_model"] = root[3][0].text
            info["serial"] = root[3][1].text
            info["os_name"] = root[4][3].text
            info["os_version"] = root[4][4].text
        except Exception:
            pass

    sock.close()
    return info


def reboot_device(
    device: dict,
    local_netid: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """Reboot a Beckhoff device via ADS Write Control.

    Args:
        device: Device dictionary from discover().
        local_netid: Local AMS Net ID hex string.
        timeout: Connection timeout.

    Returns:
        True if the reboot command was acknowledged.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((device["ip"], ADS_TCP_PORT))

    packet = construct_ams_packet(
        device["netid"], local_netid, 5, (12, 1, b"")
    )
    resp = _send_recv_tcp(sock, packet)
    sock.close()

    error = parse_ams_response(resp)["ADSData"]
    if error != "00000000":
        print(f"Reboot failed (error: {error})")
        return False
    print("Reboot command sent.")
    return True


def shutdown_device(
    device: dict,
    local_netid: str,
    delay_seconds: int = 0,
    timeout: int = DEFAULT_TIMEOUT,
) -> bool:
    """Shutdown a Beckhoff device via ADS Write Control.

    Args:
        device: Device dictionary from discover().
        local_netid: Local AMS Net ID hex string.
        delay_seconds: Shutdown delay in seconds.
        timeout: Connection timeout.

    Returns:
        True if the shutdown command was acknowledged.
    """
    delay_bytes = bytes.fromhex(
        reverse_bytes(hex(delay_seconds)[2:].zfill(8))
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((device["ip"], ADS_TCP_PORT))

    packet = construct_ams_packet(
        device["netid"], local_netid, 5,
        (12, 0, delay_bytes),
    )
    resp = _send_recv_tcp(sock, packet)
    sock.close()

    error = parse_ams_response(resp)["ADSData"]
    if error != "00000000":
        print(f"Shutdown failed (error: {error})")
        return False
    print("Shutdown command sent.")
    return True
