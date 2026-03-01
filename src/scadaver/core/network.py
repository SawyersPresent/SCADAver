"""Network interface discovery and socket helpers."""

from __future__ import annotations

import os
import socket
import subprocess
from dataclasses import dataclass


@dataclass
class NetworkInterface:
    """Represents a discovered local network interface."""

    name: str
    ip: str
    netmask: str
    mac: str = ""
    npf_device: str = ""
    raw_dev: bytes = b""


def get_interfaces() -> list[NetworkInterface]:
    """Discover local network interfaces with IP addresses.

    On Windows, parses ``ipconfig`` and ``getmac``. On Linux, parses
    ``ip address``. Returns a list of :class:`NetworkInterface` objects.
    """
    if os.name == "nt":
        return _get_interfaces_windows()
    return _get_interfaces_linux()


def _get_interfaces_windows() -> list[NetworkInterface]:
    proc = subprocess.Popen(
        'ipconfig | FINDSTR "IPv4 Address Subnet" | FINDSTR /V "IPv6"',
        shell=True,
        stdout=subprocess.PIPE,
    )
    lines = proc.stdout.readlines() if proc.stdout else []
    interfaces: list[NetworkInterface] = []
    for i in range(0, len(lines), 2):
        if i + 1 >= len(lines):
            break
        ip = lines[i].split(b":")[1].strip().decode()
        mask = lines[i + 1].split(b":")[1].strip().decode()
        interfaces.append(NetworkInterface(name=f"adapter-{len(interfaces)}", ip=ip, netmask=mask))

    # Try to enrich with MAC addresses from getmac
    try:
        proc2 = subprocess.Popen(
            "getmac /NH /V /FO csv",
            shell=True,
            stdout=subprocess.PIPE,
        )
        mac_lines = proc2.stdout.readlines() if proc2.stdout else []
        for mac_line in mac_lines:
            parts = mac_line.decode(errors="ignore").strip().strip('"').split('","')
            if len(parts) >= 4:
                mac_addr = parts[2]
                dev_name = parts[0]
                npf = parts[3] if len(parts) > 3 else ""
                # Match by position or IP
                for iface in interfaces:
                    if iface.mac == "" and mac_addr != "N/A":
                        iface.mac = mac_addr
                        iface.name = dev_name
                        iface.npf_device = npf
                        break
    except Exception:
        pass

    return interfaces


def _get_interfaces_linux() -> list[NetworkInterface]:
    proc = subprocess.Popen(
        'ip address | grep inet | grep -v "127.0.0.1" | grep -v "inet6"',
        shell=True,
        stdout=subprocess.PIPE,
    )
    interfaces: list[NetworkInterface] = []
    for line in (proc.stdout.readlines() if proc.stdout else []):
        parts = line.lstrip().split(b" ")
        ip_cidr = parts[1].split(b"/")
        ip = ip_cidr[0].decode()
        cidr = int(ip_cidr[1])
        bcidr = cidr * "1" + (32 - cidr) * "0"
        mask = (
            f"{int(bcidr[:8], 2)}.{int(bcidr[8:16], 2)}"
            f".{int(bcidr[16:24], 2)}.{int(bcidr[24:], 2)}"
        )
        dev_name = parts[-1].strip().decode()
        interfaces.append(
            NetworkInterface(
                name=dev_name,
                ip=ip,
                netmask=mask,
                raw_dev=dev_name.encode(),
            )
        )
    return interfaces


def select_interface(interfaces: list[NetworkInterface]) -> NetworkInterface:
    """Present an interactive numbered menu and return the chosen interface.

    Args:
        interfaces: List of discovered interfaces.

    Returns:
        The selected :class:`NetworkInterface`.

    Raises:
        SystemExit: If the user chooses to quit.
    """
    if not interfaces:
        raise SystemExit("No network interfaces found.")

    for idx, iface in enumerate(interfaces, 1):
        print(f"[{idx}] {iface.ip} / {iface.netmask} ({iface.name})")
    print("[Q] Quit")

    if len(interfaces) > 1:
        answer = input("Please select the adapter [1]: ").strip()
    else:
        answer = "1"

    if answer.lower() == "q":
        raise SystemExit(0)
    if not answer or not answer.isdigit() or int(answer) < 1 or int(answer) > len(interfaces):
        answer = "1"

    return interfaces[int(answer) - 1]


def create_udp_broadcast_socket(
    bind_ip: str = "",
    bind_port: int = 0,
    timeout: float = 2.0,
    interface: NetworkInterface | None = None,
) -> socket.socket:
    """Create a UDP socket configured for broadcast.

    Args:
        bind_ip: IP to bind to (empty for all interfaces).
        bind_port: Port to bind to (0 for any).
        timeout: Socket timeout in seconds.
        interface: If provided on Linux, bind to this device.

    Returns:
        Configured :class:`socket.socket`.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    if bind_ip:
        sock.bind((bind_ip, bind_port))
    elif bind_port:
        sock.bind(("", bind_port))
    if interface and os.name != "nt" and interface.raw_dev:
        sock.setsockopt(socket.SOL_SOCKET, 25, interface.raw_dev)
    return sock


def send_udp(sock: socket.socket, ip: str, port: int, hex_data: str) -> None:
    """Send a hex-encoded UDP packet.

    Args:
        sock: UDP socket.
        ip: Destination IP address.
        port: Destination port.
        hex_data: Hex string payload (spaces are stripped).
    """
    sock.sendto(bytes.fromhex(hex_data.replace(" ", "")), (ip, port))


def recv_udp(sock: socket.socket, bufsize: int = 4096) -> tuple[bytes, tuple[str, int]]:
    """Receive a UDP packet, returning data and sender address.

    Args:
        sock: UDP socket.
        bufsize: Maximum receive buffer size.

    Returns:
        Tuple of (data_bytes, (sender_ip, sender_port)).
    """
    return sock.recvfrom(bufsize)


def recv_udp_data(sock: socket.socket, bufsize: int = 1024) -> bytes:
    """Receive a UDP packet, returning only the data bytes.

    Args:
        sock: UDP socket.
        bufsize: Maximum receive buffer size.

    Returns:
        Received data bytes.
    """
    data, _ = sock.recvfrom(bufsize)
    return data


def send_tcp(sock: socket.socket, hex_data: str) -> None:
    """Send a hex-encoded TCP packet.

    Args:
        sock: Connected TCP socket.
        hex_data: Hex string payload (spaces are stripped).
    """
    sock.send(bytes.fromhex(hex_data.replace(" ", "")))


def send_recv_tcp(
    sock: socket.socket,
    hex_data: str,
    bufsize: int = 4096,
) -> bytes:
    """Send hex data over TCP and return the response.

    Args:
        sock: Connected TCP socket.
        hex_data: Hex string payload (spaces are stripped).
        bufsize: Maximum receive buffer size.

    Returns:
        Response bytes from the remote end.
    """
    sock.send(bytes.fromhex(hex_data.replace(" ", "")))
    return sock.recv(bufsize)


def send_recv_udp(
    sock: socket.socket,
    ip: str,
    port: int,
    hex_data: str,
    bufsize: int = 1024,
) -> bytes:
    """Send hex data via UDP and receive the response.

    Args:
        sock: UDP socket.
        ip: Destination IP address.
        port: Destination port.
        hex_data: Hex string payload (spaces are stripped).
        bufsize: Maximum receive buffer size.

    Returns:
        Response bytes.
    """
    sock.sendto(bytes.fromhex(hex_data.replace(" ", "")), (ip, port))
    data, _ = sock.recvfrom(bufsize)
    return data


def collect_responses(
    sock: socket.socket,
    bufsize: int = 1024,
) -> list[bytes]:
    """Collect all UDP responses until the socket times out.

    Args:
        sock: UDP socket with a timeout set.
        bufsize: Maximum receive buffer size per packet.

    Returns:
        List of received data bytes.
    """
    results: list[bytes] = []
    while True:
        try:
            data, _ = sock.recvfrom(bufsize)
            results.append(data)
        except socket.timeout:
            break
    return results


def collect_responses_with_addr(
    sock: socket.socket,
    bufsize: int = 1024,
) -> list[tuple[bytes, tuple[str, int]]]:
    """Collect all UDP responses with sender addresses until timeout.

    Args:
        sock: UDP socket with a timeout set.
        bufsize: Maximum receive buffer size per packet.

    Returns:
        List of (data_bytes, (sender_ip, sender_port)) tuples.
    """
    results: list[tuple[bytes, tuple[str, int]]] = []
    while True:
        try:
            data, addr = sock.recvfrom(bufsize)
            results.append((data, addr))
        except socket.timeout:
            break
    return results


def calculate_broadcast(ip: str, netmask: str) -> str:
    """Calculate the broadcast address for a given IP and subnet mask.

    Args:
        ip: IPv4 address string.
        netmask: Subnet mask string.

    Returns:
        Broadcast address string.
    """
    ip_parts = [int(x) for x in ip.split(".")]
    mask_parts = [int(x) for x in netmask.split(".")]
    return ".".join(
        str(ip_parts[i] | (255 - mask_parts[i])) for i in range(4)
    )
