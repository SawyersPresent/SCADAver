"""Siemens S7Comm protocol helpers for S7-1200/1500 devices.

By sawyerspresent.

Provides COTP connection setup, S7Comm read/write for inputs,
outputs and merkers, CPU state query and toggling, and device
information retrieval via COTP introspection.
"""

from __future__ import annotations

import socket
import string
from binascii import hexlify, unhexlify

S7_PORT = 102
BUFFER_SIZE = 65000

# ---------------------------------------------------------------------------
# COTP / connection helpers
# ---------------------------------------------------------------------------

def _send_recv(
    sock: socket.socket,
    hex_data: str,
    *,
    send_only: bool = False,
) -> bytes:
    """Send raw hex data over a connected TCP socket and recv response.

    Args:
        sock: Connected TCP socket.
        hex_data: Hex string payload (spaces are stripped).
        send_only: If True, do not wait for a response.

    Returns:
        Response bytes (empty if *send_only*).
    """
    sock.send(unhexlify(hex_data.replace(" ", "").lower()))
    if send_only:
        return b""
    return sock.recv(BUFFER_SIZE)


def setup_connection(ip: str, port: int = S7_PORT) -> socket.socket | None:
    """Establish a COTP + S7Comm session to a Siemens PLC.

    Performs TCP connect, COTP Connection Request, and S7Comm
    Setup Communication. Returns a connected socket ready for
    S7Comm operations.

    Args:
        ip: Target IPv4 address.
        port: Target TCP port (default 102).

    Returns:
        Connected socket, or None on failure.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        # COTP Connection Request
        cotp_resp = hexlify(
            _send_recv(
                sock,
                "03000016"
                "11e00000000100c0010ac1020100c2020101",
            )
        ).decode(errors="ignore")
        if cotp_resp[10:12] != "d0":
            print(f"COTP sync failed for {ip}:{port}")
            sock.close()
            return None

        # S7Comm Setup Communication
        s7_resp = hexlify(
            _send_recv(
                sock,
                "03000019"
                "02f080"
                "32010000722f00080000f0000001000101e0",
            )
        ).decode(errors="ignore")
        if s7_resp[18:20] != "00":
            print(f"S7Comm setup failed for {ip}:{port}")
            sock.close()
            return None

        return sock
    except Exception as exc:
        print(f"Connection error {ip}:{port} — {exc}")
        return None


# ---------------------------------------------------------------------------
# I/O read: inputs, outputs, merkers
# ---------------------------------------------------------------------------

def _parse_coil_data(
    s7_hex: str,
    label: str,
    num_words: int = 4,
) -> dict[str, int] | None:
    """Parse an S7Comm Read Var response into bit values.

    Args:
        s7_hex: Hex-decoded S7Comm response (string).
        label: Data area label (for error messages).
        num_words: Number of bytes to read (default 4 = DWord).

    Returns:
        Dict mapping ``'<byte>.<bit>'`` to ``0`` or ``1``,
        or None on error.
    """
    if s7_hex[18:20] != "00":
        print(f"S7Comm error reading {label}: {s7_hex}")
        return None

    s7_data = s7_hex[14:]
    data_length = int(s7_data[16:20], 16)
    items = s7_data[28 : 28 + data_length * 2]
    if items[:2] != "ff":
        print(f"S7Comm item error reading {label}: {s7_data}")
        return None

    result: dict[str, int] = {}
    for i in range(num_words):
        offset1 = (num_words - i) * -2
        offset2 = offset1 + 2
        if offset2 == 0:
            offset2 = None
        byte_val = int(items[offset1:offset2], 16)
        for bit in range(8):
            val = 1 if byte_val & (1 << bit) else 0
            result[f"{i}.{bit}"] = val
    return result


def read_all_data(
    ip: str,
    port: int = S7_PORT,
) -> dict[str, dict[str, int] | None]:
    """Read inputs, outputs, and merkers from an S7 PLC.

    Args:
        ip: Target device IP.
        port: S7Comm port (default 102).

    Returns:
        Dict with keys ``'inputs'``, ``'outputs'``, ``'merkers'``,
        each mapping to a bit-value dict or None on error.
    """
    sock = setup_connection(ip, port)
    if sock is None:
        return {"inputs": None, "outputs": None, "merkers": None}

    # Base packet: TPKT + COTP + S7Comm Read Var (DWord, 1 item)
    base = (
        "0300001f02f080"
        "32010000732f000e00000401120a10"
        "06000100008{area}000000"
    )
    result: dict[str, dict[str, int] | None] = {}
    try:
        for label, area in [
            ("inputs", "1"),
            ("outputs", "2"),
            ("merkers", "3"),
        ]:
            resp = hexlify(
                _send_recv(sock, base.format(area=area))
            ).decode(errors="ignore")
            result[label] = _parse_coil_data(resp, label)
    finally:
        sock.close()
    return result


# ---------------------------------------------------------------------------
# I/O write: outputs, merkers
# ---------------------------------------------------------------------------

def _bits_to_hex(binary_str: str) -> str:
    """Convert a binary string (e.g. ``'10110000'``) to two-char hex.

    The string is reversed first (LSB-first order matches bit layout).
    """
    reversed_bits = binary_str[::-1]
    h = hex(int(reversed_bits, 2))[2:]
    return h.zfill(2)


def set_outputs(
    ip: str,
    binary_str: str,
    port: int = S7_PORT,
) -> bool:
    """Write output bits to an S7 PLC.

    Args:
        ip: Target device IP.
        binary_str: 8-character binary string, e.g. ``'11000000'``.
        port: S7Comm port (default 102).

    Returns:
        True on success, False on failure.
    """
    binary_str = binary_str[:8].ljust(8, "0")
    hex_val = _bits_to_hex(binary_str)
    sock = setup_connection(ip, port)
    if sock is None:
        return False

    try:
        resp = hexlify(
            _send_recv(
                sock,
                "03000024"
                "02f080"
                "32010000732f000e00050501120a"
                "1002000100008200000000040008"
                + hex_val,
            )
        ).decode(errors="ignore")
        return resp[-2:] == "ff"
    finally:
        sock.close()


def set_merkers(
    ip: str,
    binary_str: str,
    offset: int = 0,
    port: int = S7_PORT,
) -> bool:
    """Write merker bits at a given byte offset on an S7 PLC.

    Args:
        ip: Target device IP.
        binary_str: 8-character binary string.
        offset: Merker byte offset (default 0).
        port: S7Comm port (default 102).

    Returns:
        True on success, False on failure.
    """
    binary_str = binary_str[:8].ljust(8, "0")
    hex_val = _bits_to_hex(binary_str)

    # Convert byte offset to bit address in hex
    bit_addr = bin(offset) + "000"
    merker_offset = hex(int(bit_addr[2:], 2))[2:].zfill(6)

    sock = setup_connection(ip, port)
    if sock is None:
        return False

    try:
        resp = hexlify(
            _send_recv(
                sock,
                "03000025"
                "02f080"
                "320100001500000e00060501120a"
                "100400010000 83 "
                + merker_offset
                + "00 04 0010"
                + hex_val
                + "00",
            )
        ).decode(errors="ignore")
        return resp[-2:] == "ff"
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# CPU state management
# ---------------------------------------------------------------------------

def get_cpu_state(ip: str, port: int = S7_PORT) -> str:
    """Query the CPU operating state of an S7 PLC.

    Args:
        ip: Target device IP.
        port: S7Comm connection port.

    Returns:
        ``'Running'``, ``'Stopped'``, or ``'Unknown'``.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))

        # COTP CR
        cotp = hexlify(
            _send_recv(
                sock,
                "03000016"
                "11e00000001d00c1020100c2020100c0010a",
            )
        ).decode(errors="ignore")
        if cotp[10:12] != "d0":
            sock.close()
            return "Unknown"

        # S7 Setup
        setup_data = "32010000020000080000f0000001000101e0"
        tpkt_len = hex(int((len(setup_data) + 14) / 2))[2:]
        _send_recv(sock, f"030000{tpkt_len}02f080{setup_data}")

        # S7 Read CPU State
        read_data = (
            "3207000005000008000800011204"
            "11440100ff09000404240001"
        )
        tpkt_len = hex(
            int((len(read_data.replace(" ", "")) + 14) / 2)
        )[2:]
        resp = _send_recv(
            sock, f"030000{tpkt_len}02f080{read_data}"
        )

        state = hexlify(resp[44:45]).decode(errors="ignore")
        sock.close()
        return "Stopped" if state == "03" else "Running"
    except Exception:
        return "Unknown"


def change_cpu_state(ip: str, port: int = S7_PORT) -> bool:
    """Toggle the CPU state between Running and Stopped.

    If currently Running → Stop; if Stopped → Start.

    Args:
        ip: Target device IP.
        port: S7Comm port (default 102).

    Returns:
        True on success, False on failure.
    """
    cur_state = get_cpu_state(ip, port)
    if cur_state == "Unknown":
        print("Cannot determine CPU state, aborting")
        return False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))

        # COTP CR
        _send_recv(
            sock,
            "03000016"
            "11e00000002500c1020600c2020600c0010a",
        )

        # SubscriptionContainer
        resp = hexlify(
            _send_recv(
                sock,
                "030000c002f080"
                "720100b131000004ca0000000200000120360000011d"
                "00040000000000a1000000d3821f0000a38169001516"
                "53657276657253657373696f6e5f45364635343835"
                "3434a3822100150b313a3a3a362e303a3a3a12a382"
                "2800150d4f4d532b204465627567676572a382290015"
                "00a3822a001500a3822b00048480808000a3822c0012"
                "11e1a300a3822d001500a1000000d3817f0000a38169"
                "001515537562736372697074696f6e436f6e7461696e"
                "6572a2a20000000072010000",
            )
        ).decode(errors="ignore")

        sid_byte = int("0" + resp[48:50], 16) + 0x80
        sid = hex(sid_byte).replace("0x", "").zfill(2)

        # Start or Stop command byte
        if cur_state == "Stopped":
            cmd_byte = "ce"
        else:
            cmd_byte = "88"

        _send_recv(
            sock,
            f"0300007802f080"
            f"72020069310000054200000003000003{sid}"
            f"34000003 {cmd_byte} 010182320100170000013a823b0004"
            f"8140823c00048140823d000400823e00048480c040"
            f"823f0015008240001506323b31303538824100030003"
            f"0000000004e88969001200000000896a001300896b"
            f"000400000000000072020000",
        )

        _send_recv(
            sock,
            f"0300002b02f080"
            f"7202001c31000004bb00000005000003{sid}"
            f"34000000010000000000000000000072020000",
        )

        _send_recv(
            sock,
            f"0300002b02f080"
            f"7202001c31000004bb00000006000003{sid}"
            f"34000000020001010000000000000072020000",
        )

        # Drain responses
        for _ in range(10):
            try:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    break
            except socket.timeout:
                break
            except Exception:
                break

        try:
            _send_recv(
                sock,
                f"0300004202f080"
                f"7202003331000004fc00000007000003{sid}"
                f"360000003402913d9b1e000004e88969001200"
                f"000000896a001300896b0004000000000000"
                f"0072020000",
            )
        except Exception:
            sock.close()
            return False

        # Final state-change packet
        if cur_state == "Stopped":
            action_byte = "03"
        else:
            action_byte = "01"

        _send_recv(
            sock,
            f"0300004302f080"
            f"7202003431000004f200000008000003{sid}"
            f"36000000340190770008 {action_byte} 000004e889690012"
            f"00000000896a001300896b000400000000000000"
            f"72020000",
        )

        _send_recv(
            sock,
            f"0300003d02f080"
            f"7202002e31000004d40000000a000003{sid}"
            f"34000003d000000004e88969001200000000896a"
            f"001300896b000400000000000072020000",
        )

        sock.close()
        return True
    except Exception as exc:
        print(f"Error changing CPU state: {exc}")
        return False


# ---------------------------------------------------------------------------
# Device info via COTP
# ---------------------------------------------------------------------------

def get_device_info_cotp(
    ip: str,
    port: int = S7_PORT,
) -> dict[str, str | None]:
    """Retrieve hardware/firmware info via COTP introspection.

    Args:
        ip: Target device IP.
        port: S7Comm port (default 102).

    Returns:
        Dict with ``'hardware'``, ``'firmware'``, ``'cpu_state'`` keys.
    """
    info: dict[str, str | None] = {
        "hardware": None,
        "firmware": None,
        "cpu_state": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        cotp_resp = hexlify(
            _send_recv(
                sock,
                "03000016"
                "11e00000000500c1020600c2020600c0010a",
            )
        ).decode(errors="ignore")
        if cotp_resp[10:12] != "d0":
            sock.close()
            return info

        data = (
            "720100b131000004ca0000000200000120360000011d"
            "00040000000000a1000000d3821f0000a38169001516"
            "53657276657253657373696f6e5f37423637434333"
            "41a3822100150b313a3a3a362e303a3a3a12a38228"
            "00150d4f4d532b204465627567676572a382290015"
            "00a3822a001500a3822b00048480808000a3822c0012"
            "11e1a304a3822d001500a1000000d3817f0000a38169"
            "001515537562736372697074696f6e436f6e7461696e"
            "6572a2a20000000072010000"
        )
        tpkt_len = hex(int((len(data) + 14) / 2))[2:]
        cotp_data = _send_recv(
            sock, f"030000{tpkt_len}02f080{data}"
        ).decode(errors="ignore")

        parts = cotp_data.split(";")
        if len(parts) >= 4:
            info["hardware"] = parts[2]
            firmware = "".join(
                c for c in parts[3].replace("@", ".")
                if c in string.printable
            )
            info["firmware"] = firmware

        sock.close()
    except Exception:
        pass

    info["cpu_state"] = get_cpu_state(ip, port)
    return info


def scan_port(ip: str, port: int) -> bool:
    """Check if a TCP port is open on the target.

    Args:
        ip: Target IP address.
        port: Port to check.

    Returns:
        True if the port is open.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((ip, port))
        sock.close()
        return True
    except Exception:
        return False


def tcp_scan(ip: str) -> list[int]:
    """Scan common ICS ports on a Siemens device.

    Checks ports 102 (S7Comm) and 502 (Modbus).

    Args:
        ip: Target IP address.

    Returns:
        List of open port numbers.
    """
    ports = []
    if scan_port(ip, 102):
        ports.append(102)
    if scan_port(ip, 502):
        ports.append(502)
    return ports
