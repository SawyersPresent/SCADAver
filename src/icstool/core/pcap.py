"""Thin ctypes wrapper around WinPcap/Npcap (Windows) or libpcap (Linux).

Provides raw Ethernet frame send/receive for protocols that need Layer 2
access (e.g., Profinet DCP in the Siemens module).
"""

from __future__ import annotations

import os
from ctypes import (
    CDLL,
    POINTER,
    Structure,
    byref,
    c_char,
    c_char_p,
    c_int,
    c_long,
    c_ubyte,
    c_uint,
    c_ushort,
    c_void_p,
    create_string_buffer,
)
from ctypes.util import find_library


# ---------------------------------------------------------------------------
# Pcap C struct definitions
# ---------------------------------------------------------------------------

class SockAddr(Structure):
    _fields_ = [("sa_family", c_ushort), ("sa_data", c_char * 14)]


class PcapAddr(Structure):
    pass


PcapAddr._fields_ = [
    ("next", POINTER(PcapAddr)),
    ("addr", POINTER(SockAddr)),
    ("netmask", POINTER(SockAddr)),
    ("broadaddr", POINTER(SockAddr)),
    ("dstaddr", POINTER(SockAddr)),
]


class PcapIf(Structure):
    pass


PcapIf._fields_ = [
    ("next", POINTER(PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", POINTER(PcapAddr)),
    ("flags", c_int),
]


class Timeval(Structure):
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


class PcapPkthdr(Structure):
    _fields_ = [
        ("ts", Timeval),
        ("caplen", c_uint),
        ("len", c_uint),
    ]


# ---------------------------------------------------------------------------
# Library loader
# ---------------------------------------------------------------------------

_lib: CDLL | None = None


def _load_pcap() -> CDLL:
    """Load the pcap shared library for the current platform.

    Returns:
        The loaded CDLL instance.

    Raises:
        SystemExit: If the library cannot be found.
    """
    global _lib
    if _lib is not None:
        return _lib

    if os.name == "nt":
        for dll_name in ("wpcap", "npcap\\wpcap"):
            try:
                _lib = CDLL(dll_name)
                return _lib
            except OSError:
                continue
        # Try with Npcap SDK path
        npcap_path = os.path.join(os.environ.get("SYSTEMROOT", r"C:\Windows"), "System32", "Npcap")
        if os.path.isdir(npcap_path):
            try:
                _lib = CDLL(os.path.join(npcap_path, "wpcap.dll"))
                return _lib
            except OSError:
                pass
        raise SystemExit(
            "Cannot load WinPcap/Npcap: install Npcap from https://npcap.com "
            "(enable WinPCAP compatibility mode)"
        )
    else:
        lib_path = find_library("pcap")
        if lib_path is None:
            raise SystemExit("Cannot find libpcap: install libpcap-dev")
        _lib = CDLL(lib_path)
        return _lib


def get_pcap_lib() -> CDLL:
    """Return the loaded pcap CDLL, loading it on first call.

    Returns:
        The pcap CDLL instance.
    """
    return _load_pcap()


# ---------------------------------------------------------------------------
# High-level helpers
# ---------------------------------------------------------------------------

def pcap_find_all_devs() -> list[tuple[str, str]]:
    """List all pcap-visible network devices.

    Returns:
        List of (device_name, description) tuples.
    """
    lib = get_pcap_lib()
    lib.pcap_findalldevs.restype = c_int
    lib.pcap_findalldevs.argtypes = [POINTER(POINTER(PcapIf)), c_char_p]

    alldevs = POINTER(PcapIf)()
    errbuf = create_string_buffer(256)
    if lib.pcap_findalldevs(byref(alldevs), errbuf) == -1:
        raise RuntimeError(f"pcap_findalldevs failed: {errbuf.value.decode()}")

    devices: list[tuple[str, str]] = []
    dev = alldevs
    while dev:
        name = dev.contents.name.decode() if dev.contents.name else ""
        desc = dev.contents.description.decode() if dev.contents.description else ""
        devices.append((name, desc))
        dev = dev.contents.next

    lib.pcap_freealldevs(alldevs)
    return devices


def pcap_open(device: str, snaplen: int = 65536, promisc: int = 1, timeout_ms: int = 1000):
    """Open a pcap device for capture/send.

    Args:
        device: Device name (e.g., NPF GUID or ``eth0``).
        snaplen: Snapshot length.
        promisc: Promiscuous mode (1=yes).
        timeout_ms: Read timeout in milliseconds.

    Returns:
        Pcap handle (ctypes pointer).

    Raises:
        RuntimeError: If the device cannot be opened.
    """
    lib = get_pcap_lib()
    lib.pcap_open_live.restype = POINTER(c_void_p)
    lib.pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]

    errbuf = create_string_buffer(256)
    handle = lib.pcap_open_live(
        device.encode(), snaplen, promisc, timeout_ms, errbuf
    )
    if not handle:
        raise RuntimeError(f"pcap_open_live failed: {errbuf.value.decode()}")
    return handle


def pcap_send(handle, packet_bytes: bytes) -> None:
    """Send a raw Ethernet frame.

    Args:
        handle: Pcap handle from :func:`pcap_open`.
        packet_bytes: Complete Ethernet frame bytes.

    Raises:
        RuntimeError: If sending fails.
    """
    lib = get_pcap_lib()
    lib.pcap_sendpacket.restype = c_int
    lib.pcap_sendpacket.argtypes = [POINTER(c_void_p), POINTER(c_ubyte), c_int]

    pkt_array = (c_ubyte * len(packet_bytes))(*packet_bytes)
    if lib.pcap_sendpacket(handle, pkt_array, len(packet_bytes)) != 0:
        raise RuntimeError("pcap_sendpacket failed")


def pcap_next(handle) -> tuple[bytes, int] | None:
    """Receive the next packet from a pcap handle.

    Args:
        handle: Pcap handle from :func:`pcap_open`.

    Returns:
        Tuple of (packet_bytes, capture_length), or None if timeout.
    """
    lib = get_pcap_lib()
    lib.pcap_next_ex.restype = c_int
    lib.pcap_next_ex.argtypes = [
        POINTER(c_void_p),
        POINTER(POINTER(PcapPkthdr)),
        POINTER(POINTER(c_ubyte)),
    ]

    header = POINTER(PcapPkthdr)()
    pkt_data = POINTER(c_ubyte)()
    result = lib.pcap_next_ex(handle, byref(header), byref(pkt_data))
    if result == 1:
        caplen = header.contents.caplen
        raw = bytes(pkt_data[i] for i in range(caplen))
        return raw, caplen
    return None


def pcap_close(handle) -> None:
    """Close a pcap handle.

    Args:
        handle: Pcap handle from :func:`pcap_open`.
    """
    lib = get_pcap_lib()
    lib.pcap_close.restype = None
    lib.pcap_close.argtypes = [POINTER(c_void_p)]
    lib.pcap_close(handle)
