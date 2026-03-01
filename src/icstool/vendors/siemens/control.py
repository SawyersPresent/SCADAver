"""High-level Siemens PLC control operations.

Wraps :mod:`icstool.vendors.siemens.s7comm` functions with
user-friendly interfaces for the CLI layer.
"""

from __future__ import annotations

from icstool.vendors.siemens.s7comm import (
    change_cpu_state,
    get_cpu_state,
    read_all_data,
    set_merkers,
    set_outputs,
)


def read_io(ip: str, port: int = 102) -> dict:
    """Read all inputs, outputs, and merkers from an S7 PLC.

    Args:
        ip: Target device IP address.
        port: S7Comm port (default 102).

    Returns:
        Dict with ``'inputs'``, ``'outputs'``, ``'merkers'`` keys,
        each mapping to a bit-value dict or None on error.
    """
    return read_all_data(ip, port)


def write_outputs(
    ip: str,
    bits: str,
    port: int = 102,
) -> bool:
    """Write an 8-bit binary pattern to PLC outputs.

    Args:
        ip: Target device IP.
        bits: Binary string, e.g. ``'10110000'``.
        port: S7Comm port (default 102).

    Returns:
        True on success.
    """
    return set_outputs(ip, bits, port)


def write_merkers(
    ip: str,
    bits: str,
    offset: int = 0,
    port: int = 102,
) -> bool:
    """Write an 8-bit binary pattern to PLC merkers.

    Args:
        ip: Target device IP.
        bits: Binary string, e.g. ``'01010101'``.
        offset: Merker byte offset.
        port: S7Comm port (default 102).

    Returns:
        True on success.
    """
    return set_merkers(ip, bits, offset, port)


def flip_cpu(ip: str, port: int = 102) -> bool:
    """Toggle the PLC CPU state between Running and Stopped.

    Args:
        ip: Target device IP.
        port: S7Comm port (default 102).

    Returns:
        True if the state change succeeded.
    """
    return change_cpu_state(ip, port)


def cpu_state(ip: str, port: int = 102) -> str:
    """Get the current CPU state as a string.

    Args:
        ip: Target device IP.
        port: S7Comm port (default 102).

    Returns:
        ``'Running'``, ``'Stopped'``, or ``'Unknown'``.
    """
    return get_cpu_state(ip, port)
