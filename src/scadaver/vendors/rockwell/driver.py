"""Rockwell Allen-Bradley Logix PLC driver wrapper.

Wraps pycomm3 LogixDriver for tag discovery, read/write, and monitoring.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


DATA_DIR = Path("data")


class RockwellError(Exception):
    """Raised when communication with a Rockwell Logix PLC fails."""


@contextmanager
def _connect(ip: str, **kwargs):
    """Open a LogixDriver connection, translating pycomm3 errors to RockwellError.

    Args:
        ip: PLC IP address.
        **kwargs: Forwarded to LogixDriver.

    Raises:
        RockwellError: On any connection or protocol failure.
    """
    from pycomm3 import LogixDriver
    from pycomm3.exceptions import CommError, ResponseError

    try:
        with LogixDriver(ip, **kwargs) as plc:
            yield plc
    except (ResponseError, CommError) as exc:
        raise RockwellError(str(exc)) from exc
    except Exception as exc:
        raise RockwellError(f"Unexpected error communicating with {ip}: {exc}") from exc


class RockwellPLC:
    """High-level interface to a Rockwell Logix PLC via pycomm3."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        DATA_DIR.mkdir(exist_ok=True)
        self._tags_file = DATA_DIR / f"tags_{ip.replace('.', '_')}.json"
        self._changes_file = DATA_DIR / f"changes_{ip.replace('.', '_')}.json"
        self.tags: list[str] = []
        self._previous: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Tag discovery
    # ------------------------------------------------------------------

    def discover_tags(self) -> list[str]:
        """Connect and discover all tags from the PLC. Saves to disk.

        Returns:
            Sorted list of tag names.

        Raises:
            RockwellError: If the PLC is unreachable or rejects the request.
        """
        with _connect(self.ip, init_tags=True) as plc:
            self.tags = sorted(list(plc.tags))
        self._tags_file.write_text(json.dumps(self.tags, indent=2))
        return self.tags

    def load_tags(self) -> list[str]:
        """Load tag list from saved file, discovering if not present.

        Returns:
            Sorted list of tag names.
        """
        if self._tags_file.exists():
            self.tags = json.loads(self._tags_file.read_text())
            return self.tags
        return self.discover_tags()

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    def read_all(self) -> dict[str, Any]:
        """Read current values of all known tags.

        Returns:
            Dict mapping tag name to value or "ERROR: <msg>".

        Raises:
            RockwellError: If the PLC connection fails.
        """
        if not self.tags:
            self.load_tags()
        results: dict[str, Any] = {}
        with _connect(self.ip) as plc:
            responses = plc.read(*self.tags)
            # pycomm3 returns a single Tag when only one tag is read
            if not isinstance(responses, (list, tuple)):
                responses = [responses]
            for tag, res in zip(self.tags, responses):
                results[tag] = res.value if res.error is None else f"ERROR: {res.error}"
        return results

    def read_tag(self, tag: str) -> Any:
        """Read a single tag.

        Args:
            tag: Tag name.

        Returns:
            Tag value, or "ERROR: <msg>" string on failure.

        Raises:
            RockwellError: If the PLC connection fails.
        """
        with _connect(self.ip) as plc:
            res = plc.read(tag)
            return res.value if res.error is None else f"ERROR: {res.error}"

    def write_tag(self, tag: str, value: Any) -> bool:
        """Write a single tag value.

        Args:
            tag: Tag name.
            value: Value to write (type must match PLC tag type).

        Returns:
            True on success, False on failure.

        Raises:
            RockwellError: If the PLC connection fails.
        """
        with _connect(self.ip) as plc:
            res = plc.write(tag, value)
            if isinstance(res, list):
                res = res[0]
            return res.error is None

    def write_many(self, values: dict[str, Any]) -> dict[str, bool]:
        """Write multiple tag values in a single connection.

        Args:
            values: Dict mapping tag name to new value.

        Returns:
            Dict mapping tag name to success bool.

        Raises:
            RockwellError: If the PLC connection fails.
        """
        results: dict[str, bool] = {}
        with _connect(self.ip) as plc:
            for tag, value in values.items():
                if str(value).startswith("ERROR"):
                    results[tag] = False
                    continue
                res = plc.write(tag, value)
                if isinstance(res, list):
                    res = res[0]
                results[tag] = res.error is None
        return results

    # ------------------------------------------------------------------
    # Change detection / history
    # ------------------------------------------------------------------

    def detect_changes(self, current: dict[str, Any]) -> list[dict]:
        """Compare current values against the previous snapshot.

        Args:
            current: Current tag values dict.

        Returns:
            List of change dicts with tag, old_value, new_value, timestamp.
        """
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        changes = []
        for tag, cur_val in current.items():
            if str(cur_val).startswith("ERROR"):
                continue
            if tag in self._previous:
                prev = self._previous[tag]
                if not str(prev).startswith("ERROR") and cur_val != prev:
                    changes.append({
                        "tag": tag,
                        "old_value": prev,
                        "new_value": cur_val,
                        "timestamp": ts,
                        "plc_ip": self.ip,
                    })
        return changes

    def save_changes(self, changes: list[dict]) -> None:
        """Append changes to persistent log file, capped at 1000 entries.

        Args:
            changes: List of change dicts from detect_changes().
        """
        if not changes:
            return
        history = self.load_history()
        history.extend(changes)
        history = history[-1000:]
        self._changes_file.write_text(json.dumps(history, indent=2))

    def load_history(self) -> list[dict]:
        """Load change history from disk.

        Returns:
            List of change dicts, or empty list.
        """
        if self._changes_file.exists():
            try:
                return json.loads(self._changes_file.read_text())
            except Exception:
                return []
        return []

    # ------------------------------------------------------------------
    # Monitor generator
    # ------------------------------------------------------------------

    def monitor(self, interval: float = 1.0):
        """Generator that yields (current_values, changes) at each interval.

        Keeps a persistent LogixDriver connection open for efficiency.

        Args:
            interval: Poll interval in seconds.

        Yields:
            Tuple of (current_values dict, changes list).
        """
        if not self.tags:
            self.load_tags()
        first = True
        with _connect(self.ip) as plc:
            while True:
                responses = plc.read(*self.tags)
                current: dict[str, Any] = {}
                for tag, res in zip(self.tags, responses):
                    current[tag] = res.value if res.error is None else f"ERROR: {res.error}"

                changes = [] if first else self.detect_changes(current)
                if changes:
                    self.save_changes(changes)
                self._previous = current.copy()
                first = False
                yield current, changes
                time.sleep(interval)
