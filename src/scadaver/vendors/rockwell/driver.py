"""Rockwell Allen-Bradley Logix PLC driver wrapper.

Wraps pycomm3 LogixDriver for tag discovery, read/write, and monitoring.

Performance notes:
- Tag discovery (init_tags=True) fetches full CIP type metadata for every tag.
  This is slow (5-60 s on large programs). Result is cached to data/tags_<ip>.json.
- Reads are chunked into CHUNK_SIZE batches to stay within CIP packet limits.
- Set SCADAVER_DEBUG=1 to print per-phase timing to stderr for profiling.
"""

from __future__ import annotations

import json
import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


DATA_DIR = Path("data")
CHUNK_SIZE = 50  # tags per CIP read request — lower if seeing CIP packet errors
_DEBUG = os.environ.get("SCADAVER_DEBUG", "").strip() not in ("", "0", "false")


class RockwellError(Exception):
    """Raised when communication with a Rockwell Logix PLC fails."""


@contextmanager
def _timed(label: str):
    """Print elapsed wall time for a named phase when SCADAVER_DEBUG=1."""
    start = time.perf_counter()
    yield
    if _DEBUG:
        elapsed = time.perf_counter() - start
        print(f"[debug] {label}: {elapsed:.3f}s", file=sys.stderr)


@contextmanager
def _connect(ip: str, **kwargs):
    """Open a LogixDriver connection, translating pycomm3 errors to RockwellError."""
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
        """Connect and discover all tags from the PLC. Saves result to disk.

        This is the slow path — pycomm3 fetches full CIP type metadata for
        every tag in the PLC program. Set SCADAVER_DEBUG=1 to see timings.

        Returns:
            Sorted list of tag names.

        Raises:
            RockwellError: If the PLC is unreachable or rejects the request.
        """
        with _timed("discover_tags: session open + init_tags"):
            with _connect(self.ip, init_tags=True) as plc:
                with _timed("discover_tags: enumerate plc.tags"):
                    self.tags = sorted(list(plc.tags))
        with _timed("discover_tags: write cache file"):
            self._tags_file.write_text(json.dumps(self.tags, indent=2))
        return self.tags

    def load_tags(self) -> list[str]:
        """Load tag list from saved cache, discovering from PLC if not present."""
        if self._tags_file.exists():
            with _timed("load_tags: read cache file"):
                self.tags = json.loads(self._tags_file.read_text())
            return self.tags
        return self.discover_tags()

    # ------------------------------------------------------------------
    # Read / write
    # ------------------------------------------------------------------

    def read_all(self) -> dict[str, Any]:
        """Read current values of all known tags in CHUNK_SIZE batches.

        Returns:
            Dict mapping tag name to value or "ERROR: <msg>".

        Raises:
            RockwellError: If the PLC connection fails.
        """
        if not self.tags:
            self.load_tags()
        with _timed(f"read_all: open session ({len(self.tags)} tags, chunk={CHUNK_SIZE})"):
            with _connect(self.ip) as plc:
                return self._read_chunked(plc)

    def read_all_open(self, plc: Any) -> dict[str, Any]:
        """Read all tags on an already-open LogixDriver session.

        Use this inside persistent connection loops (e.g. the interactive editor)
        to avoid the TCP + CIP session handshake on every refresh.

        Args:
            plc: An open pycomm3 LogixDriver instance.

        Returns:
            Dict mapping tag name to value or "ERROR: <msg>".
        """
        with _timed(f"read_all_open: {len(self.tags)} tags"):
            return self._read_chunked(plc)

    def _read_chunked(self, plc: Any) -> dict[str, Any]:
        """Read self.tags in CHUNK_SIZE batches using the provided open driver."""
        results: dict[str, Any] = {}
        total_chunks = -(-len(self.tags) // CHUNK_SIZE)
        for i in range(0, len(self.tags), CHUNK_SIZE):
            chunk = self.tags[i : i + CHUNK_SIZE]
            chunk_num = i // CHUNK_SIZE + 1
            with _timed(f"_read_chunked: chunk {chunk_num}/{total_chunks} ({len(chunk)} tags)"):
                responses = plc.read(*chunk)
                if not isinstance(responses, (list, tuple)):
                    responses = [responses]
                for tag, res in zip(chunk, responses):
                    results[tag] = res.value if res.error is None else f"ERROR: {res.error}"
        return results

    def read_tag(self, tag: str) -> Any:
        """Read a single tag."""
        with _connect(self.ip) as plc:
            res = plc.read(tag)
            return res.value if res.error is None else f"ERROR: {res.error}"

    def write_tag(self, tag: str, value: Any) -> bool:
        """Write a single tag value. Returns True on success."""
        with _connect(self.ip) as plc:
            res = plc.write(tag, value)
            if isinstance(res, list):
                res = res[0]
            return res.error is None

    def write_many(self, values: dict[str, Any]) -> dict[str, bool]:
        """Write multiple tag values in a single connection."""
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
        """Compare current values against the previous snapshot."""
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
        """Append changes to persistent log file, capped at 1000 entries."""
        if not changes:
            return
        history = self.load_history()
        history.extend(changes)
        history = history[-1000:]
        self._changes_file.write_text(json.dumps(history, indent=2))

    def load_history(self) -> list[dict]:
        """Load change history from disk."""
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
        """Generator yielding (current_values, changes) at each poll interval.

        Holds a single persistent LogixDriver connection open for the full session.

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
                with _timed(f"monitor: read poll ({len(self.tags)} tags)"):
                    current = self._read_chunked(plc)

                changes = [] if first else self.detect_changes(current)
                if changes:
                    self.save_changes(changes)
                self._previous = current.copy()
                first = False
                yield current, changes
                time.sleep(interval)
