"""Build a standalone zipapp (.pyz) for scadaver.

Usage::

    python scripts/build_standalone.py

Produces ``dist/scadaver.pyz`` — a single-file executable that
can be run with ``python scadaver.pyz [args]``.

Requires the package to be installed first (``pip install -e .``).
"""

from __future__ import annotations

import os
import zipapp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
DIST = os.path.join(ROOT, "dist")


def main() -> None:
    os.makedirs(DIST, exist_ok=True)
    output = os.path.join(DIST, "scadaver.pyz")

    zipapp.create_archive(
        SRC,
        target=output,
        interpreter="/usr/bin/env python3",
        main="scadaver.cli:main",
    )
    print(f"Built standalone archive: {output}")


if __name__ == "__main__":
    main()
