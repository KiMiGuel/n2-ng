#!/usr/bin/env python3
"""Compatibility launcher for the source-tree N2-ng package."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from n2ng.main import *  # noqa: F401,F403
from n2ng.main import main


if __name__ == "__main__":
    main()
