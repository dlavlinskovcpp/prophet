"""Explicit wall-clock dependency for production authorization freshness."""
from __future__ import annotations

import time


def wall_clock_ms() -> int:
    """Return the current Unix wall-clock time in milliseconds."""
    return int(time.time() * 1000)
