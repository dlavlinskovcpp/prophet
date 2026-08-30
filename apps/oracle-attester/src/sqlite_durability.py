"""Shared fail-closed SQLite durability configuration for production journals."""
from __future__ import annotations

import sqlite3
import time


SQLITE_BUSY_TIMEOUT_MS = 5_000


class SQLiteDurabilityError(RuntimeError):
    """The effective SQLite durability contract could not be established."""


def configure_durable_connection(
    connection: sqlite3.Connection, *, foreign_keys: bool = True
) -> None:
    """Set and read back the durability contract before any journal migration."""
    try:
        connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
        deadline = time.monotonic() + 5.0
        while True:
            try:
                journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
                break
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        connection.execute("PRAGMA synchronous = FULL")
        if foreign_keys:
            connection.execute("PRAGMA foreign_keys = ON")
        effective = {
            "journal_mode": str(journal_mode).lower(),
            "synchronous": int(connection.execute("PRAGMA synchronous").fetchone()[0]),
            "busy_timeout": int(connection.execute("PRAGMA busy_timeout").fetchone()[0]),
        }
        if foreign_keys:
            effective["foreign_keys"] = int(
                connection.execute("PRAGMA foreign_keys").fetchone()[0]
            )
        expected = {
            "journal_mode": "wal",
            "synchronous": 2,
            "busy_timeout": SQLITE_BUSY_TIMEOUT_MS,
        }
        if foreign_keys:
            expected["foreign_keys"] = 1
        if effective != expected:
            raise SQLiteDurabilityError(
                f"sqlite_durability_contract_mismatch:{effective!r}"
            )
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        if isinstance(exc, SQLiteDurabilityError):
            raise
        raise SQLiteDurabilityError("sqlite_durability_unavailable") from exc
