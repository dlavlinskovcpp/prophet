"""Durable, role-local, single-use admission-grant replay state for G2.

This module deliberately has no grant crypto, HTTP, Vault, RPC, or signing
dependencies.  Its results are audit facts only; G3 must perform G1
verification and then invoke this journal before it reaches a signing sink.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Literal
from .sqlite_durability import configure_durable_connection


SCHEMA_VERSION = 1
CONSUMED = "CONSUMED"
ALREADY_CONSUMED = "ALREADY_CONSUMED"


class AdmissionGrantReplayJournalError(RuntimeError):
    """Fail-closed durable storage failure."""


class AdmissionGrantReplayJournalBindingError(AdmissionGrantReplayJournalError):
    """Invalid trusted role, record field, path, or metadata binding."""


def _hex(value: Any, length: int, name: str) -> str:
    if not isinstance(value, str) or len(value) != length or any(c not in "0123456789abcdef" for c in value):
        raise AdmissionGrantReplayJournalBindingError(f"{name}_invalid")
    return value


def _timestamp(value: Any, name: str) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise AdmissionGrantReplayJournalBindingError(f"{name}_invalid")
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class AdmissionGrantReplayRecord:
    grant_id: str
    admission_request_sha256: str
    acceptance_run_id: str
    consumed_at: str
    valid_until: str


@dataclass(frozen=True)
class ReplayConsumeResult:
    """Audit data only; it is not a G3 admission capability."""
    status: Literal["CONSUMED", "ALREADY_CONSUMED"]
    record: AdmissionGrantReplayRecord


class AdmissionGrantReplayJournal:
    """One role, one persistent SQLite file, irreversible grant consumption."""

    def __init__(self, path: str | Path, *, signer_role: str) -> None:
        if signer_role not in ("A", "B"):
            raise AdmissionGrantReplayJournalBindingError("signer_role_invalid")
        candidate = Path(path)
        if not str(path) or str(path) == ":memory:" or not candidate.is_absolute():
            raise AdmissionGrantReplayJournalBindingError("persistent_absolute_replay_journal_path_required")
        self.path = str(candidate.resolve(strict=False))
        self.signer_role = signer_role
        try:
            candidate.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=5.0)
            self._db.row_factory = sqlite3.Row
            configure_durable_connection(self._db)
            self._lock = Lock()
            self._initialize()
        except AdmissionGrantReplayJournalError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise AdmissionGrantReplayJournalError("admission_grant_replay_storage_unavailable") from exc

    def close(self) -> None:
        try:
            self._db.close()
        except sqlite3.Error as exc:
            raise AdmissionGrantReplayJournalError("admission_grant_replay_close_failed") from exc

    def health(self) -> bool:
        """Run non-mutating structural checks for a signer readiness probe."""
        try:
            with self._lock:
                check = self._db.execute("PRAGMA integrity_check").fetchone()
                version = self._db.execute("PRAGMA user_version").fetchone()
                rows = dict(self._db.execute("SELECT key, value FROM admission_grant_replay_metadata"))
                return (
                    check is not None and check[0] == "ok"
                    and version is not None and version[0] == SCHEMA_VERSION
                    and rows == {"schema_version": str(SCHEMA_VERSION), "signer_role": self.signer_role}
                )
        except (sqlite3.Error, TypeError):
            return False

    def _initialize(self) -> None:
        try:
            with self._lock:
                check = self._db.execute("PRAGMA integrity_check").fetchone()
                if check is None or check[0] != "ok":
                    raise AdmissionGrantReplayJournalError("admission_grant_replay_integrity_invalid")
                version = self._db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, SCHEMA_VERSION):
                    raise AdmissionGrantReplayJournalBindingError("unsupported_admission_grant_replay_schema")
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.execute("CREATE TABLE IF NOT EXISTS admission_grant_replay_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    self._db.execute("""CREATE TABLE IF NOT EXISTS admission_grant_replay_records (
                        grant_id TEXT PRIMARY KEY,
                        admission_request_sha256 TEXT NOT NULL,
                        acceptance_run_id TEXT NOT NULL,
                        consumed_at TEXT NOT NULL,
                        valid_until TEXT NOT NULL
                    )""")
                    rows = dict(self._db.execute("SELECT key, value FROM admission_grant_replay_metadata"))
                    expected = {"schema_version": str(SCHEMA_VERSION), "signer_role": self.signer_role}
                    if not rows:
                        self._db.executemany("INSERT INTO admission_grant_replay_metadata(key, value) VALUES (?, ?)", expected.items())
                    elif rows != expected:
                        raise AdmissionGrantReplayJournalBindingError("admission_grant_replay_metadata_mismatch")
                    self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    self._db.execute("COMMIT")
                except Exception:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    raise
        except AdmissionGrantReplayJournalError:
            raise
        except sqlite3.Error as exc:
            raise AdmissionGrantReplayJournalError("admission_grant_replay_schema_unavailable") from exc

    @staticmethod
    def _record(*, grant_id: Any, admission_request_sha256: Any, acceptance_run_id: Any, consumed_at: Any, valid_until: Any) -> AdmissionGrantReplayRecord:
        return AdmissionGrantReplayRecord(
            _hex(grant_id, 32, "grant_id"),
            _hex(admission_request_sha256, 64, "admission_request_sha256"),
            _hex(acceptance_run_id, 32, "acceptance_run_id"),
            _timestamp(consumed_at, "consumed_at"),
            _timestamp(valid_until, "valid_until"),
        )

    @staticmethod
    def _row(row: sqlite3.Row | None) -> AdmissionGrantReplayRecord:
        if row is None:
            raise AdmissionGrantReplayJournalError("admission_grant_replay_record_missing")
        return AdmissionGrantReplayRecord(
            _hex(row["grant_id"], 32, "stored_grant_id"),
            _hex(row["admission_request_sha256"], 64, "stored_admission_request_sha256"),
            _hex(row["acceptance_run_id"], 32, "stored_acceptance_run_id"),
            row["consumed_at"], row["valid_until"],
        )

    def consume_once(self, *, grant_id: Any, admission_request_sha256: Any, acceptance_run_id: Any, consumed_at: Any, valid_until: Any) -> ReplayConsumeResult:
        """Atomically persist first use.  Storage error never means unused."""
        record = self._record(
            grant_id=grant_id,
            admission_request_sha256=admission_request_sha256,
            acceptance_run_id=acceptance_run_id,
            consumed_at=consumed_at,
            valid_until=valid_until,
        )
        try:
            with self._lock:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.execute(
                        "INSERT INTO admission_grant_replay_records(grant_id, admission_request_sha256, acceptance_run_id, consumed_at, valid_until) VALUES (?, ?, ?, ?, ?)",
                        (record.grant_id, record.admission_request_sha256, record.acceptance_run_id, record.consumed_at, record.valid_until),
                    )
                    self._db.execute("COMMIT")
                    return ReplayConsumeResult(CONSUMED, record)
                except sqlite3.IntegrityError:
                    self._db.execute("ROLLBACK")
                    return ReplayConsumeResult(ALREADY_CONSUMED, self.get(record.grant_id))
                except Exception:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    raise
        except AdmissionGrantReplayJournalError:
            raise
        except sqlite3.Error as exc:
            raise AdmissionGrantReplayJournalError("admission_grant_replay_consume_failed") from exc

    def get(self, grant_id: Any) -> AdmissionGrantReplayRecord:
        identifier = _hex(grant_id, 32, "grant_id")
        try:
            row = self._db.execute("SELECT * FROM admission_grant_replay_records WHERE grant_id = ?", (identifier,)).fetchone()
            return self._row(row)
        except AdmissionGrantReplayJournalError:
            raise
        except sqlite3.Error as exc:
            raise AdmissionGrantReplayJournalError("admission_grant_replay_read_failed") from exc
