"""Durable fail-closed journal for Phase 6D3 Solana settlement submission.

The journal owns blockchain execution state only.  It does not mutate coordinator
history, the signing journal, the durable 2/2 bundle, or settlement semantics.
Every transition is committed before the corresponding chain-affecting action.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from solders.hash import Hash
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction


SCHEMA_VERSION = 1

PREPARED = "PREPARED"
SUBMISSION_STARTED = "SUBMISSION_STARTED"
SIGNATURE_KNOWN = "SIGNATURE_KNOWN"
PENDING = "PENDING"
CONFIRMED = "CONFIRMED"
FAILED_FINAL = "FAILED_FINAL"
STATUS_UNKNOWN = "STATUS_UNKNOWN"
EXPIRED_UNSUBMITTED = "EXPIRED_UNSUBMITTED"

_ACTIVE_STATES = frozenset(
    {PREPARED, SUBMISSION_STARTED, SIGNATURE_KNOWN, PENDING, STATUS_UNKNOWN}
)
_TERMINAL_STATES = frozenset({CONFIRMED, FAILED_FINAL, EXPIRED_UNSUBMITTED})
_ALL_STATES = _ACTIVE_STATES | _TERMINAL_STATES


class SettlementAttemptJournalError(RuntimeError):
    pass


class SettlementAttemptJournalBindingError(SettlementAttemptJournalError):
    pass


class SettlementAttemptJournalStateError(SettlementAttemptJournalError):
    pass


class SettlementAttemptJournalConflict(SettlementAttemptJournalError):
    pass


@dataclass(frozen=True)
class PreparedSettlementAttempt:
    coordinator_job_id: str
    signing_intent_id: str
    canonical_settlement_digest: str
    serialized_transaction: bytes
    transaction_digest: str
    fee_payer_pubkey: str
    recent_blockhash: str
    program_id: str
    cluster: str
    genesis_hash: str
    local_transaction_signature: str


@dataclass(frozen=True)
class SettlementTransactionAttempt:
    attempt_id: str
    coordinator_job_id: str
    signing_intent_id: str
    canonical_settlement_digest: str
    serialized_transaction: bytes
    transaction_digest: str
    fee_payer_pubkey: str
    recent_blockhash: str
    program_id: str
    cluster: str
    genesis_hash: str
    local_transaction_signature: str
    submission_state: str
    confirmation_status: str | None
    slot: int | None
    transaction_error: str | None
    failure_category: str | None
    created_at_ms: str
    updated_at_ms: str

    @property
    def is_terminal(self) -> bool:
        return self.submission_state in _TERMINAL_STATES


def _now_ms() -> str:
    return str(int(time.time() * 1000))


def _digest_hex(value: str, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise SettlementAttemptJournalBindingError(f"{field}_invalid")
    return value


def _nonempty(value: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise SettlementAttemptJournalBindingError(f"{field}_invalid")
    return value


class SettlementAttemptJournal:
    """SQLite transaction-attempt journal with one active attempt per settlement."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if not self.path or self.path == ":memory:":
            raise SettlementAttemptJournalBindingError("persistent_attempt_journal_path_required")
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA busy_timeout = 5000")
        self._migrate()

    def close(self) -> None:
        self._db.close()

    def _migrate(self) -> None:
        with self._lock:
            version = int(self._db.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise SettlementAttemptJournalStateError("unsupported_attempt_journal_schema")
            if version == SCHEMA_VERSION:
                return
            if version != 0:
                raise SettlementAttemptJournalStateError("unsupported_attempt_journal_schema")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    """CREATE TABLE settlement_transaction_attempts (
                        attempt_id TEXT PRIMARY KEY,
                        coordinator_job_id TEXT NOT NULL,
                        signing_intent_id TEXT NOT NULL,
                        canonical_settlement_digest TEXT NOT NULL,
                        serialized_transaction BLOB NOT NULL,
                        transaction_digest TEXT NOT NULL,
                        fee_payer_pubkey TEXT NOT NULL,
                        recent_blockhash TEXT NOT NULL,
                        program_id TEXT NOT NULL,
                        cluster TEXT NOT NULL,
                        genesis_hash TEXT NOT NULL,
                        local_transaction_signature TEXT NOT NULL,
                        submission_state TEXT NOT NULL CHECK(submission_state IN (
                            'PREPARED','SUBMISSION_STARTED','SIGNATURE_KNOWN','PENDING',
                            'CONFIRMED','FAILED_FINAL','STATUS_UNKNOWN','EXPIRED_UNSUBMITTED'
                        )),
                        confirmation_status TEXT,
                        slot INTEGER,
                        transaction_error TEXT,
                        failure_category TEXT,
                        created_at_ms TEXT NOT NULL,
                        updated_at_ms TEXT NOT NULL,
                        row_binding_digest TEXT NOT NULL
                    )"""
                )
                self._db.execute(
                    "CREATE UNIQUE INDEX settlement_attempt_exact_candidate ON "
                    "settlement_transaction_attempts(signing_intent_id, transaction_digest)"
                )
                self._db.execute(
                    """CREATE UNIQUE INDEX settlement_attempt_one_active ON
                    settlement_transaction_attempts(signing_intent_id)
                    WHERE submission_state IN (
                        'PREPARED','SUBMISSION_STARTED','SIGNATURE_KNOWN','PENDING','STATUS_UNKNOWN'
                    )"""
                )
                self._db.execute(
                    "CREATE INDEX settlement_attempt_job ON "
                    "settlement_transaction_attempts(coordinator_job_id, created_at_ms)"
                )
                self._db.execute("PRAGMA user_version = 1")
                self._db.execute("COMMIT")
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def create_or_load_prepared(
        self, prepared: PreparedSettlementAttempt
    ) -> SettlementTransactionAttempt:
        prepared = self._validate_prepared(prepared)
        attempt_id = hashlib.sha256(
            b"PROPHET_SETTLEMENT_TX_ATTEMPT_V1\0"
            + prepared.signing_intent_id.encode("utf-8")
            + b"\0"
            + prepared.transaction_digest.encode("ascii")
        ).hexdigest()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                existing = self._db.execute(
                    """SELECT * FROM settlement_transaction_attempts
                    WHERE signing_intent_id = ?
                    ORDER BY created_at_ms DESC, attempt_id DESC LIMIT 1""",
                    (prepared.signing_intent_id,),
                ).fetchone()
                if existing is not None:
                    attempt = self._row(existing)
                    self._assert_same_settlement_binding(attempt, prepared)
                    self._db.execute("COMMIT")
                    return attempt

                now = _now_ms()
                values = {
                    "attempt_id": attempt_id,
                    "coordinator_job_id": prepared.coordinator_job_id,
                    "signing_intent_id": prepared.signing_intent_id,
                    "canonical_settlement_digest": prepared.canonical_settlement_digest,
                    "serialized_transaction": prepared.serialized_transaction,
                    "transaction_digest": prepared.transaction_digest,
                    "fee_payer_pubkey": prepared.fee_payer_pubkey,
                    "recent_blockhash": prepared.recent_blockhash,
                    "program_id": prepared.program_id,
                    "cluster": prepared.cluster,
                    "genesis_hash": prepared.genesis_hash,
                    "local_transaction_signature": prepared.local_transaction_signature,
                    "submission_state": PREPARED,
                    "confirmation_status": None,
                    "slot": None,
                    "transaction_error": None,
                    "failure_category": None,
                    "created_at_ms": now,
                    "updated_at_ms": now,
                }
                binding = self._binding_digest(values)
                self._db.execute(
                    """INSERT INTO settlement_transaction_attempts(
                        attempt_id, coordinator_job_id, signing_intent_id,
                        canonical_settlement_digest, serialized_transaction, transaction_digest,
                        fee_payer_pubkey, recent_blockhash, program_id, cluster, genesis_hash,
                        local_transaction_signature, submission_state, confirmation_status, slot,
                        transaction_error, failure_category, created_at_ms, updated_at_ms,
                        row_binding_digest
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        values["attempt_id"], values["coordinator_job_id"],
                        values["signing_intent_id"], values["canonical_settlement_digest"],
                        values["serialized_transaction"], values["transaction_digest"],
                        values["fee_payer_pubkey"], values["recent_blockhash"],
                        values["program_id"], values["cluster"], values["genesis_hash"],
                        values["local_transaction_signature"], values["submission_state"],
                        values["confirmation_status"], values["slot"],
                        values["transaction_error"], values["failure_category"],
                        values["created_at_ms"], values["updated_at_ms"], binding,
                    ),
                )
                row = self._db.execute(
                    "SELECT * FROM settlement_transaction_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                self._db.execute("COMMIT")
                return self._row(row)
            except sqlite3.IntegrityError:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                # A concurrent creator won. Resolve only to its durable record,
                # then prove it belongs to the same durable settlement identity.
                winner = self.get_for_signing_intent(prepared.signing_intent_id)
                self._assert_same_settlement_binding(winner, prepared)
                return winner
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def get(self, attempt_id: str) -> SettlementTransactionAttempt:
        row = self._db.execute(
            "SELECT * FROM settlement_transaction_attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise SettlementAttemptJournalStateError("settlement_attempt_not_found")
        return self._row(row)

    def get_for_job(self, coordinator_job_id: str) -> SettlementTransactionAttempt:
        _nonempty(coordinator_job_id, "coordinator_job_id")
        row = self._db.execute(
            """SELECT * FROM settlement_transaction_attempts
            WHERE coordinator_job_id = ?
            ORDER BY created_at_ms DESC, attempt_id DESC LIMIT 1""",
            (coordinator_job_id,),
        ).fetchone()
        if row is None:
            raise SettlementAttemptJournalStateError("settlement_attempt_not_found")
        return self._row(row)

    def get_for_signing_intent(self, signing_intent_id: str) -> SettlementTransactionAttempt:
        _nonempty(signing_intent_id, "signing_intent_id")
        row = self._db.execute(
            """SELECT * FROM settlement_transaction_attempts
            WHERE signing_intent_id = ?
            ORDER BY created_at_ms DESC, attempt_id DESC LIMIT 1""",
            (signing_intent_id,),
        ).fetchone()
        if row is None:
            raise SettlementAttemptJournalStateError("settlement_attempt_not_found")
        return self._row(row)

    def find_for_job(self, coordinator_job_id: str) -> SettlementTransactionAttempt | None:
        try:
            return self.get_for_job(coordinator_job_id)
        except SettlementAttemptJournalStateError as exc:
            if str(exc) == "settlement_attempt_not_found":
                return None
            raise

    def begin_submission(
        self, attempt_id: str
    ) -> tuple[SettlementTransactionAttempt, bool]:
        """Atomically claim the one chain-affecting send transition.

        The boolean is True only for the caller that changed PREPARED to
        SUBMISSION_STARTED. All other callers must reconcile and must not send.
        """
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_row(attempt_id)
                attempt = self._row(row)
                if attempt.submission_state != PREPARED:
                    self._db.execute("COMMIT")
                    return attempt, False
                updated = self._update_locked(
                    row,
                    submission_state=SUBMISSION_STARTED,
                    confirmation_status=None,
                    slot=None,
                    transaction_error=None,
                    failure_category=None,
                )
                self._db.execute("COMMIT")
                return updated, True
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def record_rpc_signature(self, attempt_id: str, rpc_signature: str) -> SettlementTransactionAttempt:
        signature = self._canonical_signature(rpc_signature)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_row(attempt_id)
                attempt = self._row(row)
                if signature != attempt.local_transaction_signature:
                    raise SettlementAttemptJournalConflict("rpc_transaction_signature_mismatch")
                if attempt.submission_state == SIGNATURE_KNOWN:
                    self._db.execute("COMMIT")
                    return attempt
                if attempt.submission_state != SUBMISSION_STARTED:
                    raise SettlementAttemptJournalStateError("rpc_signature_transition_rejected")
                updated = self._update_locked(
                    row,
                    submission_state=SIGNATURE_KNOWN,
                    failure_category=None,
                )
                self._db.execute("COMMIT")
                return updated
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def mark_status_unknown(self, attempt_id: str, category: str) -> SettlementTransactionAttempt:
        category = _nonempty(category, "failure_category")
        return self._transition(
            attempt_id,
            allowed={SUBMISSION_STARTED, SIGNATURE_KNOWN, PENDING, STATUS_UNKNOWN},
            submission_state=STATUS_UNKNOWN,
            failure_category=category,
        )

    def mark_pending(
        self,
        attempt_id: str,
        *,
        confirmation_status: str,
        slot: int,
        transaction_error: str | None = None,
        failure_category: str | None = None,
    ) -> SettlementTransactionAttempt:
        normalized_error = (
            None if transaction_error is None else _nonempty(transaction_error, "transaction_error")
        )
        normalized_category = (
            None if failure_category is None else _nonempty(failure_category, "failure_category")
        )
        if (normalized_error is None) != (normalized_category is None):
            raise SettlementAttemptJournalBindingError("pending_error_category_mismatch")
        return self._transition(
            attempt_id,
            allowed={SUBMISSION_STARTED, SIGNATURE_KNOWN, PENDING, STATUS_UNKNOWN},
            submission_state=PENDING,
            confirmation_status=self._confirmation_status(confirmation_status),
            slot=self._slot(slot),
            transaction_error=normalized_error,
            failure_category=normalized_category,
        )

    def mark_confirmed(
        self, attempt_id: str, *, confirmation_status: str, slot: int
    ) -> SettlementTransactionAttempt:
        return self._transition(
            attempt_id,
            allowed={SUBMISSION_STARTED, SIGNATURE_KNOWN, PENDING, STATUS_UNKNOWN, CONFIRMED},
            submission_state=CONFIRMED,
            confirmation_status=self._confirmation_status(confirmation_status),
            slot=self._slot(slot),
            transaction_error=None,
            failure_category=None,
        )

    def mark_failed_final(
        self,
        attempt_id: str,
        *,
        confirmation_status: str | None,
        slot: int | None,
        transaction_error: str,
        failure_category: str,
    ) -> SettlementTransactionAttempt:
        error = _nonempty(transaction_error, "transaction_error")
        category = _nonempty(failure_category, "failure_category")
        status = None if confirmation_status is None else self._confirmation_status(confirmation_status)
        normalized_slot = None if slot is None else self._slot(slot)
        return self._transition(
            attempt_id,
            allowed={PREPARED, SUBMISSION_STARTED, SIGNATURE_KNOWN, PENDING, STATUS_UNKNOWN, FAILED_FINAL},
            submission_state=FAILED_FINAL,
            confirmation_status=status,
            slot=normalized_slot,
            transaction_error=error,
            failure_category=category,
        )

    def mark_expired_unsubmitted(self, attempt_id: str) -> SettlementTransactionAttempt:
        return self._transition(
            attempt_id,
            allowed={PREPARED, EXPIRED_UNSUBMITTED},
            submission_state=EXPIRED_UNSUBMITTED,
            failure_category="blockhash_expired_before_submission",
        )

    def _transition(self, attempt_id: str, *, allowed: set[str], **changes) -> SettlementTransactionAttempt:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._require_row(attempt_id)
                attempt = self._row(row)
                if attempt.submission_state not in allowed:
                    raise SettlementAttemptJournalStateError("settlement_attempt_transition_rejected")
                if attempt.submission_state in _TERMINAL_STATES and changes.get("submission_state") != attempt.submission_state:
                    raise SettlementAttemptJournalStateError("settlement_attempt_terminal")
                updated = self._update_locked(row, **changes)
                self._db.execute("COMMIT")
                return updated
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def _update_locked(self, row: sqlite3.Row, **changes) -> SettlementTransactionAttempt:
        values = {key: row[key] for key in row.keys() if key != "row_binding_digest"}
        values.update(changes)
        values["updated_at_ms"] = _now_ms()
        binding = self._binding_digest(values)
        self._db.execute(
            """UPDATE settlement_transaction_attempts SET
                submission_state = ?, confirmation_status = ?, slot = ?, transaction_error = ?,
                failure_category = ?, updated_at_ms = ?, row_binding_digest = ?
                WHERE attempt_id = ?""",
            (
                values["submission_state"], values["confirmation_status"], values["slot"],
                values["transaction_error"], values["failure_category"], values["updated_at_ms"],
                binding, values["attempt_id"],
            ),
        )
        updated = self._require_row(values["attempt_id"])
        return self._row(updated)

    def _require_row(self, attempt_id: str) -> sqlite3.Row:
        _nonempty(attempt_id, "attempt_id")
        row = self._db.execute(
            "SELECT * FROM settlement_transaction_attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        if row is None:
            raise SettlementAttemptJournalStateError("settlement_attempt_not_found")
        return row

    @classmethod
    def _validate_prepared(cls, prepared: PreparedSettlementAttempt) -> PreparedSettlementAttempt:
        if not isinstance(prepared, PreparedSettlementAttempt):
            raise SettlementAttemptJournalBindingError("prepared_settlement_attempt_invalid")
        _nonempty(prepared.coordinator_job_id, "coordinator_job_id")
        _nonempty(prepared.signing_intent_id, "signing_intent_id")
        _digest_hex(prepared.canonical_settlement_digest, "canonical_settlement_digest")
        _digest_hex(prepared.transaction_digest, "transaction_digest")
        _nonempty(prepared.cluster, "cluster")
        try:
            if str(Pubkey.from_string(prepared.fee_payer_pubkey)) != prepared.fee_payer_pubkey:
                raise ValueError
            if str(Pubkey.from_string(prepared.program_id)) != prepared.program_id:
                raise ValueError
            if str(Hash.from_string(prepared.recent_blockhash)) != prepared.recent_blockhash:
                raise ValueError
            if str(Hash.from_string(prepared.genesis_hash)) != prepared.genesis_hash:
                raise ValueError
        except Exception as exc:
            raise SettlementAttemptJournalBindingError("prepared_solana_identity_invalid") from exc
        local_sig = cls._canonical_signature(prepared.local_transaction_signature)
        if local_sig != prepared.local_transaction_signature:
            raise SettlementAttemptJournalBindingError("local_transaction_signature_invalid")
        cls._validate_transaction_bytes(
            prepared.serialized_transaction,
            prepared.transaction_digest,
            prepared.fee_payer_pubkey,
            prepared.recent_blockhash,
            local_sig,
        )
        return prepared

    @staticmethod
    def _validate_transaction_bytes(
        serialized: bytes,
        digest: str,
        fee_payer: str,
        recent_blockhash: str,
        local_signature: str,
    ) -> None:
        if not isinstance(serialized, bytes) or not serialized:
            raise SettlementAttemptJournalBindingError("serialized_transaction_invalid")
        if hashlib.sha256(serialized).hexdigest() != digest:
            raise SettlementAttemptJournalBindingError("transaction_digest_mismatch")
        try:
            tx = VersionedTransaction.from_bytes(serialized)
            if bytes(tx) != serialized:
                raise ValueError
            signatures = tuple(tx.signatures)
            if len(signatures) != 1 or str(signatures[0]) != local_signature:
                raise ValueError
            if tuple(tx.verify_with_results()) != (True,):
                raise ValueError
            tx.verify_and_hash_message()
            message = tx.message
            account_keys = tuple(message.account_keys)
            if message.header.num_required_signatures != 1 or not account_keys:
                raise ValueError
            if str(account_keys[0]) != fee_payer:
                raise ValueError
            if str(message.recent_blockhash) != recent_blockhash:
                raise ValueError
        except Exception as exc:
            raise SettlementAttemptJournalBindingError("serialized_transaction_binding_invalid") from exc

    @classmethod
    def _row(cls, row: sqlite3.Row) -> SettlementTransactionAttempt:
        values = {key: row[key] for key in row.keys() if key != "row_binding_digest"}
        if row["submission_state"] not in _ALL_STATES:
            raise SettlementAttemptJournalBindingError("attempt_state_invalid")
        expected = cls._binding_digest(values)
        if row["row_binding_digest"] != expected:
            raise SettlementAttemptJournalBindingError("attempt_row_binding_digest_mismatch")
        cls._validate_transaction_bytes(
            bytes(row["serialized_transaction"]),
            row["transaction_digest"],
            row["fee_payer_pubkey"],
            row["recent_blockhash"],
            row["local_transaction_signature"],
        )
        return SettlementTransactionAttempt(
            row["attempt_id"], row["coordinator_job_id"], row["signing_intent_id"],
            row["canonical_settlement_digest"], bytes(row["serialized_transaction"]),
            row["transaction_digest"], row["fee_payer_pubkey"], row["recent_blockhash"],
            row["program_id"], row["cluster"], row["genesis_hash"],
            row["local_transaction_signature"], row["submission_state"],
            row["confirmation_status"], row["slot"], row["transaction_error"],
            row["failure_category"], row["created_at_ms"], row["updated_at_ms"],
        )

    @staticmethod
    def _assert_same_settlement_binding(
        existing: SettlementTransactionAttempt, prepared: PreparedSettlementAttempt
    ) -> None:
        if (
            existing.coordinator_job_id != prepared.coordinator_job_id
            or existing.signing_intent_id != prepared.signing_intent_id
            or existing.canonical_settlement_digest != prepared.canonical_settlement_digest
            or existing.program_id != prepared.program_id
            or existing.cluster != prepared.cluster
            or existing.genesis_hash != prepared.genesis_hash
        ):
            raise SettlementAttemptJournalConflict("settlement_attempt_binding_mismatch")

    @staticmethod
    def _canonical_signature(value: str) -> str:
        try:
            text = str(value)
            parsed = Signature.from_string(text)
            if str(parsed) != text:
                raise ValueError
        except Exception as exc:
            raise SettlementAttemptJournalBindingError("transaction_signature_invalid") from exc
        return text

    @staticmethod
    def _confirmation_status(value: str) -> str:
        if value not in {"processed", "confirmed", "finalized"}:
            raise SettlementAttemptJournalBindingError("confirmation_status_invalid")
        return value

    @staticmethod
    def _slot(value: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SettlementAttemptJournalBindingError("confirmation_slot_invalid")
        return value

    @staticmethod
    def _binding_digest(values: dict) -> str:
        payload = {
            "attempt_id": values["attempt_id"],
            "coordinator_job_id": values["coordinator_job_id"],
            "signing_intent_id": values["signing_intent_id"],
            "canonical_settlement_digest": values["canonical_settlement_digest"],
            "transaction_digest": values["transaction_digest"],
            "serialized_transaction_digest": hashlib.sha256(
                bytes(values["serialized_transaction"])
            ).hexdigest(),
            "fee_payer_pubkey": values["fee_payer_pubkey"],
            "recent_blockhash": values["recent_blockhash"],
            "program_id": values["program_id"],
            "cluster": values["cluster"],
            "genesis_hash": values["genesis_hash"],
            "local_transaction_signature": values["local_transaction_signature"],
            "submission_state": values["submission_state"],
            "confirmation_status": values["confirmation_status"],
            "slot": values["slot"],
            "transaction_error": values["transaction_error"],
            "failure_category": values["failure_category"],
            "created_at_ms": values["created_at_ms"],
            "updated_at_ms": values["updated_at_ms"],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(b"PROPHET_SETTLEMENT_ATTEMPT_ROW_V1\0" + encoded).hexdigest()
