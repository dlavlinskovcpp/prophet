"""Single-signer durable anti-equivocation journal.

This module has no Vault, HTTP, Solana RPC, coordinator, or second-signer
dependency.  Each future signer service owns a distinct database file.
"""
from __future__ import annotations

import hashlib
import sqlite3
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any

from solders.pubkey import Pubkey
from solders.signature import Signature

from .signer_authorization import _JournalAuthorizedSettlement
from .sqlite_durability import configure_durable_connection


SCHEMA_VERSION = 1
PREPARED = "PREPARED"
SIGNING = "SIGNING"
SIGNED = "SIGNED"
UNCERTAIN = "UNCERTAIN"
CONFLICT = "CONFLICT"
_STATES = frozenset((PREPARED, SIGNING, SIGNED, UNCERTAIN, CONFLICT))
_SCOPE_DOMAIN = b"PROPHET_INDEPENDENT_SIGNER_SCOPE_V1\0"
_SIGNER_CONFIG_DOMAIN = b"PROPHET_SIGNER_CONFIG_FINGERPRINT_V1\0"


class IndependentSignerJournalError(RuntimeError): pass
class IndependentSignerJournalConflict(IndependentSignerJournalError): pass
class IndependentSignerJournalBindingError(IndependentSignerJournalError): pass
class IndependentSignerJournalStateError(IndependentSignerJournalError): pass
class IndependentSignerJournalSignatureError(IndependentSignerJournalError): pass


def _hex32(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise IndependentSignerJournalBindingError(f"{name}_invalid")
    try:
        if bytes.fromhex(value).hex() != value:
            raise ValueError
    except ValueError as exc:
        raise IndependentSignerJournalBindingError(f"{name}_invalid") from exc
    return value


def _pubkey(value: Any, name: str) -> str:
    try:
        if not isinstance(value, str) or str(Pubkey.from_string(value)) != value:
            raise ValueError
    except Exception as exc:
        raise IndependentSignerJournalBindingError(f"{name}_invalid") from exc
    return value


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise IndependentSignerJournalBindingError(f"{name}_invalid")
    return value


def _timestamp(value: Any, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IndependentSignerJournalBindingError(f"{name}_invalid")
    return str(value)


def _text(value: Any, name: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise IndependentSignerJournalBindingError(f"{name}_invalid")
    return value


def _operation_id(value: Any) -> str:
    if (not isinstance(value, str) or len(value) != 32
            or any(character not in "0123456789abcdef" for character in value)):
        raise IndependentSignerJournalBindingError("operation_id_invalid")
    return value


def _length_prefixed(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 0xFFFF:
        raise IndependentSignerJournalBindingError("signer_config_text_too_long")
    return struct.pack("<H", len(encoded)) + encoded


def derive_signer_config_fingerprint(
    *, signer_slot: str, signer_id: str, signer_public_key: str, signer_key_epoch: int,
) -> str:
    """Return the versioned, non-secret local signer-configuration digest."""
    if signer_slot not in ("A", "B"):
        raise IndependentSignerJournalBindingError("signer_slot_invalid")
    signer_id = _text(signer_id, "signer_id")
    signer_public_key = _pubkey(signer_public_key, "signer_public_key")
    signer_key_epoch = _positive_int(signer_key_epoch, "signer_key_epoch")
    return hashlib.sha256(
        _SIGNER_CONFIG_DOMAIN
        + _length_prefixed(signer_slot)
        + _length_prefixed(signer_id)
        + bytes(Pubkey.from_string(signer_public_key))
        + struct.pack("<Q", signer_key_epoch)
    ).hexdigest()


def _now_ms() -> str:
    return str(int(time.time() * 1000))


@dataclass(frozen=True)
class IndependentSigningScope:
    cluster_genesis_hash: str
    program_id: str
    market_pubkey: str
    notary_config_pubkey: str
    notary_config_version: int

    def __post_init__(self) -> None:
        _hex32(self.cluster_genesis_hash, "cluster_genesis_hash")
        _pubkey(self.program_id, "program_id")
        _pubkey(self.market_pubkey, "market_pubkey")
        _pubkey(self.notary_config_pubkey, "notary_config_pubkey")
        _positive_int(self.notary_config_version, "notary_config_version")

    @property
    def scope_id(self) -> str:
        return hashlib.sha256(
            _SCOPE_DOMAIN + bytes.fromhex(self.cluster_genesis_hash)
            + bytes(Pubkey.from_string(self.program_id))
            + bytes(Pubkey.from_string(self.market_pubkey))
            + bytes(Pubkey.from_string(self.notary_config_pubkey))
            + struct.pack("<Q", self.notary_config_version)
        ).hexdigest()


@dataclass(frozen=True)
class IndependentSignerBinding:
    signer_slot: str
    signer_id: str
    signer_public_key: str
    signer_key_epoch: int

    def __post_init__(self) -> None:
        if self.signer_slot not in ("A", "B"):
            raise IndependentSignerJournalBindingError("signer_slot_invalid")
        _text(self.signer_id, "signer_id")
        _pubkey(self.signer_public_key, "signer_public_key")
        _positive_int(self.signer_key_epoch, "signer_key_epoch")

    @property
    def signer_config_fingerprint(self) -> str:
        return derive_signer_config_fingerprint(
            signer_slot=self.signer_slot,
            signer_id=self.signer_id,
            signer_public_key=self.signer_public_key,
            signer_key_epoch=self.signer_key_epoch,
        )


@dataclass(frozen=True)
class IndependentSigningIntent:
    scope: IndependentSigningScope
    settlement_authorization_job_id: str
    canonical_message: bytes
    canonical_message_digest: str
    @classmethod
    def from_journal_authorization(
        cls, authorization: _JournalAuthorizedSettlement,
    ) -> "IndependentSigningIntent":
        if type(authorization) is not _JournalAuthorizedSettlement:
            raise IndependentSignerJournalBindingError("journal_authorization_invalid")
        message = authorization.canonical_message_bytes
        if not isinstance(message, bytes) or len(message) != 235 or message[:18] != b"PROPHET_RESOLVE_V2":
            raise IndependentSignerJournalBindingError("authorization_message_invalid")
        digest = hashlib.sha256(message).hexdigest()
        if authorization.canonical_message_digest != digest:
            raise IndependentSignerJournalBindingError("authorization_message_digest_invalid")
        program = str(Pubkey.from_bytes(message[18:50]))
        market = str(Pubkey.from_bytes(message[50:82]))
        notary = str(Pubkey.from_bytes(message[82:114]))
        version = struct.unpack_from("<Q", message, 162)[0]
        if (program != authorization.program_id or market != authorization.market
                or notary != authorization.notary_config or version != authorization.notary_config_version):
            raise IndependentSignerJournalBindingError("authorization_scope_binding_invalid")
        return cls(
            IndependentSigningScope(authorization.cluster_genesis_hash, program, market, notary, version),
            _hex32(authorization.settlement_authorization_job_id, "settlement_authorization_job_id"),
            message, digest,
        )

    def __post_init__(self) -> None:
        if not isinstance(self.scope, IndependentSigningScope):
            raise IndependentSignerJournalBindingError("intent_binding_invalid")
        _hex32(self.settlement_authorization_job_id, "settlement_authorization_job_id")
        if not isinstance(self.canonical_message, bytes) or len(self.canonical_message) != 235:
            raise IndependentSignerJournalBindingError("canonical_message_invalid")
        if self.canonical_message[:18] != b"PROPHET_RESOLVE_V2":
            raise IndependentSignerJournalBindingError("canonical_message_domain_invalid")
        if self.canonical_message_digest != hashlib.sha256(self.canonical_message).hexdigest():
            raise IndependentSignerJournalBindingError("canonical_message_digest_invalid")


@dataclass(frozen=True)
class IndependentJournalRecord:
    scope: IndependentSigningScope
    settlement_authorization_job_id: str
    canonical_message: bytes
    canonical_message_digest: str
    binding: IndependentSignerBinding
    state: str
    operation_id: str | None
    backend_operation_id: str | None
    signature: bytes | None
    signature_key_epoch: int | None
    conflict_digest: str | None
    created_at_ms: str
    updated_at_ms: str


class IndependentSignerJournal:
    """One signer, one SQLite file, one irreversible authorization decision."""

    def __init__(self, path: str | Path, *, binding: IndependentSignerBinding) -> None:
        self.path = str(path)
        if not self.path or self.path == ":memory:":
            raise IndependentSignerJournalBindingError("persistent_independent_signer_journal_path_required")
        if not isinstance(binding, IndependentSignerBinding):
            raise IndependentSignerJournalBindingError("trusted_signer_binding_required")
        self.binding = binding
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False, timeout=0.1)
        self._db.row_factory = sqlite3.Row
        configure_durable_connection(self._db)
        self._migrate_and_recover()

    def _enable_wal(self) -> None:
        deadline = time.monotonic() + 5.0
        while True:
            try:
                self._db.execute("PRAGMA journal_mode = WAL")
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or time.monotonic() >= deadline:
                    raise IndependentSignerJournalStateError("independent_signer_journal_wal_unavailable") from exc
                time.sleep(0.01)

    def close(self) -> None:
        self._db.close()

    def health(self) -> bool:
        """Run non-mutating structural checks for readiness probes."""
        try:
            with self._lock:
                if self._db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    return False
                if self._db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                    return False
                metadata = self._db.execute("SELECT COUNT(*) FROM independent_signer_intents").fetchone()
                return metadata is not None and int(metadata[0]) >= 0
        except sqlite3.Error:
            return False

    def _migrate_and_recover(self) -> None:
        with self._lock:
            if self._db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise IndependentSignerJournalStateError("independent_signer_journal_integrity_invalid")
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            if version > SCHEMA_VERSION:
                raise IndependentSignerJournalStateError("unsupported_independent_signer_journal_schema")
            if version == 0:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.execute("""CREATE TABLE IF NOT EXISTS independent_signer_intents (
                        scope_id TEXT PRIMARY KEY,
                        cluster_genesis_hash TEXT NOT NULL, program_id TEXT NOT NULL,
                        market_pubkey TEXT NOT NULL, notary_config_pubkey TEXT NOT NULL,
                        notary_config_version INTEGER NOT NULL,
                        settlement_authorization_job_id TEXT NOT NULL,
                        canonical_message BLOB NOT NULL, canonical_message_digest TEXT NOT NULL,
                        signer_slot TEXT NOT NULL, signer_id TEXT NOT NULL, signer_public_key TEXT NOT NULL,
                        signer_key_epoch INTEGER NOT NULL, signer_config_fingerprint TEXT NOT NULL,
                        state TEXT NOT NULL,
                        operation_id TEXT UNIQUE, uncertain_reason TEXT, backend_operation_id TEXT,
                        signature BLOB, signature_key_epoch INTEGER, conflict_digest TEXT,
                        created_at_ms TEXT NOT NULL, updated_at_ms TEXT NOT NULL
                    )""")
                    self._db.execute("PRAGMA user_version = 1")
                    self._db.execute("COMMIT")
                except Exception:
                    self._db.execute("ROLLBACK")
                    raise
            self._db.execute("BEGIN IMMEDIATE")
            try:
                rows = self._db.execute("SELECT * FROM independent_signer_intents").fetchall()
                for row in rows:
                    if self._row(row).binding != self.binding:
                        raise IndependentSignerJournalBindingError("journal_signer_binding_mismatch")
                self._db.execute("UPDATE independent_signer_intents SET state = ?, updated_at_ms = ? WHERE state = ?", (UNCERTAIN, _now_ms(), SIGNING))
                self._db.execute("COMMIT")
            except Exception:
                if self._db.in_transaction: self._db.execute("ROLLBACK")
                raise

    def prepare(self, authorization: _JournalAuthorizedSettlement, *, created_at_ms: int | None = None) -> IndependentJournalRecord:
        intent = IndependentSigningIntent.from_journal_authorization(authorization)
        now = _timestamp(created_at_ms, "created_at_ms") if created_at_ms is not None else _now_ms()
        conflict = False
        with self._transaction():
            row = self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (intent.scope.scope_id,)).fetchone()
            if row is None:
                self._db.execute("""INSERT INTO independent_signer_intents(
                    scope_id,cluster_genesis_hash,program_id,market_pubkey,notary_config_pubkey,notary_config_version,
                    settlement_authorization_job_id,canonical_message,canonical_message_digest,
                        signer_slot,signer_id,signer_public_key,signer_key_epoch,signer_config_fingerprint,state,created_at_ms,updated_at_ms
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    intent.scope.scope_id,intent.scope.cluster_genesis_hash,intent.scope.program_id,intent.scope.market_pubkey,
                    intent.scope.notary_config_pubkey,intent.scope.notary_config_version,intent.settlement_authorization_job_id,
                    intent.canonical_message,intent.canonical_message_digest,self.binding.signer_slot,self.binding.signer_id,self.binding.signer_public_key,
                    self.binding.signer_key_epoch,self.binding.signer_config_fingerprint,PREPARED,now,now,
                ))
                return self._row(self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (intent.scope.scope_id,)).fetchone())
            record = self._row(row)
            if record.canonical_message_digest != intent.canonical_message_digest or record.canonical_message != intent.canonical_message:
                self._db.execute("UPDATE independent_signer_intents SET state = ?, conflict_digest = ?, updated_at_ms = ? WHERE scope_id = ?", (CONFLICT, intent.canonical_message_digest, _now_ms(), intent.scope.scope_id))
                record = self._row(self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (intent.scope.scope_id,)).fetchone())
                conflict = True
            elif (record.settlement_authorization_job_id != intent.settlement_authorization_job_id or record.binding != self.binding):
                raise IndependentSignerJournalBindingError("signing_scope_authorization_binding_mismatch")
        if conflict:
            raise IndependentSignerJournalConflict("signing_scope_already_bound_to_different_message")
        return record

    def begin_signing(self, scope_id: str) -> IndependentJournalRecord:
        _hex32(scope_id, "scope_id")
        with self._transaction():
            row = self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (scope_id,)).fetchone()
            if row is None: raise IndependentSignerJournalStateError("signing_intent_not_found")
            record = self._row(row)
            if record.state == SIGNED: return record
            if record.state in (SIGNING, UNCERTAIN): raise IndependentSignerJournalStateError("signing_outcome_uncertain")
            if record.state == CONFLICT: raise IndependentSignerJournalConflict("signing_scope_conflict")
            if record.state != PREPARED: raise IndependentSignerJournalStateError("signing_transition_rejected")
            operation = uuid.uuid4().hex
            self._db.execute("UPDATE independent_signer_intents SET state = ?, operation_id = ?, updated_at_ms = ? WHERE scope_id = ?", (SIGNING, operation, _now_ms(), scope_id))
            return self._row(self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (scope_id,)).fetchone())

    def mark_uncertain(self, scope_id: str, *, reason: str, backend_operation_id: str | None = None) -> IndependentJournalRecord:
        _hex32(scope_id, "scope_id")
        if not isinstance(reason, str) or not reason or len(reason) > 128:
            raise IndependentSignerJournalBindingError("uncertain_reason_invalid")
        if backend_operation_id is not None and (not isinstance(backend_operation_id, str) or not backend_operation_id or len(backend_operation_id) > 256):
            raise IndependentSignerJournalBindingError("backend_operation_id_invalid")
        with self._transaction():
            row = self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (scope_id,)).fetchone()
            if row is None: raise IndependentSignerJournalStateError("signing_intent_not_found")
            if self._row(row).state != SIGNING: raise IndependentSignerJournalStateError("uncertain_transition_rejected")
            self._db.execute("UPDATE independent_signer_intents SET state = ?, uncertain_reason = ?, backend_operation_id = ?, updated_at_ms = ? WHERE scope_id = ?", (UNCERTAIN, reason, backend_operation_id, _now_ms(), scope_id))
            return self._row(self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (scope_id,)).fetchone())

    def record_signature(self, scope_id: str, *, signature: bytes, signer_key_epoch: int, backend_operation_id: str | None = None) -> IndependentJournalRecord:
        return self._store_signature(scope_id, signature=signature, signer_key_epoch=signer_key_epoch, backend_operation_id=backend_operation_id, allowed_state=SIGNING)

    def reconcile_signature(self, scope_id: str, *, signature: bytes, signer_key_epoch: int, backend_operation_id: str | None = None) -> IndependentJournalRecord:
        return self._store_signature(scope_id, signature=signature, signer_key_epoch=signer_key_epoch, backend_operation_id=backend_operation_id, allowed_state=UNCERTAIN)

    def _store_signature(self, scope_id: str, *, signature: bytes, signer_key_epoch: int, backend_operation_id: str | None, allowed_state: str) -> IndependentJournalRecord:
        _hex32(scope_id, "scope_id")
        _positive_int(signer_key_epoch, "signer_key_epoch")
        if backend_operation_id is not None and (not isinstance(backend_operation_id, str) or not backend_operation_id or len(backend_operation_id) > 256):
            raise IndependentSignerJournalBindingError("backend_operation_id_invalid")
        with self._transaction():
            row = self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (scope_id,)).fetchone()
            if row is None: raise IndependentSignerJournalStateError("signing_intent_not_found")
            record = self._row(row)
            if record.state == SIGNED:
                if record.signature == signature and record.signature_key_epoch == signer_key_epoch:
                    return record
                raise IndependentSignerJournalStateError("signed_result_immutable")
            if record.state != allowed_state: raise IndependentSignerJournalStateError("signature_transition_rejected")
            if allowed_state == UNCERTAIN and record.backend_operation_id is not None and backend_operation_id != record.backend_operation_id:
                raise IndependentSignerJournalBindingError("backend_operation_id_mismatch")
            self._validate_signature(record, signature, signer_key_epoch)
            self._db.execute("UPDATE independent_signer_intents SET signature = ?, signature_key_epoch = ?, backend_operation_id = COALESCE(backend_operation_id, ?), state = ?, updated_at_ms = ? WHERE scope_id = ?", (signature, signer_key_epoch, backend_operation_id, SIGNED, _now_ms(), scope_id))
            return self._row(self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (scope_id,)).fetchone())

    def get(self, scope_id: str) -> IndependentJournalRecord:
        _hex32(scope_id, "scope_id")
        row = self._db.execute("SELECT * FROM independent_signer_intents WHERE scope_id = ?", (scope_id,)).fetchone()
        if row is None: raise IndependentSignerJournalStateError("signing_intent_not_found")
        return self._row(row)

    def _validate_signature(self, record: IndependentJournalRecord, signature: Any, signer_key_epoch: int) -> None:
        if signer_key_epoch != record.binding.signer_key_epoch:
            raise IndependentSignerJournalBindingError("signer_key_epoch_mismatch")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise IndependentSignerJournalSignatureError("signature_malformed")
        try:
            if not Signature.from_bytes(signature).verify(Pubkey.from_string(record.binding.signer_public_key), record.canonical_message):
                raise IndependentSignerJournalSignatureError("signature_invalid")
        except IndependentSignerJournalSignatureError: raise
        except Exception as exc: raise IndependentSignerJournalSignatureError("signature_malformed") from exc

    def _row(self, row: sqlite3.Row | None) -> IndependentJournalRecord:
        if row is None: raise IndependentSignerJournalStateError("journal_row_missing")
        try:
            scope = IndependentSigningScope(row["cluster_genesis_hash"], row["program_id"], row["market_pubkey"], row["notary_config_pubkey"], row["notary_config_version"])
            if row["scope_id"] != scope.scope_id or row["state"] not in _STATES: raise ValueError
            binding = IndependentSignerBinding(
                row["signer_slot"], row["signer_id"], row["signer_public_key"], row["signer_key_epoch"],
            )
            if row["signer_config_fingerprint"] != binding.signer_config_fingerprint: raise ValueError
            if binding != self.binding: raise ValueError
            message = bytes(row["canonical_message"])
            job = _hex32(row["settlement_authorization_job_id"], "settlement_authorization_job_id")
            digest = _hex32(row["canonical_message_digest"], "canonical_message_digest")
            if hashlib.sha256(message).hexdigest() != digest: raise ValueError
            if len(message) != 235 or message[:18] != b"PROPHET_RESOLVE_V2": raise ValueError
            if not isinstance(row["created_at_ms"], str) or not row["created_at_ms"].isdigit() or not isinstance(row["updated_at_ms"], str) or not row["updated_at_ms"].isdigit(): raise ValueError
            signature = None if row["signature"] is None else bytes(row["signature"])
            epoch = row["signature_key_epoch"]
            if signature is not None and (not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0): raise ValueError
            conflict = row["conflict_digest"]
            if conflict is not None: _hex32(conflict, "conflict_digest")
            record = IndependentJournalRecord(scope,job,message,digest,binding,row["state"],row["operation_id"],row["backend_operation_id"],signature,epoch,conflict,row["created_at_ms"],row["updated_at_ms"])
            if record.state == SIGNED:
                if record.signature is None or record.signature_key_epoch is None: raise ValueError
                self._validate_signature(record, record.signature, record.signature_key_epoch)
            if record.state == PREPARED and record.operation_id is not None: raise ValueError
            if record.state in (SIGNING, UNCERTAIN, SIGNED): _operation_id(record.operation_id)
            if record.state == CONFLICT and record.operation_id is not None: _operation_id(record.operation_id)
            if record.state == CONFLICT and record.conflict_digest is None: raise ValueError
            return record
        except (IndependentSignerJournalBindingError, ValueError, TypeError, struct.error) as exc:
            raise IndependentSignerJournalStateError("independent_signer_journal_row_invalid") from exc

    class _Transaction:
        def __init__(self, journal: "IndependentSignerJournal") -> None: self.journal=journal
        def __enter__(self):
            self.journal._lock.acquire(); self.journal._db.execute("BEGIN IMMEDIATE"); return self
        def __exit__(self, typ, value, trace) -> None:
            try:
                if typ is None: self.journal._db.execute("COMMIT")
                elif self.journal._db.in_transaction: self.journal._db.execute("ROLLBACK")
            finally: self.journal._lock.release()
    def _transaction(self) -> "IndependentSignerJournal._Transaction":
        return self._Transaction(self)
