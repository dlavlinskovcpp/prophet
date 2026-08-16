"""Durable, fail-closed anti-equivocation journal for Vault 2-of-2 signing."""
from __future__ import annotations

import hashlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from solders.pubkey import Pubkey
from solders.signature import Signature

from .vault_transit_signer_identity import VaultTransitSignature


SCHEMA_VERSION = 2
INTENT_RECORDED = "INTENT_RECORDED"
A_SIGNING = "A_SIGNING"
A_SIGNED = "A_SIGNED"
B_SIGNING = "B_SIGNING"
BOTH_SIGNED = "BOTH_SIGNED"
NOT_STARTED = "NOT_STARTED"
SIGNATURE_STATUS_UNKNOWN = "SIGNATURE_STATUS_UNKNOWN"
SIGNATURE_RECORDED = "SIGNATURE_RECORDED"


class SigningJournalError(RuntimeError): pass
class SigningJournalConflict(SigningJournalError): pass
class SigningJournalBindingError(SigningJournalError): pass
class SigningJournalUncertain(SigningJournalError): pass
class SigningJournalStateError(SigningJournalError): pass
class SigningJournalSignatureError(SigningJournalError): pass


@dataclass(frozen=True)
class JournalSignerBinding:
    signer_id: str
    public_key: str
    key_version: int


@dataclass(frozen=True)
class SigningJournalIntent:
    signing_scope_id: str
    canonical_message_digest: str
    canonical_message: bytes
    signer_a: JournalSignerBinding
    signer_b: JournalSignerBinding
    state: str
    signer_a_result: VaultTransitSignature | None
    signer_b_result: VaultTransitSignature | None
    created_at_ms: str
    updated_at_ms: str


@dataclass(frozen=True)
class CoordinatorSigningLink:
    coordinator_job_id: str
    signing_scope_id: str
    canonical_message_digest: str
    created_at_ms: str


@dataclass(frozen=True)
class SigningRecoveryStatus:
    """Public, non-secret recovery view. It never performs a Vault action."""

    signing_scope_id: str
    canonical_message_digest: str
    signer_a_state: str
    signer_b_state: str
    category: str
    created_at_ms: str
    updated_at_ms: str


def _now_ms() -> str:
    return str(int(time.time() * 1000))


def settlement_signing_scope(canonical_message: bytes) -> str:
    """Protocol-native settlement identity, excluding result commitments.

    The authoritative V2 layout is 235 bytes.  All fields through
    `notary_config_version` identify the resolution scope; outcome, proof hash,
    and public inputs are precisely the values whose conflicting variants must
    collide in this journal.
    """
    if not isinstance(canonical_message, bytes) or len(canonical_message) != 235:
        raise SigningJournalBindingError("canonical_settlement_message_invalid")
    if canonical_message[:18] != b"PROPHET_RESOLVE_V2":
        raise SigningJournalBindingError("canonical_settlement_message_domain_invalid")
    return hashlib.sha256(b"PROPHET_SIGNING_SCOPE_V1\0" + canonical_message[:170]).hexdigest()


class SigningJournal:
    """SQLite journal. It has no Vault calls and never retries signing."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if not self.path or self.path == ":memory:":
            raise SigningJournalBindingError("persistent_signing_journal_path_required")
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
                raise SigningJournalStateError("unsupported_signing_journal_schema")
            if version == 0:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.execute("""CREATE TABLE signing_intents (
                        signing_scope_id TEXT PRIMARY KEY,
                        canonical_message_digest TEXT NOT NULL,
                        canonical_message BLOB NOT NULL,
                        signer_a_id TEXT NOT NULL, signer_a_public_key TEXT NOT NULL, signer_a_key_version INTEGER NOT NULL,
                        signer_b_id TEXT NOT NULL, signer_b_public_key TEXT NOT NULL, signer_b_key_version INTEGER NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('INTENT_RECORDED','A_SIGNING','A_SIGNED','B_SIGNING','BOTH_SIGNED')),
                        signer_a_signature BLOB, signer_a_signature_digest TEXT,
                        signer_b_signature BLOB, signer_b_signature_digest TEXT,
                        created_at_ms TEXT NOT NULL, updated_at_ms TEXT NOT NULL
                    )""")
                    self._db.execute("CREATE UNIQUE INDEX signing_intents_scope_digest ON signing_intents(signing_scope_id, canonical_message_digest)")
                    self._db.execute("""CREATE TABLE coordinator_signing_links (
                        coordinator_job_id TEXT PRIMARY KEY,
                        signing_scope_id TEXT NOT NULL,
                        canonical_message_digest TEXT NOT NULL,
                        created_at_ms TEXT NOT NULL,
                        FOREIGN KEY(signing_scope_id) REFERENCES signing_intents(signing_scope_id)
                    )""")
                    self._db.execute("CREATE INDEX coordinator_signing_links_scope ON coordinator_signing_links(signing_scope_id)")
                    self._db.execute("PRAGMA user_version = 2")
                    self._db.execute("COMMIT")
                except Exception:
                    self._db.execute("ROLLBACK")
                    raise
                return
            if version == 1:
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.execute("""CREATE TABLE coordinator_signing_links (
                        coordinator_job_id TEXT PRIMARY KEY,
                        signing_scope_id TEXT NOT NULL,
                        canonical_message_digest TEXT NOT NULL,
                        created_at_ms TEXT NOT NULL,
                        FOREIGN KEY(signing_scope_id) REFERENCES signing_intents(signing_scope_id)
                    )""")
                    self._db.execute("CREATE INDEX coordinator_signing_links_scope ON coordinator_signing_links(signing_scope_id)")
                    self._db.execute("PRAGMA user_version = 2")
                    self._db.execute("COMMIT")
                except Exception:
                    self._db.execute("ROLLBACK")
                    raise

    @staticmethod
    def _binding(value: JournalSignerBinding) -> JournalSignerBinding:
        if not isinstance(value, JournalSignerBinding) or not value.signer_id or not value.public_key or not isinstance(value.key_version, int) or value.key_version <= 0:
            raise SigningJournalBindingError("signer_binding_invalid")
        try:
            if str(Pubkey.from_string(value.public_key)) != value.public_key:
                raise ValueError
        except Exception as exc:
            raise SigningJournalBindingError("signer_public_key_invalid") from exc
        return value

    @classmethod
    def _validate_bindings(cls, signer_a: JournalSignerBinding, signer_b: JournalSignerBinding) -> tuple[JournalSignerBinding, JournalSignerBinding]:
        signer_a, signer_b = cls._binding(signer_a), cls._binding(signer_b)
        if signer_a.signer_id == signer_b.signer_id or signer_a.public_key == signer_b.public_key:
            raise SigningJournalBindingError("journal_signers_must_be_distinct")
        return signer_a, signer_b

    def reserve_intent(
        self, canonical_message: bytes, *, signer_a: JournalSignerBinding, signer_b: JournalSignerBinding,
        created_at_ms: int | None = None, coordinator_job_id: str | None = None,
    ) -> SigningJournalIntent:
        signer_a, signer_b = self._validate_bindings(signer_a, signer_b)
        scope, digest = settlement_signing_scope(canonical_message), hashlib.sha256(canonical_message).hexdigest()
        if coordinator_job_id is not None and (not isinstance(coordinator_job_id, str) or not coordinator_job_id):
            raise SigningJournalBindingError("coordinator_job_id_invalid")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT * FROM signing_intents WHERE signing_scope_id = ?", (scope,)).fetchone()
                if row is None:
                    if created_at_ms is not None and (isinstance(created_at_ms, bool) or not isinstance(created_at_ms, int) or created_at_ms < 0):
                        raise SigningJournalBindingError("signing_intent_creation_time_invalid")
                    now = str(created_at_ms) if created_at_ms is not None else _now_ms()
                    self._db.execute("""INSERT INTO signing_intents(
                        signing_scope_id,canonical_message_digest,canonical_message,
                        signer_a_id,signer_a_public_key,signer_a_key_version,
                        signer_b_id,signer_b_public_key,signer_b_key_version,state,created_at_ms,updated_at_ms
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                        scope,digest,canonical_message,signer_a.signer_id,signer_a.public_key,signer_a.key_version,
                        signer_b.signer_id,signer_b.public_key,signer_b.key_version,INTENT_RECORDED,now,now,
                    ))
                else:
                    self._assert_intent_binding(row, canonical_message, signer_a, signer_b)
                if coordinator_job_id is not None:
                    link = self._db.execute("SELECT * FROM coordinator_signing_links WHERE coordinator_job_id = ?", (coordinator_job_id,)).fetchone()
                    if link is None:
                        self._db.execute(
                            "INSERT INTO coordinator_signing_links(coordinator_job_id, signing_scope_id, canonical_message_digest, created_at_ms) VALUES (?, ?, ?, ?)",
                            (coordinator_job_id, scope, digest, _now_ms()),
                        )
                    elif link["signing_scope_id"] != scope or link["canonical_message_digest"] != digest:
                        raise SigningJournalBindingError("coordinator_job_signing_binding_mismatch")
                updated = self._db.execute("SELECT * FROM signing_intents WHERE signing_scope_id = ?", (scope,)).fetchone()
                self._db.execute("COMMIT")
                return self._row(updated)
            except Exception:
                if self._db.in_transaction: self._db.execute("ROLLBACK")
                raise

    def get(self, signing_scope_id: str) -> SigningJournalIntent:
        row = self._db.execute("SELECT * FROM signing_intents WHERE signing_scope_id = ?", (signing_scope_id,)).fetchone()
        if row is None: raise SigningJournalStateError("signing_intent_not_found")
        return self._row(row)

    def get_coordinator_link(self, coordinator_job_id: str) -> CoordinatorSigningLink:
        row = self._db.execute("SELECT * FROM coordinator_signing_links WHERE coordinator_job_id = ?", (coordinator_job_id,)).fetchone()
        if row is None:
            raise SigningJournalStateError("coordinator_signing_link_not_found")
        return CoordinatorSigningLink(row["coordinator_job_id"], row["signing_scope_id"], row["canonical_message_digest"], row["created_at_ms"])

    def get_for_coordinator_job(self, coordinator_job_id: str) -> SigningJournalIntent:
        return self.get(self.get_coordinator_link(coordinator_job_id).signing_scope_id)

    def validate_completed_intent(self, signing_scope_id: str) -> SigningJournalIntent:
        """Return one cryptographically revalidated durable 2/2 intent read-only.

        This deliberately performs no state transition. It reuses the journal's
        existing slot binding, digest, key-version, and Ed25519 validation logic.
        """
        row = self._db.execute(
            "SELECT * FROM signing_intents WHERE signing_scope_id = ?", (signing_scope_id,)
        ).fetchone()
        if row is None:
            raise SigningJournalStateError("signing_intent_not_found")
        if row["state"] != BOTH_SIGNED:
            raise SigningJournalStateError("completed_2of2_signing_intent_required")
        signed_a, signed_b = self._signature(row, "A"), self._signature(row, "B")
        if signed_a is None or signed_b is None:
            raise SigningJournalStateError("completed_2of2_signature_bundle_missing")
        self._validate_signature_for_slot(row, "A", signed_a)
        self._validate_signature_for_slot(row, "B", signed_b)
        return self._row(row)

    def inspect_recovery(self, signing_scope_id: str) -> SigningRecoveryStatus:
        """Classify one durable record without changing state or calling Vault."""
        return self._recovery_status(self.get(signing_scope_id))

    def scan_recovery(self) -> tuple[SigningRecoveryStatus, ...]:
        """Read-only startup inspection; callers must not auto-sign its output."""
        rows = self._db.execute("SELECT * FROM signing_intents ORDER BY created_at_ms, signing_scope_id").fetchall()
        return tuple(self._recovery_status(self._row(row)) for row in rows)

    def begin_signer(self, signing_scope_id: str, slot: str) -> VaultTransitSignature | None:
        """Durably reserve a signer call, or return its exact persisted result.

        A process crash after this transition is intentionally uncertain: a later
        caller cannot blindly ask Vault to sign again.
        """
        if slot not in ("A", "B"): raise SigningJournalBindingError("unsupported_signer_slot")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT * FROM signing_intents WHERE signing_scope_id = ?", (signing_scope_id,)).fetchone()
                if row is None: raise SigningJournalStateError("signing_intent_not_found")
                state = row["state"]
                signature = self._signature(row, slot)
                if signature is not None:
                    self._db.execute("COMMIT")
                    return signature
                if (slot == "A" and state == A_SIGNING) or (slot == "B" and state == B_SIGNING):
                    raise SigningJournalUncertain("previous_vault_signing_outcome_unknown")
                if slot == "A":
                    if state != INTENT_RECORDED: raise SigningJournalStateError("signer_a_transition_rejected")
                    next_state = A_SIGNING
                else:
                    if state != A_SIGNED: raise SigningJournalStateError("signer_b_requires_durable_signer_a_result")
                    next_state = B_SIGNING
                self._db.execute("UPDATE signing_intents SET state = ?, updated_at_ms = ? WHERE signing_scope_id = ?", (next_state, _now_ms(), signing_scope_id))
                self._db.execute("COMMIT")
                return None
            except Exception:
                if self._db.in_transaction: self._db.execute("ROLLBACK")
                raise

    def record_signature(self, signing_scope_id: str, slot: str, signed: VaultTransitSignature) -> SigningJournalIntent:
        if slot not in ("A", "B"): raise SigningJournalBindingError("unsupported_signer_slot")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT * FROM signing_intents WHERE signing_scope_id = ?", (signing_scope_id,)).fetchone()
                if row is None: raise SigningJournalStateError("signing_intent_not_found")
                self._validate_signature_for_slot(row, slot, signed)
                existing = self._signature(row, slot)
                if existing is not None:
                    if existing == signed:
                        self._db.execute("COMMIT")
                        return self._row(row)
                    raise SigningJournalConflict("signer_result_immutable")
                expected_state = A_SIGNING if slot == "A" else B_SIGNING
                if row["state"] != expected_state: raise SigningJournalStateError("signer_result_not_reserved")
                prefix = f"signer_{slot.lower()}"
                next_state = A_SIGNED if slot == "A" else BOTH_SIGNED
                self._db.execute(f"UPDATE signing_intents SET {prefix}_signature = ?, {prefix}_signature_digest = ?, state = ?, updated_at_ms = ? WHERE signing_scope_id = ?", (signed.signature, signed.message_digest, next_state, _now_ms(), signing_scope_id))
                updated = self._db.execute("SELECT * FROM signing_intents WHERE signing_scope_id = ?", (signing_scope_id,)).fetchone()
                self._db.execute("COMMIT")
                return self._row(updated)
            except Exception:
                if self._db.in_transaction: self._db.execute("ROLLBACK")
                raise

    def _assert_intent_binding(self, row: sqlite3.Row, message: bytes, signer_a: JournalSignerBinding, signer_b: JournalSignerBinding) -> None:
        if row["canonical_message_digest"] != hashlib.sha256(message).hexdigest() or bytes(row["canonical_message"]) != message:
            raise SigningJournalConflict("signing_scope_already_bound_to_different_message")
        actual_a = JournalSignerBinding(row["signer_a_id"], row["signer_a_public_key"], row["signer_a_key_version"])
        actual_b = JournalSignerBinding(row["signer_b_id"], row["signer_b_public_key"], row["signer_b_key_version"])
        if actual_a != signer_a or actual_b != signer_b:
            raise SigningJournalBindingError("signing_scope_signer_binding_mismatch")

    @staticmethod
    def _signature(row: sqlite3.Row, slot: str) -> VaultTransitSignature | None:
        prefix = f"signer_{slot.lower()}"
        raw = row[f"{prefix}_signature"]
        if raw is None: return None
        return VaultTransitSignature(row[f"{prefix}_id"], row[f"{prefix}_key_version"], row[f"{prefix}_public_key"], bytes(raw), row[f"{prefix}_signature_digest"])

    def _validate_signature_for_slot(self, row: sqlite3.Row, slot: str, signed: VaultTransitSignature) -> None:
        if not isinstance(signed, VaultTransitSignature): raise SigningJournalSignatureError("signing_result_invalid")
        prefix = f"signer_{slot.lower()}"
        if signed.signer_id != row[f"{prefix}_id"] or signed.public_key != row[f"{prefix}_public_key"]:
            raise SigningJournalBindingError("signer_result_slot_identity_mismatch")
        if signed.key_version != row[f"{prefix}_key_version"]:
            raise SigningJournalBindingError("signer_result_key_version_mismatch")
        message = bytes(row["canonical_message"])
        digest = hashlib.sha256(message).hexdigest()
        if signed.message_digest != digest or row["canonical_message_digest"] != digest:
            raise SigningJournalSignatureError("signing_result_message_digest_mismatch")
        if not isinstance(signed.signature, bytes) or len(signed.signature) != 64:
            raise SigningJournalSignatureError("signing_result_malformed")
        try:
            if not Signature.from_bytes(signed.signature).verify(Pubkey.from_string(signed.public_key), message):
                raise SigningJournalSignatureError("signing_result_does_not_verify")
        except SigningJournalSignatureError: raise
        except Exception as exc: raise SigningJournalSignatureError("signing_result_malformed") from exc

    @staticmethod
    def _row(row: sqlite3.Row) -> SigningJournalIntent:
        a = JournalSignerBinding(row["signer_a_id"], row["signer_a_public_key"], row["signer_a_key_version"])
        b = JournalSignerBinding(row["signer_b_id"], row["signer_b_public_key"], row["signer_b_key_version"])
        return SigningJournalIntent(row["signing_scope_id"], row["canonical_message_digest"], bytes(row["canonical_message"]), a, b, row["state"], SigningJournal._signature(row, "A"), SigningJournal._signature(row, "B"), row["created_at_ms"], row["updated_at_ms"])

    @staticmethod
    def _recovery_status(intent: SigningJournalIntent) -> SigningRecoveryStatus:
        states = {
            INTENT_RECORDED: (NOT_STARTED, NOT_STARTED, "INCOMPLETE"),
            A_SIGNING: (SIGNATURE_STATUS_UNKNOWN, NOT_STARTED, "UNCERTAIN"),
            A_SIGNED: (SIGNATURE_RECORDED, NOT_STARTED, "INCOMPLETE"),
            B_SIGNING: (SIGNATURE_RECORDED, SIGNATURE_STATUS_UNKNOWN, "UNCERTAIN"),
            BOTH_SIGNED: (SIGNATURE_RECORDED, SIGNATURE_RECORDED, "COMPLETE"),
        }
        try:
            a, b, category = states[intent.state]
        except KeyError as exc:
            raise SigningJournalStateError("unknown_signing_journal_state") from exc
        return SigningRecoveryStatus(intent.signing_scope_id, intent.canonical_message_digest, a, b, category, intent.created_at_ms, intent.updated_at_ms)
