"""Durable, in-process Resolver V2 A/B coordination state.

This module persists canonical verifier results and delegates agreement
interpretation to the existing multi-verifier agreement implementation.  It has
no network, signing, or settlement side effects.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Any, Mapping

from .resolver_v2_multi_verifier import AgreementPolicy, evaluate_agreement
from .resolver_v2_pipeline import PipelineRejected

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


SCHEMA_VERSION = 1
PENDING = "PENDING"
A_RECORDED = "A_RECORDED"
B_RECORDED = "B_RECORDED"
AGREED = "AGREED"
CONFLICT = "CONFLICT"
TERMINAL_STATES = frozenset((AGREED, CONFLICT))


class CoordinatorRejected(ValueError):
    """A fail-closed coordinator transition or binding rejection."""


@dataclass(frozen=True)
class VerifierBinding:
    """The exact implementation descriptor allowed to fill one durable slot."""

    slot: str
    descriptor: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.slot not in ("A", "B"):
            raise CoordinatorRejected("unsupported_verifier_slot")
        try:
            canonical = resolver_v2._validate_adapter(self.descriptor)
        except resolver_v2.ResolverV2Error as exc:
            raise CoordinatorRejected("invalid_verifier_binding") from exc
        object.__setattr__(self, "descriptor", MappingProxyType(dict(canonical)))


@dataclass(frozen=True)
class ResolutionJob:
    job_id: str
    market: str
    resolver_definition_hash: str
    evidence_hash: str
    state: str
    verifier_a: Mapping[str, Any]
    verifier_b: Mapping[str, Any]
    verifier_a_result: Mapping[str, Any] | None
    verifier_b_result: Mapping[str, Any] | None
    outcome: str | None
    conflict_reason: str | None
    created_at_ms: str
    updated_at_ms: str


def _now_ms() -> str:
    return str(int(time.time() * 1000))


def _canonical_json(value: Mapping[str, Any]) -> str:
    return resolver_v2.canonical_json_bytes(value).decode("utf-8")


def _job_id(*, market: str, definition_hash: str, evidence_hash: str, verifier_a: Mapping[str, Any], verifier_b: Mapping[str, Any]) -> str:
    payload = {
        "market": market,
        "resolver_definition_hash": definition_hash,
        "evidence_hash": evidence_hash,
        "verifier_a": dict(verifier_a),
        "verifier_b": dict(verifier_b),
    }
    return hashlib.sha256(
        b"PROPHET_RESOLUTION_COORDINATOR_JOB_V1\0" + resolver_v2.canonical_json_bytes(payload)
    ).hexdigest()


class ResolutionCoordinatorStore:
    """SQLite-backed, finite-state coordination of exactly two verifier slots."""

    def __init__(self, path: str | Path, *, verifier_a: VerifierBinding, verifier_b: VerifierBinding):
        if verifier_a.slot != "A" or verifier_b.slot != "B":
            raise CoordinatorRejected("verifier_binding_slot_mismatch")
        if verifier_a.descriptor["adapter_id"] == verifier_b.descriptor["adapter_id"]:
            raise CoordinatorRejected("duplicate_verifier_identity")
        self.path = str(path)
        self.verifier_a = verifier_a
        self.verifier_b = verifier_b
        self._lock = Lock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA busy_timeout = 5000")
        self._migrate()

    def close(self) -> None:
        self._db.close()

    def schema_version(self) -> int:
        return int(self._db.execute("PRAGMA user_version").fetchone()[0])

    def _migrate(self) -> None:
        with self._lock:
            current = self.schema_version()
            if current > SCHEMA_VERSION:
                raise CoordinatorRejected("unsupported_coordinator_schema")
            if current == 0:
                timestamp = _now_ms()
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    self._db.execute(
                        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at_ms TEXT NOT NULL)"
                    )
                    self._db.execute(
                        """CREATE TABLE resolution_jobs (
                            job_id TEXT PRIMARY KEY,
                            market TEXT NOT NULL,
                            resolver_definition_hash TEXT NOT NULL,
                            evidence_hash TEXT NOT NULL,
                            state TEXT NOT NULL CHECK(state IN ('PENDING','A_RECORDED','B_RECORDED','AGREED','CONFLICT')),
                            verifier_a_json TEXT NOT NULL,
                            verifier_b_json TEXT NOT NULL,
                            verifier_a_result_json TEXT,
                            verifier_a_result_hash TEXT,
                            verifier_b_result_json TEXT,
                            verifier_b_result_hash TEXT,
                            outcome TEXT,
                            conflict_reason TEXT,
                            created_at_ms TEXT NOT NULL,
                            updated_at_ms TEXT NOT NULL
                        )"""
                    )
                    self._db.execute(
                        """CREATE TABLE verifier_result_conflicts (
                            job_id TEXT NOT NULL REFERENCES resolution_jobs(job_id),
                            slot TEXT NOT NULL CHECK(slot IN ('A','B')),
                            existing_result_hash TEXT NOT NULL,
                            submitted_result_hash TEXT NOT NULL,
                            submitted_result_json TEXT NOT NULL,
                            reason TEXT NOT NULL,
                            created_at_ms TEXT NOT NULL,
                            PRIMARY KEY(job_id, slot, submitted_result_hash)
                        )"""
                    )
                    self._db.execute("INSERT INTO schema_migrations(version, applied_at_ms) VALUES (?, ?)", (SCHEMA_VERSION, timestamp))
                    self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                    self._db.execute("COMMIT")
                except Exception:
                    self._db.execute("ROLLBACK")
                    raise

    def register_job(self, *, market: str, resolver_definition: Mapping[str, Any], evidence: Mapping[str, Any]) -> ResolutionJob:
        try:
            if not isinstance(market, str) or len(market) != 64 or bytes.fromhex(market).hex() != market:
                raise CoordinatorRejected("invalid_market_identifier")
            definition = resolver_v2.validate_resolver_definition(resolver_definition)
            canonical_evidence = resolver_v2.validate_evidence_envelope(evidence)
            definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
            evidence_hash = resolver_v2.evidence_hash(canonical_evidence).hex()
            if canonical_evidence["definition_hash"] != definition_hash:
                raise CoordinatorRejected("job_evidence_resolver_mismatch")
        except (ValueError, resolver_v2.ResolverV2Error) as exc:
            if isinstance(exc, CoordinatorRejected):
                raise
            raise CoordinatorRejected("invalid_canonical_job") from exc
        job_id = _job_id(
            market=market,
            definition_hash=definition_hash,
            evidence_hash=evidence_hash,
            verifier_a=self.verifier_a.descriptor,
            verifier_b=self.verifier_b.descriptor,
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT * FROM resolution_jobs WHERE job_id = ?", (job_id,)).fetchone()
                if row is None:
                    timestamp = _now_ms()
                    self._db.execute(
                        """INSERT INTO resolution_jobs(
                            job_id, market, resolver_definition_hash, evidence_hash, state,
                            verifier_a_json, verifier_b_json, outcome, conflict_reason,
                            created_at_ms, updated_at_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)""",
                        (job_id, market, definition_hash, evidence_hash, PENDING, _canonical_json(self.verifier_a.descriptor), _canonical_json(self.verifier_b.descriptor), timestamp, timestamp),
                    )
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
        return self.get_job(job_id)

    def get_job(self, job_id: str) -> ResolutionJob:
        row = self._db.execute("SELECT * FROM resolution_jobs WHERE job_id = ?", (job_id,)).fetchone()
        if row is None:
            raise CoordinatorRejected("resolution_job_not_found")
        return self._row_to_job(row)

    def record_result(self, *, job_id: str, slot: str, result: Mapping[str, Any]) -> ResolutionJob:
        binding = self._binding(slot)
        try:
            canonical = resolver_v2.validate_verification_result(result)
            result_hash = resolver_v2.verification_result_hash(canonical).hex()
        except resolver_v2.ResolverV2Error as exc:
            raise CoordinatorRejected("invalid_canonical_verification_result") from exc
        result_json = _canonical_json(canonical)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT * FROM resolution_jobs WHERE job_id = ?", (job_id,)).fetchone()
                if row is None:
                    raise CoordinatorRejected("resolution_job_not_found")
                self._validate_result_binding(row, binding, canonical)
                existing_hash = row[f"verifier_{slot.lower()}_result_hash"]
                if existing_hash is not None:
                    if existing_hash == result_hash:
                        self._db.execute("COMMIT")
                        return self._row_to_job(row)
                    if row["state"] in TERMINAL_STATES:
                        raise CoordinatorRejected("completed_job_result_immutable")
                    self._persist_equivocation(row, slot, existing_hash, result_hash, result_json)
                    self._db.execute("COMMIT")
                    raise CoordinatorRejected("verifier_slot_equivocation")
                if row["state"] in TERMINAL_STATES:
                    raise CoordinatorRejected("completed_job_result_immutable")
                self._store_new_result(row, slot, result_hash, result_json)
                updated = self._db.execute("SELECT * FROM resolution_jobs WHERE job_id = ?", (job_id,)).fetchone()
                self._db.execute("COMMIT")
                return self._row_to_job(updated)
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def _binding(self, slot: str) -> VerifierBinding:
        if slot == "A":
            return self.verifier_a
        if slot == "B":
            return self.verifier_b
        raise CoordinatorRejected("unsupported_verifier_slot")

    def _validate_result_binding(self, row: sqlite3.Row, binding: VerifierBinding, result: Mapping[str, Any]) -> None:
        if result["definition_hash"] != row["resolver_definition_hash"] or result["evidence_hash"] != row["evidence_hash"]:
            raise CoordinatorRejected("verification_result_job_binding_mismatch")
        if dict(result["verifier"]) != dict(binding.descriptor):
            raise CoordinatorRejected("unexpected_verifier_identity")

    def _persist_equivocation(self, row: sqlite3.Row, slot: str, existing_hash: str, submitted_hash: str, submitted_json: str) -> None:
        timestamp = _now_ms()
        self._db.execute(
            """INSERT OR IGNORE INTO verifier_result_conflicts(
                job_id, slot, existing_result_hash, submitted_result_hash, submitted_result_json, reason, created_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (row["job_id"], slot, existing_hash, submitted_hash, submitted_json, "verifier_slot_equivocation", timestamp),
        )
        self._db.execute(
            "UPDATE resolution_jobs SET state = ?, conflict_reason = ?, updated_at_ms = ? WHERE job_id = ?",
            (CONFLICT, "verifier_slot_equivocation", timestamp, row["job_id"]),
        )

    def _store_new_result(self, row: sqlite3.Row, slot: str, result_hash: str, result_json: str) -> None:
        column = slot.lower()
        timestamp = _now_ms()
        self._db.execute(
            f"UPDATE resolution_jobs SET verifier_{column}_result_json = ?, verifier_{column}_result_hash = ?, updated_at_ms = ? WHERE job_id = ?",
            (result_json, result_hash, timestamp, row["job_id"]),
        )
        fresh = self._db.execute("SELECT * FROM resolution_jobs WHERE job_id = ?", (row["job_id"],)).fetchone()
        results = self._stored_results(fresh)
        if len(results) == 1:
            state = A_RECORDED if slot == "A" else B_RECORDED
            self._db.execute("UPDATE resolution_jobs SET state = ?, updated_at_ms = ? WHERE job_id = ?", (state, timestamp, row["job_id"]))
            return
        policy = AgreementPolicy(
            required_verifier_ids=(self.verifier_a.descriptor["adapter_id"], self.verifier_b.descriptor["adapter_id"]),
            required_verifier_count=2,
            minimum_agreeing_verifiers=2,
            exact_agreement=True,
        )
        try:
            decision = evaluate_agreement(results, policy)
        except (PipelineRejected, KeyError, ValueError) as exc:
            raise CoordinatorRejected("agreement_evaluation_rejected") from exc
        state = AGREED if decision.allowed else CONFLICT
        self._db.execute(
            "UPDATE resolution_jobs SET state = ?, outcome = ?, conflict_reason = ?, updated_at_ms = ? WHERE job_id = ?",
            (state, decision.canonical_outcome, None if decision.allowed else (decision.conflict_classification or decision.reason), timestamp, row["job_id"]),
        )

    def _stored_results(self, row: sqlite3.Row) -> list[Mapping[str, Any]]:
        return [json.loads(row[column]) for column in ("verifier_a_result_json", "verifier_b_result_json") if row[column] is not None]

    @staticmethod
    def _row_to_job(row: sqlite3.Row) -> ResolutionJob:
        decode = lambda value: None if value is None else MappingProxyType(json.loads(value))
        return ResolutionJob(
            job_id=row["job_id"], market=row["market"], resolver_definition_hash=row["resolver_definition_hash"], evidence_hash=row["evidence_hash"], state=row["state"],
            verifier_a=MappingProxyType(json.loads(row["verifier_a_json"])), verifier_b=MappingProxyType(json.loads(row["verifier_b_json"])),
            verifier_a_result=decode(row["verifier_a_result_json"]), verifier_b_result=decode(row["verifier_b_result_json"]),
            outcome=row["outcome"], conflict_reason=row["conflict_reason"], created_at_ms=row["created_at_ms"], updated_at_ms=row["updated_at_ms"],
        )
