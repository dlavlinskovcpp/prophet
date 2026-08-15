"""Canonical multi-verifier agreement, durable conflict, and equivocation monitoring."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .resolver_v2_pipeline import PipelineRejected

try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:
    from .resolver_v2_pipeline import resolver_v2


@dataclass(frozen=True)
class AgreementPolicy:
    required_verifier_ids: Tuple[str, ...]
    required_verifier_count: int
    minimum_agreeing_verifiers: int
    exact_agreement: bool = True


@dataclass(frozen=True)
class AgreementDecision:
    allowed: bool
    reason: str
    canonical_outcome: Optional[str]
    verifier_ids: Tuple[str, ...]
    conflict_classification: Optional[str] = None


def _outcome(result: Mapping[str, Any]) -> str:
    facts = resolver_v2.parse_canonical_json(bytes.fromhex(str(result["verified_facts_hex"])))
    outcome = facts.get("outcome")
    if facts.get("status") != result.get("result") or outcome not in ("YES", "NO", "INVALID"):
        raise PipelineRejected("malformed_verifier_facts")
    return outcome


def evaluate_agreement(results: Sequence[Mapping[str, Any]], policy: AgreementPolicy, *, now_ms: Optional[int] = None) -> AgreementDecision:
    """Compare only structured, normalized commitments; never error strings."""
    if policy.required_verifier_count < 1 or policy.minimum_agreeing_verifiers < 1:
        raise PipelineRejected("invalid_multi_verifier_policy")
    rows = []
    for result in results:
        verifier = result.get("verifier", {})
        verifier_id, version = verifier.get("adapter_id"), verifier.get("adapter_version")
        if not isinstance(verifier_id, str) or not isinstance(version, str):
            return AgreementDecision(False, "verifier_identity_invalid", None, (), "verifier_version_mismatch")
        rows.append((verifier_id, version, result.get("evidence_hash"), result.get("definition_hash"), result.get("result"), _outcome(result)))
    ids = tuple(sorted(row[0] for row in rows))
    if len(set(ids)) != len(ids):
        return AgreementDecision(False, "duplicate_verifier_identity", None, ids, "same_verifier_identity_conflict")
    if len(rows) < policy.required_verifier_count or not set(policy.required_verifier_ids).issubset(ids):
        return AgreementDecision(False, "required_verifier_set_incomplete", None, ids, "missing_required_verifier")
    if any(row[4] != "VERIFIED" for row in rows):
        return AgreementDecision(False, "verifier_rejected_evidence", None, ids, "invalid_vs_valid")
    if now_ms is not None:
        freshness = {int(item["valid_until_ms"]) >= now_ms for item in results}
        if len(freshness) != 1:
            return AgreementDecision(False, "stale_fresh_disagreement", None, ids, "stale_vs_fresh_evidence")
    evidence_hashes, definitions, outcomes = {r[2] for r in rows}, {r[3] for r in rows}, {r[5] for r in rows}
    if len(definitions) != 1:
        return AgreementDecision(False, "resolver_binding_conflict", None, ids, "resolver_binding_conflict")
    if len(evidence_hashes) != 1:
        return AgreementDecision(False, "evidence_hash_conflict", None, ids, "different_normalized_evidence")
    if len(outcomes) != 1:
        return AgreementDecision(False, "outcome_conflict", None, ids, "same_evidence_different_outcome")
    outcome = next(iter(outcomes))
    if len(rows) < policy.minimum_agreeing_verifiers:
        return AgreementDecision(False, "minimum_agreement_not_met", None, ids, "insufficient_agreement")
    return AgreementDecision(True, "agreed", outcome, ids, None)


class ConflictStateStore:
    """Append-only local conflict state; an open conflict blocks all retries."""
    def __init__(self, path: str):
        self.path, self._lock, self._open = Path(path), Lock(), {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                item = json.loads(line)
                if item["action"] == "open": self._open[item["key"]] = item
                elif item["action"] == "clear": self._open.pop(item["key"], None)

    @staticmethod
    def key(bundle: Mapping[str, Any]) -> str:
        return ":".join((bundle["market"], bundle["resolver_definition_hash"], bundle["cluster_genesis_hash"], bundle["notary_config"], bundle["notary_config_version"], bundle["resolution_nonce"]))

    def open(self, bundle: Mapping[str, Any], decision: AgreementDecision, attempt_id: str, timestamp_ms: str) -> None:
        key = self.key(bundle)
        item = {"action": "open", "key": key, "attempt_id": attempt_id, "classification": decision.conflict_classification or decision.reason, "timestamp_ms": timestamp_ms, "evidence_hashes": sorted({r["evidence_hash"] for r in bundle["verification_results"]})}
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f: f.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
            self._open[key] = item

    def is_open(self, bundle: Mapping[str, Any]) -> bool:
        return self.key(bundle) in self._open

    def open_duration_ms(self, bundle: Mapping[str, Any], now_ms: str) -> int:
        item = self._open.get(self.key(bundle))
        return 0 if item is None else max(0, int(now_ms) - int(item["timestamp_ms"]))

    def clear(self, bundle: Mapping[str, Any], *, fresh_evidence: bool, policy_override: bool, attempt_id: str, timestamp_ms: str) -> None:
        key = self.key(bundle)
        with self._lock:
            prior = self._open.get(key)
            if prior is None: return
            current = sorted({r["evidence_hash"] for r in bundle["verification_results"]})
            if not policy_override and (not fresh_evidence or current == prior["evidence_hashes"]):
                raise PipelineRejected("conflict_clear_requires_fresh_evidence_or_override")
            item = {"action": "clear", "key": key, "attempt_id": attempt_id, "timestamp_ms": timestamp_ms, "reason": "policy_override" if policy_override else "fresh_evidence"}
            with self.path.open("a", encoding="utf-8") as f: f.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
            self._open.pop(key, None)


class MultiVerifierCoordinator:
    """Operational agreement boundary with audit and existing-metrics hooks."""
    def __init__(self, policy: AgreementPolicy, conflicts: ConflictStateStore, *, audit=None, metrics=None):
        self.policy, self.conflicts, self.audit, self.metrics = policy, conflicts, audit, metrics

    def evaluate(self, bundle: Mapping[str, Any], *, now_ms: int, attempt_id: str, timestamp_ms: str) -> AgreementDecision:
        start = time.perf_counter()
        decision = evaluate_agreement(bundle["verification_results"], self.policy, now_ms=now_ms)
        if self.metrics:
            self.metrics.inc("prophet_resolver_v2_verifier_agreement_total", labels={"result": "agree" if decision.allowed else "disagree"})
            self.metrics.observe_histogram("prophet_resolver_v2_verifier_latency_seconds", time.perf_counter() - start)
            if not decision.allowed:
                self.metrics.inc("prophet_resolver_v2_verifier_disagreement_total", labels={"classification": decision.conflict_classification or decision.reason})
                if decision.conflict_classification == "stale_vs_fresh_evidence": self.metrics.inc("prophet_resolver_v2_stale_evidence_rejection_total")
        if self.audit:
            # Verification results are canonical commitments only; raw evidence,
            # proof bytes, credentials, and authenticated session data are absent.
            self.audit.write("resolver_v2_verifier_agreement", {"attempt_id": attempt_id, "market": bundle["market"], "resolver": bundle["resolver_definition_hash"], "verifier_outputs": list(bundle["verification_results"]), "agreement": decision.reason, "conflict_classification": decision.conflict_classification})
        if not decision.allowed:
            self.conflicts.open(bundle, decision, attempt_id, timestamp_ms)
        return decision

    def reconcile(self, bundle: Mapping[str, Any], *, fresh_evidence: bool, policy_override: bool, attempt_id: str, timestamp_ms: str) -> None:
        duration = self.conflicts.open_duration_ms(bundle, timestamp_ms)
        self.conflicts.clear(bundle, fresh_evidence=fresh_evidence, policy_override=policy_override, attempt_id=attempt_id, timestamp_ms=timestamp_ms)
        if self.metrics and duration:
            self.metrics.observe_histogram("prophet_resolver_v2_conflict_open_duration_seconds", duration / 1000.0)


class EquivocationMonitor:
    """Persistent verifier/signer equivocation detector with metric hooks."""
    def __init__(self, path: str, *, audit=None, metrics=None):
        self.path, self.audit, self.metrics, self._lock, self._seen = Path(path), audit, metrics, Lock(), {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                item = json.loads(line); self._seen[item["key"]] = item

    def _observe(self, kind: str, domain: str, identity: str, outcome: str, bundle_hash: str, timestamp_ms: str, resolver: str, market: str) -> bool:
        key = ":".join((kind, domain, identity)); item = {"key": key, "kind": kind, "domain": domain, "identity": identity, "outcome": outcome, "bundle_hash": bundle_hash, "timestamp_ms": timestamp_ms, "resolver": resolver, "market": market}
        with self._lock:
            previous = self._seen.get(key)
            if previous is not None and (previous["outcome"] != outcome or previous["bundle_hash"] != bundle_hash):
                alert = {**item, "alert": "equivocation_detected", "previous_outcome": previous["outcome"], "previous_bundle_hash": previous["bundle_hash"]}
                if self.audit: self.audit.write("resolver_v2_equivocation", alert)
                if self.metrics: self.metrics.inc("prophet_resolver_v2_equivocation_total", labels={"kind": kind})
                return True
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f: f.write(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n")
            self._seen[key] = item
            return False

    def observe_verifier(self, result: Mapping[str, Any], *, domain: str, bundle_hash: str, market: str, timestamp_ms: str) -> bool:
        return self._observe("verifier", domain, result["verifier"]["adapter_id"], _outcome(result), bundle_hash, timestamp_ms, result["definition_hash"], market)

    def observe_signer(self, signer: str, *, domain: str, outcome: str, bundle_hash: str, resolver: str, market: str, timestamp_ms: str) -> bool:
        return self._observe("signer", domain, signer, outcome, bundle_hash, timestamp_ms, resolver, market)
