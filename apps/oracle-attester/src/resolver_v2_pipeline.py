"""Fail-closed, off-chain Resolver V2 attestation pipeline.

This module deliberately terminates in the existing ``PROPHET_RESOLVE_V2``
message.  It neither changes the program nor gives a signer access to raw
evidence.  Each boundary uses canonical Resolver V2 values from the shared
``prophet_sdk.resolver_v2`` library.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Callable, Dict, Mapping, Optional, Protocol, Sequence, Tuple

from solders.pubkey import Pubkey

# Resolver V2's hashing implementation is intentionally shared with the SDK.
# Installed deployments import the package normally; the checked-out operated
# bundle also supports running the attester directly from the monorepo.
try:
    from prophet_sdk import resolver_v2
except ModuleNotFoundError:  # pragma: no cover - exercised by source-tree deployments
    _sdk_root = Path(__file__).resolve().parents[3] / "sdk" / "python"
    if not (_sdk_root / "prophet_sdk" / "resolver_v2.py").is_file():
        raise RuntimeError("Resolver V2 canonical hash library is unavailable")
    sys.path.insert(0, str(_sdk_root))
    from prophet_sdk import resolver_v2

from .audit import JsonlAuditLogger
from .signer_backend import SignerBackend


LEGACY_SETTLEMENT_DOMAIN = b"PROPHET_RESOLVE_V2"
OUTCOME_INDEX = {"YES": 1, "NO": 2, "INVALID": 3}


class PipelineRejected(ValueError):
    """A deterministic, fail-closed pipeline rejection."""


@dataclass(frozen=True)
class AcquisitionRequest:
    resolver_id: str
    adapter_digest: str
    source_id: str
    requested_at_ms: str
    request_commitment: str


@dataclass(frozen=True)
class AcquiredEvidence:
    """Adapter-neutral raw acquisition; it contains no settlement decision."""

    adapter_digest: str
    resolver_id: str
    source_id: str
    acquired_at_ms: str
    raw_bytes: bytes
    source_metadata: Mapping[str, Any]
    source_time_ms: Optional[str] = None
    source_sequence: Optional[str] = None
    acquisition_id: Optional[str] = None


class EvidenceAcquirer(Protocol):
    def acquire(self, request: AcquisitionRequest) -> AcquiredEvidence: ...


@dataclass(frozen=True)
class VerificationReport:
    """Independent verifier output before canonical V2 result construction."""

    outcome: str
    status: str
    confidence: str
    checks: Sequence[Mapping[str, Any]]
    verifier: Mapping[str, Any]
    verified_facts: Mapping[str, Any]
    observed_at_ms: str
    valid_from_ms: str
    valid_until_ms: str
    failure_code: Optional[str] = None
    finality: Optional[Mapping[str, Any]] = None


class EvidenceVerifier(Protocol):
    def verify(
        self,
        definition: Mapping[str, Any],
        evidence: Mapping[str, Any],
        trust_model: Mapping[str, Any],
    ) -> VerificationReport: ...


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return resolver_v2.canonical_json_bytes(value)


def _hex32(value: str, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise PipelineRejected(f"{field} must be lowercase 32-byte hex")
    return value


def _uint(value: str, field: str) -> int:
    try:
        resolver_v2._uint(value, field)  # Shared V2 canonical integer rules.
        return int(value)
    except (resolver_v2.ResolverV2Error, ValueError) as exc:
        raise PipelineRejected(str(exc)) from exc


def normalize_evidence(
    acquired: AcquiredEvidence,
    *,
    definition_hash: str,
    collector: Mapping[str, Any],
    transport: Mapping[str, Any],
    provenance: Mapping[str, Any],
    previous_evidence_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Make one deterministic EvidenceEnvelopeV2 without interpreting bytes."""
    _hex32(definition_hash, "definition_hash")
    _hex32(acquired.adapter_digest, "adapter_digest")
    _uint(acquired.acquired_at_ms, "acquired_at_ms")
    if acquired.source_time_ms is not None:
        _uint(acquired.source_time_ms, "source_time_ms")
    if acquired.source_sequence is not None:
        _uint(acquired.source_sequence, "source_sequence")
    raw_hash = _sha256_hex(acquired.raw_bytes)
    metadata = dict(acquired.source_metadata)
    source_commitment = _sha256_hex(_canonical_bytes({
        "adapter_digest": acquired.adapter_digest,
        "resolver_id": acquired.resolver_id,
        "source_id": acquired.source_id,
        "source_metadata": metadata,
    }))
    # evidence_id is a deterministic raw-evidence identity, avoiding a hash cycle.
    evidence_id = _sha256_hex(_canonical_bytes({
        "definition_hash": definition_hash,
        "raw_evidence_hash": raw_hash,
        "source_commitment": source_commitment,
    }))
    envelope: Dict[str, Any] = {
        "schema": resolver_v2.SCHEMAS["evidence"],
        "schema_version": resolver_v2.VERSION,
        "evidence_id": evidence_id,
        "definition_hash": definition_hash,
        "acquisition_id": acquired.acquisition_id or f"acq-{raw_hash}",
        "acquired_at_ms": acquired.acquired_at_ms,
        "source_time_ms": acquired.source_time_ms,
        "source_sequence": acquired.source_sequence,
        "source_locator": {"source_id": acquired.source_id},
        "source_commitment": source_commitment,
        "payload_hex": acquired.raw_bytes.hex(),
        "payload_hash": raw_hash,
        "provenance": dict(provenance),
        "transport": dict(transport),
        "collector": dict(collector),
        "previous_evidence_hash": previous_evidence_hash,
    }
    resolver_v2.validate_evidence_envelope(envelope)
    return envelope


def verification_result_from_report(
    *,
    definition_hash: str,
    evidence: Mapping[str, Any],
    report: VerificationReport,
) -> Dict[str, Any]:
    """Bind a verifier report to immutable evidence; no signer may reinterpret it."""
    if report.outcome not in OUTCOME_INDEX:
        raise PipelineRejected("verification outcome is unsupported")
    if report.status not in ("VERIFIED", "REJECTED", "INCONCLUSIVE"):
        raise PipelineRejected("verification status is unsupported")
    facts = {
        "confidence": report.confidence,
        "failure_code": report.failure_code,
        "outcome": report.outcome,
        "status": report.status,
        "verified_facts": dict(report.verified_facts),
    }
    facts_bytes = _canonical_bytes(facts)
    result: Dict[str, Any] = {
        "schema": resolver_v2.SCHEMAS["verification"],
        "schema_version": resolver_v2.VERSION,
        "definition_hash": definition_hash,
        "evidence_hash": resolver_v2.evidence_hash(evidence).hex(),
        "verifier": dict(report.verifier),
        "result": report.status,
        "checks": [dict(check) for check in report.checks],
        "verified_facts_hex": facts_bytes.hex(),
        "verified_facts_hash": _sha256_hex(facts_bytes),
        "observed_at_ms": report.observed_at_ms,
        "valid_from_ms": report.valid_from_ms,
        "valid_until_ms": report.valid_until_ms,
        "finality": None if report.finality is None else dict(report.finality),
    }
    resolver_v2.validate_verification_result(result)
    return result


def _verified_outcome(result: Mapping[str, Any]) -> str:
    """Extract, without evaluating, the verifier's committed outcome."""
    try:
        facts = resolver_v2.parse_canonical_json(bytes.fromhex(str(result["verified_facts_hex"])))
        outcome = facts["outcome"]
        status = facts["status"]
    except (KeyError, ValueError, resolver_v2.ResolverV2Error) as exc:
        raise PipelineRejected("malformed_verifier_facts") from exc
    if status != result.get("result") or outcome not in OUTCOME_INDEX:
        raise PipelineRejected("inconsistent_verifier_facts")
    return outcome


@dataclass(frozen=True)
class BundleContext:
    market: str
    cluster_genesis_hash: str
    settlement_program_id: str
    notary_config: str
    notary_config_version: str
    resolution_nonce: str
    observed_at_ms: str
    valid_until_ms: str
    signer_policy: Mapping[str, Any]


def build_resolution_bundle(
    *,
    definition: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    verification_results: Sequence[Mapping[str, Any]],
    trust_model: Mapping[str, Any],
    verifier: Mapping[str, Any],
    outcome: str,
    context: BundleContext,
) -> Dict[str, Any]:
    """Build exactly one canonical ResolutionBundleV2 from stage outputs."""
    if outcome not in OUTCOME_INDEX:
        raise PipelineRejected("unsupported settlement outcome")
    if not verification_results or any(_verified_outcome(result) != outcome for result in verification_results):
        raise PipelineRejected("verification_outcome_mismatch")
    definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
    bundle: Dict[str, Any] = {
        "schema": resolver_v2.SCHEMAS["bundle"], "schema_version": resolver_v2.VERSION,
        "market": context.market, "resolver_definition": dict(definition),
        "resolver_definition_hash": definition_hash,
        "evidence": sorted((dict(item) for item in evidence), key=lambda item: item["evidence_id"]),
        "verification_results": sorted(
            (dict(item) for item in verification_results),
            key=lambda item: resolver_v2.verification_result_hash(item).hex(),
        ),
        "trust_model": dict(trust_model),
        "trust_model_digest": resolver_v2.trust_model_digest(trust_model).hex(),
        "verifier": dict(verifier), "signer_policy": dict(context.signer_policy),
        "outcome": outcome, "observed_at_ms": context.observed_at_ms,
        "valid_until_ms": context.valid_until_ms,
        "cluster_genesis_hash": context.cluster_genesis_hash,
        "settlement_program_id": context.settlement_program_id,
        "notary_config": context.notary_config,
        "notary_config_version": context.notary_config_version,
        "resolution_nonce": context.resolution_nonce,
    }
    try:
        resolver_v2.validate_resolution_bundle(bundle)
    except resolver_v2.ResolverV2Error as exc:
        raise PipelineRejected(str(exc)) from exc
    return bundle


class ResolverV2Pipeline:
    """Orchestrates explicit V2 stages without coupling them to a signer."""
    def __init__(self, acquirer: EvidenceAcquirer, verifier: EvidenceVerifier):
        self.acquirer = acquirer
        self.verifier = verifier

    def acquire_and_normalize(
        self,
        request: AcquisitionRequest,
        *,
        definition_hash: str,
        collector: Mapping[str, Any],
        transport: Mapping[str, Any],
        provenance: Mapping[str, Any],
    ) -> Dict[str, Any]:
        acquired = self.acquirer.acquire(request)
        if acquired.resolver_id != request.resolver_id or acquired.adapter_digest != request.adapter_digest:
            raise PipelineRejected("acquisition_identity_mismatch")
        return normalize_evidence(
            acquired, definition_hash=definition_hash, collector=collector,
            transport=transport, provenance=provenance,
        )

    def verify(
        self,
        definition: Mapping[str, Any], evidence: Mapping[str, Any], trust_model: Mapping[str, Any],
    ) -> Tuple[VerificationReport, Dict[str, Any]]:
        definition_hash = resolver_v2.resolver_definition_hash(definition).hex()
        if evidence.get("definition_hash") != definition_hash or definition.get("trust_model") != trust_model:
            raise PipelineRejected("verification_input_binding_mismatch")
        report = self.verifier.verify(definition, evidence, trust_model)
        result = verification_result_from_report(definition_hash=definition_hash, evidence=evidence, report=report)
        return report, result

    def build_bundle(
        self,
        *, definition: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]],
        reports_and_results: Sequence[Tuple[VerificationReport, Mapping[str, Any]]],
        trust_model: Mapping[str, Any], verifier: Mapping[str, Any], context: BundleContext,
    ) -> Dict[str, Any]:
        if not reports_and_results:
            raise PipelineRejected("verification_required")
        outcomes = {report.outcome for report, _ in reports_and_results}
        if len(outcomes) != 1 or any(report.status != "VERIFIED" for report, _ in reports_and_results):
            raise PipelineRejected("verification_not_signable")
        return build_resolution_bundle(
            definition=definition, evidence=evidence,
            verification_results=[result for _, result in reports_and_results],
            trust_model=trust_model, verifier=verifier, outcome=next(iter(outcomes)), context=context,
        )


@dataclass(frozen=True)
class SignerPolicy:
    policy_id: str
    policy_version: str
    allowed_resolver_ids: Tuple[str, ...]
    allowed_adapter_digests: Tuple[str, ...]
    allowed_trust_model_digests: Tuple[str, ...]
    allowed_verifier_ids: Tuple[str, ...]
    allowed_verifier_versions: Tuple[str, ...]
    max_evidence_age_ms: int
    max_verification_age_ms: int
    market: str
    cluster_genesis_hash: str
    signer_set_version: str
    threshold: int
    emergency_denylist: Tuple[str, ...] = ()
    forbid_deprecated_resolvers: bool = True
    required_verifier_count: int = 1
    required_verifier_ids: Tuple[str, ...] = ()
    minimum_agreeing_verifiers: int = 1
    exact_verifier_agreement: bool = True
    # Explicit local trust policy for the implementation behind each verifier
    # identity.  A signed bundle cannot choose or widen this set.
    trusted_verifier_implementations: Tuple[Tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    policy_id: str
    policy_version: str


class SignerPolicyEngine:
    def __init__(self, policy: SignerPolicy, *, deprecated_resolver_ids: Sequence[str] = ()):
        if policy.threshold <= 0 or policy.required_verifier_count <= 0 or policy.minimum_agreeing_verifiers <= 0:
            raise PipelineRejected("policy threshold must be positive")
        self.policy = policy
        self.deprecated_resolver_ids = frozenset(deprecated_resolver_ids)

    def evaluate(self, bundle: Mapping[str, Any], *, now_ms: int, expected_bundle_hash: Optional[str] = None) -> PolicyDecision:
        try:
            resolver_v2.validate_resolution_bundle(bundle, now_ms=now_ms)
            bundle_hash = resolver_v2.resolution_bundle_hash(bundle).hex()
        except resolver_v2.ResolverV2Error as exc:
            return PolicyDecision(False, f"invalid_bundle:{exc}", self.policy.policy_id, self.policy.policy_version)
        if expected_bundle_hash is not None and bundle_hash != expected_bundle_hash:
            return PolicyDecision(False, "bundle_hash_mismatch", self.policy.policy_id, self.policy.policy_version)
        definition = bundle["resolver_definition"]
        verifier = bundle["verifier"]
        trusted = set(self.policy.trusted_verifier_implementations)
        if trusted:
            top_identity = (verifier["adapter_id"], verifier["adapter_version"], verifier["implementation_digest"])
            if top_identity not in trusted:
                return PolicyDecision(False, "untrusted_verifier_implementation", self.policy.policy_id, self.policy.policy_version)
        if definition["resolver_id"] not in self.policy.allowed_resolver_ids:
            return PolicyDecision(False, "unknown_resolver", self.policy.policy_id, self.policy.policy_version)
        if definition["resolver_id"] in self.policy.emergency_denylist:
            return PolicyDecision(False, "emergency_denied", self.policy.policy_id, self.policy.policy_version)
        if self.policy.forbid_deprecated_resolvers and definition["resolver_id"] in self.deprecated_resolver_ids:
            return PolicyDecision(False, "deprecated_resolver", self.policy.policy_id, self.policy.policy_version)
        if definition["adapter"]["implementation_digest"] not in self.policy.allowed_adapter_digests:
            return PolicyDecision(False, "unknown_adapter", self.policy.policy_id, self.policy.policy_version)
        if bundle["trust_model_digest"] not in self.policy.allowed_trust_model_digests:
            return PolicyDecision(False, "unknown_trust_model", self.policy.policy_id, self.policy.policy_version)
        if verifier["adapter_id"] not in self.policy.allowed_verifier_ids or verifier["adapter_version"] not in self.policy.allowed_verifier_versions:
            return PolicyDecision(False, "unexpected_verifier", self.policy.policy_id, self.policy.policy_version)
        # The agreement engine compares only normalized structured V2 results.
        from .resolver_v2_multi_verifier import AgreementPolicy, evaluate_agreement
        agreement = evaluate_agreement(bundle["verification_results"], AgreementPolicy(
            required_verifier_ids=self.policy.required_verifier_ids,
            required_verifier_count=self.policy.required_verifier_count,
            minimum_agreeing_verifiers=self.policy.minimum_agreeing_verifiers,
            exact_agreement=self.policy.exact_verifier_agreement,
        ), now_ms=now_ms)
        if not agreement.allowed:
            return PolicyDecision(False, agreement.reason, self.policy.policy_id, self.policy.policy_version)
        for result in bundle["verification_results"]:
            result_verifier = result["verifier"]
            if result_verifier["adapter_id"] not in self.policy.allowed_verifier_ids or result_verifier["adapter_version"] not in self.policy.allowed_verifier_versions:
                return PolicyDecision(False, "unexpected_verifier", self.policy.policy_id, self.policy.policy_version)
            if trusted and (result_verifier["adapter_id"], result_verifier["adapter_version"], result_verifier["implementation_digest"]) not in trusted:
                return PolicyDecision(False, "untrusted_verifier_implementation", self.policy.policy_id, self.policy.policy_version)
        if bundle["market"] != self.policy.market:
            return PolicyDecision(False, "market_mismatch", self.policy.policy_id, self.policy.policy_version)
        if bundle["cluster_genesis_hash"] != self.policy.cluster_genesis_hash:
            return PolicyDecision(False, "cluster_mismatch", self.policy.policy_id, self.policy.policy_version)
        if int(bundle["signer_policy"]["threshold"]) != self.policy.threshold or bundle["signer_policy"]["policy_version"] != self.policy.signer_set_version:
            return PolicyDecision(False, "signer_set_mismatch", self.policy.policy_id, self.policy.policy_version)
        for item in bundle["evidence"]:
            if now_ms - int(item["acquired_at_ms"]) > self.policy.max_evidence_age_ms:
                return PolicyDecision(False, "stale_evidence", self.policy.policy_id, self.policy.policy_version)
        for item in bundle["verification_results"]:
            if now_ms - int(item["observed_at_ms"]) > self.policy.max_verification_age_ms:
                return PolicyDecision(False, "stale_verification", self.policy.policy_id, self.policy.policy_version)
            if item["result"] != "VERIFIED":
                return PolicyDecision(False, "unverified_result", self.policy.policy_id, self.policy.policy_version)
            try:
                if _verified_outcome(item) != bundle["outcome"]:
                    return PolicyDecision(False, "verification_outcome_mismatch", self.policy.policy_id, self.policy.policy_version)
            except PipelineRejected:
                return PolicyDecision(False, "malformed_verifier_facts", self.policy.policy_id, self.policy.policy_version)
        return PolicyDecision(True, "allowed", self.policy.policy_id, self.policy.policy_version)


class EquivocationStore:
    """Durable local guard: same market/domain may only receive one outcome."""
    def __init__(self, path: str):
        self.path = Path(path)
        self._lock = Lock()
        self._records: Dict[str, Dict[str, str]] = {}
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                self._records[record["key"]] = record

    @staticmethod
    def _key(bundle: Mapping[str, Any]) -> str:
        return ":".join((bundle["market"], bundle["cluster_genesis_hash"], bundle["notary_config"], bundle["notary_config_version"], bundle["resolution_nonce"]))

    def reserve(self, bundle: Mapping[str, Any], bundle_hash: str) -> bool:
        key = self._key(bundle)
        record = {"key": key, "outcome": bundle["outcome"], "bundle_hash": bundle_hash}
        with self._lock:
            old = self._records.get(key)
            if old is not None:
                if old == record:
                    return False  # Exact retry; no inconsistent state is created.
                if old["outcome"] != record["outcome"]:
                    raise PipelineRejected("equivocation_conflicting_outcome")
                raise PipelineRejected("equivocation_conflicting_bundle")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._records[key] = record
            return True


def build_legacy_settlement_message(
    *, program_id: str, market: str, notary_config: str, resolver_hash: str,
    open_ts: int, resolve_ts: int, notary_config_version: int, outcome: str,
    proof_hash: str, public_inputs_hash: str,
) -> bytes:
    """Byte-for-byte copy of the established PROPHET_RESOLVE_V2 wire layout."""
    if outcome not in OUTCOME_INDEX:
        raise PipelineRejected("unsupported settlement outcome")
    for name, value in (("resolver_hash", resolver_hash), ("proof_hash", proof_hash), ("public_inputs_hash", public_inputs_hash)):
        _hex32(value, name)
    if proof_hash == "00" * 32 or public_inputs_hash == "00" * 32:
        raise PipelineRejected("settlement hashes must be non-zero")
    return (LEGACY_SETTLEMENT_DOMAIN + bytes(Pubkey.from_string(program_id)) + bytes(Pubkey.from_string(market))
            + bytes(Pubkey.from_string(notary_config)) + bytes.fromhex(resolver_hash)
            + int(open_ts).to_bytes(8, "little", signed=True) + int(resolve_ts).to_bytes(8, "little", signed=True)
            + int(notary_config_version).to_bytes(8, "little") + bytes((OUTCOME_INDEX[outcome],))
            + bytes.fromhex(proof_hash) + bytes.fromhex(public_inputs_hash))


@dataclass(frozen=True)
class SigningAuthorization:
    canonical_bundle: bytes
    bundle_hash: str
    settlement_message: bytes
    policy: PolicyDecision


class ThresholdSigningGate:
    """The only signer-facing boundary; raw source bytes never cross it."""
    def __init__(self, backend: SignerBackend, policy: SignerPolicyEngine, equivocation: EquivocationStore, audit: JsonlAuditLogger, *, conflict_state: Any = None, equivocation_monitor: Any = None):
        self.backend, self.policy, self.equivocation, self.audit = backend, policy, equivocation, audit
        self.conflict_state, self.equivocation_monitor = conflict_state, equivocation_monitor

    def authorize(self, bundle: Mapping[str, Any], *, now_ms: int, expected_bundle_hash: Optional[str], settlement_message: bytes) -> SigningAuthorization:
        bundle_hash = resolver_v2.resolution_bundle_hash(bundle).hex()
        if self.conflict_state is not None and self.conflict_state.is_open(bundle):
            self.audit.write("resolver_v2_signer_rejected", {"market": bundle.get("market", ""), "bundle_hash": bundle_hash, "reason": "conflict_open"})
            raise PipelineRejected("conflict_open")
        decision = self.policy.evaluate(bundle, now_ms=now_ms, expected_bundle_hash=expected_bundle_hash)
        if not decision.allowed:
            self.audit.write("resolver_v2_signer_rejected", {"market": bundle.get("market", ""), "bundle_hash": bundle_hash, "reason": decision.reason, "policy_version": decision.policy_version})
            raise PipelineRejected(decision.reason)
        self.equivocation.reserve(bundle, bundle_hash)
        self.audit.write("resolver_v2_signer_authorized", {"resolver_id": bundle["resolver_definition"]["resolver_id"], "market": bundle["market"], "evidence_hashes": [resolver_v2.evidence_hash(item).hex() for item in bundle["evidence"]], "verifier": bundle["verifier"], "verification_results": [item["result"] for item in bundle["verification_results"]], "bundle_hash": bundle_hash, "signer_policy_version": decision.policy_version, "decision": decision.reason})
        return SigningAuthorization(_canonical_bytes(bundle), bundle_hash, settlement_message, decision)

    def sign(self, authorization: SigningAuthorization, pubkeys: Sequence[Pubkey]) -> Dict[str, bytes]:
        signatures: Dict[str, bytes] = {}
        bundle = resolver_v2.parse_canonical_json(authorization.canonical_bundle)
        domain = ":".join((bundle["market"], bundle["cluster_genesis_hash"], bundle["notary_config"], bundle["notary_config_version"], bundle["resolution_nonce"]))
        for pubkey in pubkeys:
            # Reserve the signer observation before calling the signing backend.
            # A conflicting candidate therefore cannot obtain a new signature.
            if self.equivocation_monitor is not None and self.equivocation_monitor.observe_signer(
                str(pubkey), domain=domain, outcome=bundle["outcome"], bundle_hash=authorization.bundle_hash,
                resolver=bundle["resolver_definition_hash"], market=bundle["market"], timestamp_ms=bundle["observed_at_ms"],
            ):
                raise PipelineRejected("signer_equivocation_detected")
            # Context contains only commitments and policy metadata, never source bytes.
            signatures[str(pubkey)] = self.backend.sign(pubkey, authorization.settlement_message, {
                "bundle_hash": authorization.bundle_hash,
                "policy_id": authorization.policy.policy_id,
                "policy_version": authorization.policy.policy_version,
            })
        self.audit.write("resolver_v2_signatures_produced", {"bundle_hash": authorization.bundle_hash, "signatures_produced": sorted(signatures), "signer_decision": authorization.policy.reason})
        return signatures
