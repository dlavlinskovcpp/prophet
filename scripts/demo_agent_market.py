#!/usr/bin/env python3
"""Deterministic agent-native Resolver V2 lifecycle demonstration.

The default mode deliberately uses an in-memory submission harness: all
security artifacts and the exact legacy settlement bytes are real, while no
network, wallet file, or public price endpoint is required for CI. Production
localnet transaction coverage remains in ``operated_localnet_smoke.py``.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "sdk" / "python"), str(ROOT / "apps" / "oracle-attester")]

from solders.keypair import Keypair
from prophet_sdk import MarketHandle, ProphetAgent, ResolverConfig
from prophet_sdk import resolver_v2
from prophet_sdk.pdas import derive_market_pda
from src.audit import JsonlAuditLogger
from src.resolver_v2_independent_verifier import IndependentOracleVerifier
from src.resolver_v2_multi_verifier import AgreementPolicy, ConflictStateStore, MultiVerifierCoordinator
from src.resolver_v2_oracle_adapters import PythAdapter, PythMaterial
from src.resolver_v2_pipeline import (
    BundleContext, EquivocationStore, PipelineRejected, SignerPolicy,
    SignerPolicyEngine, ThresholdSigningGate, build_legacy_settlement_message,
    build_resolution_bundle, normalize_evidence, verification_result_from_report,
)
from src.signer_backend import SignerBackend

H = lambda b: f"{b:02x}" * 32
PROGRAM_ID = "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A"
MARKET_OPEN, MARKET_RESOLVE = 1_000, 1_100


def descriptor(name: str, digest: int) -> dict[str, str]:
    return {"schema": "prophet.adapter-descriptor.v2", "schema_version": "2.0.0", "adapter_id": name, "adapter_version": "2.0.0", "implementation_digest": H(digest)}


def definition() -> dict[str, Any]:
    trust = {"schema": "prophet.trust-model-descriptor.v2", "schema_version": "2.0.0", "trust_model_id": "demo-pyth-fixture", "trust_model_version": "2.0.0", "document_hash": H(9)}
    return {"schema": "prophet.resolver-definition.v2", "schema_version": "2.0.0", "resolver_id": "demo-pyth-eth-5000", "resolver_type": "pyth", "adapter": descriptor("prophet.resolver.pyth", 3), "trust_model": trust,
            "source": {"feed_id": H(1), "network": "deterministic-local", "cluster_genesis_hash": H(2), "price_exponent": "-2", "max_publish_age_ms": "50", "max_confidence_bps": "100", "predicate": {"operator": ">=", "threshold_value": "500000", "threshold_exponent": "-2", "outcome_if_true": "YES", "outcome_if_false": "NO"}, "outcome_mapping": {"numeric_predicate": "v1"}, "account_schema_version": "pyth-price-v2", "adapter_version": "2.0.0"},
            "verification_policy": {"fail_closed": True}, "evaluation": {"mode": "numeric-v1"}, "timing": {"not_before_ms": "0", "observation_deadline_ms": "999999", "max_evidence_age_ms": "50"}, "conflict_policy": {"mode": "reject"}, "fallback_policy": {"outcome": "INVALID"}}


class DeterministicSigner(SignerBackend):
    name = "deterministic-demo-notary"
    def __init__(self, keys: Mapping[str, Keypair]): self.keys = dict(keys)
    def sign(self, pubkey, message: bytes, context: Mapping[str, Any]) -> bytes:
        if "bundle_hash" not in context: raise PipelineRejected("missing_signer_context")
        return bytes(self.keys[str(pubkey)].sign_message(message))


class DemoBackend:
    """Deterministic local submission harness implementing the agent facade."""
    def __init__(self, *, conflict: bool):
        self.conflict, self.orders, self.matched, self.resolved = conflict, [], False, False
        self.notaries = [Keypair.from_seed(bytes((21 + i,)) * 32) for i in range(2)]
        self.definition = definition()

    def create_market(self, question: str, resolver: ResolverConfig) -> MarketHandle:
        resolver_hash = bytes.fromhex(resolver_v2.resolver_definition_hash(self.definition).hex())
        pda, _ = derive_market_pda(resolver_hash, MARKET_OPEN, __import__("solders.pubkey", fromlist=["Pubkey"]).Pubkey.from_string(PROGRAM_ID))
        self.market = MarketHandle("demo-market-eth-5000", str(pda), question, resolver)
        return self.market

    def place_order(self, market: MarketHandle, owner: str, side: str, quantity: int, price_e8: int) -> Mapping[str, Any]:
        if self.resolved or quantity <= 0 or not 0 < price_e8 < 100_000_000: raise PipelineRejected("invalid_demo_order")
        order = {"order_id": f"{owner}-{side}-1", "owner": owner, "side": side, "quantity": quantity, "price_e8": price_e8}
        self.orders.append(order); return order

    def match(self, market: MarketHandle) -> Mapping[str, Any]:
        if len(self.orders) != 2 or {o["side"] for o in self.orders} != {"YES", "NO"}: raise PipelineRejected("demo_match_requires_cross_orders")
        self.matched = True
        committed = {"orders": [{**order, "quantity": str(order["quantity"]), "price_e8": str(order["price_e8"])} for order in self.orders]}
        return {"match_tx": hashlib.sha256(resolver_v2.canonical_json_bytes(committed)).hexdigest(), "matched_quantity": min(o["quantity"] for o in self.orders)}

    def _evidence(self):
        primary = PythAdapter(adapter_digest=H(3), verifier_descriptor=descriptor("prophet.verifier.pyth.primary", 4), clock_ms=lambda: 1_020)
        acquired = primary.acquire(self.definition, PythMaterial(H(1), "deterministic-local", H(2), "500000", "-2", "10", "TRADING", "1000", "77", b"deterministic-pyth-account-v1", "1020"))
        evidence = normalize_evidence(acquired, definition_hash=resolver_v2.resolver_definition_hash(self.definition).hex(), collector={"implementation": "agent-demo"}, transport={"kind": "deterministic-pyth"}, provenance={"fixture": "pyth-v1"})
        one = primary.verify(self.definition, evidence, self.definition["trust_model"])
        two = IndependentOracleVerifier(descriptor("prophet.verifier.pyth.independent", 5), clock_ms=lambda: 1_020).verify(self.definition, evidence, self.definition["trust_model"])
        if self.conflict: two = replace(two, outcome="NO", verified_facts={**two.verified_facts, "fault_injection": "opposite_outcome"})
        return evidence, one, two

    def resolve(self, market: MarketHandle) -> Mapping[str, Any]:
        if not self.matched: raise PipelineRejected("demo_resolve_requires_match")
        evidence, one, two = self._evidence()
        results = [verification_result_from_report(definition_hash=evidence["definition_hash"], evidence=evidence, report=report) for report in (one, two)]
        # V2 canonical bundle bindings use bytes32 market identity; the PDA is
        # retained separately for the unchanged Solana settlement message.
        context = BundleContext(H(6), H(2), H(10), H(8), "1", H(7), "1020", "1050", {"policy_id": "demo-2of2", "policy_version": "2.0.0", "threshold": "2", "allowed_adapter_digest": H(4)})
        # A conflicting candidate cannot form a valid settlement bundle. Keep a
        # valid single-result candidate commitment for audit, then pass both
        # raw canonical verifier results to the conflict coordinator.
        if self.conflict:
            candidate = build_resolution_bundle(definition=self.definition, evidence=[evidence], verification_results=[results[0]], trust_model=self.definition["trust_model"], verifier=one.verifier, outcome="YES", context=context)
            bundle = {**candidate, "verification_results": results}
            candidate_hash = resolver_v2.resolution_bundle_hash(candidate).hex()
        else:
            bundle = build_resolution_bundle(definition=self.definition, evidence=[evidence], verification_results=results, trust_model=self.definition["trust_model"], verifier=one.verifier, outcome="YES", context=context)
            candidate_hash = resolver_v2.resolution_bundle_hash(bundle).hex()
        agreement = AgreementPolicy((one.verifier["adapter_id"], two.verifier["adapter_id"]), 2, 2)
        with tempfile.TemporaryDirectory() as directory:
            conflicts = ConflictStateStore(f"{directory}/conflicts.jsonl")
            decision = MultiVerifierCoordinator(agreement, conflicts).evaluate(bundle, now_ms=1_020, attempt_id="deterministic-attempt-1", timestamp_ms="1020")
            base = {"evidence_hash": resolver_v2.evidence_hash(evidence).hex(), "verifier_identities": [one.verifier["adapter_id"], two.verifier["adapter_id"]], "agreement": decision.reason, "resolution_bundle_hash": candidate_hash, "conflict_persisted": conflicts.is_open(bundle)}
            if not decision.allowed:
                return {**base, "state": "conflicted", "outcome": None, "threshold_signer_result": None, "settlement_tx": None}
            policy = SignerPolicy(policy_id="demo-2of2", policy_version="2.0.0", allowed_resolver_ids=(self.definition["resolver_id"],), allowed_adapter_digests=(H(3),), allowed_trust_model_digests=(resolver_v2.trust_model_digest(self.definition["trust_model"]).hex(),), allowed_verifier_ids=(one.verifier["adapter_id"], two.verifier["adapter_id"]), allowed_verifier_versions=("2.0.0",), max_evidence_age_ms=100, max_verification_age_ms=100, market=H(6), cluster_genesis_hash=H(2), signer_set_version="2.0.0", threshold=2, required_verifier_count=2, required_verifier_ids=agreement.required_verifier_ids, minimum_agreeing_verifiers=2)
            message = build_legacy_settlement_message(program_id=PROGRAM_ID, market=market.market_pda, notary_config=str(self.notaries[0].pubkey()), resolver_hash=bundle["resolver_definition_hash"], open_ts=MARKET_OPEN, resolve_ts=MARKET_RESOLVE, notary_config_version=1, outcome="YES", proof_hash=bytes.fromhex(evidence["payload_hash"]).hex(), public_inputs_hash=resolver_v2.resolution_bundle_hash(bundle).hex())
            backend = DeterministicSigner({str(key.pubkey()): key for key in self.notaries})
            gate = ThresholdSigningGate(backend, SignerPolicyEngine(policy), EquivocationStore(f"{directory}/equivocation.jsonl"), JsonlAuditLogger(f"{directory}/audit.jsonl", "agent-demo"), conflict_state=conflicts)
            auth = gate.authorize(bundle, now_ms=1_020, expected_bundle_hash=base["resolution_bundle_hash"], settlement_message=message)
            signatures = gate.sign(auth, [key.pubkey() for key in self.notaries])
            self.resolved = True
            # This is the deterministic local submission receipt for the exact existing wire bytes.
            return {**base, "state": "resolved", "outcome": "YES", "threshold_signer_result": {"threshold": 2, "signature_count": len(signatures)}, "settlement_tx": hashlib.sha256(message).hexdigest(), "legacy_settlement_message_hash": hashlib.sha256(message).hexdigest()}

    def redeem(self, market: MarketHandle, owner: str) -> Mapping[str, Any]:
        if not self.resolved or owner != "agent-a": return {"owner": owner, "amount": 0}
        return {"owner": owner, "amount": 100, "redemption_tx": hashlib.sha256(f"{market.market_id}:{owner}:100".encode()).hexdigest()}


def run(conflict: bool) -> dict[str, Any]:
    backend = DemoBackend(conflict=conflict)
    resolver = ResolverConfig(backend.definition["resolver_id"], backend.definition, ("prophet.verifier.pyth.primary", "prophet.verifier.pyth.independent"), 2)
    prophet = ProphetAgent(backend)
    market = prophet.create_market(question="Will ETH exceed $5,000?", resolver=resolver)
    yes = prophet.buy_yes(market, agent_id="agent-a", quantity=100, price_e8=60_000_000)
    no = prophet.buy_no(market, agent_id="agent-b", quantity=100, price_e8=40_000_000)
    match = prophet.match_orders(market)
    resolution = prophet.resolve(market)
    redemption = prophet.redeem(market, agent_id="agent-a") if resolution["state"] == "resolved" else None
    return {"mode": "conflict" if conflict else "success", "market_id": market.market_id, "market_pda": market.market_pda, "resolver": {"id": resolver.resolver_id, "type": "pyth", "required_verifiers": list(resolver.required_verifiers)}, "orders": [yes, no], "match": match, **resolution, "redemption": redemption, "probability": "0.60000000"}


if __name__ == "__main__":
    import json
    parser = argparse.ArgumentParser(); parser.add_argument("--conflict", action="store_true")
    print(json.dumps(run(parser.parse_args().conflict), sort_keys=True, separators=(",", ":")))
