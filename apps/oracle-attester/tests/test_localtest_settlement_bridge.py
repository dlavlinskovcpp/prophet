"""Permanent P0C4 negative coverage for the public A/B settlement bridge."""
from __future__ import annotations

import hashlib

import pytest
from solders.hash import Hash
from solders.keypair import Keypair

from prophet_sdk.settlement_message import build_resolution_message_v2
from src.localtest_chain_binding import LocaltestChainBindingV1
from src.localtest_raw_settlement_bridge import (
    LocaltestRawSettlementBridgeError,
    build_localtest_raw_settlement_signatures,
)
from src.localtest_settlement_submission import build_localtest_settlement_message


def _binding(a: Keypair, b: Keypair) -> LocaltestChainBindingV1:
    return LocaltestChainBindingV1.from_mapping({
        "schema": "PROPHET_LOCALTEST_CHAIN_BINDING_V1", "version": 1,
        "cluster_classification": "FUNCTIONAL_TEST_ONLY", "genesis_hash": "01" * 32,
        "program_id": "3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE",
        "signer_a_public_key": str(a.pubkey()), "signer_b_public_key": str(b.pubkey()),
        "notary_config": str(Keypair.from_seed(bytes([8]) * 32).pubkey()), "notary_config_version": 1,
        "threshold": 2, "market": str(Keypair.from_seed(bytes([7]) * 32).pubkey()),
        "creator": str(Keypair.from_seed(bytes([9]) * 32).pubkey()), "market_nonce": 0,
        "resolver_definition_hash": "02" * 32, "open_ts": 10, "lock_ts": 10, "resolve_ts": 20,
        "outcome": "YES", "evidence_hash": "03" * 32, "proof_hash": "04" * 32,
        "public_inputs_hash": "05" * 32, "finalized_bootstrap_slot": 1,
        "finalized_bootstrap_block_time": 20, "finalized_account_context_slot": 1,
    })


def _bundle(binding: LocaltestChainBindingV1, a: Keypair, b: Keypair):
    message = build_resolution_message_v2(
        program_id=binding["program_id"], market=binding["market"], notary_config=binding["notary_config"],
        resolver_hash=bytes.fromhex(binding["resolver_definition_hash"]), open_ts=10, resolve_ts=20,
        notary_config_version=1, outcome="YES", proof_hash=bytes.fromhex(binding["proof_hash"]),
        public_inputs_hash=bytes.fromhex(binding["public_inputs_hash"]),
    )
    bundle = build_localtest_raw_settlement_signatures(
        canonical_message=message, signer_a_id="signer-a", signer_a_public_key=str(a.pubkey()),
        signer_a_key_version=1, signer_a_signature=bytes(a.sign_message(message)), signer_b_id="signer-b",
        signer_b_public_key=str(b.pubkey()), signer_b_key_version=1, signer_b_signature=bytes(b.sign_message(message)),
    )
    return message, bundle


def test_one_role_or_swapped_identity_cannot_materialize_a_bundle():
    a, b = Keypair(), Keypair()
    binding = _binding(a, b)
    message, bundle = _bundle(binding, a, b)
    with pytest.raises(LocaltestRawSettlementBridgeError):
        bundle.validate(expected_message=message, signer_a_id="signer-a", signer_a_public_key=str(b.pubkey()), signer_a_key_version=1, signer_b_id="signer-b", signer_b_public_key=str(a.pubkey()), signer_b_key_version=1)


@pytest.mark.parametrize("role", ["A", "B"])
def test_single_role_cannot_materialize_raw_bundle_or_message_v0(role):
    a, b = Keypair(), Keypair()
    binding = _binding(a, b)
    message, bundle = _bundle(binding, a, b)
    fields = {
        "canonical_message": message,
        "signer_a_id": "signer-a",
        "signer_a_public_key": str(a.pubkey()),
        "signer_a_key_version": 1,
        "signer_a_signature": bundle.signer_a_signature,
    }
    with pytest.raises((TypeError, LocaltestRawSettlementBridgeError)):
        build_localtest_raw_settlement_signatures(**fields)


@pytest.mark.parametrize("which", ["a", "b"])
def test_invalid_a_or_b_signature_is_rejected(which):
    a, b = Keypair(), Keypair()
    binding = _binding(a, b)
    message, bundle = _bundle(binding, a, b)
    bad = bytearray(bundle.signer_a_signature if which == "a" else bundle.signer_b_signature)
    bad[0] ^= 1
    mutated = type(bundle)(
        bundle.canonical_message, hashlib.sha256(message).hexdigest(), bundle.signer_a_id, bundle.signer_a_public_key,
        1, bytes(bad) if which == "a" else bundle.signer_a_signature, bundle.signer_b_id, bundle.signer_b_public_key,
        1, bytes(bad) if which == "b" else bundle.signer_b_signature,
    )
    with pytest.raises(LocaltestRawSettlementBridgeError):
        mutated.validate(expected_message=message, signer_a_id="signer-a", signer_a_public_key=str(a.pubkey()), signer_a_key_version=1, signer_b_id="signer-b", signer_b_public_key=str(b.pubkey()), signer_b_key_version=1)


def test_canonical_message_mismatch_is_rejected():
    a, b = Keypair(), Keypair()
    binding = _binding(a, b)
    message, bundle = _bundle(binding, a, b)
    with pytest.raises(LocaltestRawSettlementBridgeError):
        bundle.validate(expected_message=message + b"x", signer_a_id="signer-a", signer_a_public_key=str(a.pubkey()), signer_a_key_version=1, signer_b_id="signer-b", signer_b_public_key=str(b.pubkey()), signer_b_key_version=1)


def test_message_has_exact_three_instructions_and_fee_payer_only_signer():
    a, b, payer = Keypair(), Keypair(), Keypair()
    binding = _binding(a, b)
    _message, bundle = _bundle(binding, a, b)
    artifact = build_localtest_settlement_message(binding=binding, signatures=bundle, fee_payer_pubkey=str(payer.pubkey()), recent_blockhash=str(Hash.from_bytes(bytes([6]) * 32)))
    assert len(artifact.instructions) == 3
    assert artifact.message.header.num_required_signatures == 1
    assert artifact.message.account_keys[0] == payer.pubkey()
