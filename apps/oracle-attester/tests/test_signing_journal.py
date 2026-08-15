import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from solders.keypair import Keypair

from src.resolver_v2_pipeline import build_legacy_settlement_message
from src.runtime_config import parse_runtime_config
from src.signing_journal import (
    A_SIGNED,
    A_SIGNING,
    BOTH_SIGNED,
    JournalSignerBinding,
    SigningJournal,
    SigningJournalBindingError,
    SigningJournalConflict,
    SigningJournalSignatureError,
    SigningJournalUncertain,
)
from src.vault_transit_signer_identity import DeterministicTestVaultTransit, VaultTransitSignature, VaultTransitSignerClient
from src.vault_transit_threshold_signer import ThresholdResolutionSigner


def _message(**changes):
    fields = {"program_id":"11111111111111111111111111111111", "market":"11111111111111111111111111111111", "notary_config":"11111111111111111111111111111111", "resolver_hash":"04" * 32, "open_ts":-7, "resolve_ts":42, "notary_config_version":9, "outcome":"INVALID", "proof_hash":"05" * 32, "public_inputs_hash":"06" * 32}
    fields.update(changes)
    return build_legacy_settlement_message(**fields)


class CountingTransit(DeterministicTestVaultTransit):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.calls = []
    def sign_versioned(self, key_name, message, *, key_version):
        self.calls.append((key_name, bytes(message), key_version))
        return super().sign_versioned(key_name, message, key_version=key_version)


def _runtime(first, second):
    signer = lambda ident, key, pub: {"signer_id":ident,"key_name":key,"expected_public_key":str(pub),"expected_key_version":1}
    return parse_runtime_config({"schema_version":1,"environment":"localtest","mode":"test","solana":{"cluster":"localnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"test","version":"2"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":1,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"INTERNAL"},"signing":{"vault":{"address":"http://vault.test","auth":{"token_env":"VAULT_TOKEN"},"transit_mount":"transit","request_timeout_seconds":1,"backend":"deterministic-test"},"signers":{"a":signer("signer-a","key-a",first.pubkey()),"b":signer("signer-b","key-b",second.pubkey())}}})


def _fixture(tmp_path, monkeypatch):
    first, second = Keypair.from_seed(bytes(range(32))), Keypair.from_seed(bytes(range(32,64)))
    runtime = _runtime(first, second); monkeypatch.setenv("VAULT_TOKEN", "token")
    metadata = lambda key: {"type":"ed25519","supports_signing":True,"keys":{"1":{"public_key":str(key.pubkey())}}}
    transport = CountingTransit({"key-a":metadata(first),"key-b":metadata(second)}, signers_by_key={"key-a":first,"key-b":second})
    a = VaultTransitSignerClient.from_runtime(runtime, slot="A", transport=transport)
    b = VaultTransitSignerClient.from_runtime(runtime, slot="B", transport=transport)
    journal = SigningJournal(tmp_path / "journal.sqlite")
    return ThresholdResolutionSigner(signer_a=a, signer_b=b, journal=journal), journal, a, b, transport


def _bindings(a, b):
    return JournalSignerBinding(a.signer.signer_id,a.signer.expected_public_key,a.signer.expected_key_version), JournalSignerBinding(b.signer.signer_id,b.signer.expected_public_key,b.signer.expected_key_version)


def test_intent_duplicate_and_conflict_are_durable_before_vault_calls(tmp_path, monkeypatch):
    threshold, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); first = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    assert journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1]) == first
    with pytest.raises(SigningJournalConflict):
        threshold.sign_2_of_2(_message(outcome="YES"))
    assert transport.calls == []
    journal.close()


def test_threshold_journals_two_signatures_and_terminal_retry_is_zero_calls(tmp_path, monkeypatch):
    threshold, journal, _, _, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); bundle = threshold.sign_2_of_2(message)
    intent = journal.get(journal.reserve_intent(message, signer_a=JournalSignerBinding(bundle.signer_a_id,bundle.signer_a_public_key,bundle.signer_a_key_version), signer_b=JournalSignerBinding(bundle.signer_b_id,bundle.signer_b_public_key,bundle.signer_b_key_version)).signing_scope_id)
    assert intent.state == BOTH_SIGNED and intent.signer_a_result and intent.signer_b_result
    before = len(transport.calls); assert threshold.sign_2_of_2(message) == bundle and len(transport.calls) == before
    journal.close()


def test_result_recording_is_idempotent_and_immutable(tmp_path, monkeypatch):
    _, journal, a, b, _ = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.begin_signer(intent.signing_scope_id,"A"); signed = a.sign_canonical_message(message)
    assert journal.record_signature(intent.signing_scope_id,"A",signed).state == A_SIGNED
    assert journal.record_signature(intent.signing_scope_id,"A",signed).state == A_SIGNED
    changed = replace(signed, signature=bytes(64))
    with pytest.raises(SigningJournalSignatureError): journal.record_signature(intent.signing_scope_id,"A",changed)
    with pytest.raises(SigningJournalBindingError): journal.record_signature(intent.signing_scope_id,"B",signed)
    journal.close()


def test_signature_for_another_message_and_wrong_version_reject(tmp_path, monkeypatch):
    _, journal, a, b, _ = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.begin_signer(intent.signing_scope_id,"A")
    other = a.sign_canonical_message(_message(outcome="YES"))
    with pytest.raises(SigningJournalSignatureError): journal.record_signature(intent.signing_scope_id,"A",other)
    expected = a.sign_canonical_message(message)
    with pytest.raises(SigningJournalBindingError): journal.record_signature(intent.signing_scope_id,"A",replace(expected, key_version=2))
    # The pre-call reservation remains uncertain instead of accepting a mismatch.
    assert journal.get(intent.signing_scope_id).state == A_SIGNING
    journal.close()


def test_restart_preserves_partial_and_uncertain_crash_boundary(tmp_path, monkeypatch):
    threshold, journal, a, b, transport = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.begin_signer(intent.signing_scope_id,"A")
    journal.close()
    reopened = SigningJournal(tmp_path / "journal.sqlite")
    assert reopened.get(intent.signing_scope_id).state == A_SIGNING
    threshold._journal = reopened
    with pytest.raises(SigningJournalUncertain): threshold.sign_2_of_2(message)
    assert transport.calls == []
    reopened.close()


def test_restart_after_a_and_both_signed_preserves_exact_history(tmp_path, monkeypatch):
    threshold, journal, a, b, _ = _fixture(tmp_path, monkeypatch)
    message = _message(); intent = journal.reserve_intent(message, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1])
    journal.begin_signer(intent.signing_scope_id,"A"); a_result = a.sign_canonical_message(message); journal.record_signature(intent.signing_scope_id,"A",a_result)
    journal.close(); reopened = SigningJournal(tmp_path / "journal.sqlite")
    partial = reopened.get(intent.signing_scope_id); assert partial.state == A_SIGNED and partial.signer_a_result == a_result
    assert reopened.begin_signer(intent.signing_scope_id,"B") is None
    b_result = b.sign_canonical_message(message); final = reopened.record_signature(intent.signing_scope_id,"B",b_result)
    assert final.state == BOTH_SIGNED and final.signer_b_result == b_result
    with pytest.raises(SigningJournalBindingError): reopened.record_signature(intent.signing_scope_id, "A", b_result)
    reopened.close(); assert SigningJournal(tmp_path / "journal.sqlite").get(intent.signing_scope_id).state == BOTH_SIGNED


def test_concurrent_intents_allow_one_digest_only(tmp_path, monkeypatch):
    _, journal, a, b, _ = _fixture(tmp_path, monkeypatch)
    message, conflict = _message(), _message(outcome="YES")
    def reserve(value):
        local = SigningJournal(tmp_path / "journal.sqlite")
        try: return local.reserve_intent(value, signer_a=_bindings(a,b)[0], signer_b=_bindings(a,b)[1]).canonical_message_digest
        finally: local.close()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(reserve, value) for value in (message, conflict)]
        results = []
        for future in futures:
            try: results.append(future.result())
            except SigningJournalConflict: results.append("conflict")
    assert results.count("conflict") == 1 and len([result for result in results if result != "conflict"]) == 1
    journal.close()


def test_public_devnet_requires_explicit_persistent_journal_path():
    first, second = Keypair.from_seed(bytes(range(32))), Keypair.from_seed(bytes(range(32,64)))
    raw = {"schema_version":1,"environment":"public-devnet","mode":"production","solana":{"cluster":"devnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"test","version":"2"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":1,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"INTERNAL"},"signing":{"vault":{"address":"https://vault.example","auth":{"token_env":"VAULT_TOKEN"},"transit_mount":"transit","request_timeout_seconds":1,"backend":"vault-transit"},"signers":{"a":{"signer_id":"a","key_name":"a","expected_public_key":str(first.pubkey()),"expected_key_version":1},"b":{"signer_id":"b","key_name":"b","expected_public_key":str(second.pubkey()),"expected_key_version":1}}}}
    from src.runtime_config import RuntimeConfigError
    with pytest.raises(RuntimeConfigError): parse_runtime_config(raw)
    raw["signing"]["journal_path"] = "/var/lib/prophet/signing.sqlite"
    assert parse_runtime_config(raw).signing.journal_path == "/var/lib/prophet/signing.sqlite"
