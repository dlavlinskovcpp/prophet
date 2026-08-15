from dataclasses import replace

import pytest
from solders.keypair import Keypair

from src.runtime_config import RuntimeConfigError, parse_runtime_config
from src.signing_journal import JournalSignerBinding, SigningJournal
from src.vault_transit_signer_identity import (
    DeterministicTestVaultTransit,
    VaultSignerPublicKeyMismatch,
    VaultSignerRotationError,
    VaultTransitSignerClient,
    select_signer_epoch,
)
from src.vault_transit_threshold_signer import ThresholdResolutionSigner
from tests.test_signing_journal import CountingTransit, _message


def _raw(a1, a2, b1, b2, *, a_epochs=None, b_epochs=None):
    epochs = lambda one, two: [{"key_version":1,"public_key":str(one.pubkey()),"activation_time_ms":0,"retirement_time_ms":100},{"key_version":2,"public_key":str(two.pubkey()),"activation_time_ms":100,"retirement_time_ms":None}]
    signer = lambda ident, key, values: {"signer_id":ident,"key_name":key,"key_epochs":values}
    return {"schema_version":1,"environment":"localtest","mode":"test","solana":{"cluster":"localnet","genesis_hash":"g","prophet_program_id":"p"},"resolver_v2":{"schema_version":2},"verifier":{"implementation_id":"test","version":"2"},"allowed_adapters":["pyth"],"limits":{"request_max_bytes":1,"request_timeout_seconds":1},"freshness":{"default_max_evidence_age_seconds":1,"default_max_verification_age_seconds":1},"internal_auth":{"token_env":"INTERNAL"},"signing":{"vault":{"address":"http://vault.test","auth":{"token_env":"VAULT_TOKEN"},"transit_mount":"transit","request_timeout_seconds":1,"backend":"deterministic-test"},"signers":{"a":signer("signer-a","key-a",a_epochs or epochs(a1,a2)),"b":signer("signer-b","key-b",b_epochs or epochs(b1,b2))}}}


def _fixture(tmp_path, monkeypatch, *, raw=None):
    a1,a2,b1,b2=(Keypair.from_seed(bytes(range(offset,offset+32))) for offset in (0,32,64,96))
    config=parse_runtime_config(raw or _raw(a1,a2,b1,b2)); monkeypatch.setenv("VAULT_TOKEN","token")
    meta=lambda one,two: {"type":"ed25519","supports_signing":True,"keys":{"1":{"public_key":str(one.pubkey())},"2":{"public_key":str(two.pubkey())}}}
    transport=CountingTransit({"key-a":meta(a1,a2),"key-b":meta(b1,b2)},signers_by_key={("key-a",1):a1,("key-a",2):a2,("key-b",1):b1,("key-b",2):b2})
    a=VaultTransitSignerClient.from_runtime(config,slot="A",transport=transport); b=VaultTransitSignerClient.from_runtime(config,slot="B",transport=transport)
    journal=SigningJournal(tmp_path/"journal.sqlite")
    return config, ThresholdResolutionSigner(signer_a=a,signer_b=b,journal=journal), journal,a,b,transport,(a1,a2,b1,b2)


def test_epoch_boundaries_are_activation_inclusive_retirement_exclusive(tmp_path, monkeypatch):
    config, _, journal, _, _, _, _ = _fixture(tmp_path,monkeypatch)
    epochs=config.signing.signer_a.key_epochs
    assert select_signer_epoch(config.signing.signer_a,99).key_version == 1
    assert select_signer_epoch(config.signing.signer_a,100).key_version == 2
    assert select_signer_epoch(config.signing.signer_a,101).key_version == 2
    journal.close()


def test_new_intents_pin_both_epochs_and_rotation_does_not_change_message(tmp_path, monkeypatch):
    _, threshold, journal, _, _, transport, _ = _fixture(tmp_path,monkeypatch)
    old_message, new_message = _message(), _message(open_ts=-6)
    old=threshold.sign_2_of_2(old_message,intent_created_at_ms=50)
    new=threshold.sign_2_of_2(new_message,intent_created_at_ms=100)
    assert (old.signer_a_key_version,old.signer_b_key_version)==(1,1)
    assert (new.signer_a_key_version,new.signer_b_key_version)==(2,2)
    threshold.validate_bundle(old, old_message)  # journal rehydrates v1, not current v2
    assert old_message == _message() and new_message == _message(open_ts=-6)
    assert [(key,version) for key,_,version in transport.calls] == [("key-a",1),("key-b",1),("key-a",2),("key-b",2)]
    journal.close()


def test_restart_uses_persisted_old_epochs_for_a_and_pending_b(tmp_path, monkeypatch):
    config, _, journal, a, b, transport, _ = _fixture(tmp_path,monkeypatch)
    message=_message(); a1=select_signer_epoch(config.signing.signer_a,50); b1=select_signer_epoch(config.signing.signer_b,50)
    old_a,old_b=a.for_epoch(a1),b.for_epoch(b1)
    intent=journal.reserve_intent(message,signer_a=JournalSignerBinding("signer-a",a1.public_key,1),signer_b=JournalSignerBinding("signer-b",b1.public_key,1),created_at_ms=50)
    journal.begin_signer(intent.signing_scope_id,"A"); journal.record_signature(intent.signing_scope_id,"A",old_a.sign_canonical_message(message))
    journal.close(); reopened=SigningJournal(tmp_path/"journal.sqlite")
    ThresholdResolutionSigner(signer_a=a,signer_b=b,journal=reopened).resume_2_of_2(message)
    assert [(key,version) for key,_,version in transport.calls] == [("key-a",1),("key-b",1)]
    reopened.close()


def test_uncertain_old_epoch_cannot_migrate_when_historical_epoch_removed(tmp_path, monkeypatch):
    config, _, journal, a, b, _, keys = _fixture(tmp_path,monkeypatch)
    message=_message(); a1=select_signer_epoch(config.signing.signer_a,50); b1=select_signer_epoch(config.signing.signer_b,50)
    intent=journal.reserve_intent(message,signer_a=JournalSignerBinding("signer-a",a1.public_key,1),signer_b=JournalSignerBinding("signer-b",b1.public_key,1),created_at_ms=50)
    journal.begin_signer(intent.signing_scope_id,"A"); journal.close()
    a1k,a2k,b1k,b2k=keys
    only_new=lambda pair: [{"key_version":2,"public_key":str(pair.pubkey()),"activation_time_ms":100,"retirement_time_ms":None}]
    changed=parse_runtime_config(_raw(a1k,a2k,b1k,b2k,a_epochs=only_new(a2k),b_epochs=only_new(b2k)))
    new_a=VaultTransitSignerClient.from_runtime(changed,slot="A",transport=a._transport); new_b=VaultTransitSignerClient.from_runtime(changed,slot="B",transport=b._transport)
    with pytest.raises(VaultSignerRotationError): ThresholdResolutionSigner(signer_a=new_a,signer_b=new_b,journal=SigningJournal(tmp_path/"journal.sqlite")).resume_2_of_2(message)


def test_epoch_validation_and_fingerprint_are_strict_and_order_independent(tmp_path, monkeypatch):
    a1,a2,b1,b2=(Keypair.from_seed(bytes(range(offset,offset+32))) for offset in (0,32,64,96))
    raw=_raw(a1,a2,b1,b2); reversed_raw=_raw(a1,a2,b1,b2)
    reversed_raw["signing"]["signers"]["a"]["key_epochs"].reverse()
    assert parse_runtime_config(raw).fingerprint()==parse_runtime_config(reversed_raw).fingerprint()
    replacement=Keypair.from_seed(bytes(range(128,160)))
    fingerprint_changed=_raw(a1,a2,b1,b2); fingerprint_changed["signing"]["signers"]["a"]["key_epochs"][1]["public_key"]=str(replacement.pubkey())
    assert parse_runtime_config(raw).fingerprint()!=parse_runtime_config(fingerprint_changed).fingerprint()
    changed=_raw(a1,a2,b1,b2); changed["signing"]["signers"]["a"]["key_epochs"][1]["activation_time_ms"]=101
    with pytest.raises(RuntimeConfigError): parse_runtime_config(changed) # gap is forbidden
    duplicate=_raw(a1,a2,b1,b2); duplicate["signing"]["signers"]["a"]["key_epochs"][1]["key_version"]=1
    with pytest.raises(RuntimeConfigError): parse_runtime_config(duplicate)
    overlap=_raw(a1,a2,b1,b2); overlap["signing"]["signers"]["a"]["key_epochs"][0]["retirement_time_ms"]=101
    with pytest.raises(RuntimeConfigError): parse_runtime_config(overlap)


def test_vault_version_public_key_mismatch_fails_closed(tmp_path, monkeypatch):
    a1,a2,b1,b2=(Keypair.from_seed(bytes(range(offset,offset+32))) for offset in (0,32,64,96))
    config=parse_runtime_config(_raw(a1,a2,b1,b2)); monkeypatch.setenv("VAULT_TOKEN","token")
    metadata=lambda one,two: {"type":"ed25519","supports_signing":True,"keys":{"1":{"public_key":str(one.pubkey())},"2":{"public_key":str(two.pubkey())}}}
    # Vault reports A version 2 with A version 1's key, contrary to policy.
    transport=DeterministicTestVaultTransit({"key-a":metadata(a1,a1),"key-b":metadata(b1,b2)},signers_by_key={("key-a",1):a1,("key-a",2):a2,("key-b",1):b1,("key-b",2):b2})
    a=VaultTransitSignerClient.from_runtime(config,slot="A",transport=transport); b=VaultTransitSignerClient.from_runtime(config,slot="B",transport=transport)
    signer=ThresholdResolutionSigner(signer_a=a,signer_b=b,journal=SigningJournal(tmp_path/"journal.sqlite"))
    with pytest.raises(VaultSignerPublicKeyMismatch): signer.sign_2_of_2(_message(),intent_created_at_ms=100)
