import copy
import dataclasses
import hashlib
import sqlite3
import struct
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from prophet_sdk.pdas import derive_market_pda, derive_notary_config_snapshot_pda
from src.independent_signer_journal import (
    CONFLICT, PREPARED, SIGNED, SIGNING, UNCERTAIN,
    IndependentSignerBinding, IndependentSignerJournal,
    IndependentSignerJournalBindingError, IndependentSignerJournalConflict,
    IndependentSignerJournalSignatureError, IndependentSignerJournalStateError,
    IndependentSigningIntent,
    derive_signer_config_fingerprint,
)
from src.signer_authorization import (
    AUTHORIZATION_SCHEMA, Account, FinalizedAccountRead, FinalizedAccountsRead,
    AuthorizationResult, SignerAuthorizationConfig, VerifierPin, authorize, authorize_for_journal,
)
from src.verifier_attestation import VerifierAttestationSigner, settlement_authorization_job_id


H = lambda n: f"{n:02x}" * 32
PROGRAM = str(Pubkey.from_bytes(bytes([9]) * 32))
CREATOR = str(Pubkey.from_bytes(bytes([8]) * 32))
ADMIN = str(Pubkey.from_bytes(bytes([7]) * 32))
GENESIS = H(6)


def _key(seed): return Keypair.from_seed(bytes([seed]) * 32)


class _Rpc:
    def __init__(self, accounts): self.accounts = accounts
    def genesis_hash(self): return GENESIS
    def finalized_slot(self): return 1
    def block_time(self, slot): return 20
    def finalized_account(self, pubkey, *, min_context_slot): return FinalizedAccountRead(self.accounts.get(pubkey), 1)
    def finalized_accounts(self, pubkeys, *, min_context_slot): return FinalizedAccountsRead({key: self.accounts.get(key) for key in pubkeys}, 1)


def _authorized(outcome="YES", evidence_hash=H(2)):
    notary_a, notary_b = _key(11), _key(12)
    verifier_a, verifier_b = _key(13), _key(14)
    notary, notary_bump = derive_notary_config_snapshot_pda(Pubkey.from_string(ADMIN), 1, Pubkey.from_string(PROGRAM))
    notary_data = (hashlib.sha256(b"account:NotaryConfig").digest()[:8] + bytes(Pubkey.from_string(ADMIN))
        + bytes((2, 2, notary_bump)) + bytes(5) + struct.pack("<Q", 1)
        + bytes(notary_a.pubkey()) + bytes(notary_b.pubkey()) + bytes(30 * 32))
    resolver_hash = bytes.fromhex(H(1))
    market, market_bump = derive_market_pda(Pubkey.from_string(CREATOR), resolver_hash, 10, 0, Pubkey.from_string(PROGRAM))
    market_data = (hashlib.sha256(b"account:Market").digest()[:8] + bytes(32) * 5 + bytes(notary) + resolver_hash
        + bytes(64) + struct.pack("<qqqq", 10, 10, 20, 0) + bytes(32) + bytes(8) + bytes(4) + bytes(6)
        + bytes((0, 0, 0, market_bump, 0)) + bytes(Pubkey.from_string(CREATOR)) + struct.pack("<Q", 0) + bytes(1))
    binding = {"cluster_genesis_hash": GENESIS, "program_id": PROGRAM, "market": str(market), "resolver_definition_hash": H(1), "evidence_hash": evidence_hash, "proof_hash": H(3), "public_inputs_hash": H(4)}
    job_id = settlement_authorization_job_id(binding)
    def attestation(key, verifier_id, digest):
        signer = VerifierAttestationSigner(verifier_id, "1.0.0", digest, key)
        payload = {"attestation_schema": "prophet.verifier-attestation.v1", "attestation_version": "1", "verifier_id": verifier_id, "verifier_version": "1.0.0", "verifier_implementation_digest": digest, "job_id": job_id, **binding, "outcome": outcome, "acquired_at_ms": "10", "valid_until_ms": "30"}
        return signer.sign(payload, now_ms=20).as_transport(), VerifierPin(str(key.pubkey()), verifier_id, "1.0.0", digest)
    first, pin_a = attestation(verifier_a, "a", H(5)); second, pin_b = attestation(verifier_b, "b", H(6))
    request = {"schema": AUTHORIZATION_SCHEMA, "version": "1", **{name: binding[name] for name in ("cluster_genesis_hash", "program_id", "market")}, "verifier_a_attestation": first, "verifier_b_attestation": second}
    config = SignerAuthorizationConfig("A", str(notary_a.pubkey()), str(notary_b.pubkey()), pin_a, pin_b, GENESIS, PROGRAM)
    return authorize_for_journal(request=request, config=config, rpc=_Rpc({str(market): Account(PROGRAM, market_data), str(notary): Account(PROGRAM, notary_data)}), now_ms=20)


def _binding(key, *, slot="A", signer_id="signer-a", epoch=1):
    return IndependentSignerBinding(slot, signer_id, str(key.pubkey()), epoch)


def _scope_id(authorization):
    return IndependentSigningIntent.from_journal_authorization(authorization).scope.scope_id


def _intent(*, outcome="YES", job=H(2)):
    return _authorized(outcome=outcome, evidence_hash=job)


def _message(intent):
    return intent.canonical_message_bytes


def _journal(tmp_path, name="a.sqlite", binding=None):
    return IndependentSignerJournal(tmp_path / name, binding=binding or _binding(_key(1)))


def test_prepared_is_durable_idempotent_and_binding_strict(tmp_path):
    key = _key(1); binding = _binding(key); journal = _journal(tmp_path, binding=binding); intent = _intent()
    first = journal.prepare(intent, created_at_ms=1)
    assert first.state == PREPARED and journal.prepare(intent) == first
    for changed in (
        _intent(job=H(9)),
    ):
        with pytest.raises(IndependentSignerJournalBindingError): journal.prepare(changed)
    journal.close()
    for changed_binding in (_binding(_key(2)), _binding(key, epoch=2), _binding(key, signer_id="other")):
        with pytest.raises(IndependentSignerJournalStateError):
            _journal(tmp_path, binding=changed_binding)


def test_prepare_rejects_raw_intent_even_when_its_bytes_are_valid(tmp_path):
    authorization = _intent()
    raw = IndependentSigningIntent.from_journal_authorization(authorization)
    journal = _journal(tmp_path)
    with pytest.raises(IndependentSignerJournalBindingError): journal.prepare(raw)
    journal.close()


def test_p0c1_public_result_cannot_mint_or_replace_into_journal_authorization(tmp_path):
    public = AuthorizationResult("00" * 32, "x", "y", "YES", b"x", "00" * 32, "A", "z")
    clone = dataclasses.replace(public, canonical_message_bytes=b"different")
    journal = _journal(tmp_path)
    for value in (public, clone, copy.copy(public), copy.deepcopy(public)):
        with pytest.raises(IndependentSignerJournalBindingError): journal.prepare(value)
    journal.close()


def test_same_scope_different_digest_persists_terminal_conflict(tmp_path):
    journal = _journal(tmp_path); intent = _intent()
    journal.prepare(intent)
    with pytest.raises(IndependentSignerJournalConflict): journal.prepare(_intent(outcome="NO"))
    assert journal.get(_scope_id(intent)).state == CONFLICT
    with pytest.raises(IndependentSignerJournalConflict): journal.begin_signing(_scope_id(intent))
    journal.close()


def test_begin_is_durable_restart_makes_signing_uncertain(tmp_path):
    path = tmp_path / "journal.sqlite"; binding = _binding(_key(1)); journal = IndependentSignerJournal(path, binding=binding); intent = _intent()
    journal.prepare(intent); signing = journal.begin_signing(_scope_id(intent))
    assert signing.state == SIGNING and signing.operation_id
    operation_id = signing.operation_id
    journal.close(); reopened = IndependentSignerJournal(path, binding=binding)
    assert reopened.get(_scope_id(intent)).state == UNCERTAIN
    assert reopened.get(_scope_id(intent)).operation_id == operation_id
    with pytest.raises(IndependentSignerJournalStateError): reopened.begin_signing(_scope_id(intent))
    reopened.close()


def test_operation_id_is_local_immutable_and_unique_per_journal(tmp_path):
    binding = _binding(_key(1)); intent = _intent()
    first = _journal(tmp_path, "first.sqlite", binding)
    first.prepare(intent)
    with pytest.raises(TypeError):
        first.begin_signing(_scope_id(intent), operation_id="caller-chosen")
    first_record = first.begin_signing(_scope_id(intent))
    assert isinstance(first_record.operation_id, str) and len(first_record.operation_id) == 32
    with pytest.raises(IndependentSignerJournalStateError): first.begin_signing(_scope_id(intent))
    assert first.get(_scope_id(intent)).operation_id == first_record.operation_id
    second = _journal(tmp_path, "second.sqlite", binding)
    second.prepare(intent)
    second_record = second.begin_signing(_scope_id(intent))
    assert second_record.operation_id != first_record.operation_id
    first.close(); second.close()


def test_config_fingerprint_is_local_deterministic_and_binds_identity(tmp_path):
    key = _key(1); binding = _binding(key)
    assert binding.signer_config_fingerprint == derive_signer_config_fingerprint(
        signer_slot="A", signer_id="signer-a", signer_public_key=str(key.pubkey()), signer_key_epoch=1,
    )
    assert binding.signer_config_fingerprint == _binding(key).signer_config_fingerprint
    assert binding.signer_config_fingerprint != _binding(key, signer_id="other").signer_config_fingerprint
    assert binding.signer_config_fingerprint != _binding(_key(2)).signer_config_fingerprint
    assert binding.signer_config_fingerprint != _binding(key, epoch=2).signer_config_fingerprint
    with pytest.raises(IndependentSignerJournalBindingError): _binding(key, epoch=True)
    with pytest.raises(TypeError): IndependentSignerBinding("A", "signer-a", str(key.pubkey()), 1, H(5))
    journal = _journal(tmp_path, binding=binding); journal.prepare(_intent()); journal.close()
    db = sqlite3.connect(tmp_path / "a.sqlite")
    columns = {row[1] for row in db.execute("PRAGMA table_info(independent_signer_intents)")}
    assert not {"secret", "token", "private_key"} & columns
    db.close()


def test_signature_is_verified_before_signed_and_signed_replay_is_idempotent(tmp_path):
    key = _key(1); journal = _journal(tmp_path, binding=_binding(key)); intent = _intent()
    journal.prepare(intent); journal.begin_signing(_scope_id(intent))
    signature = bytes(key.sign_message(_message(intent)))
    signed = journal.record_signature(_scope_id(intent), signature=signature, signer_key_epoch=1)
    assert signed.state == SIGNED and signed.signature == signature
    assert journal.record_signature(_scope_id(intent), signature=signature, signer_key_epoch=1) == signed
    journal.close()


def test_wrong_signature_message_key_or_epoch_never_becomes_signed(tmp_path):
    key = _key(1); journal = _journal(tmp_path, binding=_binding(key)); intent = _intent()
    journal.prepare(intent); journal.begin_signing(_scope_id(intent))
    with pytest.raises(IndependentSignerJournalSignatureError):
        journal.record_signature(_scope_id(intent), signature=bytes(key.sign_message(_message(_intent(outcome="NO")))), signer_key_epoch=1)
    with pytest.raises(IndependentSignerJournalSignatureError):
        journal.record_signature(_scope_id(intent), signature=bytes(_key(2).sign_message(_message(intent))), signer_key_epoch=1)
    with pytest.raises(IndependentSignerJournalBindingError):
        journal.record_signature(_scope_id(intent), signature=bytes(key.sign_message(_message(intent))), signer_key_epoch=2)
    assert journal.get(_scope_id(intent)).state == SIGNING
    journal.close()


def test_uncertain_requires_cryptographic_reconciliation(tmp_path):
    key = _key(1); journal = _journal(tmp_path, binding=_binding(key)); intent = _intent()
    journal.prepare(intent); journal.begin_signing(_scope_id(intent))
    journal.mark_uncertain(_scope_id(intent), reason="timeout", backend_operation_id="backend-1")
    with pytest.raises(IndependentSignerJournalBindingError):
        journal.reconcile_signature(_scope_id(intent), signature=bytes(key.sign_message(_message(intent))), signer_key_epoch=1, backend_operation_id="other")
    assert journal.reconcile_signature(_scope_id(intent), signature=bytes(key.sign_message(_message(intent))), signer_key_epoch=1, backend_operation_id="backend-1").state == SIGNED
    journal.close()


def test_concurrent_identical_and_conflicting_prepares_are_durable(tmp_path):
    path = tmp_path / "journal.sqlite"; binding = _binding(_key(1)); first, other = _intent(), _intent(outcome="NO")
    def prepare(intent):
        journal = IndependentSignerJournal(path, binding=binding)
        try: return journal.prepare(intent).canonical_message_digest
        except IndependentSignerJournalConflict: return "conflict"
        finally: journal.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert len(set(pool.map(prepare, (first, first)))) == 1
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = tuple(pool.map(prepare, (first, other)))
    reopened = IndependentSignerJournal(path, binding=binding)
    assert "conflict" in result and reopened.get(_scope_id(first)).state == CONFLICT
    reopened.close()


def test_true_concurrent_conflicting_prepare_leaves_terminal_conflict(tmp_path):
    path = tmp_path / "race.sqlite"; binding = _binding(_key(1)); first, other, barrier = _intent(), _intent(outcome="NO"), Barrier(2)
    def prepare(intent):
        journal = IndependentSignerJournal(path, binding=binding)
        try:
            barrier.wait(); return journal.prepare(intent).canonical_message_digest
        except IndependentSignerJournalConflict: return "conflict"
        finally: journal.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        result = tuple(pool.map(prepare, (first, other)))
    journal = IndependentSignerJournal(path, binding=binding)
    assert "conflict" in result and journal.get(_scope_id(first)).state == CONFLICT
    journal.close()


def test_signer_journals_are_independent(tmp_path):
    a, b = _journal(tmp_path, "a.sqlite", _binding(_key(1), slot="A")), _journal(tmp_path, "b.sqlite", _binding(_key(2), slot="B", signer_id="signer-b"))
    ia, ib = _intent(), _intent()
    assert a.prepare(ia).state == PREPARED and b.prepare(ib).state == PREPARED
    with pytest.raises(IndependentSignerJournalConflict): a.prepare(_intent(outcome="NO"))
    assert a.get(_scope_id(ia)).state == CONFLICT and b.get(_scope_id(ib)).state == PREPARED
    a.close(); b.close()


@pytest.mark.parametrize("value", [True, False, 0, -1, "1"])
def test_bool_and_invalid_numeric_inputs_reject(value, tmp_path):
    with pytest.raises(IndependentSignerJournalBindingError): IndependentSigningIntent.from_journal_authorization(object())
    with pytest.raises(IndependentSignerJournalBindingError): _binding(_key(1), epoch=value)
    journal = _journal(tmp_path)
    if type(value) is int and value == 0:
        assert journal.prepare(_intent(), created_at_ms=value).created_at_ms == "0"
    else:
        with pytest.raises(IndependentSignerJournalBindingError): journal.prepare(_intent(), created_at_ms=value)
    journal.close()


def test_corrupt_future_schema_and_authorization_boundary_reject(tmp_path):
    path = tmp_path / "future.sqlite"; db = sqlite3.connect(path); db.execute("PRAGMA user_version = 99"); db.commit(); db.close()
    with pytest.raises(IndependentSignerJournalStateError): IndependentSignerJournal(path, binding=_binding(_key(1)))
    derived = IndependentSigningIntent.from_journal_authorization(_intent())
    assert derived.scope.market_pubkey


def test_restart_matrix_preserves_terminal_states_and_marks_only_signing_uncertain(tmp_path):
    binding = _binding(_key(1)); prepared = _journal(tmp_path, "prepared.sqlite", binding); intent = _intent(); prepared.prepare(intent); prepared.close()
    assert IndependentSignerJournal(tmp_path / "prepared.sqlite", binding=binding).get(_scope_id(intent)).state == PREPARED

    key = _key(1); signed = _journal(tmp_path, "signed.sqlite", _binding(key)); signed_intent = _intent(); signed.prepare(signed_intent); signed_record = signed.begin_signing(_scope_id(signed_intent))
    signature = bytes(key.sign_message(_message(signed_intent))); signed.record_signature(_scope_id(signed_intent), signature=signature, signer_key_epoch=1); signed.close()
    reopened_signed = IndependentSignerJournal(tmp_path / "signed.sqlite", binding=_binding(key)); assert reopened_signed.get(_scope_id(signed_intent)).state == SIGNED; assert reopened_signed.get(_scope_id(signed_intent)).operation_id == signed_record.operation_id; reopened_signed.close()

    uncertain = _journal(tmp_path, "uncertain.sqlite", binding); uncertain.prepare(intent); uncertain.begin_signing(_scope_id(intent)); uncertain.mark_uncertain(_scope_id(intent), reason="timeout"); uncertain.close()
    reopened_uncertain = IndependentSignerJournal(tmp_path / "uncertain.sqlite", binding=binding); assert reopened_uncertain.get(_scope_id(intent)).state == UNCERTAIN; reopened_uncertain.close()

    conflict = _journal(tmp_path, "conflict.sqlite", binding); conflict.prepare(intent)
    with pytest.raises(IndependentSignerJournalConflict): conflict.prepare(_intent(outcome="NO"))
    conflict.close(); reopened_conflict = IndependentSignerJournal(tmp_path / "conflict.sqlite", binding=binding); assert reopened_conflict.get(_scope_id(intent)).state == CONFLICT; reopened_conflict.close()


def test_corrupt_signed_row_fails_closed_on_reopen(tmp_path):
    path = tmp_path / "corrupt.sqlite"; binding = _binding(_key(1)); journal = IndependentSignerJournal(path, binding=binding); intent = _intent(); journal.prepare(intent); journal.close()
    db = sqlite3.connect(path); db.execute("UPDATE independent_signer_intents SET state = ?", (SIGNED,)); db.commit(); db.close()
    with pytest.raises(IndependentSignerJournalStateError): IndependentSignerJournal(path, binding=binding)


@pytest.mark.parametrize("state,operation_id", [
    (PREPARED, "a" * 32), (SIGNING, None), (SIGNING, "not-an-operation-id"),
    (UNCERTAIN, None), (UNCERTAIN, "not-an-operation-id"),
    (SIGNED, None), (SIGNED, "not-an-operation-id"),
    (CONFLICT, "not-an-operation-id"),
])
def test_corrupt_operation_id_state_combinations_fail_closed(tmp_path, state, operation_id):
    path = tmp_path / f"{state}-{operation_id}.sqlite"; key = _key(1); binding = _binding(key); authorization = _intent()
    journal = IndependentSignerJournal(path, binding=binding); prepared = journal.prepare(authorization); scope_id = prepared.scope.scope_id
    if state in (SIGNING, UNCERTAIN, SIGNED):
        journal.begin_signing(scope_id)
    if state == UNCERTAIN:
        journal.mark_uncertain(scope_id, reason="timeout")
    if state == SIGNED:
        journal.record_signature(scope_id, signature=bytes(key.sign_message(_message(authorization))), signer_key_epoch=1)
    if state == CONFLICT:
        with pytest.raises(IndependentSignerJournalConflict): journal.prepare(_intent(outcome="NO"))
    journal.close()
    db = sqlite3.connect(path); db.execute("UPDATE independent_signer_intents SET operation_id = ?", (operation_id,)); db.commit(); db.close()
    with pytest.raises(IndependentSignerJournalStateError): IndependentSignerJournal(path, binding=binding)


@pytest.mark.parametrize("column,value", [
    ("signer_id", "tampered"),
    ("signer_public_key", str(_key(2).pubkey())),
    ("signer_key_epoch", 2),
    ("signer_config_fingerprint", "f" * 64),
])
def test_persisted_individual_binding_tamper_fails_closed(tmp_path, column, value):
    path = tmp_path / f"binding-{column}.sqlite"; binding = _binding(_key(1)); journal = IndependentSignerJournal(path, binding=binding)
    journal.prepare(_intent()); journal.close()
    db = sqlite3.connect(path); db.execute(f"UPDATE independent_signer_intents SET {column} = ?", (value,)); db.commit(); db.close()
    with pytest.raises(IndependentSignerJournalStateError): IndependentSignerJournal(path, binding=binding)


def test_alternate_internally_consistent_binding_is_rejected_on_startup_and_after_open(tmp_path):
    path = tmp_path / "alternate-binding.sqlite"; key_a, key_b = _key(1), _key(2); binding_a, binding_b = _binding(key_a), _binding(key_b, signer_id="signer-b", epoch=2)
    journal = IndependentSignerJournal(path, binding=binding_a); record = journal.prepare(_intent()); scope_id = record.scope.scope_id
    def tamper():
        db = sqlite3.connect(path)
        db.execute("UPDATE independent_signer_intents SET signer_id = ?, signer_public_key = ?, signer_key_epoch = ?, signer_config_fingerprint = ?", (binding_b.signer_id, binding_b.signer_public_key, binding_b.signer_key_epoch, binding_b.signer_config_fingerprint))
        db.commit(); db.close()
    tamper()
    with pytest.raises(IndependentSignerJournalStateError): journal.begin_signing(scope_id)
    journal.close()
    with pytest.raises(IndependentSignerJournalStateError): IndependentSignerJournal(path, binding=binding_a)


def test_post_startup_binding_tamper_blocks_signed_read_and_replay(tmp_path):
    path = tmp_path / "signed-binding.sqlite"; key_a, key_b = _key(1), _key(2); binding_a, binding_b = _binding(key_a), _binding(key_b, signer_id="signer-b", epoch=2)
    authorization = _intent(); journal = IndependentSignerJournal(path, binding=binding_a); record = journal.prepare(authorization); journal.begin_signing(record.scope.scope_id)
    signature = bytes(key_a.sign_message(_message(authorization))); journal.record_signature(record.scope.scope_id, signature=signature, signer_key_epoch=1)
    db = sqlite3.connect(path)
    db.execute("UPDATE independent_signer_intents SET signer_id = ?, signer_public_key = ?, signer_key_epoch = ?, signer_config_fingerprint = ?", (binding_b.signer_id, binding_b.signer_public_key, binding_b.signer_key_epoch, binding_b.signer_config_fingerprint))
    db.commit(); db.close()
    with pytest.raises(IndependentSignerJournalStateError): journal.get(record.scope.scope_id)
    with pytest.raises(IndependentSignerJournalStateError): journal.record_signature(record.scope.scope_id, signature=signature, signer_key_epoch=1)
    journal.close()
