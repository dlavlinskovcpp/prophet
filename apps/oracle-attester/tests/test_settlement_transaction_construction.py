import hashlib
import importlib.metadata
import inspect
import sqlite3
import struct
from dataclasses import FrozenInstanceError, replace

import pytest
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.message import MessageV0
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.sysvar import INSTRUCTIONS as SYSVAR_INSTRUCTIONS_ID

from prophet_sdk.ed25519 import ED25519_PROGRAM_ID
from prophet_sdk.pdas import derive_market_pda

from src.agreed_settlement_signer import AgreedSettlementSigner
from src.resolution_coordinator_store import (
    CONFLICT,
    ResolutionCoordinatorStore,
    SettlementMessageContext,
    SettlementRuntimeBinding,
    VerifierBinding,
)
from src.runtime_config import SolanaRuntimeConfig
from src.settlement_transaction_builder import (
    SettlementTransactionArtifact,
    SettlementTransactionBindingError,
    SettlementTransactionBuilder,
    SettlementTransactionInput,
    SettlementTransactionJobError,
    SettlementTransactionSigningStateError,
)
from tests.test_agreed_settlement_signing_integration import H, _canonical_inputs, _verification
from tests.test_signing_journal import _fixture as signing_fixture


OPEN_TS = -7
RESOLVE_TS = 42
NOTARY_VERSION = 9
PROGRAM_ID = "11111111111111111111111111111111"
NOTARY_CONFIG = "11111111111111111111111111111111"
GENESIS_HASH = str(Hash.from_bytes(bytes([7]) * 32))
BLOCKHASH_1 = str(Hash.from_bytes(bytes([8]) * 32))
BLOCKHASH_2 = str(Hash.from_bytes(bytes([9]) * 32))
FEE_PAYER_1 = str(Pubkey.from_bytes(bytes([21]) * 32))
FEE_PAYER_2 = str(Pubkey.from_bytes(bytes([22]) * 32))


def _setup(tmp_path, monkeypatch, *, terminal="AGREED", signing_mode="complete"):
    definition, evidence = _canonical_inputs()
    a = _verification(definition, evidence, slot="A")
    b = _verification(definition, evidence, slot="B", outcome="NO" if terminal == "CONFLICT" else "INVALID")
    program = Pubkey.from_string(PROGRAM_ID)
    resolver_hash = bytes.fromhex(a["definition_hash"])
    market, _ = derive_market_pda(Pubkey.default(), resolver_hash, OPEN_TS, 0, program)
    store = ResolutionCoordinatorStore(
        tmp_path / "coordinator.sqlite",
        verifier_a=VerifierBinding("A", a["verifier"]),
        verifier_b=VerifierBinding("B", b["verifier"]),
    )
    job = store.register_job(market=bytes(market).hex(), resolver_definition=definition, evidence=evidence)
    context = SettlementMessageContext(
        program_id=PROGRAM_ID,
        creator=str(Pubkey.default()),
        market_nonce=0,
        notary_config=NOTARY_CONFIG,
        open_ts=OPEN_TS,
        resolve_ts=RESOLVE_TS,
        notary_config_version=NOTARY_VERSION,
        proof_hash=H(5),
        public_inputs_hash=H(6),
    )
    store.bind_settlement_context(job.job_id, context)
    store.bind_settlement_runtime(
        job.job_id,
        SettlementRuntimeBinding(cluster="localnet", genesis_hash=GENESIS_HASH, program_id=PROGRAM_ID),
    )
    if terminal in ("PARTIAL", "AGREED", "CONFLICT"):
        job = store.record_result(job_id=job.job_id, slot="A", result=a)
    if terminal in ("AGREED", "CONFLICT"):
        job = store.record_result(job_id=job.job_id, slot="B", result=b)

    threshold, journal, signer_a, signer_b, transport = signing_fixture(tmp_path, monkeypatch)
    signing = AgreedSettlementSigner(
        coordinator_state=store, signing_journal=journal, threshold_signer=threshold
    )
    signing_result = None
    intent = None
    if terminal == "AGREED":
        if signing_mode == "complete":
            signing_result = signing.sign_agreed_job(job.job_id)
            intent = journal.get(signing_result.signing_intent_id)
        elif signing_mode in ("intent", "uncertain"):
            message = signing._canonical_message(job)
            intent = threshold.prepare_2_of_2(message, coordinator_job_id=job.job_id)
            if signing_mode == "uncertain":
                journal.begin_signer(intent.signing_scope_id, "A")
                intent = journal.get(intent.signing_scope_id)

    runtime = SolanaRuntimeConfig("localnet", GENESIS_HASH, PROGRAM_ID)
    builder = SettlementTransactionBuilder(
        coordinator_state=store,
        signing_journal=journal,
        threshold_signer=threshold,
        solana_runtime=runtime,
    )
    signing_intent_id = (
        signing_result.signing_intent_id if signing_result is not None
        else intent.signing_scope_id if intent is not None
        else H(99)
    )
    request = SettlementTransactionInput(
        coordinator_job_id=job.job_id,
        signing_intent_id=signing_intent_id,
        fee_payer_pubkey=FEE_PAYER_1,
        recent_blockhash=BLOCKHASH_1,
    )
    return {
        "store": store,
        "job": store.get_job(job.job_id),
        "context": context,
        "threshold": threshold,
        "journal": journal,
        "signer_a": signer_a,
        "signer_b": signer_b,
        "transport": transport,
        "signing": signing,
        "signing_result": signing_result,
        "intent": intent,
        "runtime": runtime,
        "builder": builder,
        "request": request,
    }


def _expected_resolve_data(outcome_idx=3):
    return (
        hashlib.sha256(b"global:resolve_market_threshold").digest()[:8]
        + struct.pack("B", outcome_idx)
        + bytes.fromhex(H(5))
        + bytes.fromhex(H(6))
    )


def _expected_ed25519_payload(message, signature, public_key):
    return (
        struct.pack("<BBHHHHHHH", 1, 0, 48, 0xFFFF, 16, 0xFFFF, 112, len(message), 0xFFFF)
        + bytes(Pubkey.from_string(public_key))
        + signature
        + message
    )


def _db_rows(db, table):
    return tuple(tuple(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall())


def test_01_completed_agreed_bundle_builds_unsigned_transaction_artifact(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert isinstance(artifact, SettlementTransactionArtifact)
    assert isinstance(artifact.message, MessageV0)
    assert artifact.serialized_message == bytes(artifact.message)
    assert len(artifact.instructions) == 3


def test_02_conflict_job_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch, terminal="CONFLICT", signing_mode="none")
    assert x["job"].state == CONFLICT
    with pytest.raises(SettlementTransactionJobError, match="not_agreed"):
        x["builder"].build(x["request"])


def test_03_partial_job_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch, terminal="PARTIAL", signing_mode="none")
    with pytest.raises(SettlementTransactionJobError, match="not_agreed"):
        x["builder"].build(x["request"])


def test_04_incomplete_signing_intent_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch, signing_mode="intent")
    with pytest.raises(SettlementTransactionSigningStateError):
        x["builder"].build(x["request"])


def test_05_uncertain_signing_state_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch, signing_mode="uncertain")
    with pytest.raises(SettlementTransactionSigningStateError):
        x["builder"].build(x["request"])


def test_06_coordinator_signing_link_mismatch_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    bad = replace(x["request"], signing_intent_id=H(90))
    with pytest.raises(SettlementTransactionBindingError, match="intent_mismatch"):
        x["builder"].build(bad)


def test_07_canonical_digest_mismatch_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    x["journal"]._db.execute(
        "UPDATE coordinator_signing_links SET canonical_message_digest = ? WHERE coordinator_job_id = ?",
        (H(88), x["job"].job_id),
    )
    with pytest.raises(SettlementTransactionBindingError, match="digest_mismatch"):
        x["builder"].build(x["request"])


def test_08_ed25519_a_and_b_payloads_are_exact(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    a, b = artifact.instructions[:2]
    result = x["signing_result"]
    assert a.program_id == b.program_id == ED25519_PROGRAM_ID
    assert bytes(a.data) == _expected_ed25519_payload(artifact.canonical_message, result.signature_bundle.signer_a_signature, result.signature_bundle.signer_a_public_key)
    assert bytes(b.data) == _expected_ed25519_payload(artifact.canonical_message, result.signature_bundle.signer_b_signature, result.signature_bundle.signer_b_public_key)


def test_09_signer_order_is_runtime_a_then_b_not_pubkey_sort(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert bytes(artifact.instructions[0].data)[16:48] == bytes(Pubkey.from_string(artifact.signer_a_public_key))
    assert bytes(artifact.instructions[1].data)[16:48] == bytes(Pubkey.from_string(artifact.signer_b_public_key))


def test_10_prophet_resolve_instruction_data_matches_frozen_existing_path(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert bytes(artifact.instructions[2].data) == _expected_resolve_data(3)


def test_10b_resolve_instruction_matches_existing_solana_client_builder(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])

    # Known-good comparison comes from the pre-existing localnet/client builder,
    # not from a second serializer introduced by Phase 6D1.  Bypass __init__ so
    # no RPC client or keypair loading occurs during the compatibility proof.
    from src.solana_client import SolanaClient

    legacy = object.__new__(SolanaClient)
    legacy.program_id = Pubkey.from_string(PROGRAM_ID)
    expected = SolanaClient.build_resolve_threshold_ix(
        legacy,
        market=Pubkey.from_bytes(bytes.fromhex(x["job"].market)),
        notary_config=Pubkey.from_string(NOTARY_CONFIG),
        outcome_idx=3,
        proof_hash=bytes.fromhex(H(5)),
        public_inputs_hash=bytes.fromhex(H(6)),
    )
    actual = artifact.instructions[2]
    assert actual.program_id == expected.program_id
    assert list(actual.accounts) == list(expected.accounts)
    assert bytes(actual.data) == bytes(expected.data)


def test_11_prophet_account_metas_match_frozen_existing_path(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    market = Pubkey.from_bytes(bytes.fromhex(x["job"].market))
    expected = [
        AccountMeta(market, False, True),
        AccountMeta(Pubkey.from_string(NOTARY_CONFIG), False, False),
        AccountMeta(SYSVAR_INSTRUCTIONS_ID, False, False),
    ]
    assert list(artifact.instructions[2].accounts) == expected
    assert artifact.instructions[2].program_id == Pubkey.from_string(PROGRAM_ID)


def test_12_instruction_order_is_ed25519_a_ed25519_b_prophet(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert [ix.program_id for ix in artifact.instructions] == [
        ED25519_PROGRAM_ID,
        ED25519_PROGRAM_ID,
        Pubkey.from_string(PROGRAM_ID),
    ]


def test_13_fee_payer_change_does_not_change_canonical_resolution_bytes(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    first = x["builder"].build(x["request"])
    second = x["builder"].build(replace(x["request"], fee_payer_pubkey=FEE_PAYER_2))
    assert first.canonical_message == second.canonical_message
    assert first.signer_a_signature == second.signer_a_signature
    assert first.signer_b_signature == second.signer_b_signature
    assert first.serialized_message != second.serialized_message


def test_14_blockhash_change_does_not_change_canonical_resolution_bytes(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    first = x["builder"].build(x["request"])
    second = x["builder"].build(replace(x["request"], recent_blockhash=BLOCKHASH_2))
    assert first.canonical_message == second.canonical_message
    assert first.canonical_message_digest == second.canonical_message_digest


def test_15_identical_inputs_produce_byte_identical_message(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    first = x["builder"].build(x["request"])
    second = x["builder"].build(x["request"])
    assert first.serialized_message == second.serialized_message
    assert first.message_digest == second.message_digest


def test_16_different_blockhash_changes_transaction_message(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    first = x["builder"].build(x["request"])
    second = x["builder"].build(replace(x["request"], recent_blockhash=BLOCKHASH_2))
    assert first.serialized_message != second.serialized_message
    assert first.message_digest != second.message_digest


def test_17_wrong_program_id_runtime_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    wrong = SolanaRuntimeConfig("localnet", GENESIS_HASH, str(Pubkey.from_bytes(bytes([31]) * 32)))
    builder = SettlementTransactionBuilder(coordinator_state=x["store"], signing_journal=x["journal"], threshold_signer=x["threshold"], solana_runtime=wrong)
    with pytest.raises(SettlementTransactionBindingError, match="runtime_binding_mismatch"):
        builder.build(x["request"])


def test_18_wrong_cluster_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    wrong = SolanaRuntimeConfig("devnet", GENESIS_HASH, PROGRAM_ID)
    builder = SettlementTransactionBuilder(coordinator_state=x["store"], signing_journal=x["journal"], threshold_signer=x["threshold"], solana_runtime=wrong)
    with pytest.raises(SettlementTransactionBindingError, match="runtime_binding_mismatch"):
        builder.build(x["request"])


def test_19_wrong_genesis_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    wrong = SolanaRuntimeConfig("localnet", BLOCKHASH_2, PROGRAM_ID)
    builder = SettlementTransactionBuilder(coordinator_state=x["store"], signing_journal=x["journal"], threshold_signer=x["threshold"], solana_runtime=wrong)
    with pytest.raises(SettlementTransactionBindingError, match="runtime_binding_mismatch"):
        builder.build(x["request"])


def test_20_corrupt_a_signature_rejects_via_existing_journal_validation(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    intent = x["journal"].get(x["request"].signing_intent_id)
    x["journal"]._db.execute(
        "UPDATE signing_intents SET signer_a_signature = ? WHERE signing_scope_id = ?",
        (intent.signer_b_result.signature, intent.signing_scope_id),
    )
    with pytest.raises(SettlementTransactionSigningStateError):
        x["builder"].build(x["request"])


def test_21_duplicate_a_into_b_rejects_via_existing_journal_validation(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    intent = x["journal"].get(x["request"].signing_intent_id)
    x["journal"]._db.execute(
        "UPDATE signing_intents SET signer_b_signature = ? WHERE signing_scope_id = ?",
        (intent.signer_a_result.signature, intent.signing_scope_id),
    )
    with pytest.raises(SettlementTransactionSigningStateError):
        x["builder"].build(x["request"])


def test_22_wrong_key_version_metadata_rejects(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    x["journal"]._db.execute(
        "UPDATE signing_intents SET signer_a_key_version = signer_a_key_version + 1 WHERE signing_scope_id = ?",
        (x["request"].signing_intent_id,),
    )
    with pytest.raises(SettlementTransactionSigningStateError):
        x["builder"].build(x["request"])


def test_23_caller_cannot_override_outcome(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    with pytest.raises(TypeError):
        SettlementTransactionInput(**{**x["request"].__dict__, "outcome": "YES"})


def test_24_caller_cannot_override_resolver_or_signatures(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    for key, value in (("resolver_id", "evil"), ("signature_a", b"x" * 64), ("market", H(1))):
        with pytest.raises(TypeError):
            SettlementTransactionInput(**{**x["request"].__dict__, key: value})


def test_25_builder_performs_zero_vault_calls(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    before = len(x["transport"].calls)
    monkeypatch.setattr(
        x["transport"], "read_key_metadata",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("Vault metadata called")),
    )
    monkeypatch.setattr(
        x["transport"], "sign_versioned",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("Vault signing called")),
    )
    x["builder"].build(x["request"])
    assert len(x["transport"].calls) == before == 2


def test_26_builder_has_no_verifier_or_rpc_dependency_in_public_boundary(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    params = list(inspect.signature(SettlementTransactionBuilder.__init__).parameters)
    assert params == [
        "self", "coordinator_state", "signing_journal", "threshold_signer", "solana_runtime", "clock_ms"
    ]
    assert not any("verifier" in name.lower() or "rpc" in name.lower() for name in params)
    x["builder"].build(x["request"])


def test_27_builder_does_not_call_submit_path(tmp_path, monkeypatch):
    import src.solana_client as solana_client
    monkeypatch.setattr(solana_client.SolanaClient, "submit_and_confirm", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("submission called")))
    x = _setup(tmp_path, monkeypatch)
    x["builder"].build(x["request"])


def test_28_coordinator_state_is_unchanged(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    before = x["store"].get_job(x["job"].job_id)
    before_context = x["store"].get_settlement_context(x["job"].job_id)
    before_runtime = x["store"].get_settlement_runtime(x["job"].job_id)
    x["builder"].build(x["request"])
    assert x["store"].get_job(x["job"].job_id) == before
    assert x["store"].get_settlement_context(x["job"].job_id) == before_context
    assert x["store"].get_settlement_runtime(x["job"].job_id) == before_runtime


def test_29_signing_journal_is_read_only_during_repeated_build(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    before_intents = _db_rows(x["journal"]._db, "signing_intents")
    before_links = _db_rows(x["journal"]._db, "coordinator_signing_links")
    x["builder"].build(x["request"])
    x["builder"].build(x["request"])
    assert _db_rows(x["journal"]._db, "signing_intents") == before_intents
    assert _db_rows(x["journal"]._db, "coordinator_signing_links") == before_links


def test_30_fee_payer_role_never_replaces_resolution_authorization(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    base = x["builder"].build(x["request"])
    same_pubkey_as_a = replace(
        x["request"], fee_payer_pubkey=x["signing_result"].signer_a_public_key
    )
    artifact = x["builder"].build(same_pubkey_as_a)
    assert artifact.canonical_message == base.canonical_message
    assert artifact.signer_a_signature == base.signer_a_signature
    assert artifact.signer_b_signature == base.signer_b_signature
    assert bytes(artifact.instructions[0].data) == bytes(base.instructions[0].data)
    assert bytes(artifact.instructions[1].data) == bytes(base.instructions[1].data)
    assert bytes(artifact.instructions[2].data) == bytes(base.instructions[2].data)
    assert artifact.serialized_message != base.serialized_message


def test_31_runtime_binding_is_immutable_and_bound_before_verifier_progress(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    same = SettlementRuntimeBinding("localnet", GENESIS_HASH, PROGRAM_ID)
    assert x["store"].bind_settlement_runtime(x["job"].job_id, same) == same
    with pytest.raises(Exception, match="immutable"):
        x["store"].bind_settlement_runtime(
            x["job"].job_id,
            SettlementRuntimeBinding("devnet", GENESIS_HASH, PROGRAM_ID),
        )


def test_32_market_pda_corruption_rejects_before_instruction_build(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    x["store"]._db.execute("UPDATE resolution_jobs SET market = ? WHERE job_id = ?", (H(0), x["job"].job_id))
    with pytest.raises(SettlementTransactionBindingError, match="market_pda_binding_mismatch"):
        x["builder"].build(x["request"])


def test_33_exact_durable_canonical_bytes_feed_both_ed25519_instructions(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert bytes(artifact.instructions[0].data)[112:] == artifact.canonical_message
    assert bytes(artifact.instructions[1].data)[112:] == artifact.canonical_message
    assert hashlib.sha256(artifact.canonical_message).hexdigest() == artifact.canonical_message_digest


def test_34_messagev0_has_no_address_lookup_tables_or_compute_budget_instruction(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert tuple(artifact.message.address_table_lookups) == ()
    assert len(artifact.instructions) == 3
    assert all(str(ix.program_id) != "ComputeBudget111111111111111111111111111111" for ix in artifact.instructions)


def test_35_artifact_is_frozen_and_contains_no_private_material(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    with pytest.raises(FrozenInstanceError):
        artifact.program_id = FEE_PAYER_2
    names = set(artifact.__dataclass_fields__)
    assert not any("private" in name or "secret" in name or "token" in name or "authorization" in name for name in names)


def test_36_real_solders_021_types_are_used(tmp_path, monkeypatch):
    assert importlib.metadata.version("solders") == "0.21.0"
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert isinstance(Pubkey.from_string(artifact.program_id), Pubkey)
    assert isinstance(Signature.from_bytes(artifact.signer_a_signature), Signature)
    assert all(isinstance(ix, Instruction) for ix in artifact.instructions)
    assert all(isinstance(meta, AccountMeta) for meta in artifact.instructions[2].accounts)
    assert isinstance(Hash.from_string(artifact.recent_blockhash), Hash)
    assert isinstance(artifact.message, MessageV0)


def test_37_no_transaction_object_or_transaction_signature_is_created(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    artifact = x["builder"].build(x["request"])
    assert isinstance(artifact.message, MessageV0)
    assert not hasattr(artifact, "transaction_signature")
    assert not hasattr(artifact, "signed_transaction")


def test_38_runtime_binding_missing_rejects_fail_closed(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    x["store"]._db.execute("DELETE FROM resolution_job_solana_bindings WHERE job_id = ?", (x["job"].job_id,))
    with pytest.raises(SettlementTransactionBindingError, match="binding_missing_or_invalid"):
        x["builder"].build(x["request"])


def test_39_persisted_protocol_field_mutation_rejects_against_durable_signed_bytes(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    x["store"]._db.execute(
        "UPDATE resolution_job_settlement_contexts SET proof_hash = ? WHERE job_id = ?",
        (H(77), x["job"].job_id),
    )
    with pytest.raises(SettlementTransactionBindingError, match="canonical_message_mismatch"):
        x["builder"].build(x["request"])


def test_40_notary_config_version_mutation_rejects_against_durable_signed_bytes(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    x["store"]._db.execute(
        "UPDATE resolution_job_settlement_contexts SET notary_config_version = ? WHERE job_id = ?",
        (str(NOTARY_VERSION + 1), x["job"].job_id),
    )
    with pytest.raises(SettlementTransactionBindingError, match="canonical_message_mismatch"):
        x["builder"].build(x["request"])


def test_41_v2_coordinator_schema_migrates_without_retroactive_runtime_binding(tmp_path, monkeypatch):
    x = _setup(tmp_path, monkeypatch)
    path = tmp_path / "coordinator.sqlite"
    job_id = x["job"].job_id
    x["store"].close()
    db = sqlite3.connect(path)
    db.execute("DROP TABLE resolution_job_solana_bindings")
    db.execute("DELETE FROM schema_migrations WHERE version IN (3, 4)")
    db.execute("PRAGMA user_version = 2")
    db.commit()
    db.close()

    definition, evidence = _canonical_inputs()
    a = _verification(definition, evidence, slot="A")
    b = _verification(definition, evidence, slot="B", outcome="INVALID")
    reopened = ResolutionCoordinatorStore(
        path,
        verifier_a=VerifierBinding("A", a["verifier"]),
        verifier_b=VerifierBinding("B", b["verifier"]),
    )
    assert reopened.schema_version() == 4
    assert reopened.get_job(job_id).state == "AGREED"
    with pytest.raises(Exception, match="settlement_runtime_binding_not_found"):
        reopened.get_settlement_runtime(job_id)
    with pytest.raises(Exception, match="settlement_runtime_binding_too_late"):
        reopened.bind_settlement_runtime(
            job_id, SettlementRuntimeBinding("localnet", GENESIS_HASH, PROGRAM_ID)
        )
    reopened.close()
