from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from threading import Barrier, Lock

import pytest
import httpx
from solders.keypair import Keypair

from src.independent_signer_execution import (
    IndependentSignerEngine, IndependentSignerExecutionError,
    IndependentSignerStartupError, IndependentSignerVaultAdapter,
)
from src.independent_signer_journal import (
    CONFLICT, PREPARED, SIGNED, SIGNING, UNCERTAIN,
    IndependentSignerBinding, IndependentSignerJournal,
)
from src.independent_signer_runtime import IndependentSignerServiceConfig
from tests.test_signer_authorization import GEN, PROGRAM, fixture
from src.signer_authorization import SignerAuthorizationConfig
from src.vault_transit import VaultTransitError
from src.verifier_attestation import VerifierAttestationSigner


class _Vault:
    def __init__(self, key, *, metadata=None, error=None, reported_version=1, signature=None):
        self.key, self.metadata_override, self.error = key, metadata, error
        self.reported_version, self.signature = reported_version, signature
        self.metadata_calls, self.sign_calls, self.messages, self.versions = 0, 0, [], []
        self._lock = Lock()

    def read_key_metadata(self, key_name):
        with self._lock:
            self.metadata_calls += 1
        if self.metadata_override is not None:
            return self.metadata_override
        return {"type": "ed25519", "supports_signing": True, "keys": {"1": {"public_key": str(self.key.pubkey())}}}

    def sign_versioned(self, key_name, message, *, key_version):
        with self._lock:
            self.sign_calls += 1; self.messages.append(message); self.versions.append(key_version)
        if self.error is not None: raise self.error
        signature = self.signature if self.signature is not None else bytes(self.key.sign_message(message))
        return self.reported_version, signature


def _service(key, *, role="A"):
    lower = role.lower()
    return IndependentSignerServiceConfig.from_mapping({
        "environment": "public-devnet", "mode": "production", "topology_classification": "OPERATED_2OF2",
        "signer": {"role": role, "signer_id": f"signer-{lower}", "public_key": str(key.pubkey()), "key_version": 1},
        "vault": {"address": f"https://vault-{lower}.example", "transit_mount": "transit", "key_name": f"notary-{lower}", "token_env": f"SIGNER_{role}_VAULT_TOKEN", "admin_domain_id": f"vault-admin-{lower}", "account_or_tenant_id": f"vault-account-{lower}", "auth_principal_id": f"vault-principal-{lower}", "timeout_seconds": 10},
        "rpc": {"url_env": f"SIGNER_{role}_RPC_URL", "provider_domain_id": f"rpc-provider-{lower}", "account_or_project_id": f"rpc-account-{lower}", "credential_principal_id": f"rpc-principal-{lower}"},
        "solana": {"expected_genesis_hash": GEN, "expected_program_id": PROGRAM},
        "journal_path": f"/tmp/unused-{lower}-by-test.sqlite", "admission_token_env": f"SIGNER_{role}_ADMISSION_TOKEN",
    })


def _engine(tmp_path, monkeypatch, *, vault=None, journal=None, service=None, authorization=None, rpc=None):
    request, auth, local_rpc, *_ = fixture()
    key = Keypair.from_seed(bytes(range(32)))
    service = service or _service(key)
    auth = authorization or auth
    local_rpc = rpc or local_rpc
    journal = journal or IndependentSignerJournal(tmp_path / "signer.sqlite", binding=IndependentSignerBinding("A", "signer-a", str(key.pubkey()), 1))
    vault = vault or _Vault(key)
    monkeypatch.setenv("SIGNER_A_VAULT_TOKEN", "a-token")
    adapter = IndependentSignerVaultAdapter(service, transport=vault)
    return IndependentSignerEngine(service_config=service, authorization_config=auth, journal=journal, rpc=local_rpc, vault=adapter), request, journal, vault, key


def test_valid_request_authorizes_prepares_signs_and_persists_exact_journal_message(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    result = engine.execute(request, now_ms=20)
    record = journal.get(result.scope_id)
    assert result.state == SIGNED and record.state == SIGNED
    assert vault.sign_calls == 1 and vault.messages == [record.canonical_message] and vault.versions == [1]
    assert len(vault.messages[0]) == 235 and vault.messages[0][:18] == b"PROPHET_RESOLVE_V2"
    journal.close()


def test_invalid_and_raw_inputs_never_reach_vault(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    with pytest.raises(IndependentSignerExecutionError): engine.execute(b"x" * 235, now_ms=20)
    request["cluster_genesis_hash"] = "00" * 32
    with pytest.raises(Exception): engine.execute(request, now_ms=20)
    assert vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("metadata", (
    {"type": "ed25519", "supports_signing": True, "keys": {"1": {"public_key": "11111111111111111111111111111111"}}},
    {"type": "ed25519", "supports_signing": True, "keys": {}},
))
def test_bad_vault_metadata_rejects_before_durable_signing(tmp_path, monkeypatch, metadata):
    key = Keypair.from_seed(bytes(range(32))); vault = _Vault(key, metadata=metadata)
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch, vault=vault)
    with pytest.raises(Exception): engine.execute(request, now_ms=20)
    carrier_scope = None
    from src.signer_authorization import authorize_for_journal
    _, auth, rpc, *_ = fixture(); carrier = authorize_for_journal(request=request, config=auth, rpc=rpc, now_ms=20)
    from src.independent_signer_journal import IndependentSigningIntent
    carrier_scope = IndependentSigningIntent.from_journal_authorization(carrier).scope.scope_id
    assert journal.get(carrier_scope).state == PREPARED and vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("capability", (False, None, 1, 0, "true", "false", [], {}), ids=("false", "none", "integer_one", "integer_zero", "text_true", "text_false", "list", "object"))
def test_non_boolean_or_missing_vault_signing_capability_rejects_before_signing(tmp_path, monkeypatch, capability):
    key = Keypair.from_seed(bytes(range(32)))
    metadata = {"type": "ed25519", "keys": {"1": {"public_key": str(key.pubkey())}}}
    if capability != "missing":
        metadata["supports_signing"] = capability
    vault = _Vault(key, metadata=metadata)
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch, vault=vault)
    with pytest.raises(Exception):
        engine.execute(request, now_ms=20)
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    assert journal.get(scope).state == PREPARED and vault.sign_calls == 0
    journal.close()


def test_missing_vault_signing_capability_rejects_before_signing(tmp_path, monkeypatch):
    key = Keypair.from_seed(bytes(range(32)))
    vault = _Vault(key, metadata={"type": "ed25519", "keys": {"1": {"public_key": str(key.pubkey())}}})
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch, vault=vault)
    with pytest.raises(Exception):
        engine.execute(request, now_ms=20)
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    assert journal.get(scope).state == PREPARED and vault.sign_calls == 0
    journal.close()


@pytest.mark.parametrize("vault_kwargs", (
    {"error": VaultTransitError("timeout")},
    {"reported_version": 2},
    {"signature": b"x" * 64},
))
def test_post_signing_vault_failures_become_uncertain_once(tmp_path, monkeypatch, vault_kwargs):
    key = Keypair.from_seed(bytes(range(32))); vault = _Vault(key, **vault_kwargs)
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch, vault=vault)
    with pytest.raises(IndependentSignerExecutionError): engine.execute(request, now_ms=20)
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    operation_id = journal.get(scope).operation_id
    assert journal.get(scope).state == UNCERTAIN and vault.sign_calls == 1 and operation_id is not None
    with pytest.raises(IndependentSignerExecutionError): engine.execute(request, now_ms=20)
    assert vault.sign_calls == 1 and journal.get(scope).operation_id == operation_id
    journal.close()


def test_repeat_signed_returns_stored_result_without_resigning(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    first = engine.execute(request, now_ms=20); second = engine.execute(request, now_ms=20)
    assert first == second and vault.sign_calls == 1
    journal.close()


def test_fresh_engine_and_journal_replay_durable_signed_without_resigning(tmp_path, monkeypatch):
    first, request, journal, vault, key = _engine(tmp_path, monkeypatch)
    signed = first.execute(request, now_ms=20)
    persisted = journal.get(signed.scope_id)
    assert persisted.state == SIGNED and vault.sign_calls == 1
    journal.close()
    reopened = IndependentSignerJournal(tmp_path / "signer.sqlite", binding=IndependentSignerBinding("A", "signer-a", str(key.pubkey()), 1))
    second, _, _, _, _ = _engine(tmp_path, monkeypatch, journal=reopened, vault=vault)
    replayed = second.execute(request, now_ms=20)
    assert replayed.signature == persisted.signature
    assert replayed.operation_id == persisted.operation_id
    assert replayed.scope_id == persisted.scope.scope_id
    assert replayed.canonical_message_digest == persisted.canonical_message_digest
    assert vault.sign_calls == 1
    reopened.close()


def test_restart_after_durable_signing_is_uncertain_and_never_resigns(tmp_path, monkeypatch):
    engine, request, journal, vault, key = _engine(tmp_path, monkeypatch)
    from src.signer_authorization import authorize_for_journal
    _, auth, rpc, *_ = fixture(); carrier = authorize_for_journal(request=request, config=auth, rpc=rpc, now_ms=20)
    prepared = journal.prepare(carrier); journal.begin_signing(prepared.scope.scope_id); journal.close()
    reopened = IndependentSignerJournal(tmp_path / "signer.sqlite", binding=IndependentSignerBinding("A", "signer-a", str(key.pubkey()), 1))
    engine, _, reopened, vault, _ = _engine(tmp_path, monkeypatch, journal=reopened, vault=vault)
    assert reopened.get(prepared.scope.scope_id).state == UNCERTAIN
    with pytest.raises(IndependentSignerExecutionError): engine.execute(request, now_ms=20)
    assert vault.sign_calls == 0
    reopened.close()


@pytest.mark.parametrize("failure", (
    httpx.ReadError("connection reset"),
    VaultTransitError("unauthorized", status_code=401),
    VaultTransitError("forbidden", status_code=403),
    VaultTransitError("server error", status_code=500),
), ids=("transport_reset", "http_401", "http_403", "http_500"))
def test_explicit_post_signing_vault_failure_classes_become_uncertain_once(tmp_path, monkeypatch, failure):
    key = Keypair.from_seed(bytes(range(32))); vault = _Vault(key, error=failure)
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch, vault=vault)
    with pytest.raises(IndependentSignerExecutionError):
        engine.execute(request, now_ms=20)
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    record = journal.get(scope)
    assert vault.metadata_calls == 1 and vault.sign_calls == 1
    assert record.state == UNCERTAIN and record.operation_id is not None
    with pytest.raises(IndependentSignerExecutionError):
        engine.execute(request, now_ms=20)
    assert vault.sign_calls == 1 and journal.get(scope).operation_id == record.operation_id
    journal.close()


def test_startup_cross_bindings_and_counterpart_secret_boundary(tmp_path, monkeypatch):
    engine, request, journal, vault, key = _engine(tmp_path, monkeypatch)
    service = _service(key)
    _, auth, rpc, *_ = fixture()
    with pytest.raises(IndependentSignerStartupError):
        IndependentSignerEngine(service_config=replace(service, signer_role="B"), authorization_config=auth, journal=journal, rpc=rpc, vault=IndependentSignerVaultAdapter(service, transport=vault))
    calls = []
    import src.independent_signer_execution as execution
    actual = execution.os.getenv
    monkeypatch.setattr(execution.os, "getenv", lambda name, default="": calls.append(name) or actual(name, default))
    IndependentSignerVaultAdapter(service, transport=vault)
    assert calls == ["SIGNER_A_VAULT_TOKEN"] and "SIGNER_B_VAULT_TOKEN" not in calls
    key_b = Keypair.from_seed(bytes([33]) * 32); service_b = _service(key_b, role="B")
    monkeypatch.setenv("SIGNER_B_VAULT_TOKEN", "b-token"); calls.clear()
    IndependentSignerVaultAdapter(service_b, transport=_Vault(key_b))
    assert calls == ["SIGNER_B_VAULT_TOKEN"] and "SIGNER_A_VAULT_TOKEN" not in calls
    journal.close()


@pytest.mark.parametrize("mutation", (
    lambda service, auth, journal: (replace(service, signer_role="B"), auth, journal),
    lambda service, auth, journal: (service, replace(auth, own_notary_public_key=str(Keypair.from_seed(bytes([3]) * 32).pubkey())), journal),
    lambda service, auth, journal: (service, replace(auth, expected_cluster_genesis_hash="00" * 32), journal),
    lambda service, auth, journal: (service, replace(auth, expected_program_id="11111111111111111111111111111111"), journal),
))
def test_startup_rejects_service_to_p0c1_cross_binding_mismatches(tmp_path, monkeypatch, mutation):
    engine, _, journal, vault, key = _engine(tmp_path, monkeypatch)
    service, auth = _service(key), engine._authorization_config
    service, auth, journal = mutation(service, auth, journal)
    with pytest.raises(IndependentSignerStartupError):
        IndependentSignerEngine(service_config=service, authorization_config=auth, journal=journal, rpc=engine._rpc, vault=IndependentSignerVaultAdapter(_service(key), transport=vault))
    journal.close()


def test_startup_rejects_service_to_p0c2_journal_binding_mismatch(tmp_path, monkeypatch):
    engine, _, journal, vault, key = _engine(tmp_path, monkeypatch)
    _, auth, rpc, *_ = fixture()
    mismatched = IndependentSignerJournal(
        tmp_path / "other.sqlite",
        binding=IndependentSignerBinding("A", "other-signer", str(key.pubkey()), 1),
    )
    with pytest.raises(IndependentSignerStartupError):
        IndependentSignerEngine(service_config=_service(key), authorization_config=auth, journal=mismatched, rpc=rpc, vault=IndependentSignerVaultAdapter(_service(key), transport=vault))
    mismatched.close(); journal.close()


def test_record_signature_failure_after_valid_vault_signature_becomes_uncertain(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    monkeypatch.setattr(journal, "record_signature", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("storage failed")))
    with pytest.raises(IndependentSignerExecutionError): engine.execute(request, now_ms=20)
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    assert vault.sign_calls == 1 and journal.get(scope).state == UNCERTAIN
    journal.close()


def test_mark_uncertain_persistence_failure_hard_fails_without_resigning_and_recovers_on_restart(tmp_path, monkeypatch):
    key = Keypair.from_seed(bytes(range(32))); vault = _Vault(key, error=VaultTransitError("timeout"))
    engine, request, journal, vault, key = _engine(tmp_path, monkeypatch, vault=vault)
    monkeypatch.setattr(journal, "mark_uncertain", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("storage unavailable")))
    with pytest.raises(IndependentSignerExecutionError):
        engine.execute(request, now_ms=20)
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    assert vault.sign_calls == 1 and journal.get(scope).state == SIGNING
    journal.close()
    reopened = IndependentSignerJournal(tmp_path / "signer.sqlite", binding=IndependentSignerBinding("A", "signer-a", str(key.pubkey()), 1))
    assert reopened.get(scope).state == UNCERTAIN and vault.sign_calls == 1
    reopened.close()


def test_record_signature_post_commit_failure_returns_only_matching_persisted_signed_result(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    original = journal.record_signature
    def persist_then_raise(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("response lost after commit")
    monkeypatch.setattr(journal, "record_signature", persist_then_raise)
    result = engine.execute(request, now_ms=20)
    record = journal.get(result.scope_id)
    assert result.state == SIGNED and result.signature == record.signature
    assert vault.sign_calls == 1 and result.operation_id == record.operation_id
    journal.close()


def test_record_signature_failure_with_unavailable_journal_hard_fails_without_resigning(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    original_get = journal.get
    monkeypatch.setattr(journal, "record_signature", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("storage failed")))
    monkeypatch.setattr(journal, "get", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("storage unavailable")))
    with pytest.raises(IndependentSignerExecutionError):
        engine.execute(request, now_ms=20)
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    assert vault.sign_calls == 1 and original_get(scope).state == SIGNING
    journal.close()


def test_concurrent_identical_and_conflicting_execution_never_double_signs(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    def run(value):
        try: return engine.execute(value, now_ms=20).state
        except Exception: return "rejected"
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(run, (request, request)))
    assert vault.sign_calls <= 1 and "SIGNED" in results
    journal.close()


def test_concurrent_conflicting_authorizations_never_double_sign(tmp_path, monkeypatch):
    engine, request, journal, vault, _ = _engine(tmp_path, monkeypatch)
    conflicting = deepcopy(request)
    for name, seed, verifier_id, digest in (
        ("verifier_a_attestation", bytes(range(64, 96)), "a", "05" * 32),
        ("verifier_b_attestation", bytes(range(96, 128)), "b", "06" * 32),
    ):
        payload = dict(conflicting[name]["payload"]); payload["outcome"] = "NO"
        conflicting[name] = VerifierAttestationSigner(verifier_id, "1.0.0", digest, Keypair.from_seed(seed)).sign(payload, now_ms=20).as_transport()
    def run(value):
        try: return engine.execute(value, now_ms=20).state
        except Exception: return "rejected"
    with ThreadPoolExecutor(max_workers=2) as pool:
        tuple(pool.map(run, (request, conflicting)))
    scope = next(iter(journal._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    assert vault.sign_calls <= 1 and journal.get(scope).state == CONFLICT
    journal.close()


def test_separate_journal_connections_identical_execution_signs_at_most_once(tmp_path, monkeypatch):
    key = Keypair.from_seed(bytes(range(32))); vault = _Vault(key)
    binding = IndependentSignerBinding("A", "signer-a", str(key.pubkey()), 1)
    path = tmp_path / "shared.sqlite"
    first_journal = IndependentSignerJournal(path, binding=binding)
    second_journal = IndependentSignerJournal(path, binding=binding)
    first, request, _, _, _ = _engine(tmp_path, monkeypatch, journal=first_journal, vault=vault)
    second, _, _, _, _ = _engine(tmp_path, monkeypatch, journal=second_journal, vault=vault)
    barrier = Barrier(2)
    def run(engine):
        try:
            barrier.wait()
            return engine.execute(deepcopy(request), now_ms=20)
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(run, (first, second)))
    first_journal.close(); second_journal.close()
    reopened = IndependentSignerJournal(path, binding=binding)
    scope = next(iter(reopened._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    record = reopened.get(scope)
    assert vault.sign_calls <= 1 and record.state == SIGNED
    assert len({item.operation_id for item in results if item is not None}) <= 1
    assert vault.messages == [record.canonical_message]
    reopened.close()


def test_separate_journal_connections_conflicting_execution_never_double_sign(tmp_path, monkeypatch):
    key = Keypair.from_seed(bytes(range(32))); vault = _Vault(key)
    binding = IndependentSignerBinding("A", "signer-a", str(key.pubkey()), 1)
    path = tmp_path / "shared-conflict.sqlite"
    first_journal = IndependentSignerJournal(path, binding=binding)
    second_journal = IndependentSignerJournal(path, binding=binding)
    first, request, _, _, _ = _engine(tmp_path, monkeypatch, journal=first_journal, vault=vault)
    second, _, _, _, _ = _engine(tmp_path, monkeypatch, journal=second_journal, vault=vault)
    conflicting = deepcopy(request)
    for name, seed, verifier_id, digest in (
        ("verifier_a_attestation", bytes(range(64, 96)), "a", "05" * 32),
        ("verifier_b_attestation", bytes(range(96, 128)), "b", "06" * 32),
    ):
        payload = dict(conflicting[name]["payload"]); payload["outcome"] = "NO"
        conflicting[name] = VerifierAttestationSigner(verifier_id, "1.0.0", digest, Keypair.from_seed(seed)).sign(payload, now_ms=20).as_transport()
    barrier = Barrier(2)
    def run(engine, value):
        try:
            barrier.wait()
            return engine.execute(value, now_ms=20)
        except Exception:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda item: run(*item), ((first, request), (second, conflicting))))
    first_journal.close(); second_journal.close()
    reopened = IndependentSignerJournal(path, binding=binding)
    scope = next(iter(reopened._db.execute("SELECT scope_id FROM independent_signer_intents")))[0]
    assert vault.sign_calls <= 1 and reopened.get(scope).state == CONFLICT
    assert len({item.operation_id for item in results if item is not None}) <= 1
    reopened.close()
