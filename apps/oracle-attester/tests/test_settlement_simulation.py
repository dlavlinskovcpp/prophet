import hashlib
import importlib.metadata
import inspect
import json
from dataclasses import FrozenInstanceError

import pytest
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction

from src.runtime_config import (
    SettlementExecutionRuntimeConfig,
    SettlementFeePayerConfig,
    SettlementRpcConfig,
    parse_settlement_execution_config,
)
from src.settlement_fee_payer import (
    FilesystemFeePayerSigner,
    SettlementFeePayerConfigError,
)
from src.settlement_rpc import (
    RpcSimulationResult,
    SettlementRpcResponseError,
    SettlementRpcTransportError,
    SolanaSettlementRpcClient,
)
from src.settlement_simulation import (
    PROGRAM_REJECTED,
    READY_CANDIDATE,
    STALE_BLOCKHASH,
    SettlementExecutionBindingError,
    SettlementExecutionConfigError,
    SettlementExecutionRpcError,
    SettlementSimulationRequest,
    SettlementSimulationService,
    SignedSettlementTransactionArtifact,
)
from tests.test_settlement_transaction_construction import (
    BLOCKHASH_1,
    BLOCKHASH_2,
    GENESIS_HASH,
    _db_rows,
    _setup as construction_setup,
)


class FakeSettlementRpc:
    is_test_transport = True

    def __init__(
        self,
        *,
        genesis_hash=GENESIS_HASH,
        blockhash=BLOCKHASH_1,
        simulation=None,
        fail_at=None,
    ):
        self.genesis_hash = genesis_hash
        self.blockhash = blockhash
        self.simulation = simulation or RpcSimulationResult(None, ("ok",), 1234, None, None)
        self.fail_at = fail_at
        self.calls = []
        self.simulated_bytes = None
        self.send_calls = 0

    def get_genesis_hash(self):
        self.calls.append("genesis")
        if self.fail_at == "genesis":
            raise SettlementRpcTransportError("boom")
        return self.genesis_hash

    def get_latest_blockhash(self):
        self.calls.append("blockhash")
        if self.fail_at == "blockhash":
            raise SettlementRpcTransportError("boom")
        return self.blockhash

    def simulate_transaction(self, transaction):
        self.calls.append("simulate")
        if self.fail_at == "simulate":
            raise SettlementRpcTransportError("boom")
        self.simulated_bytes = bytes(transaction)
        return self.simulation

    # Architectural tripwires: Phase 6D2 must never touch these.
    def send_transaction(self, *_args, **_kwargs):
        self.send_calls += 1
        raise AssertionError("sendTransaction must not be called")

    def send_raw_transaction(self, *_args, **_kwargs):
        self.send_calls += 1
        raise AssertionError("sendRawTransaction must not be called")

    def confirm_transaction(self, *_args, **_kwargs):
        self.send_calls += 1
        raise AssertionError("confirmTransaction must not be called")


class CountingFeePayerSigner(FilesystemFeePayerSigner):
    def __init__(self, keypair):
        super().__init__(keypair)
        self.sign_calls = 0

    def sign_transaction_message(self, message):
        self.sign_calls += 1
        return super().sign_transaction_message(message)


def _execution_config(runtime):
    return SettlementExecutionRuntimeConfig(
        rpc_url_env="PROPHET_TEST_RPC_URL",
        expected_cluster=runtime.cluster,
        expected_genesis_hash=runtime.genesis_hash,
        fee_payer=SettlementFeePayerConfig("PROPHET_TEST_FEE_PAYER_KEYPAIR_PATH"),
        rpc=SettlementRpcConfig(10, "confirmed"),
    )


def _service(tmp_path, monkeypatch, *, seed=41, rpc=None):
    x = construction_setup(tmp_path, monkeypatch)
    signer = CountingFeePayerSigner(Keypair.from_seed(bytes([seed]) * 32))
    rpc = rpc or FakeSettlementRpc()
    service = SettlementSimulationService(
        builder=x["builder"],
        solana_runtime=x["runtime"],
        execution_config=_execution_config(x["runtime"]),
        fee_payer_signer=signer,
        rpc=rpc,
        environment="localtest",
        mode="test",
    )
    request = SettlementSimulationRequest(
        coordinator_job_id=x["job"].job_id,
        signing_intent_id=x["request"].signing_intent_id,
    )
    return x, signer, rpc, service, request


def _state_snapshot(x):
    return (
        x["store"].get_job(x["job"].job_id),
        x["store"].get_settlement_context(x["job"].job_id),
        x["store"].get_settlement_runtime(x["job"].job_id),
        _db_rows(x["journal"]._db, "signing_intents"),
        _db_rows(x["journal"]._db, "coordinator_signing_links"),
    )


def test_01_completed_agreed_bundle_is_signed_and_simulated(tmp_path, monkeypatch):
    x, signer, rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    assert result.status == READY_CANDIDATE
    assert result.ready_for_submission is True
    assert isinstance(result.transaction, SignedSettlementTransactionArtifact)
    assert isinstance(result.transaction.transaction, VersionedTransaction)
    assert rpc.calls == ["genesis", "blockhash", "simulate"]
    assert signer.sign_calls == 1
    assert rpc.send_calls == 0


def test_02_rpc_genesis_mismatch_rejects_before_blockhash_or_signing(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(genesis_hash=BLOCKHASH_2)
    _x, signer, rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementExecutionBindingError, match="genesis_hash_mismatch"):
        service.simulate(request)
    assert rpc.calls == ["genesis"]
    assert signer.sign_calls == 0
    assert rpc.send_calls == 0


def test_03_blockhash_comes_only_from_rpc(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(blockhash=BLOCKHASH_2)
    _x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    result = service.simulate(request)
    assert result.transaction.recent_blockhash == BLOCKHASH_2
    assert not hasattr(request, "recent_blockhash")


def test_04_request_cannot_override_outcome_resolver_or_blockhash(tmp_path, monkeypatch):
    x, *_ = _service(tmp_path, monkeypatch)
    base = {
        "coordinator_job_id": x["job"].job_id,
        "signing_intent_id": x["request"].signing_intent_id,
    }
    for extra in (
        {"outcome": "YES"},
        {"resolver_id": "evil"},
        {"recent_blockhash": BLOCKHASH_2},
        {"signature_a": b"x" * 64},
    ):
        with pytest.raises(TypeError):
            SettlementSimulationRequest(**base, **extra)


def test_05_phase_6d1_builder_is_reused_with_rpc_blockhash(tmp_path, monkeypatch):
    x, signer, rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    expected = x["builder"].build(
        x["request"].__class__(
            coordinator_job_id=request.coordinator_job_id,
            signing_intent_id=request.signing_intent_id,
            fee_payer_pubkey=str(signer.public_key),
            recent_blockhash=rpc.blockhash,
        )
    )
    assert result.transaction.unsigned == expected


def test_06_resolution_bytes_and_signatures_remain_unchanged_after_fee_payer_signing(tmp_path, monkeypatch):
    x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    original = x["signing_result"].signature_bundle
    assert result.transaction.canonical_message == x["journal"].get(request.signing_intent_id).canonical_message
    assert result.transaction.signer_a_signature == original.signer_a_signature
    assert result.transaction.signer_b_signature == original.signer_b_signature


def test_07_fee_payer_is_only_transaction_level_required_signer(tmp_path, monkeypatch):
    _x, signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    message = result.transaction.transaction.message
    assert isinstance(message, MessageV0)
    assert message.header.num_required_signatures == 1
    assert tuple(message.account_keys)[0] == signer.public_key
    assert len(tuple(result.transaction.transaction.signatures)) == 1


def test_08_vault_resolution_private_keys_are_not_transaction_signers(tmp_path, monkeypatch):
    _x, signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    required = tuple(result.transaction.transaction.message.account_keys)[
        : result.transaction.transaction.message.header.num_required_signatures
    ]
    assert required == (signer.public_key,)
    assert Pubkey.from_string(result.transaction.signer_a_public_key) not in required
    assert Pubkey.from_string(result.transaction.signer_b_public_key) not in required


def test_09_fee_payer_cannot_share_resolution_signer_identity(tmp_path, monkeypatch):
    x = construction_setup(tmp_path, monkeypatch)
    a_seed = None
    # The deterministic signing fixture exposes only public identities, so use a
    # tiny boundary fake to prove identity overlap is rejected before tx signing.
    class OverlapSigner:
        def __init__(self, public):
            self.public_key = Pubkey.from_string(public)
            self.calls = 0
        def sign_transaction_message(self, _message):
            self.calls += 1
            raise AssertionError("must reject before signing")
    signer = OverlapSigner(x["signing_result"].signer_a_public_key)
    rpc = FakeSettlementRpc()
    service = SettlementSimulationService(
        builder=x["builder"],
        solana_runtime=x["runtime"],
        execution_config=_execution_config(x["runtime"]),
        fee_payer_signer=signer,
        rpc=rpc,
        environment="localtest",
        mode="test",
    )
    request = SettlementSimulationRequest(x["job"].job_id, x["request"].signing_intent_id)
    with pytest.raises(SettlementExecutionBindingError, match="identity_overlap"):
        service.simulate(request)
    assert signer.calls == 0
    assert rpc.calls == ["genesis", "blockhash"]


def test_10_fee_payer_transaction_signature_verifies_locally(tmp_path, monkeypatch):
    _x, signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    tx = result.transaction.transaction
    assert tuple(tx.verify_with_results()) == (True,)
    tx.verify_and_hash_message()
    signature = tuple(tx.signatures)[0]
    assert signature.verify(signer.public_key, to_bytes_versioned(tx.message))


def test_11_exact_signed_transaction_candidate_is_simulated(tmp_path, monkeypatch):
    _x, _signer, rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    assert rpc.simulated_bytes == result.transaction.serialized_transaction
    assert rpc.simulated_bytes == bytes(result.transaction.transaction)


def test_12_program_error_is_typed_not_ready_and_never_sent(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(
        simulation=RpcSimulationResult(
            "InstructionError(2, Custom(6001))", ("Program log: rejected",), 4321, None, None
        )
    )
    x, _signer, rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    before = _state_snapshot(x)
    result = service.simulate(request)
    assert result.status == PROGRAM_REJECTED
    assert result.ready_for_submission is False
    assert result.program_error == "InstructionError(2, Custom(6001))"
    assert result.logs == ("Program log: rejected",)
    assert result.units_consumed == 4321
    assert rpc.send_calls == 0
    assert _state_snapshot(x) == before


def test_13_stale_blockhash_is_typed_and_not_retried(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(
        simulation=RpcSimulationResult("BlockhashNotFound", (), None, None, None)
    )
    _x, signer, rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    result = service.simulate(request)
    assert result.status == STALE_BLOCKHASH
    assert result.ready_for_submission is False
    assert rpc.calls == ["genesis", "blockhash", "simulate"]
    assert signer.sign_calls == 1
    assert rpc.send_calls == 0


def test_14_rpc_transport_failure_fails_closed_without_fallback(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(fail_at="simulate")
    _x, signer, rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementExecutionRpcError, match="rpc_simulation_failed"):
        service.simulate(request)
    assert rpc.calls == ["genesis", "blockhash", "simulate"]
    assert signer.sign_calls == 1
    assert rpc.send_calls == 0


def test_15_genesis_transport_failure_stops_immediately(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(fail_at="genesis")
    _x, signer, rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementExecutionRpcError, match="genesis_validation_failed"):
        service.simulate(request)
    assert rpc.calls == ["genesis"]
    assert signer.sign_calls == 0


def test_16_blockhash_transport_failure_stops_before_construction_signing_simulation(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(fail_at="blockhash")
    _x, signer, rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    with pytest.raises(SettlementExecutionRpcError, match="blockhash_acquisition_failed"):
        service.simulate(request)
    assert rpc.calls == ["genesis", "blockhash"]
    assert signer.sign_calls == 0


def test_17_changing_fee_payer_changes_tx_but_not_resolution_authorization(tmp_path, monkeypatch):
    x1, _s1, _r1, service1, request1 = _service(tmp_path / "one", monkeypatch, seed=41)
    first = service1.simulate(request1)
    x2, _s2, _r2, service2, request2 = _service(tmp_path / "two", monkeypatch, seed=42)
    second = service2.simulate(request2)
    assert first.transaction.fee_payer_pubkey != second.transaction.fee_payer_pubkey
    assert first.transaction.serialized_transaction != second.transaction.serialized_transaction
    assert first.transaction.canonical_message == second.transaction.canonical_message
    assert first.transaction.signer_a_signature == second.transaction.signer_a_signature
    assert first.transaction.signer_b_signature == second.transaction.signer_b_signature
    assert x1["signing_result"].signature_bundle.canonical_message_digest == x2["signing_result"].signature_bundle.canonical_message_digest


def test_18_changing_blockhash_changes_tx_but_not_resolution_authorization(tmp_path, monkeypatch):
    x, signer, _rpc, _service1, request = _service(tmp_path, monkeypatch)
    service1 = SettlementSimulationService(
        builder=x["builder"], solana_runtime=x["runtime"], execution_config=_execution_config(x["runtime"]),
        fee_payer_signer=signer, rpc=FakeSettlementRpc(blockhash=BLOCKHASH_1), environment="localtest", mode="test"
    )
    service2 = SettlementSimulationService(
        builder=x["builder"], solana_runtime=x["runtime"], execution_config=_execution_config(x["runtime"]),
        fee_payer_signer=signer, rpc=FakeSettlementRpc(blockhash=BLOCKHASH_2), environment="localtest", mode="test"
    )
    first = service1.simulate(request)
    second = service2.simulate(request)
    assert first.transaction.serialized_transaction != second.transaction.serialized_transaction
    assert first.transaction.canonical_message == second.transaction.canonical_message
    assert first.transaction.signer_a_signature == second.transaction.signer_a_signature
    assert first.transaction.signer_b_signature == second.transaction.signer_b_signature


def test_19_same_execution_inputs_produce_byte_identical_signed_transaction(tmp_path, monkeypatch):
    _x, signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    first = service.simulate(request)
    second = service.simulate(request)
    assert first.transaction.serialized_transaction == second.transaction.serialized_transaction
    assert first.transaction.transaction_digest == second.transaction.transaction_digest
    assert first.transaction.transaction_signatures == second.transaction.transaction_signatures
    assert signer.sign_calls == 2


def test_20_no_durable_coordinator_or_signing_mutation(tmp_path, monkeypatch):
    x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    before = _state_snapshot(x)
    service.simulate(request)
    service.simulate(request)
    assert _state_snapshot(x) == before


def test_21_zero_new_vault_calls_during_execution(tmp_path, monkeypatch):
    x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    before = len(x["transport"].calls)
    service.simulate(request)
    assert len(x["transport"].calls) == before == 2


def test_22_service_has_no_verifier_dependency(tmp_path, monkeypatch):
    _x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    params = inspect.signature(SettlementSimulationService.__init__).parameters
    assert not any("verifier" in name.lower() for name in params)
    service.simulate(request)


def test_23_no_submission_api_is_exposed_by_production_rpc_abstraction():
    public = {
        name
        for name, member in inspect.getmembers(SolanaSettlementRpcClient, callable)
        if not name.startswith("_")
    }
    assert "get_genesis_hash" in public
    assert "get_latest_blockhash" in public
    assert "simulate_transaction" in public
    assert "send_transaction" not in public
    assert "send_raw_transaction" not in public
    assert "confirm_transaction" not in public


def test_24_simulation_result_and_signed_artifact_are_immutable(tmp_path, monkeypatch):
    _x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    with pytest.raises(FrozenInstanceError):
        result.status = PROGRAM_REJECTED
    with pytest.raises(FrozenInstanceError):
        result.transaction.recent_blockhash = BLOCKHASH_2


def test_25_safe_artifact_contains_no_fee_payer_private_material(tmp_path, monkeypatch):
    _x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    artifact = service.simulate(request).transaction
    names = set(artifact.__dataclass_fields__)
    assert not any(
        token in name
        for name in names
        for token in ("private", "secret", "seed", "keypair", "authorization")
    )


def test_26_filesystem_fee_payer_loads_only_exact_64_byte_json_array(tmp_path):
    keypair = Keypair.from_seed(bytes([55]) * 32)
    path = tmp_path / "fee-payer.json"
    path.write_text(json.dumps(list(bytes(keypair))), encoding="utf-8")
    signer = FilesystemFeePayerSigner.from_path(path)
    assert signer.public_key == keypair.pubkey()
    assert signer.is_test_signer is False


@pytest.mark.parametrize(
    "payload",
    [
        [1] * 32,
        [1] * 65,
        "base58-secret",
        {"secret": [1] * 64},
        [True] + [1] * 63,
        [256] + [1] * 63,
    ],
)
def test_27_fee_payer_rejects_ambiguous_or_invalid_file_formats(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SettlementFeePayerConfigError, match="file_invalid"):
        FilesystemFeePayerSigner.from_path(path)


def test_28_fee_payer_environment_reference_must_resolve(tmp_path):
    with pytest.raises(SettlementFeePayerConfigError, match="path_unresolved"):
        FilesystemFeePayerSigner.from_environment("MISSING_FEE_PAYER", environ={})


def test_29_production_rejects_test_fee_payer_and_fake_rpc(tmp_path, monkeypatch):
    x = construction_setup(tmp_path, monkeypatch)
    signer = CountingFeePayerSigner(Keypair.from_seed(bytes([44]) * 32))
    with pytest.raises(SettlementExecutionConfigError):
        SettlementSimulationService(
            builder=x["builder"],
            solana_runtime=x["runtime"],
            execution_config=_execution_config(x["runtime"]),
            fee_payer_signer=signer,
            rpc=FakeSettlementRpc(),
            environment="public-devnet",
            mode="production",
        )


def test_30_mainnet_execution_is_not_introduced(tmp_path, monkeypatch):
    x = construction_setup(tmp_path, monkeypatch)
    with pytest.raises(SettlementExecutionConfigError, match="mainnet"):
        SettlementSimulationService(
            builder=x["builder"],
            solana_runtime=x["runtime"],
            execution_config=_execution_config(x["runtime"]),
            fee_payer_signer=CountingFeePayerSigner(Keypair.from_seed(bytes([45]) * 32)),
            rpc=FakeSettlementRpc(),
            environment="mainnet",
            mode="test",
        )


def test_31_settlement_execution_runtime_config_is_sol_identity_bound():
    from src.runtime_config import SolanaRuntimeConfig
    runtime = SolanaRuntimeConfig("devnet", GENESIS_HASH, str(Pubkey.default()))
    raw = {
        "rpc_url_env": "PROPHET_DEVNET_RPC_URL",
        "expected_cluster": "devnet",
        "expected_genesis_hash": GENESIS_HASH,
        "fee_payer": {"keypair_path_env": "PROPHET_DEVNET_FEE_PAYER_KEYPAIR_PATH"},
        "rpc": {"timeout_seconds": 10, "commitment": "confirmed"},
    }
    parsed = parse_settlement_execution_config(raw, solana=runtime)
    assert parsed.expected_cluster == runtime.cluster
    assert parsed.expected_genesis_hash == runtime.genesis_hash
    assert parsed.rpc_url_env == "PROPHET_DEVNET_RPC_URL"
    bad = {**raw, "expected_cluster": "mainnet-beta"}
    with pytest.raises(Exception, match="identity mismatch"):
        parse_settlement_execution_config(bad, solana=runtime)


def test_32_runtime_config_rejects_inline_rpc_or_inline_private_key_fields():
    from src.runtime_config import SolanaRuntimeConfig
    runtime = SolanaRuntimeConfig("devnet", GENESIS_HASH, str(Pubkey.default()))
    base = {
        "rpc_url_env": "PROPHET_DEVNET_RPC_URL",
        "expected_cluster": "devnet",
        "expected_genesis_hash": GENESIS_HASH,
        "fee_payer": {"keypair_path_env": "PROPHET_DEVNET_FEE_PAYER_KEYPAIR_PATH"},
        "rpc": {"timeout_seconds": 10, "commitment": "confirmed"},
    }
    with pytest.raises(Exception, match="unknown or missing"):
        parse_settlement_execution_config({**base, "rpc_url": "https://secret.example"}, solana=runtime)
    with pytest.raises(Exception, match="unknown or missing"):
        parse_settlement_execution_config(
            {**base, "fee_payer": {**base["fee_payer"], "private_key": [1] * 64}},
            solana=runtime,
        )
    for forbidden in (
        {"seed_phrase": "not-allowed"},
        {"test_signer": True},
        {"fixture_keypair": "fixture.json"},
    ):
        with pytest.raises(Exception, match="unknown or missing"):
            parse_settlement_execution_config(
                {**base, "fee_payer": {**base["fee_payer"], **forbidden}},
                solana=runtime,
            )


def test_33_runtime_config_rejects_invalid_commitment_or_env_names():
    from src.runtime_config import SolanaRuntimeConfig
    runtime = SolanaRuntimeConfig("devnet", GENESIS_HASH, str(Pubkey.default()))
    base = {
        "rpc_url_env": "PROPHET_DEVNET_RPC_URL",
        "expected_cluster": "devnet",
        "expected_genesis_hash": GENESIS_HASH,
        "fee_payer": {"keypair_path_env": "PROPHET_DEVNET_FEE_PAYER_KEYPAIR_PATH"},
        "rpc": {"timeout_seconds": 10, "commitment": "confirmed"},
    }
    with pytest.raises(Exception, match="commitment"):
        parse_settlement_execution_config(
            {**base, "rpc": {"timeout_seconds": 10, "commitment": "optimistic"}},
            solana=runtime,
        )
    with pytest.raises(Exception, match="environment-variable name"):
        parse_settlement_execution_config({**base, "rpc_url_env": "not-valid"}, solana=runtime)


def test_34_real_solders_020_signing_and_serialization(tmp_path, monkeypatch):
    assert importlib.metadata.version("solders") == "0.20.0"
    _x, signer, rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    tx = result.transaction.transaction
    assert isinstance(signer.public_key, Pubkey)
    assert isinstance(Hash.from_string(result.transaction.recent_blockhash), Hash)
    assert isinstance(tx, VersionedTransaction)
    assert isinstance(tuple(tx.signatures)[0], Signature)
    assert VersionedTransaction.from_bytes(result.transaction.serialized_transaction) == tx
    assert tuple(tx.verify_with_results()) == (True,)
    assert rpc.simulated_bytes == bytes(tx)


def test_35_transaction_digest_is_exact_serialized_candidate_digest(tmp_path, monkeypatch):
    _x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    artifact = service.simulate(request).transaction
    assert artifact.transaction_digest == hashlib.sha256(artifact.serialized_transaction).hexdigest()


def test_36_rpc_simulation_ed25519_failure_is_not_repaired_or_resigned(tmp_path, monkeypatch):
    rpc = FakeSettlementRpc(
        simulation=RpcSimulationResult(
            "InstructionError(0, InvalidInstructionData)",
            ("Program Ed25519SigVerify failed",),
            900,
            None,
            None,
        )
    )
    _x, signer, rpc, service, request = _service(tmp_path, monkeypatch, rpc=rpc)
    result = service.simulate(request)
    assert result.status == PROGRAM_REJECTED
    assert result.ready_for_submission is False
    assert signer.sign_calls == 1
    assert rpc.calls == ["genesis", "blockhash", "simulate"]


def test_37_rpc_wrapper_strictly_validates_response_shapes(monkeypatch):
    class RawClient:
        def __init__(self, *_args, **_kwargs): pass
        def get_genesis_hash(self): return type("R", (), {"value": GENESIS_HASH})()
        def get_latest_blockhash(self, **_kwargs):
            return type("R", (), {"value": type("V", (), {"blockhash": BLOCKHASH_1})()})()
        def simulate_transaction(self, *_args, **_kwargs):
            return type("R", (), {"value": object()})()
    monkeypatch.setattr("src.settlement_rpc.Client", RawClient)
    rpc = SolanaSettlementRpcClient("https://rpc.example.invalid", timeout_seconds=10, commitment="confirmed")
    assert rpc.get_genesis_hash() == GENESIS_HASH
    assert rpc.get_latest_blockhash() == BLOCKHASH_1
    payer = Keypair.from_seed(bytes([73]) * 32)
    message = MessageV0.try_compile(payer.pubkey(), [], [], Hash.from_string(BLOCKHASH_1))
    tx = VersionedTransaction(message, [payer])
    with pytest.raises(SettlementRpcResponseError, match="response_invalid"):
        rpc.simulate_transaction(tx)


def test_38_rpc_url_credentials_are_not_exposed_by_endpoint_label(monkeypatch):
    class RawClient:
        def __init__(self, *_args, **_kwargs): pass
    monkeypatch.setattr("src.settlement_rpc.Client", RawClient)
    rpc = SolanaSettlementRpcClient(
        "https://rpc.example.invalid/provider-secret-token?api-key=another-secret",
        timeout_seconds=10,
        commitment="confirmed",
    )
    assert rpc.endpoint_label == "rpc.example.invalid"
    assert "secret" not in rpc.endpoint_label


def test_39_signed_candidate_serialization_roundtrip_is_exact(tmp_path, monkeypatch):
    _x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    artifact = service.simulate(request).transaction
    assert bytes(VersionedTransaction.from_bytes(artifact.serialized_transaction)) == artifact.serialized_transaction


def test_40_simulation_success_is_not_called_confirmed_or_settled(tmp_path, monkeypatch):
    _x, _signer, _rpc, service, request = _service(tmp_path, monkeypatch)
    result = service.simulate(request)
    assert result.status == READY_CANDIDATE
    assert "confirmed" not in result.status.lower()
    assert "settled" not in result.status.lower()


def test_41_no_retry_rebroadcast_or_confirmation_surface_on_service():
    public = {
        name
        for name, member in inspect.getmembers(SettlementSimulationService, callable)
        if not name.startswith("_")
    }
    assert public == {"from_runtime_config", "simulate"}


def test_42_production_filesystem_signer_requires_real_filesystem_load(tmp_path, monkeypatch):
    x = construction_setup(tmp_path, monkeypatch)
    direct_test_signer = FilesystemFeePayerSigner(Keypair.from_seed(bytes([61]) * 32))
    assert direct_test_signer.is_test_signer is True
    class ProductionLikeRpc(FakeSettlementRpc):
        is_test_transport = False
    with pytest.raises(SettlementExecutionConfigError, match="production_fee_payer"):
        SettlementSimulationService(
            builder=x["builder"],
            solana_runtime=x["runtime"],
            execution_config=_execution_config(x["runtime"]),
            fee_payer_signer=direct_test_signer,
            rpc=ProductionLikeRpc(),
            environment="public-devnet",
            mode="production",
        )


def _minimal_runtime_raw(*, with_execution=False):
    raw = {
        "schema_version": 1,
        "environment": "localtest",
        "mode": "test",
        "solana": {
            "cluster": "localnet",
            "genesis_hash": GENESIS_HASH,
            "prophet_program_id": str(Pubkey.default()),
        },
        "resolver_v2": {"schema_version": 2},
        "verifier": {"implementation_id": "runtime-test", "version": "1.0.0"},
        "allowed_adapters": ["pyth"],
        "limits": {"request_max_bytes": 1024, "request_timeout_seconds": 10},
        "freshness": {
            "default_max_evidence_age_seconds": 60,
            "default_max_verification_age_seconds": 60,
        },
        "internal_auth": {"token_env": "PROPHET_INTERNAL_TOKEN"},
    }
    if with_execution:
        raw["settlement_execution"] = {
            "rpc_url_env": "PROPHET_TEST_RPC_URL",
            "expected_cluster": "localnet",
            "expected_genesis_hash": GENESIS_HASH,
            "fee_payer": {
                "keypair_path_env": "PROPHET_TEST_FEE_PAYER_KEYPAIR_PATH"
            },
            "rpc": {"timeout_seconds": 10, "commitment": "confirmed"},
        }
    return raw


def test_43_full_runtime_parser_integrates_optional_settlement_execution_without_changing_absent_shape():
    from src.runtime_config import parse_runtime_config
    base = parse_runtime_config(_minimal_runtime_raw())
    extended = parse_runtime_config(_minimal_runtime_raw(with_execution=True))
    assert base.settlement_execution is None
    assert extended.settlement_execution is not None
    assert extended.settlement_execution.expected_cluster == base.solana.cluster
    assert extended.settlement_execution.expected_genesis_hash == base.solana.genesis_hash
    assert extended.fingerprint() != base.fingerprint()


def test_44_from_runtime_config_rejects_unresolved_rpc_or_fee_payer_path(tmp_path, monkeypatch):
    from src.runtime_config import parse_runtime_config
    x = construction_setup(tmp_path, monkeypatch)
    runtime = parse_runtime_config(_minimal_runtime_raw(with_execution=True))
    with pytest.raises(SettlementExecutionConfigError, match="rpc_url_unresolved"):
        SettlementSimulationService.from_runtime_config(
            builder=x["builder"], runtime_config=runtime, environ={}
        )
    with pytest.raises(SettlementExecutionConfigError, match="dependency_invalid"):
        SettlementSimulationService.from_runtime_config(
            builder=x["builder"],
            runtime_config=runtime,
            environ={"PROPHET_TEST_RPC_URL": "https://rpc.example.invalid"},
        )


def test_45_rpc_wrapper_rejects_malformed_genesis_and_blockhash(monkeypatch):
    class BadGenesisClient:
        def __init__(self, *_args, **_kwargs): pass
        def get_genesis_hash(self): return type("R", (), {"value": "not-a-hash"})()
    monkeypatch.setattr("src.settlement_rpc.Client", BadGenesisClient)
    rpc = SolanaSettlementRpcClient("https://rpc.example.invalid", timeout_seconds=10, commitment="confirmed")
    with pytest.raises(SettlementRpcResponseError, match="genesis_hash_response_invalid"):
        rpc.get_genesis_hash()

    class BadBlockhashClient:
        def __init__(self, *_args, **_kwargs): pass
        def get_latest_blockhash(self, **_kwargs): return type("R", (), {"value": object()})()
    monkeypatch.setattr("src.settlement_rpc.Client", BadBlockhashClient)
    rpc = SolanaSettlementRpcClient("https://rpc.example.invalid", timeout_seconds=10, commitment="confirmed")
    with pytest.raises(SettlementRpcResponseError, match="latest_blockhash_response_invalid"):
        rpc.get_latest_blockhash()


def test_46_exact_execution_call_order_includes_build_and_sign(tmp_path, monkeypatch):
    x = construction_setup(tmp_path, monkeypatch)
    trace = []
    signer = CountingFeePayerSigner(Keypair.from_seed(bytes([81]) * 32))
    original_sign = signer.sign_transaction_message
    def traced_sign(message):
        trace.append("sign")
        return original_sign(message)
    signer.sign_transaction_message = traced_sign

    class TracedRpc(FakeSettlementRpc):
        def get_genesis_hash(self):
            trace.append("genesis")
            return super().get_genesis_hash()
        def get_latest_blockhash(self):
            trace.append("blockhash")
            return super().get_latest_blockhash()
        def simulate_transaction(self, transaction):
            trace.append("simulate")
            return super().simulate_transaction(transaction)
    rpc = TracedRpc()
    original_build = x["builder"].build
    def traced_build(request):
        trace.append("build")
        return original_build(request)
    monkeypatch.setattr(x["builder"], "build", traced_build)
    service = SettlementSimulationService(
        builder=x["builder"],
        solana_runtime=x["runtime"],
        execution_config=_execution_config(x["runtime"]),
        fee_payer_signer=signer,
        rpc=rpc,
        environment="localtest",
        mode="test",
    )
    service.simulate(SettlementSimulationRequest(x["job"].job_id, x["request"].signing_intent_id))
    assert trace == ["genesis", "blockhash", "build", "sign", "simulate"]


def test_47_production_rejects_filesystem_fixture_keypair(tmp_path, monkeypatch):
    x = construction_setup(tmp_path, monkeypatch)
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    fixture_path = fixture_dir / "fee-payer.json"
    keypair = Keypair.from_seed(bytes([91]) * 32)
    fixture_path.write_text(json.dumps(list(bytes(keypair))), encoding="utf-8")
    signer = FilesystemFeePayerSigner.from_path(fixture_path)
    assert signer.is_test_signer is True

    class ProductionLikeRpc(FakeSettlementRpc):
        is_test_transport = False

    with pytest.raises(SettlementExecutionConfigError, match="production_fee_payer"):
        SettlementSimulationService(
            builder=x["builder"],
            solana_runtime=x["runtime"],
            execution_config=_execution_config(x["runtime"]),
            fee_payer_signer=signer,
            rpc=ProductionLikeRpc(),
            environment="public-devnet",
            mode="production",
        )
