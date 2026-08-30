"""Permanent I4A-I1 standalone fixed-role signer application boundaries."""
from __future__ import annotations

import inspect

import pytest
from fastapi.testclient import TestClient
from solders.keypair import Keypair

from src.fixed_role_signer_application import FixedRoleSignerApplicationStartupError
from src.independent_signer_execution import IndependentSignerEngine, IndependentSignerVaultAdapter
from src.independent_signer_journal import IndependentSignerBinding, IndependentSignerJournal
from src.signer_a_main import create_signer_a_application
from src.signer_authorization import SignerAuthorizationConfig
from src.signer_b_main import create_signer_b_application
from tests.test_independent_signer_execution import _Vault, _engine, _service
from tests.test_independent_signer_service import _admission, _grant_header
from tests.test_signer_authorization import fixture


def _mapping(config):
    return {
        "environment": config.environment, "mode": config.mode,
        "topology_classification": config.topology_classification,
        "signer": {"role": config.signer_role, "signer_id": config.signer_id,
                   "public_key": config.signer_public_key, "key_version": config.signer_key_version},
        "vault": {"address": config.vault_address, "transit_mount": config.vault_transit_mount,
                  "key_name": config.vault_key_name, "token_env": config.vault_token_env,
                  "admin_domain_id": config.vault_admin_domain_id,
                  "account_or_tenant_id": config.vault_account_or_tenant_id,
                  "auth_principal_id": config.vault_auth_principal_id,
                  "timeout_seconds": config.vault_timeout_seconds},
        "rpc": {"url_env": config.rpc_url_env, "provider_domain_id": config.rpc_provider_domain_id,
                "account_or_project_id": config.rpc_account_or_project_id,
                "credential_principal_id": config.rpc_credential_principal_id},
        "solana": {"expected_genesis_hash": config.expected_genesis_hash,
                   "expected_program_id": config.expected_program_id},
        "journal_path": config.journal_path, "admission_token_env": config.admission_token_env,
    }


def _components(tmp_path, monkeypatch, role):
    if role == "A":
        engine, request, journal, vault, key = _engine(tmp_path, monkeypatch)
        config = engine._service_config
    else:
        request, auth_a, rpc, *_ = fixture()
        key = Keypair.from_seed(bytes(range(32, 64)))
        config = _service(key, role="B")
        auth = SignerAuthorizationConfig(
            "B", auth_a.counterpart_notary_public_key, auth_a.own_notary_public_key,
            auth_a.verifier_a, auth_a.verifier_b, auth_a.expected_cluster_genesis_hash,
            auth_a.expected_program_id,
        )
        journal = IndependentSignerJournal(
            tmp_path / "settlement-b.sqlite",
            binding=IndependentSignerBinding("B", "signer-b", str(key.pubkey()), 1),
        )
        monkeypatch.setenv("SIGNER_B_VAULT_TOKEN", "b-token")
        vault = _Vault(key)
        engine = IndependentSignerEngine(
            service_config=config, authorization_config=auth, journal=journal, rpc=rpc,
            vault=IndependentSignerVaultAdapter(config, transport=vault),
        )
    admission, replay, issuer_key = _admission(tmp_path, role=role, service_id=config.signer_id)
    return config, engine, request, journal, vault, admission, replay, issuer_key


@pytest.mark.parametrize("role,factory", (("A", create_signer_a_application), ("B", create_signer_b_application)))
def test_fixed_role_app_happy_path_is_one_engine_and_one_role_local_signature(tmp_path, monkeypatch, role, factory):
    config, engine, request, journal, vault, admission, replay, issuer_key = _components(tmp_path, monkeypatch, role)
    calls = []
    app = factory(
        _mapping(config), admission_factory=lambda value: admission,
        engine_factory=lambda value: calls.append(value) or engine, clock=lambda: 20,
    )
    header = _grant_header(request, role=role, service_id=config.signer_id, key=issuer_key, grant_id=("a" if role == "A" else "b") * 32)
    response = TestClient(app).post("/v1/settlement-authorizations", json=request, headers={
        "Content-Type": "application/json", "X-Prophet-Admission-Grant": header,
    })
    assert response.status_code == 200
    assert response.json()["signer_role"] == role
    assert response.json()["public_key"] == config.signer_public_key
    assert len(calls) == 1 and vault.sign_calls == 1
    journal.close(); replay.close()


@pytest.mark.parametrize("role,factory", (("A", create_signer_a_application), ("B", create_signer_b_application)))
def test_fixed_role_app_rejects_config_role_override_before_factories(tmp_path, monkeypatch, role, factory):
    config, engine, request, journal, vault, admission, replay, issuer_key = _components(tmp_path, monkeypatch, role)
    value = _mapping(config); value["signer"]["role"] = "B" if role == "A" else "A"
    with pytest.raises(Exception):
        factory(value, admission_factory=lambda _: pytest.fail("admission factory called"), engine_factory=lambda _: pytest.fail("engine factory called"))
    journal.close(); replay.close()


@pytest.mark.parametrize("role,factory", (("A", create_signer_a_application), ("B", create_signer_b_application)))
def test_fixed_role_app_rejects_peer_environment_before_factories(tmp_path, monkeypatch, role, factory):
    config, engine, request, journal, vault, admission, replay, issuer_key = _components(tmp_path, monkeypatch, role)
    peer = "B" if role == "A" else "A"
    monkeypatch.setenv(f"SIGNER_{peer}_VAULT_TOKEN", "peer-secret")
    with pytest.raises(FixedRoleSignerApplicationStartupError, match="peer_environment"):
        factory(_mapping(config), admission_factory=lambda _: pytest.fail("admission factory called"), engine_factory=lambda _: pytest.fail("engine factory called"))
    journal.close(); replay.close()


@pytest.mark.parametrize("role,factory", (("A", create_signer_a_application), ("B", create_signer_b_application)))
def test_fixed_role_app_rejects_peer_rpc_reference_before_factories(tmp_path, monkeypatch, role, factory):
    config, engine, request, journal, vault, admission, replay, issuer_key = _components(tmp_path, monkeypatch, role)
    peer = "B" if role == "A" else "A"
    value = _mapping(config); value["rpc"]["url_env"] = f"SIGNER_{peer}_RPC_URL"
    with pytest.raises(FixedRoleSignerApplicationStartupError, match="config_invalid"):
        factory(value, admission_factory=lambda _: pytest.fail("admission factory called"), engine_factory=lambda _: pytest.fail("engine factory called"))
    journal.close(); replay.close()


@pytest.mark.parametrize("role,factory", (("A", create_signer_a_application), ("B", create_signer_b_application)))
def test_fixed_role_app_rejects_cross_role_grant_and_retired_bearer(tmp_path, monkeypatch, role, factory):
    config, engine, request, journal, vault, admission, replay, issuer_key = _components(tmp_path, monkeypatch, role)
    app = factory(_mapping(config), admission_factory=lambda _: admission, engine_factory=lambda _: engine, clock=lambda: 20)
    peer = "B" if role == "A" else "A"
    peer_grant = _grant_header(request, role=peer, service_id=f"signer-{peer.lower()}", key=Keypair.from_seed(bytes(range(96, 128))), grant_id="c" * 32)
    client = TestClient(app)
    assert client.post("/v1/settlement-authorizations", json=request, headers={"Content-Type": "application/json", "X-Prophet-Admission-Grant": peer_grant}).status_code == 403
    assert client.post("/v1/settlement-authorizations", json=request, headers={"Content-Type": "application/json", "Authorization": "Bearer retired"}).status_code == 403
    assert vault.sign_calls == 0
    journal.close(); replay.close()


def test_fixed_role_entrypoints_have_no_generic_remote_signer_or_role_parameter():
    import src.signer_a_main as signer_a_main
    import src.signer_b_main as signer_b_main
    for module, factory in ((signer_a_main, create_signer_a_application), (signer_b_main, create_signer_b_application)):
        source = inspect.getsource(module)
        assert "remote_signer_main" not in source and "--role" not in source
        assert "role" not in inspect.signature(factory).parameters
