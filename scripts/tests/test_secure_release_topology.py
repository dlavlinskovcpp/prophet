import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


release = _module("p01p02_release", ROOT / "scripts/release.py")
preflight = _module(
    "p01p02_preflight", ROOT / "scripts/public_devnet_runtime_preflight.py"
)


def _config():
    return {
        "service_endpoints": {
            "verifier_a_base_url": "https://a.example",
            "verifier_b_base_url": "https://b.example",
            "coordinator_base_url": "https://coordinator.example",
            "secure_settlement_base_url": "https://settlement.example",
            "resolver_registry_url": "https://registry.example",
            "matching_keeper_base_url": "https://keeper.example",
        },
        "secure_settlement": {
            "resolution_mode": "secure-coordinator",
            "direct_attester_settlement_enabled": False,
            "generic_remote_signer_settlement_enabled": False,
            "coordinator_sqlite_path": "/var/lib/prophet/coordinator.sqlite",
            "signing_journal_path": "/var/lib/prophet/signing.sqlite",
            "submission_journal_path": "/var/lib/prophet/submission.sqlite",
            "required_signer_count": 2,
            "verifier_a": {
                "identity": "a",
                "backend_ref": "backend-a",
                "auth_ref": "auth-a",
            },
            "verifier_b": {
                "identity": "b",
                "backend_ref": "backend-b",
                "auth_ref": "auth-b",
            },
            "signer_a": {
                "identity": "signer-a",
                "vault_key_ref": "key-a",
                "auth_ref": "vault-auth-a",
            },
            "signer_b": {
                "identity": "signer-b",
                "vault_key_ref": "key-b",
                "auth_ref": "vault-auth-b",
            },
        },
    }


def test_release_secure_topology_is_accepted_structurally():
    cfg = _config()
    release._service_endpoints(cfg, env_name="devnet")
    release._secure_settlement_metadata(cfg, env_name="devnet")


@pytest.mark.parametrize(
    "mutate,match",
    [
        (lambda c: c["service_endpoints"].pop("coordinator_base_url"), "Missing required"),
        (lambda c: c["service_endpoints"].pop("verifier_b_base_url"), "Missing required"),
        (
            lambda c: c["service_endpoints"].__setitem__(
                "verifier_b_base_url", c["service_endpoints"]["verifier_a_base_url"]
            ),
            "must be distinct",
        ),
        (
            lambda c: c["secure_settlement"].__setitem__(
                "generic_remote_signer_settlement_enabled", True
            ),
            "Generic remote",
        ),
        (
            lambda c: c["secure_settlement"].__setitem__(
                "direct_attester_settlement_enabled", True
            ),
            "Direct attester",
        ),
        (
            lambda c: c["secure_settlement"]["signer_b"].__setitem__(
                "identity", c["secure_settlement"]["signer_a"]["identity"]
            ),
            "Signer A/B",
        ),
        (
            lambda c: c["secure_settlement"].__setitem__(
                "signing_journal_path", ":memory:"
            ),
            "persistent absolute",
        ),
    ],
)
def test_release_rejects_insecure_topology(mutate, match):
    cfg = _config()
    mutate(cfg)
    with pytest.raises(release.ReleaseError, match=match):
        release._service_endpoints(cfg, env_name="devnet")
        release._secure_settlement_metadata(cfg, env_name="devnet")


def _values():
    return {
        key: "value" for key in preflight.REQUIRED
    } | {
        "EXPECTED_CLUSTER": "devnet",
        "RPC_URL": "https://api.devnet.solana.com",
        "RESOLUTION_MODE": "secure-coordinator",
        "DIRECT_ATTESTER_SETTLEMENT_ENABLED": "0",
        "GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED": "0",
        "STRICT_SIGNER_COUNT": "2",
        "VERIFIER_A_URL": "http://verifier-a:8301",
        "VERIFIER_B_URL": "http://verifier-b:8302",
        "VERIFIER_A_IDENTITY": "a",
        "VERIFIER_B_IDENTITY": "b",
        "VERIFIER_A_AUTH_REF": "auth-a",
        "VERIFIER_B_AUTH_REF": "auth-b",
        "VERIFIER_A_PROOF_BACKEND_URL": "https://proof-a.example",
        "VERIFIER_B_PROOF_BACKEND_URL": "https://proof-b.example",
        "MANAGED_SIGNER_A_PUBLIC_KEY": "pub-a",
        "MANAGED_SIGNER_B_PUBLIC_KEY": "pub-b",
        "SIGNER_A_IDENTITY": "signer-a",
        "SIGNER_B_IDENTITY": "signer-b",
        "SIGNER_A_VAULT_KEY": "key-a",
        "SIGNER_B_VAULT_KEY": "key-b",
        "SIGNER_A_AUTH_REF": "vault-a",
        "SIGNER_B_AUTH_REF": "vault-b",
        "COORDINATOR_SQLITE_PATH": "/var/lib/prophet/coordinator.sqlite",
        "SIGNING_JOURNAL_PATH": "/var/lib/prophet/signing.sqlite",
        "SUBMISSION_JOURNAL_PATH": "/var/lib/prophet/submission.sqlite",
        "ALERT_RECEIVER_CONFIGURED": "1",
    }


def _compose(tmp_path):
    path = tmp_path / "compose.yml"
    path.write_text(
        "services:\n"
        "  verifier-a:\n    image: test\n"
        "  verifier-b:\n    image: test\n"
        "  coordinator:\n    image: test\n"
        "  secure-settlement:\n    image: test\n"
    )
    return path


def test_preflight_secure_topology_is_structurally_accepted(tmp_path):
    code, infra = preflight.topology_errors(_values(), compose_path=_compose(tmp_path))
    assert code == []
    assert infra == []


@pytest.mark.parametrize(
    "key,value,needle",
    [
        ("RESOLUTION_MODE", "legacy", "secure-coordinator"),
        ("GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED", "1", "generic remote"),
        ("DIRECT_ATTESTER_SETTLEMENT_ENABLED", "1", "direct attester"),
        ("COORDINATOR_URL", "", "missing COORDINATOR_URL"),
        ("VERIFIER_B_URL", "", "missing VERIFIER_B_URL"),
        ("VERIFIER_B_URL", "http://verifier-a:8301", "URLs"),
        ("VERIFIER_B_IDENTITY", "a", "identities"),
        ("SIGNER_B_IDENTITY", "signer-a", "signer identities"),
        ("SIGNER_B_AUTH_REF", "vault-a", "auth references"),
        ("COORDINATOR_SQLITE_PATH", ":memory:", "persistent"),
        ("SIGNING_JOURNAL_PATH", ":memory:", "persistent"),
    ],
)
def test_preflight_rejects_insecure_topology(tmp_path, key, value, needle):
    values = _values()
    values[key] = value
    code, _infra = preflight.topology_errors(values, compose_path=_compose(tmp_path))
    assert any(needle in item for item in code)
