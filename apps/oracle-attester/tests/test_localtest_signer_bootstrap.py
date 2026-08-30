import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from solders.keypair import Keypair


ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec); assert spec and spec.loader
    sys.modules[name] = module; spec.loader.exec_module(module)
    return module


ISSUER_A = _load("localtest_issuer_a", "scripts/localtest_signer_a_admission_issuer.py")
ISSUER_B = _load("localtest_issuer_b", "scripts/localtest_signer_b_admission_issuer.py")


def test_fixed_issuer_initializers_create_distinct_public_only_identities(tmp_path, capsys):
    a = ISSUER_A.initialize_localtest_signer_a_issuer(str(tmp_path / "issuer-a"), issuer_id="issuer-a", key_id="key-a")
    b = ISSUER_B.initialize_localtest_signer_b_issuer(str(tmp_path / "issuer-b"), issuer_id="issuer-b", key_id="key-b")
    assert a["role"] == "A" and b["role"] == "B" and a["public_key"] != b["public_key"]
    assert "seed" not in a and "seed" not in b and capsys.readouterr().out == ""
    assert (tmp_path / "issuer-a" / "admission-issuer.seed").stat().st_size == 32
    assert ISSUER_A.initialize_localtest_signer_a_issuer(str(tmp_path / "issuer-a"), issuer_id="issuer-a", key_id="key-a")["public_key"] == a["public_key"]


def _bootstrap(role, issuer_public_key):
    other = str(Keypair.from_seed(bytes([9]) * 32).pubkey())
    verifier_a = str(Keypair.from_seed(bytes([10]) * 32).pubkey())
    verifier_b = str(Keypair.from_seed(bytes([11]) * 32).pubkey())
    return {
        "service": {
            "environment": "localtest", "mode": "test", "topology_classification": "FUNCTIONAL_TEST_ONLY",
            "signer": {"role": role, "signer_id": f"localtest-signer-{role.lower()}", "public_key": other, "key_version": 1},
            "vault": {"address": "http://vault.localtest", "transit_mount": "transit", "key_name": f"localtest-notary-{role.lower()}", "token_env": f"SIGNER_{role}_VAULT_TOKEN", "admin_domain_id": f"vault-{role.lower()}", "account_or_tenant_id": f"account-{role.lower()}", "auth_principal_id": f"principal-{role.lower()}", "timeout_seconds": 1},
            "rpc": {"url_env": f"SIGNER_{role}_RPC_URL", "provider_domain_id": "rpc-localtest", "account_or_project_id": "localtest", "credential_principal_id": "localtest"},
            "solana": {"expected_genesis_hash": "00" * 32, "expected_program_id": "11111111111111111111111111111111"},
            "journal_path": "/tmp/ignored.sqlite", "admission_token_env": f"SIGNER_{role}_ADMISSION_TOKEN",
        },
        "authorization": {"counterpart_notary_public_key": other, "verifier_a": {"public_key": verifier_a, "verifier_id": "verifier-a", "verifier_version": "1", "implementation_digest": "aa" * 32}, "verifier_b": {"public_key": verifier_b, "verifier_id": "verifier-b", "verifier_version": "1", "implementation_digest": "bb" * 32}},
        "admission": {"issuer_id": f"issuer-{role.lower()}", "key_id": f"key-{role.lower()}", "issuer_public_key": issuer_public_key, "git_sha": "ab" * 20, "evidence_set_id": "localtest-evidence", "acceptance_run_id": "cd" * 16, "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"},
        "rpc_fixture": {"genesis_hash": "00" * 32, "finalized_slot": 1, "block_time": 1, "accounts": {}},
    }


def _start_worker(tmp_path, role, issuer_public_key):
    state = tmp_path / f"signer-{role.lower()}"; state.mkdir(mode=0o700)
    bootstrap = tmp_path / f"{role}.json"; bootstrap.write_text(json.dumps(_bootstrap(role, issuer_public_key)), encoding="utf-8")
    script = ROOT / "scripts" / f"localtest_signer_{role.lower()}_worker.py"
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
    process = subprocess.Popen([sys.executable, str(script), "--state-dir", str(state), "--bootstrap-file", str(bootstrap)], cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    readiness = state / "readiness.json"
    for _ in range(100):
        if readiness.exists(): return process, json.loads(readiness.read_text())
        if process.poll() is not None: break
        time.sleep(0.03)
    stdout, stderr = process.communicate(timeout=1)
    raise AssertionError(f"worker did not become ready: {stdout} {stderr}")


def test_fixed_workers_are_distinct_processes_with_public_only_readiness(tmp_path):
    issuer_a = ISSUER_A.initialize_localtest_signer_a_issuer(str(tmp_path / "issuer-a"), issuer_id="issuer-a", key_id="key-a")
    issuer_b = ISSUER_B.initialize_localtest_signer_b_issuer(str(tmp_path / "issuer-b"), issuer_id="issuer-b", key_id="key-b")
    a, ready_a = _start_worker(tmp_path, "A", issuer_a["public_key"])
    b, ready_b = _start_worker(tmp_path, "B", issuer_b["public_key"])
    try:
        assert ready_a["role"] == "A" and ready_b["role"] == "B"
        assert ready_a["pid"] != ready_b["pid"] and ready_a["endpoint"] != ready_b["endpoint"]
        assert ready_a["signer_public_key"] != ready_b["signer_public_key"]
        assert set(ready_a) == {"schema", "version", "role", "signer_service_id", "endpoint", "signer_public_key", "pid", "ready"}
        assert (tmp_path / "signer-a" / "signer.seed").stat().st_size == 32
        assert (tmp_path / "signer-a" / "admission-replay.sqlite3").exists()
        assert (tmp_path / "signer-a" / "independent-signer.sqlite3").exists()
    finally:
        for process in (a, b):
            process.terminate(); process.wait(timeout=5)


def test_worker_sources_have_fixed_roles_and_no_generic_remote_signer():
    a = (ROOT / "scripts/localtest_signer_a_worker.py").read_text(); b = (ROOT / "scripts/localtest_signer_b_worker.py").read_text()
    assert 'fixed_role="A"' in a and 'fixed_role="B"' in b
    assert "--role" not in a + b and "SIGNER_ROLE" not in a + b and "remote_signer_main" not in a + b


def test_worker_rejects_non_localtest_config_before_seed_creation(tmp_path):
    from src.localtest_signer_worker_support import _preflight_localtest_service, LocaltestSignerWorkerError
    raw = _bootstrap("A", str(Keypair.from_seed(bytes([4]) * 32).pubkey()))
    raw["service"]["environment"] = "public-devnet"; raw["service"]["mode"] = "production"
    with pytest.raises(LocaltestSignerWorkerError, match="environment_rejected"):
        _preflight_localtest_service(raw, role="A")
    assert not (tmp_path / "signer-a" / "signer.seed").exists()


def test_stale_readiness_is_removed_but_live_process_readiness_is_not(tmp_path):
    from src.localtest_signer_worker_support import _remove_stale_readiness, LocaltestSignerWorkerError
    readiness = tmp_path / "readiness.json"
    readiness.write_text(json.dumps({"pid": 999_999_999}), encoding="utf-8")
    _remove_stale_readiness(readiness); assert not readiness.exists()
    readiness.write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
    with pytest.raises(LocaltestSignerWorkerError, match="already_running"):
        _remove_stale_readiness(readiness)
