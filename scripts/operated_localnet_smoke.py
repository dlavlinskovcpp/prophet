#!/usr/bin/env python3
"""Localtest-only fixed-role A/B signer smoke controller.

This controller deliberately has no generic signer, Vault credential, or legacy
authentication path.  It supplies only public bootstrap data to two separate
fixed-role child processes and validates their independently produced signatures.
It is not a public-devnet deployment tool.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
ATTESTER = ROOT / "apps" / "oracle-attester"
if str(ATTESTER) not in sys.path:
    sys.path.insert(0, str(ATTESTER))

from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solana.rpc.api import Client
from solana.rpc.commitment import Finalized

from prophet_sdk.settlement_message import build_resolution_message_v2
from src.signer_admission_grant import (
    AdmissionGrantV1,
    StrictSignerAuthorizationRequestV1,
    admission_request_binding,
    parse_strict_signer_authorization_request,
)
from src.verifier_attestation import VerifierAttestationSigner, settlement_authorization_job_id
from src.localtest_chain_binding import LocaltestChainBindingV1
from src.localtest_chain_bootstrap import LocaltestChainBootstrapError, bootstrap_localtest_chain
from src.localtest_raw_settlement_bridge import build_localtest_raw_settlement_signatures
from src.localtest_settlement_submission import (
    build_localtest_settlement_message,
    sign_localtest_fee_payer,
    submit_localtest_settlement,
)
from src.localtest_solana_finalized_rpc import LocaltestSolanaFinalizedRpc
from src.localtest_chain_bootstrap import _market_fields


PROGRAM = "3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE"
RESOLVER_HASH = "01" * 32
EVIDENCE_HASH = "02" * 32
PROOF_HASH = "03" * 32
PUBLIC_INPUTS_HASH = "04" * 32
GIT_SHA = "af50c01f562b6cb1a0851fa0f59c45d820d595f8"
EVIDENCE_SET_ID = "localtest-evidence"


class SmokeError(RuntimeError):
    pass


def _child_env() -> dict[str, str]:
    """The only environment inherited by secret-bearing localtest children."""
    return {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ} | {"COPYFILE_DISABLE": "1"}


def _run(argv: list[str], *, cwd: Path, env: dict[str, str]) -> str:
    completed = subprocess.run(argv, cwd=str(cwd), env=env, text=True, capture_output=True)
    if completed.returncode:
        raise SmokeError(f"localtest child failed ({' '.join(argv)}): {completed.stderr[-2000:]}")
    return completed.stdout


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")


def _free_port() -> int:
    import socket

    listener = socket.socket()
    try:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
    finally:
        listener.close()


def _rpc_is_ready(url: str) -> bool:
    try:
        Client(url, timeout=1).get_version()
        return True
    except Exception:
        return False


def _validator_program_is_loaded(url: str) -> bool:
    try:
        account = Client(url, timeout=2).get_account_info(Pubkey.from_string(PROGRAM), commitment=Finalized).value
        return account is not None and bool(account.executable)
    except Exception:
        return False


def _ensure_local_validator(root: Path) -> tuple[str, subprocess.Popen[str] | None]:
    """Use an existing loopback validator or start a throwaway preloaded one."""
    known = "http://127.0.0.1:8899"
    if _rpc_is_ready(known) and _validator_program_is_loaded(known):
        return known, None
    binary = shutil.which("solana-test-validator")
    program = ROOT / "target" / "deploy" / "prophet.so"
    if binary is None or not program.is_file():
        raise SmokeError("local_validator_binary_or_program_missing")
    port = 8899 if not _rpc_is_ready(known) else _free_port()
    ledger = root / "ledger"
    process = subprocess.Popen(
        [binary, "--reset", "--bind-address", "127.0.0.1", "--gossip-port", str(_free_port()), "--rpc-port", str(port), "--faucet-port", str(_free_port()), "--ledger", str(ledger), "--bpf-program", PROGRAM, str(program), "--quiet"],
        cwd=str(ROOT), env=_child_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout = process.stdout.read() if process.stdout else ""
            stderr = process.stderr.read() if process.stderr else ""
            raise SmokeError(f"local_validator_exited: {(stdout + stderr)[-4000:]}")
        if _rpc_is_ready(url) and _validator_program_is_loaded(url):
            return url, process
        time.sleep(0.2)
    process.terminate()
    process.wait(timeout=10)
    raise SmokeError("local_validator_start_timeout")


def _request(url: str, body: bytes, grant: bytes) -> dict[str, Any]:
    request = urllib.request.Request(
        url + "/v1/settlement-authorizations",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Prophet-Admission-Grant": base64.b64encode(grant).decode("ascii")},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise SmokeError("signer_http_status_invalid")
            value = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        # A grant is single-use.  Never resend after any ambiguous transport result.
        raise SmokeError("signer_http_ambiguous_no_retry") from exc
    if not isinstance(value, dict):
        raise SmokeError("signer_response_invalid")
    return value


def _expect_rejected(url: str, body: bytes, grant: bytes, *, reason: str) -> None:
    request = urllib.request.Request(
        url + "/v1/settlement-authorizations",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "X-Prophet-Admission-Grant": base64.b64encode(grant).decode("ascii")},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raise SmokeError(f"{reason}_unexpected_success_{response.status}")
    except urllib.error.HTTPError as exc:
        if exc.code != 403:
            raise SmokeError(f"{reason}_wrong_status_{exc.code}") from exc
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except (OSError, ValueError) as parse_exc:
            raise SmokeError(f"{reason}_invalid_rejection") from parse_exc
        if payload != {"error": "admission_rejected"}:
            raise SmokeError(f"{reason}_wrong_rejection")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise SmokeError(f"{reason}_transport_failure") from exc


def _readiness(state: Path, role: str, process: subprocess.Popen[str]) -> dict[str, Any]:
    path = state / "readiness.json"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeError(f"signer_{role.lower()}_exited_before_ready")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            endpoint = value["endpoint"]
            if (
                value["schema"] == "PROPHET_LOCALTEST_SIGNER_READINESS_V1"
                and value["version"] == 1
                and value["role"] == role
                and value["ready"] is True
                and value["pid"] == process.pid
                and isinstance(value["signer_service_id"], str)
                and str(Pubkey.from_string(value["signer_public_key"])) == value["signer_public_key"]
                and isinstance(endpoint, str)
                and endpoint.startswith("http://127.0.0.1:")
            ):
                return value
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(0.05)
    raise SmokeError(f"signer_{role.lower()}_readiness_timeout")


def _stop(processes: list[subprocess.Popen[str]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def _bootstrap(role: str, counterpart: str, issuer: dict[str, Any], run_id: str, *, rpc_url: str, genesis: str) -> dict[str, Any]:
    service = {
            "environment": "localtest", "mode": "test", "topology_classification": "FUNCTIONAL_TEST_ONLY",
            "signer": {"role": role, "signer_id": f"localtest-signer-{role.lower()}", "public_key": counterpart, "key_version": 1},
            "vault": {"address": "http://vault.localtest", "transit_mount": "transit", "key_name": f"localtest-notary-{role.lower()}", "token_env": f"LOCALTEST_SIGNER_{role}_TOKEN", "admin_domain_id": f"vault-{role.lower()}-admin", "account_or_tenant_id": f"vault-{role.lower()}-tenant", "auth_principal_id": f"vault-{role.lower()}-principal", "timeout_seconds": 1},
            "rpc": {"url_env": f"LOCALTEST_SIGNER_{role}_RPC", "provider_domain_id": "rpc-localtest", "account_or_project_id": "localtest", "credential_principal_id": "localtest"},
            "solana": {"expected_genesis_hash": genesis, "expected_program_id": PROGRAM},
            "journal_path": "/tmp/localtest-worker-owned.sqlite",
        }
    return {
        "service": service,
        "authorization": {"counterpart_notary_public_key": counterpart, "verifier_a": {"public_key": issuer["verifier_a"], "verifier_id": "verifier-a", "verifier_version": "1.0.0", "implementation_digest": "05" * 32}, "verifier_b": {"public_key": issuer["verifier_b"], "verifier_id": "verifier-b", "verifier_version": "1.0.0", "implementation_digest": "06" * 32}},
        "admission": {"issuer_id": issuer["issuer_id"], "key_id": issuer["key_id"], "issuer_public_key": issuer["public_key"], "git_sha": GIT_SHA, "evidence_set_id": EVIDENCE_SET_ID, "acceptance_run_id": run_id, "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z"},
        "localtest_rpc_mode": "real-local-validator-finalized",
        "localtest_rpc_url": rpc_url,
        "localtest_genesis_hash": genesis,
    }


def _start(role: str, state: Path, bootstrap: Path) -> subprocess.Popen[str]:
    worker = f"scripts/localtest_signer_{role.lower()}_worker.py"
    return subprocess.Popen(["poetry", "run", "python", worker, "--state-dir", str(state), "--bootstrap-file", str(bootstrap), "--port", str(_free_port())], cwd=str(ATTESTER), env=_child_env(), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _issuer(role: str, state: Path) -> dict[str, Any]:
    name = f"scripts/localtest_signer_{role.lower()}_admission_issuer.py"
    output = _run(["poetry", "run", "python", name, "--state-dir", str(state), "--issuer-id", f"localtest-issuer-{role.lower()}", "--key-id", f"localtest-key-{role.lower()}"], cwd=ATTESTER, env=_child_env())
    value = json.loads(output.strip().splitlines()[-1])
    if value.get("role") != role or value.get("ready") is not True:
        raise SmokeError("issuer_initialization_invalid")
    return value


def _issue(role: str, issuer_dir: Path, config_path: Path, request_path: Path, run_id: str, output: Path) -> bytes:
    name = f"scripts/localtest_signer_{role.lower()}_admission_issuer.py"
    _run(["poetry", "run", "python", name, "--state-dir", str(issuer_dir), "--issuer-id", f"localtest-issuer-{role.lower()}", "--key-id", f"localtest-key-{role.lower()}", "--request-file", str(request_path), "--issuer-config-file", str(config_path), "--acceptance-run-id", run_id, "--grant-output", str(output)], cwd=ATTESTER, env=_child_env())
    return output.read_bytes()


def _request_material(issuer: dict[str, Any], binding: LocaltestChainBindingV1) -> tuple[bytes, bytes]:
    now = int(time.time() * 1000)
    request_binding = {"cluster_genesis_hash": binding["genesis_hash"], "program_id": binding["program_id"], "market": binding["market"], "resolver_definition_hash": binding["resolver_definition_hash"], "evidence_hash": binding["evidence_hash"], "proof_hash": binding["proof_hash"], "public_inputs_hash": binding["public_inputs_hash"]}
    job = settlement_authorization_job_id(request_binding)
    def attest(key: Keypair, verifier_id: str, digest: str) -> dict[str, Any]:
        payload = {"attestation_schema": "prophet.verifier-attestation.v1", "attestation_version": "1", "verifier_id": verifier_id, "verifier_version": "1.0.0", "verifier_implementation_digest": digest, "job_id": job, **request_binding, "outcome": binding["outcome"], "acquired_at_ms": str(now - 1000), "valid_until_ms": str(now + 60_000)}
        return VerifierAttestationSigner(verifier_id, "1.0.0", digest, key).sign(payload, now_ms=now).as_transport()
    raw = {"schema": "PROPHET_SETTLEMENT_AUTHORIZATION_V1", "version": "1", "cluster_genesis_hash": binding["genesis_hash"], "program_id": binding["program_id"], "market": binding["market"], "verifier_a_attestation": attest(issuer["verifier_a_key"], "verifier-a", "05" * 32), "verifier_b_attestation": attest(issuer["verifier_b_key"], "verifier-b", "06" * 32)}
    body = json.dumps(raw, separators=(",", ":")).encode("utf-8")
    request = parse_strict_signer_authorization_request(body)
    canonical = build_resolution_message_v2(program_id=binding["program_id"], market=binding["market"], notary_config=binding["notary_config"], resolver_hash=bytes.fromhex(binding["resolver_definition_hash"]), open_ts=binding["open_ts"], resolve_ts=binding["resolve_ts"], notary_config_version=binding["notary_config_version"], outcome=binding["outcome"], proof_hash=bytes.fromhex(binding["proof_hash"]), public_inputs_hash=bytes.fromhex(binding["public_inputs_hash"]))
    if len(canonical) != 235:
        raise SmokeError("settlement_message_layout_invalid")
    return body, canonical


def _verify_response(response: dict[str, Any], *, role: str, readiness: dict[str, Any], message: bytes) -> bytes:
    expected = {"signer_role": role, "signer_id": readiness["signer_service_id"], "public_key": readiness["signer_public_key"], "state": "SIGNED", "canonical_message_digest": hashlib.sha256(message).hexdigest()}
    if any(response.get(key) != value for key, value in expected.items()):
        raise SmokeError("signer_response_identity_or_digest_invalid")
    try:
        signature = base64.b64decode(response["signature"], validate=True)
        if len(signature) != 64 or not Signature.from_bytes(signature).verify(Pubkey.from_string(readiness["signer_public_key"]), message):
            raise ValueError
    except Exception as exc:
        raise SmokeError("signer_response_signature_invalid") from exc
    return signature


def run_smoke(*, keep_artifacts: bool = False) -> dict[str, Any]:
    """Execute the complete real-chain fixed-role A/B P0C4 proof."""
    if os.getenv("PROPHET_SMOKE_ENVIRONMENT", "localtest") != "localtest":
        raise SmokeError("localtest_network_guard_rejected")
    run_id = secrets.token_hex(16)
    # Solana's genesis archive handling on macOS rejects AppleDouble metadata
    # sometimes created under the system per-user temporary tree.
    root = Path(tempfile.mkdtemp(prefix="prophet-localtest-fixed-role-", dir="/tmp"))
    a_state, b_state, a_issuer, b_issuer = (root / "signer-a", root / "signer-b", root / "issuer-a", root / "issuer-b")
    for directory in (a_state, b_state, a_issuer, b_issuer):
        directory.mkdir(mode=0o700)
    if len({path.resolve() for path in (a_state, b_state, a_issuer, b_issuer)}) != 4:
        raise SmokeError("role_local_state_alias")
    processes: list[subprocess.Popen[str]] = []
    validator: subprocess.Popen[str] | None = None
    try:
        rpc_url, validator = _ensure_local_validator(root)
        rpc = LocaltestSolanaFinalizedRpc(rpc_url, environment="localtest", mode="test", topology_classification="FUNCTIONAL_TEST_ONLY")
        genesis = rpc.genesis_hash()
        fee_payer = Keypair()
        airdrop = rpc.client.request_airdrop(fee_payer.pubkey(), 10_000_000_000).value
        rpc.client.confirm_transaction(airdrop, commitment=Finalized)
        issuer_a, issuer_b = _issuer("A", a_issuer), _issuer("B", b_issuer)
        if issuer_a["issuer_id"] == issuer_b["issuer_id"] or issuer_a["public_key"] == issuer_b["public_key"]:
            raise SmokeError("issuer_identity_collision")
        verifier_a, verifier_b = Keypair.from_seed(bytes(range(64, 96))), Keypair.from_seed(bytes(range(96, 128)))
        common = {"verifier_a": str(verifier_a.pubkey()), "verifier_b": str(verifier_b.pubkey()), "verifier_a_key": verifier_a, "verifier_b_key": verifier_b}
        provisional_a, provisional_b = str(Keypair.from_seed(bytes(range(32))).pubkey()), str(Keypair.from_seed(bytes(range(32, 64))).pubkey())
        boot_a, boot_b = root / "bootstrap-a.json", root / "bootstrap-b.json"
        _write_json(boot_a, _bootstrap("A", provisional_b, {**issuer_a, **common}, run_id, rpc_url=rpc_url, genesis=genesis))
        _write_json(boot_b, _bootstrap("B", provisional_a, {**issuer_b, **common}, run_id, rpc_url=rpc_url, genesis=genesis))
        process_a, process_b = _start("A", a_state, boot_a), _start("B", b_state, boot_b)
        processes = [process_a, process_b]
        ready_a, ready_b = _readiness(a_state, "A", process_a), _readiness(b_state, "B", process_b)
        if process_a.pid == process_b.pid or ready_a["endpoint"] == ready_b["endpoint"] or ready_a["signer_public_key"] == ready_b["signer_public_key"]:
            raise SmokeError("signer_runtime_identity_collision")
        _stop(processes); processes = []
        binding = bootstrap_localtest_chain(
            rpc_url=rpc_url,
            program_id=PROGRAM,
            signer_a_public_key=ready_a["signer_public_key"],
            signer_b_public_key=ready_b["signer_public_key"],
            fee_payer=fee_payer,
            resolver_definition_hash=RESOLVER_HASH,
            evidence_hash=EVIDENCE_HASH,
            proof_hash=PROOF_HASH,
            public_inputs_hash=PUBLIC_INPUTS_HASH,
            outcome="YES",
        )
        _write_json(boot_a, _bootstrap("A", ready_b["signer_public_key"], {**issuer_a, **common}, run_id, rpc_url=rpc_url, genesis=binding["genesis_hash"]))
        _write_json(boot_b, _bootstrap("B", ready_a["signer_public_key"], {**issuer_b, **common}, run_id, rpc_url=rpc_url, genesis=binding["genesis_hash"]))
        process_a, process_b = _start("A", a_state, boot_a), _start("B", b_state, boot_b)
        processes = [process_a, process_b]
        ready_a, ready_b = _readiness(a_state, "A", process_a), _readiness(b_state, "B", process_b)
        if ready_a["signer_public_key"] != binding["signer_a_public_key"] or ready_b["signer_public_key"] != binding["signer_b_public_key"]:
            raise SmokeError("signer_public_key_collision")
        common.update({"notary": binding["notary_config"]})
        body, message = _request_material(common, binding)
        request = StrictSignerAuthorizationRequestV1.from_mapping(json.loads(body))
        _, _, request_digest = admission_request_binding(request)
        request_path = root / "request.json"; request_path.write_bytes(body)
        grants: dict[str, bytes] = {}
        grant_values: dict[str, AdmissionGrantV1] = {}
        for role, issuer, issuer_dir, ready in (("A", issuer_a, a_issuer, ready_a), ("B", issuer_b, b_issuer, ready_b)):
            config = {"signer_role": role, "signer_service_id": ready["signer_service_id"], "environment": "localtest", "git_sha": GIT_SHA, "evidence_set_id": EVIDENCE_SET_ID, "issuer_id": issuer["issuer_id"], "key_id": issuer["key_id"], "issuer_public_key": issuer["public_key"], "issuer_private_key_env": f"LOCALTEST_ISSUER_{role}_KEY", "ttl_seconds": 60, "excluded_public_keys": []}
            config_path, grant_path = root / f"issuer-{role.lower()}-config.json", root / f"grant-{role.lower()}.json"
            _write_json(config_path, config)
            grants[role] = _issue(role, issuer_dir, config_path, request_path, run_id, grant_path)
            envelope = json.loads(grants[role])
            grant_values[role] = AdmissionGrantV1.from_mapping(envelope["unsigned_grant"])
        a_grant, b_grant = grant_values["A"].values, grant_values["B"].values
        if a_grant["grant_id"] == b_grant["grant_id"] or a_grant["issuer_id"] == b_grant["issuer_id"] or a_grant["acceptance_run_id"] != run_id or b_grant["acceptance_run_id"] != run_id or a_grant["admission_request_sha256"] != request_digest or b_grant["admission_request_sha256"] != request_digest:
            raise SmokeError("role_local_grant_binding_invalid")
        response_a = _request(ready_a["endpoint"], body, grants["A"])
        response_b = _request(ready_b["endpoint"], body, grants["B"])
        signature_a = _verify_response(response_a, role="A", readiness=ready_a, message=message)
        signature_b = _verify_response(response_b, role="B", readiness=ready_b, message=message)
        _expect_rejected(ready_a["endpoint"], body, grants["B"], reason="cross_role_b_to_a")
        _expect_rejected(ready_b["endpoint"], body, grants["A"], reason="cross_role_a_to_b")
        old_a_pid = process_a.pid
        _stop([process_a])
        process_a = _start("A", a_state, boot_a)
        processes = [process_a, process_b]
        restarted_a = _readiness(a_state, "A", process_a)
        if restarted_a["pid"] == old_a_pid or restarted_a["signer_public_key"] != ready_a["signer_public_key"]:
            raise SmokeError("signer_a_restart_identity_invalid")
        _expect_rejected(restarted_a["endpoint"], body, grants["A"], reason="restart_replay_a")
        if response_a.get("canonical_message_digest") != response_b.get("canonical_message_digest") or response_a.get("canonical_message_digest") != hashlib.sha256(message).hexdigest():
            raise SmokeError("canonical_message_mismatch")
        bundle = build_localtest_raw_settlement_signatures(
            canonical_message=message,
            signer_a_id=ready_a["signer_service_id"],
            signer_a_public_key=ready_a["signer_public_key"],
            signer_a_key_version=1,
            signer_a_signature=signature_a,
            signer_b_id=ready_b["signer_service_id"],
            signer_b_public_key=ready_b["signer_public_key"],
            signer_b_key_version=1,
            signer_b_signature=signature_b,
        )
        latest = rpc.client.get_latest_blockhash(commitment=Finalized).value.blockhash
        unsigned = build_localtest_settlement_message(binding=binding, signatures=bundle, fee_payer_pubkey=str(fee_payer.pubkey()), recent_blockhash=str(latest))
        signed = sign_localtest_fee_payer(unsigned, fee_payer)
        submitted = submit_localtest_settlement(rpc=rpc, artifact=signed)
        post = rpc.finalized_account(binding["market"], min_context_slot=binding["finalized_account_context_slot"])
        if post.account is None or post.account.owner != binding["program_id"]:
            raise SmokeError("resolved_market_missing")
        fields = _market_fields(post.account.data)
        if fields["status"] != 2 or fields["outcome"] != 1 or fields["resolved_ts"] < binding["resolve_ts"] or fields["proof_hash"] != bytes.fromhex(binding["proof_hash"]) or fields["public_inputs_hash"] != bytes.fromhex(binding["public_inputs_hash"]) or fields["notary_config"] != binding["notary_config"] or fields["creator"] != binding["creator"]:
            raise SmokeError("resolved_market_state_mismatch")
        return {"status": "PASS", "environment": "localtest", "acceptance_run_id": run_id, "signer_a": ready_a["signer_service_id"], "signer_b": ready_b["signer_service_id"], "signer_a_pid": ready_a["pid"], "signer_b_pid": ready_b["pid"], "signer_a_public_key": ready_a["signer_public_key"], "signer_b_public_key": ready_b["signer_public_key"], "market": binding["market"], "transaction": submitted.signature, "message_bytes": len(message), "canonical_message_protocol": "PROPHET_RESOLVE_V2"}
    finally:
        _stop(processes)
        if validator is not None and validator.poll() is None:
            validator.terminate()
            try:
                validator.wait(timeout=10)
            except subprocess.TimeoutExpired:
                validator.kill()
                validator.wait(timeout=10)
        if not keep_artifacts:
            shutil.rmtree(root, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()
    print(json.dumps(run_smoke(keep_artifacts=args.keep_artifacts), sort_keys=True))


if __name__ == "__main__":
    main()
