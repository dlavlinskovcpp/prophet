#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple


ROOT = Path(__file__).resolve().parent.parent
ATTESTER_DIR = ROOT / "apps" / "oracle-attester"
SDK_DIR = ROOT / "sdk" / "python"
NATIVE_MINT = "So11111111111111111111111111111111111111112"


class SmokeError(RuntimeError):
    pass


def _run(
    argv: list[str],
    *,
    cwd: Path = ROOT,
    env: Optional[Dict[str, str]] = None,
    input_text: str = "",
) -> str:
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            input=input_text,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise SmokeError(f"Required command not found: {argv[0]}") from exc
    if proc.returncode != 0:
        raise SmokeError(
            f"Command failed ({' '.join(argv)}):\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout


def _poetry_python(cwd: Path, code: str, env: Dict[str, str]) -> Dict[str, object]:
    stdout = _run(["poetry", "run", "python", "-"], cwd=cwd, env=env, input_text=code)
    line = stdout.strip().splitlines()[-1]
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        raise SmokeError(f"Expected JSON output, got:\n{stdout}") from exc


def _rpc_call(rpc_url: str, method: str, params: Iterable[object]) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if "error" in body:
        raise SmokeError(f"RPC {method} failed: {body['error']}")
    return body.get("result")


def _wait_for_balance(rpc_url: str, pubkey: str, lamports: int, *, timeout_s: float = 30.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        result = _rpc_call(rpc_url, "getBalance", [pubkey])
        value = int((result or {}).get("value", 0))
        if value >= lamports:
            return
        time.sleep(1)
    raise SmokeError(f"Timed out waiting for balance on {pubkey}")


def _airdrop(rpc_url: str, pubkey: str, lamports: int) -> None:
    _rpc_call(rpc_url, "requestAirdrop", [pubkey, lamports])
    _wait_for_balance(rpc_url, pubkey, lamports)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _http_json(
    url: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, object]] = None,
    token: str = "",
    timeout_s: float = 10.0,
) -> Tuple[int, str]:
    headers = {}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def _wait_for_health(url: str, *, timeout_s: float = 20.0) -> Dict[str, object]:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            status, body = _http_json(url)
            if status == 200:
                payload = json.loads(body)
                if payload.get("ok", False):
                    return payload
        except Exception:
            pass
        time.sleep(0.5)
    raise SmokeError(f"Timed out waiting for health endpoint {url}")


def _assert_status(status: int, expected: int, label: str, body: str) -> None:
    if status != expected:
        raise SmokeError(f"{label} returned HTTP {status}, expected {expected}: {body}")


def _tail(path: Path, lines: int = 60) -> str:
    if not path.exists():
        return f"[missing log: {path}]"
    data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(data[-lines:])


def _generate_keypair(path: Path) -> str:
    _run(
        [
            "solana-keygen",
            "new",
            "--no-bip39-passphrase",
            "--silent",
            "--force",
            "-o",
            str(path),
        ]
    )
    return _run(["solana", "address", "-k", str(path)]).strip()


def _derive_program_id(cli_arg: str) -> str:
    if cli_arg:
        return cli_arg
    env_value = os.getenv("PROPHET_PROGRAM_ID", "").strip()
    if env_value:
        return env_value
    keypair_path = ROOT / "target" / "deploy" / "prophet-keypair.json"
    if keypair_path.exists():
        return _run(["solana", "address", "-k", str(keypair_path)]).strip()
    raise SmokeError("PROPHET_PROGRAM_ID is required or target/deploy/prophet-keypair.json must exist.")


class _VerifierHandler(BaseHTTPRequestHandler):
    def _write(self, status: int, payload: Dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._write(200, {"ok": True})
            return
        self._write(404, {"detail": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/verify":
            self._write(404, {"detail": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length)
        try:
            payload = json.loads(raw.decode("utf-8"))
            proof = base64.b64decode(payload.get("proof_bytes_b64", ""), validate=True)
            public_inputs_bytes = base64.b64decode(payload.get("public_inputs_bytes_b64", ""), validate=True)
            public_inputs = json.loads(public_inputs_bytes.decode("utf-8"))
            resolver = payload.get("resolver", {})
            target = resolver.get("target_value")
            answer = ((public_inputs or {}).get("data") or {}).get("answer")
            ok = bool(proof) and answer == target
            self._write(
                200,
                {
                    "ok": ok,
                    "reason": "" if ok else "proof_or_public_inputs_invalid",
                    "provider": "fake_reclaim_http",
                },
            )
        except Exception as exc:
            self._write(200, {"ok": False, "reason": f"invalid_payload:{exc}"})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A003
        return


@dataclass
class ServiceProcess:
    name: str
    process: subprocess.Popen[str]
    log_path: Path
    handle: object

    def stop(self) -> None:
        if self.process.poll() is not None:
            try:
                self.handle.close()
            except Exception:
                pass
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        try:
            self.handle.close()
        except Exception:
            pass


def _start_service(
    name: str,
    module: str,
    port: int,
    env: Dict[str, str],
    log_path: Path,
) -> ServiceProcess:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = log_path.open("w", encoding="utf-8")
    try:
        proc = subprocess.Popen(
            [
                "poetry",
                "run",
                "uvicorn",
                module,
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
            ],
            cwd=str(ATTESTER_DIR),
            env=env,
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError as exc:
        handle.close()
        raise SmokeError("Required command not found: poetry") from exc
    return ServiceProcess(name=name, process=proc, log_path=log_path, handle=handle)


def _ensure_running(service: ServiceProcess) -> None:
    if service.process.poll() is None:
        return
    raise SmokeError(f"{service.name} exited early:\n{_tail(service.log_path)}")


def _sdk_create_market(env: Dict[str, str]) -> Dict[str, object]:
    code = """
import json
import os
import time
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from prophet_sdk import ProphetClient, derive_market_pda
from prophet_sdk.resolver_hash import compute_resolver_hash

client = ProphetClient(
    rpc_url=os.environ["RPC_URL"],
    payer_keypair_path=os.environ["PAYER_KEYPAIR_PATH"],
    program_id=os.environ["PROPHET_PROGRAM_ID"],
)
resolver_def = json.loads(open(os.environ["RESOLVER_FILE"], "r", encoding="utf-8").read())
resolver_hash = compute_resolver_hash(resolver_def)
rpc = Client(os.environ["RPC_URL"])
slot = rpc.get_slot().value
chain_time = rpc.get_block_time(slot).value or int(time.time())
open_ts = chain_time - 20
lock_ts = chain_time - 10
resolve_ts = chain_time - 5
notary = Pubkey.from_string(os.environ["NOTARY_PUBKEY"])
cfg, cfg_sig = client.initialize_notary_config(1, [notary])
market_sig = client.initialize_market_v2(
    resolver_hash=resolver_hash,
    open_ts=open_ts,
    lock_ts=lock_ts,
    resolve_ts=resolve_ts,
    notary_config=cfg,
    oracle_authority=client.payer.pubkey(),
    quote_mint=Pubkey.from_string(os.environ["QUOTE_MINT"]),
)
market, _ = derive_market_pda(resolver_hash, open_ts, client.program_id)
print(json.dumps({
    "market": str(market),
    "notary_config": str(cfg),
    "notary_config_signature": cfg_sig,
    "market_signature": market_sig,
    "resolver_hash_hex": resolver_hash.hex(),
    "resolve_ts": resolve_ts,
}))
"""
    return _poetry_python(SDK_DIR, code, env)


def _sdk_verify_market(env: Dict[str, str]) -> Dict[str, object]:
    code = """
import json
import os
from solders.pubkey import Pubkey
from prophet_sdk import MarketOutcome, MarketStatus, ProphetClient

client = ProphetClient(
    rpc_url=os.environ["RPC_URL"],
    payer_keypair_path=os.environ["PAYER_KEYPAIR_PATH"],
    program_id=os.environ["PROPHET_PROGRAM_ID"],
)
market = Pubkey.from_string(os.environ["MARKET_PUBKEY"])
state = client.fetch_market(market)
if state is None:
    raise SystemExit("market not found")
if state.status != MarketStatus.Resolved:
    raise SystemExit(f"unexpected status: {state.status}")
if state.outcome != MarketOutcome.Yes:
    raise SystemExit(f"unexpected outcome: {state.outcome}")
print(json.dumps({
    "status": str(state.status),
    "outcome": str(state.outcome),
    "proof_hash_hex": state.proof_hash.hex(),
    "public_inputs_hash_hex": state.public_inputs_hash.hex(),
}))
"""
    return _poetry_python(SDK_DIR, code, env)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run an auth-protected operated localnet smoke flow.")
    parser.add_argument("--rpc-url", default=os.getenv("RPC_URL", "http://127.0.0.1:8899"))
    parser.add_argument("--program-id", default="")
    parser.add_argument("--quote-mint", default=os.getenv("QUOTE_MINT", NATIVE_MINT))
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args()

    program_id = _derive_program_id(args.program_id)
    temp_root = Path(tempfile.mkdtemp(prefix="prophet-operated-smoke-"))
    services: list[ServiceProcess] = []
    verifier_server: Optional[ThreadingHTTPServer] = None
    verifier_thread: Optional[threading.Thread] = None
    success = False

    try:
        payer_path = temp_root / "payer.json"
        relayer_path = temp_root / "relayer.json"
        notary_path = temp_root / "notary.json"
        resolver_path = temp_root / "resolver.json"
        proof_path = temp_root / "proof.bin"
        public_inputs_path = temp_root / "public_inputs.json"
        allowlist_path = temp_root / "signer_allowlist.txt"
        resolver_store = temp_root / "resolver_store"
        proof_store = temp_root / "proof_store"
        audit_dir = temp_root / "audit"
        logs_dir = temp_root / "logs"
        for path in (resolver_store, proof_store, audit_dir, logs_dir):
            path.mkdir(parents=True, exist_ok=True)

        payer_pubkey = _generate_keypair(payer_path)
        relayer_pubkey = _generate_keypair(relayer_path)
        notary_pubkey = _generate_keypair(notary_path)
        allowlist_path.write_text(f"{notary_pubkey}\n", encoding="utf-8")

        _airdrop(args.rpc_url, payer_pubkey, 10_000_000_000)
        _airdrop(args.rpc_url, relayer_pubkey, 10_000_000_000)

        resolver_def = {
            "url": "https://example.test/value",
            "method": "GET",
            "path": "data.answer",
            "predicate": "equals",
            "target_value": 42,
        }
        resolver_path.write_text(json.dumps(resolver_def, indent=2) + "\n", encoding="utf-8")
        proof_path.write_bytes(b"operated-localnet-proof")
        public_inputs_path.write_text(json.dumps({"data": {"answer": 42}}), encoding="utf-8")

        registry_token = "localnet-registry-token"
        signer_token = "localnet-signer-token"
        attester_token = "localnet-attester-token"

        registry_port = _free_port()
        signer_port = _free_port()
        attester_port = _free_port()
        verifier_port = _free_port()

        verifier_server = ThreadingHTTPServer(("127.0.0.1", verifier_port), _VerifierHandler)
        verifier_thread = threading.Thread(target=verifier_server.serve_forever, daemon=True)
        verifier_thread.start()
        _wait_for_health(f"http://127.0.0.1:{verifier_port}/health")

        base_env = os.environ.copy()
        base_env["PYTHONUNBUFFERED"] = "1"

        registry_env = {
            **base_env,
            "APP_ENV": "development",
            "RESOLVER_STORE_DIR": str(resolver_store),
            "RESOLVER_REGISTRY_SERVICE_API_KEY": registry_token,
            "RESOLVER_REGISTRY_REQUIRE_AUTH": "1",
            "RESOLVER_REGISTRY_AUDIT_LOG_PATH": str(audit_dir / "resolver-registry.jsonl"),
            "RATE_LIMIT_ENABLED": "0",
            "METRICS_ENABLED": "1",
        }
        services.append(
            _start_service(
                "resolver-registry",
                "src.resolver_registry_main:app",
                registry_port,
                registry_env,
                logs_dir / "resolver-registry.log",
            )
        )

        signer_env = {
            **base_env,
            "APP_ENV": "development",
            "ALLOW_LOCAL_NOTARY_KEYS": "1",
            "NOTARY_KEYPAIR_PATHS": str(notary_path),
            "REMOTE_SIGNER_REQUIRE_AUTH": "1",
            "REMOTE_SIGNER_API_KEY": signer_token,
            "REMOTE_SIGNER_REQUIRE_ALLOWLIST": "1",
            "REMOTE_SIGNER_ALLOWLIST_MODE": "file",
            "REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH": str(allowlist_path),
            "REMOTE_SIGNER_BACKEND": "local_keypairs",
            "REMOTE_SIGNER_AUDIT_LOG_PATH": str(audit_dir / "remote-signer.jsonl"),
            "RATE_LIMIT_ENABLED": "0",
            "METRICS_ENABLED": "1",
        }
        services.append(
            _start_service(
                "remote-signer",
                "src.remote_signer_main:app",
                signer_port,
                signer_env,
                logs_dir / "remote-signer.log",
            )
        )

        attester_env = {
            **base_env,
            "RPC_URL": args.rpc_url,
            "PROPHET_PROGRAM_ID": program_id,
            "ORACLE_KEYPAIR_PATH": str(payer_path),
            "RELAYER_KEYPAIR_PATH": str(relayer_path),
            "PROOF_STORE_DIR": str(proof_store),
            "ATTESTER_AUDIT_LOG_PATH": str(audit_dir / "attester.jsonl"),
            "APP_ENV": "development",
            "ZKTLS_MODE": "reclaim_http",
            "REQUIRE_ZKTLS": "1",
            "RECLAIM_VERIFY_URL": f"http://127.0.0.1:{verifier_port}/verify",
            "PROOF_FETCH_MODE": "local",
            "NOTARY_SIGNER_MODE": "remote",
            "REMOTE_SIGNER_URL": f"http://127.0.0.1:{signer_port}/sign",
            "REMOTE_SIGNER_API_KEY": signer_token,
            "REMOTE_SIGNER_REQUIRE_TLS": "0",
            "RESOLVER_REGISTRY_MODE": "http",
            "RESOLVER_REGISTRY_URL": f"http://127.0.0.1:{registry_port}/resolvers",
            "RESOLVER_REGISTRY_API_KEY": registry_token,
            "RESOLVER_REGISTRY_REQUIRE_TLS": "0",
            "REQUIRE_API_AUTH": "1",
            "API_AUTH_TOKEN": attester_token,
            "RATE_LIMIT_ENABLED": "0",
            "METRICS_ENABLED": "1",
        }
        services.append(
            _start_service(
                "oracle-attester",
                "src.main:app",
                attester_port,
                attester_env,
                logs_dir / "oracle-attester.log",
            )
        )

        registry_health = _wait_for_health(f"http://127.0.0.1:{registry_port}/health")
        signer_health = _wait_for_health(f"http://127.0.0.1:{signer_port}/health")
        attester_health = _wait_for_health(f"http://127.0.0.1:{attester_port}/health")
        for service in services:
            _ensure_running(service)

        status, body = _http_json(f"http://127.0.0.1:{registry_port}/resolvers?limit=1")
        _assert_status(status, 401, "resolver registry unauthorized list", body)
        status, body = _http_json(
            f"http://127.0.0.1:{signer_port}/sign",
            method="POST",
            payload={"public_key": notary_pubkey, "message_b64": "", "context": {}},
        )
        _assert_status(status, 401, "remote signer unauthorized sign", body)
        status, body = _http_json(
            f"http://127.0.0.1:{attester_port}/resolve",
            method="POST",
            payload={"market": "11111111111111111111111111111111", "outcome": "YES"},
        )
        _assert_status(status, 401, "attester unauthorized resolve", body)

        publish_status, publish_body = _http_json(
            f"http://127.0.0.1:{registry_port}/resolvers",
            method="POST",
            token=registry_token,
            payload={"resolver": resolver_def},
        )
        _assert_status(publish_status, 200, "resolver publish", publish_body)
        published = json.loads(publish_body)

        sdk_env = {
            **base_env,
            "RPC_URL": args.rpc_url,
            "PROPHET_PROGRAM_ID": program_id,
            "PAYER_KEYPAIR_PATH": str(payer_path),
            "RESOLVER_FILE": str(resolver_path),
            "NOTARY_PUBKEY": notary_pubkey,
            "QUOTE_MINT": args.quote_mint,
        }
        created = _sdk_create_market(sdk_env)

        proof_b64 = base64.b64encode(proof_path.read_bytes()).decode("ascii")
        pi_b64 = base64.b64encode(public_inputs_path.read_bytes()).decode("ascii")
        resolve_status, resolve_body = _http_json(
            f"http://127.0.0.1:{attester_port}/resolve",
            method="POST",
            token=attester_token,
            payload={
                "market": created["market"],
                "outcome": "YES",
                "proof_bytes_b64": proof_b64,
                "public_inputs_bytes_b64": pi_b64,
            },
        )
        _assert_status(resolve_status, 200, "attester resolve", resolve_body)
        resolved = json.loads(resolve_body)

        verified = _sdk_verify_market(
            {
                **sdk_env,
                "MARKET_PUBKEY": str(created["market"]),
            }
        )
        if created["resolver_hash_hex"] != published["resolver_hash"]:
            raise SmokeError("published resolver hash does not match created market resolver hash")

        registry_audit = (audit_dir / "resolver-registry.jsonl").read_text(encoding="utf-8")
        signer_audit = (audit_dir / "remote-signer.jsonl").read_text(encoding="utf-8")
        attester_audit = (audit_dir / "attester.jsonl").read_text(encoding="utf-8")
        if '"event":"resolver_published"' not in registry_audit:
            raise SmokeError("resolver registry audit log missing resolver_published event")
        if '"event":"sign_success"' not in signer_audit:
            raise SmokeError("remote signer audit log missing sign_success event")
        if '"event":"resolve_submitted"' not in attester_audit:
            raise SmokeError("attester audit log missing resolve_submitted event")

        summary = {
            "market": created["market"],
            "resolver_hash_hex": created["resolver_hash_hex"],
            "published_resolver_hash": published["resolver_hash"],
            "signature": resolved["signature"],
            "proof_hash_hex": verified["proof_hash_hex"],
            "public_inputs_hash_hex": verified["public_inputs_hash_hex"],
            "registry_health": registry_health,
            "signer_health": signer_health,
            "attester_health": attester_health,
            "artifacts_retained": bool(args.keep_artifacts),
        }
        if args.keep_artifacts:
            summary["artifacts_dir"] = str(temp_root)
        print(json.dumps(summary, indent=2, sort_keys=True))
        success = True
        return 0
    except Exception as exc:
        print(f"operated smoke failed: {exc}", file=sys.stderr)
        for service in services:
            print(f"\n[{service.name} log]\n{_tail(service.log_path)}", file=sys.stderr)
        print(f"\nArtifacts kept at: {temp_root}", file=sys.stderr)
        return 1
    finally:
        if verifier_server is not None:
            verifier_server.shutdown()
            verifier_server.server_close()
        if verifier_thread is not None:
            verifier_thread.join(timeout=5)
        for service in reversed(services):
            service.stop()
        if success and not args.keep_artifacts:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
