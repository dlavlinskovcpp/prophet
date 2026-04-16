#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


ROOT = Path(__file__).resolve().parent.parent
ATTESTER_DIR = ROOT / "apps" / "oracle-attester"
SDK_DIR = ROOT / "sdk" / "python"
DEVNET_RPC_URL = "https://api.devnet.solana.com"


class DevnetSmokeError(RuntimeError):
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


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
        raise DevnetSmokeError(f"Required command not found: {argv[0]}") from exc
    if proc.returncode != 0:
        raise DevnetSmokeError(
            f"Command failed ({' '.join(argv)}):\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc.stdout


def _poetry_python(cwd: Path, code: str, env: Dict[str, str]) -> Dict[str, Any]:
    stdout = _run(["poetry", "run", "python", "-"], cwd=cwd, env=env, input_text=code)
    line = stdout.strip().splitlines()[-1]
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        raise DevnetSmokeError(f"Expected JSON output, got:\n{stdout}") from exc


def _rpc_call(rpc_url: str, method: str, params: Iterable[object]) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)}).encode("utf-8")
    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = json.loads(resp.read().decode("utf-8"))
    if "error" in body:
        raise DevnetSmokeError(f"RPC {method} failed: {body['error']}")
    return body.get("result")


def _chain_time(rpc_url: str) -> int:
    slot = _rpc_call(rpc_url, "getSlot", [])
    block_time = _rpc_call(rpc_url, "getBlockTime", [slot])
    if isinstance(block_time, int):
        return block_time
    return int(time.time())


def _wait_for_chain_time(rpc_url: str, target_ts: int, *, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if _chain_time(rpc_url) >= target_ts:
            return
        time.sleep(1)
    raise DevnetSmokeError(f"Timed out waiting for devnet time to reach {target_ts}")


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
    timeout_s: float = 20.0,
) -> Tuple[int, str]:
    headers: Dict[str, str] = {}
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


def _wait_for_health(url: str, *, timeout_s: float = 30.0) -> Dict[str, Any]:
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
    raise DevnetSmokeError(f"Timed out waiting for health endpoint {url}")


def _assert_status(status: int, expected: int, label: str, body: str) -> None:
    if status != expected:
        raise DevnetSmokeError(f"{label} returned HTTP {status}, expected {expected}: {body}")


def _tail(path: Path, lines: int = 60) -> str:
    if not path.exists():
        return f"[missing log: {path}]"
    data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(data[-lines:])


def _load_json(path: Path, *, label: str) -> Dict[str, Any]:
    if not path.exists():
        raise DevnetSmokeError(f"{label} file missing: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DevnetSmokeError(f"{label} file is not valid JSON: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise DevnetSmokeError(f"{label} file must contain a JSON object: {path}")
    return payload


def _extract_value(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _evaluate_resolver(definition: Dict[str, Any], public_inputs: Dict[str, Any]) -> str:
    actual = _extract_value(public_inputs, str(definition.get("path", "")))
    if actual is None:
        return "INVALID"

    target = definition.get("target_value")
    predicate = str(definition.get("predicate", "")).strip().lower()
    if isinstance(target, (int, float)):
        try:
            actual = float(actual)
            target = float(target)
        except (TypeError, ValueError):
            return "INVALID"

    if predicate == "equals":
        matched = actual == target
    elif predicate == "contains":
        matched = str(target) in str(actual)
    elif predicate == "gt":
        matched = actual > target
    elif predicate == "gte":
        matched = actual >= target
    elif predicate == "lt":
        matched = actual < target
    elif predicate == "lte":
        matched = actual <= target
    else:
        return "INVALID"
    return "YES" if matched else "NO"


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


def _write_allowlist(path: Path, pubkeys: Iterable[str]) -> None:
    entries = [str(item).strip() for item in pubkeys if str(item).strip()]
    if not entries:
        raise DevnetSmokeError("allowlist requires at least one pubkey")
    path.write_text("".join(f"{entry}\n" for entry in entries), encoding="utf-8")


def _bootstrap_vault_notary(
    *,
    base_env: Dict[str, str],
    vault_addr: str,
    vault_namespace: str,
    vault_token: str,
    vault_token_file: str,
    vault_cacert: str,
    vault_skip_verify: bool,
    vault_transit_mount: str,
    vault_transit_timeout_s: float,
    vault_key_name: str,
) -> Dict[str, Any]:
    env = {
        **base_env,
        "VAULT_ADDR": vault_addr,
        "VAULT_NAMESPACE": vault_namespace,
        "VAULT_TRANSIT_MOUNT": vault_transit_mount,
        "VAULT_TRANSIT_TIMEOUT_S": str(vault_transit_timeout_s),
        "VAULT_TRANSIT_KEY_NAME": vault_key_name,
    }
    if vault_token:
        env["VAULT_TOKEN"] = vault_token
    if vault_token_file:
        env["VAULT_TOKEN_FILE"] = vault_token_file
    if vault_cacert:
        env["VAULT_CACERT"] = vault_cacert
    if vault_skip_verify:
        env["VAULT_SKIP_VERIFY"] = "1"

    code = """
import json
import os
from src.vault_transit import VaultTransitConfig, bootstrap_vault_transit_keys

config = VaultTransitConfig.from_env()
payload = bootstrap_vault_transit_keys(
    config=config,
    key_names=[os.environ["VAULT_TRANSIT_KEY_NAME"]],
)
print(json.dumps(payload, sort_keys=True))
"""
    payload = _poetry_python(ATTESTER_DIR, code, env)
    pubkeys = payload.get("allowlist_pubkeys")
    if not isinstance(pubkeys, list) or len(pubkeys) != 1:
        raise DevnetSmokeError(
            "Vault Transit bootstrap must resolve exactly one notary pubkey for operated-devnet."
        )
    key_map = payload.get("key_map")
    if not isinstance(key_map, dict):
        raise DevnetSmokeError("Vault Transit bootstrap did not return a key_map payload.")
    return payload


def _remote_signer_direct_smoke(
    *,
    signer_url: str,
    api_key: str,
    public_key: str,
) -> Dict[str, Any]:
    smoke_message = base64.b64encode(b"PROPHET_OPERATED_DEVNET_SIGNER_SMOKE").decode("ascii")
    status, body = _http_json(
        signer_url,
        method="POST",
        token=api_key,
        payload={
            "public_key": public_key,
            "message_b64": smoke_message,
            "context": {"operation": "operated_devnet_smoke"},
        },
    )
    _assert_status(status, 200, "remote signer authorized sign", body)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise DevnetSmokeError(f"remote signer authorized sign returned invalid JSON: {body}") from exc
    if not isinstance(payload, dict):
        raise DevnetSmokeError("remote signer authorized sign returned a non-object payload")

    returned_pubkey = str(payload.get("public_key", "")).strip()
    if returned_pubkey != public_key:
        raise DevnetSmokeError(
            f"remote signer authorized sign returned unexpected public_key {returned_pubkey!r}"
        )

    signature_b64 = str(payload.get("signature_b64", "")).strip()
    if not signature_b64:
        raise DevnetSmokeError("remote signer authorized sign missing signature_b64")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise DevnetSmokeError(f"remote signer authorized sign returned invalid signature_b64: {exc}")
    if len(signature) != 64:
        raise DevnetSmokeError(
            f"remote signer authorized sign returned invalid signature length: {len(signature)}"
        )
    return {
        "public_key": returned_pubkey,
        "signature_len": len(signature),
    }


def _derive_program_id(cli_arg: str) -> str:
    if cli_arg:
        return cli_arg
    env_value = os.getenv("PROPHET_PROGRAM_ID", "").strip()
    if env_value:
        return env_value
    keypair_path = ROOT / "target" / "deploy" / "prophet-keypair.json"
    if keypair_path.exists():
        return _run(["solana", "address", "-k", str(keypair_path)]).strip()
    raise DevnetSmokeError("PROPHET_PROGRAM_ID is required or target/deploy/prophet-keypair.json must exist.")


def _ensure_program_exists(rpc_url: str, program_id: str) -> None:
    result = _rpc_call(rpc_url, "getAccountInfo", [program_id, {"encoding": "base64"}])
    if not isinstance(result, dict) or result.get("value") is None:
        raise DevnetSmokeError(
            f"Program {program_id} was not found on {rpc_url}. Deploy the program before running operated-devnet."
        )


def _ensure_wallet_has_balance(rpc_url: str, pubkey: str) -> int:
    result = _rpc_call(rpc_url, "getBalance", [pubkey])
    value = int((result or {}).get("value", 0))
    if value <= 0:
        raise DevnetSmokeError(
            f"Payer wallet {pubkey} has zero lamports on devnet. Fund it before running operated-devnet."
        )
    return value


def _default_resolver() -> Dict[str, Any]:
    return {
        "url": "https://example.com/value",
        "method": "GET",
        "path": "data.answer",
        "predicate": "equals",
        "target_value": 42,
    }


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
        raise DevnetSmokeError("Required command not found: poetry") from exc
    return ServiceProcess(name=name, process=proc, log_path=log_path, handle=handle)


def _ensure_running(service: ServiceProcess) -> None:
    if service.process.poll() is None:
        return
    raise DevnetSmokeError(f"{service.name} exited early:\n{_tail(service.log_path)}")


def _sdk_create_market(env: Dict[str, str]) -> Dict[str, Any]:
    code = """
import json
import os
import time
from solders.pubkey import Pubkey
from solana.rpc.api import Client
from prophet_sdk import ProphetClient, derive_market_pda, derive_notary_config_pda
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
resolve_delay_s = int(os.environ.get("RESOLVE_DELAY_S", "15"))
open_ts = chain_time - 30
lock_ts = chain_time - 10
resolve_ts = chain_time + resolve_delay_s
notary = Pubkey.from_string(os.environ["NOTARY_PUBKEY"])
cfg_action = "initialized"
update_sig = ""
cfg, cfg_sig = None, ""
try:
    cfg, cfg_sig = client.initialize_notary_config(1, [notary])
    if cfg_sig == "":
        cfg_action = "reused"
except RuntimeError as err:
    if "already in use" not in str(err):
        raise
    if os.environ.get("ALLOW_UPDATE_NOTARY_CONFIG", "") != "1":
        raise SystemExit(
            "existing NotaryConfig differs for this admin wallet; use a fresh payer or rerun with --allow-update-notary-config"
        )
    cfg, _ = derive_notary_config_pda(client.payer.pubkey(), client.program_id)
    update_sig = client.update_notary_config(1, [notary])
    cfg_action = "updated"
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
    "notary_config_action": cfg_action,
    "notary_config_signature": cfg_sig,
    "notary_config_update_signature": update_sig,
    "market_signature": market_sig,
    "resolver_hash_hex": resolver_hash.hex(),
    "open_ts": open_ts,
    "lock_ts": lock_ts,
    "resolve_ts": resolve_ts,
}))
"""
    return _poetry_python(SDK_DIR, code, env)


def _sdk_verify_market(env: Dict[str, str]) -> Dict[str, Any]:
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
expected = os.environ["EXPECTED_OUTCOME"]
expected_map = {
    "YES": MarketOutcome.Yes,
    "NO": MarketOutcome.No,
    "INVALID": MarketOutcome.Invalid,
}
state = client.fetch_market(market)
if state is None:
    raise SystemExit("market not found")
if state.status != MarketStatus.Resolved:
    raise SystemExit(f"unexpected status: {state.status}")
if state.outcome != expected_map[expected]:
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
    parser = argparse.ArgumentParser(
        description="Run the full operated devnet walkthrough with local auth-protected services."
    )
    parser.add_argument("--rpc-url", default=os.getenv("RPC_URL", DEVNET_RPC_URL))
    parser.add_argument("--program-id", default="")
    parser.add_argument("--quote-mint", default=os.getenv("QUOTE_MINT", ""))
    parser.add_argument("--payer-keypair", default=os.getenv("PAYER_KEYPAIR_PATH", ""))
    parser.add_argument("--relayer-keypair", default=os.getenv("RELAYER_KEYPAIR_PATH", ""))
    parser.add_argument("--notary-keypair", default=os.getenv("NOTARY_KEYPAIR_PATH", ""))
    parser.add_argument("--resolver-file", default=os.getenv("RESOLVER_FILE", ""))
    parser.add_argument("--proof-file", default=os.getenv("PROOF_FILE", ""))
    parser.add_argument("--public-inputs-file", default=os.getenv("PUBLIC_INPUTS_FILE", ""))
    parser.add_argument("--reclaim-verify-url", default=os.getenv("RECLAIM_VERIFY_URL", ""))
    parser.add_argument("--reclaim-api-key", default=os.getenv("RECLAIM_API_KEY", ""))
    parser.add_argument("--outcome", choices=["YES", "NO", "INVALID"], default=os.getenv("OUTCOME", "YES"))
    parser.add_argument("--resolve-delay-s", type=int, default=int(os.getenv("RESOLVE_DELAY_S", "15")))
    parser.add_argument("--allow-update-notary-config", action="store_true")
    parser.add_argument("--keep-artifacts", action="store_true")
    parser.add_argument(
        "--signer-backend",
        choices=["command", "local_keypairs", "vault_transit"],
        default=os.getenv("SIGNER_BACKEND", "command"),
    )
    parser.add_argument("--vault-addr", default=os.getenv("VAULT_ADDR", ""))
    parser.add_argument("--vault-namespace", default=os.getenv("VAULT_NAMESPACE", ""))
    parser.add_argument("--vault-token", default=os.getenv("VAULT_TOKEN", ""))
    parser.add_argument("--vault-token-file", default=os.getenv("VAULT_TOKEN_FILE", ""))
    parser.add_argument("--vault-cacert", default=os.getenv("VAULT_CACERT", ""))
    parser.add_argument(
        "--vault-skip-verify",
        action="store_true",
        default=_env_bool("VAULT_SKIP_VERIFY", False),
    )
    parser.add_argument(
        "--vault-transit-mount",
        default=os.getenv("VAULT_TRANSIT_MOUNT", "transit"),
    )
    parser.add_argument(
        "--vault-transit-timeout-s",
        type=float,
        default=float(os.getenv("VAULT_TRANSIT_TIMEOUT_S", "5")),
    )
    parser.add_argument(
        "--vault-key-name",
        default=os.getenv("VAULT_TRANSIT_KEY_NAME", ""),
    )
    args = parser.parse_args()

    if not args.quote_mint:
        parser.error("--quote-mint is required (or set QUOTE_MINT).")
    if not args.payer_keypair:
        parser.error("--payer-keypair is required (or set PAYER_KEYPAIR_PATH).")
    if not args.reclaim_verify_url:
        parser.error("--reclaim-verify-url is required (or set RECLAIM_VERIFY_URL).")
    if not args.proof_file:
        parser.error("--proof-file is required (or set PROOF_FILE).")
    if not args.public_inputs_file:
        parser.error("--public-inputs-file is required (or set PUBLIC_INPUTS_FILE).")
    if args.signer_backend == "vault_transit":
        if not args.vault_addr:
            parser.error("--vault-addr is required when --signer-backend vault_transit.")
        if not args.vault_key_name:
            parser.error("--vault-key-name is required when --signer-backend vault_transit.")
        if not (args.vault_token or args.vault_token_file):
            parser.error(
                "--vault-token or --vault-token-file is required when --signer-backend vault_transit."
            )
        if args.vault_transit_timeout_s <= 0:
            parser.error("--vault-transit-timeout-s must be > 0.")

    proof_path = Path(args.proof_file).expanduser().resolve()
    public_inputs_path = Path(args.public_inputs_file).expanduser().resolve()
    payer_path = Path(args.payer_keypair).expanduser().resolve()
    relayer_path = Path(args.relayer_keypair).expanduser().resolve() if args.relayer_keypair else payer_path
    resolver_input_path = Path(args.resolver_file).expanduser().resolve() if args.resolver_file else None

    if not payer_path.exists():
        raise SystemExit(f"payer keypair missing: {payer_path}")
    if not relayer_path.exists():
        raise SystemExit(f"relayer keypair missing: {relayer_path}")
    if not proof_path.exists():
        raise SystemExit(f"proof file missing: {proof_path}")
    if not public_inputs_path.exists():
        raise SystemExit(f"public inputs file missing: {public_inputs_path}")
    if resolver_input_path is not None and not resolver_input_path.exists():
        raise SystemExit(f"resolver file missing: {resolver_input_path}")
    if args.vault_token_file:
        vault_token_file = Path(args.vault_token_file).expanduser().resolve()
        if not vault_token_file.exists():
            raise SystemExit(f"vault token file missing: {vault_token_file}")
        args.vault_token_file = str(vault_token_file)
    if args.vault_cacert:
        vault_cacert = Path(args.vault_cacert).expanduser().resolve()
        if not vault_cacert.exists():
            raise SystemExit(f"vault CA bundle missing: {vault_cacert}")
        args.vault_cacert = str(vault_cacert)

    temp_root = Path(tempfile.mkdtemp(prefix="prophet-operated-devnet-"))
    services: list[ServiceProcess] = []
    success = False

    try:
        artifacts_dir = temp_root
        resolver_path = artifacts_dir / "resolver.json"
        allowlist_path = artifacts_dir / "signer_allowlist.txt"
        signer_secrets_dir = artifacts_dir / "remote-signer-secrets"
        resolver_store = artifacts_dir / "resolver_store"
        proof_store = artifacts_dir / "proof_store"
        audit_dir = artifacts_dir / "audit"
        logs_dir = artifacts_dir / "logs"
        for path in (resolver_store, proof_store, audit_dir, logs_dir, signer_secrets_dir):
            path.mkdir(parents=True, exist_ok=True)

        resolver_def = _load_json(resolver_input_path, label="resolver") if resolver_input_path else _default_resolver()
        resolver_path.write_text(json.dumps(resolver_def, indent=2) + "\n", encoding="utf-8")
        public_inputs = _load_json(public_inputs_path, label="public inputs")
        evaluated = _evaluate_resolver(resolver_def, public_inputs)
        if evaluated != args.outcome:
            raise DevnetSmokeError(
                f"resolver/public inputs evaluate to {evaluated}, but requested outcome is {args.outcome}"
            )

        program_id = _derive_program_id(args.program_id)
        _ensure_program_exists(args.rpc_url, program_id)
        payer_pubkey = _run(["solana", "address", "-k", str(payer_path)]).strip()
        payer_balance = _ensure_wallet_has_balance(args.rpc_url, payer_pubkey)

        registry_token = secrets.token_hex(16)
        signer_token = secrets.token_hex(16)
        attester_token = secrets.token_hex(16)

        registry_port = _free_port()
        signer_port = _free_port()
        attester_port = _free_port()

        base_env = os.environ.copy()
        base_env["PYTHONUNBUFFERED"] = "1"

        signer_env = {
            **base_env,
            "APP_ENV": "development",
            "ALLOW_LOCAL_NOTARY_KEYS": "0",
            "NOTARY_KEYPAIR_PATHS": "",
            "REMOTE_SIGNER_REQUIRE_AUTH": "1",
            "REMOTE_SIGNER_API_KEY": signer_token,
            "REMOTE_SIGNER_REQUIRE_ALLOWLIST": "1",
            "REMOTE_SIGNER_ALLOWLIST_MODE": "file",
            "REMOTE_SIGNER_ALLOWED_PUBKEYS_PATH": str(allowlist_path),
            "REMOTE_SIGNER_COMMAND_PUBLIC_KEYS": "",
            "REMOTE_SIGNER_AUDIT_LOG_PATH": str(audit_dir / "remote-signer.jsonl"),
            "RATE_LIMIT_ENABLED": "0",
            "METRICS_ENABLED": "1",
        }

        notary_path = None
        vault_bootstrap = None
        if args.signer_backend == "vault_transit":
            key_map_path = signer_secrets_dir / "vault-transit-key-map.json"
            vault_bootstrap = _bootstrap_vault_notary(
                base_env=base_env,
                vault_addr=args.vault_addr,
                vault_namespace=args.vault_namespace,
                vault_token=args.vault_token,
                vault_token_file=args.vault_token_file,
                vault_cacert=args.vault_cacert,
                vault_skip_verify=bool(args.vault_skip_verify),
                vault_transit_mount=args.vault_transit_mount,
                vault_transit_timeout_s=args.vault_transit_timeout_s,
                vault_key_name=args.vault_key_name,
            )
            notary_pubkey = str(vault_bootstrap["allowlist_pubkeys"][0])
            _write_allowlist(allowlist_path, [notary_pubkey])
            key_map_path.write_text(
                json.dumps(vault_bootstrap["key_map"], indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            signer_env.update(
                {
                    "ALLOW_LOCAL_NOTARY_KEYS": "0",
                    "REMOTE_SIGNER_BACKEND": "command",
                    "REMOTE_SIGNER_COMMAND": "python scripts/vault_transit_signer.py",
                    "REMOTE_SIGNER_COMMAND_TIMEOUT_S": str(max(args.vault_transit_timeout_s + 5.0, 10.0)),
                    "REMOTE_SIGNER_COMMAND_PUBLIC_KEYS": str(
                        vault_bootstrap.get("command_public_keys_csv", notary_pubkey)
                    ),
                    "VAULT_ADDR": args.vault_addr,
                    "VAULT_NAMESPACE": args.vault_namespace,
                    "VAULT_TRANSIT_MOUNT": args.vault_transit_mount,
                    "VAULT_TRANSIT_TIMEOUT_S": str(args.vault_transit_timeout_s),
                    "VAULT_TRANSIT_KEY_MAP_PATH": str(key_map_path),
                    "VAULT_TRANSIT_KEY_NAME": "",
                }
            )
            if args.vault_token:
                signer_env["VAULT_TOKEN"] = args.vault_token
            if args.vault_token_file:
                signer_env["VAULT_TOKEN_FILE"] = args.vault_token_file
            if args.vault_cacert:
                signer_env["VAULT_CACERT"] = args.vault_cacert
            if args.vault_skip_verify:
                signer_env["VAULT_SKIP_VERIFY"] = "1"
        else:
            if args.notary_keypair:
                notary_path = Path(args.notary_keypair).expanduser().resolve()
                if not notary_path.exists():
                    raise DevnetSmokeError(f"notary keypair missing: {notary_path}")
                notary_pubkey = _run(["solana", "address", "-k", str(notary_path)]).strip()
            else:
                notary_path = artifacts_dir / "notary.json"
                notary_pubkey = _generate_keypair(notary_path)
            _write_allowlist(allowlist_path, [notary_pubkey])

            signer_env["ALLOW_LOCAL_NOTARY_KEYS"] = "1"
            signer_env["NOTARY_KEYPAIR_PATHS"] = str(notary_path)
            if args.signer_backend == "command":
                signer_env["REMOTE_SIGNER_BACKEND"] = "command"
                signer_env["REMOTE_SIGNER_COMMAND"] = "python scripts/local_command_signer.py"
                signer_env["REMOTE_SIGNER_COMMAND_TIMEOUT_S"] = "5"
            else:
                signer_env["REMOTE_SIGNER_BACKEND"] = "local_keypairs"
                signer_env["REMOTE_SIGNER_COMMAND"] = ""

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
            "RECLAIM_VERIFY_URL": args.reclaim_verify_url,
            "RECLAIM_API_KEY": args.reclaim_api_key,
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

        if registry_health.get("require_auth") is not True:
            raise DevnetSmokeError("resolver registry is not enforcing auth")
        loaded_pubkeys = signer_health.get("pubkeys") or signer_health.get("loaded_pubkeys") or []
        if not isinstance(loaded_pubkeys, list) or notary_pubkey not in [str(item) for item in loaded_pubkeys]:
            raise DevnetSmokeError("remote signer health does not include the requested notary pubkey")
        if attester_health.get("notary_signer_mode") != "remote":
            raise DevnetSmokeError("attester health does not report notary_signer_mode=remote")
        resolver_health = attester_health.get("resolver_registry", {})
        if not isinstance(resolver_health, dict) or resolver_health.get("mode") != "http":
            raise DevnetSmokeError("attester health does not report resolver registry mode http")

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
            payload={"market": "11111111111111111111111111111111", "outcome": args.outcome},
        )
        _assert_status(status, 401, "attester unauthorized resolve", body)

        signer_direct_smoke = _remote_signer_direct_smoke(
            signer_url=f"http://127.0.0.1:{signer_port}/sign",
            api_key=signer_token,
            public_key=notary_pubkey,
        )

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
            "RESOLVE_DELAY_S": str(args.resolve_delay_s),
            "ALLOW_UPDATE_NOTARY_CONFIG": "1" if args.allow_update_notary_config else "0",
        }
        created = _sdk_create_market(sdk_env)
        _wait_for_chain_time(args.rpc_url, int(created["resolve_ts"]), timeout_s=max(args.resolve_delay_s + 60, 90))

        proof_b64 = base64.b64encode(proof_path.read_bytes()).decode("ascii")
        public_inputs_b64 = base64.b64encode(public_inputs_path.read_bytes()).decode("ascii")
        resolve_status, resolve_body = _http_json(
            f"http://127.0.0.1:{attester_port}/resolve",
            method="POST",
            token=attester_token,
            payload={
                "market": created["market"],
                "outcome": args.outcome,
                "proof_bytes_b64": proof_b64,
                "public_inputs_bytes_b64": public_inputs_b64,
            },
            timeout_s=60.0,
        )
        _assert_status(resolve_status, 200, "attester resolve", resolve_body)
        resolved = json.loads(resolve_body)

        verified = _sdk_verify_market(
            {
                **sdk_env,
                "MARKET_PUBKEY": str(created["market"]),
                "EXPECTED_OUTCOME": args.outcome,
            }
        )
        if created["resolver_hash_hex"] != published["resolver_hash"]:
            raise DevnetSmokeError("published resolver hash does not match created market resolver hash")

        registry_audit = (audit_dir / "resolver-registry.jsonl").read_text(encoding="utf-8")
        signer_audit = (audit_dir / "remote-signer.jsonl").read_text(encoding="utf-8")
        attester_audit = (audit_dir / "attester.jsonl").read_text(encoding="utf-8")
        if '"event":"resolver_published"' not in registry_audit:
            raise DevnetSmokeError("resolver registry audit log missing resolver_published event")
        if '"event":"sign_success"' not in signer_audit:
            raise DevnetSmokeError("remote signer audit log missing sign_success event")
        if '"event":"resolve_submitted"' not in attester_audit:
            raise DevnetSmokeError("attester audit log missing resolve_submitted event")

        summary = {
            "market": created["market"],
            "notary_config": created["notary_config"],
            "notary_config_action": created["notary_config_action"],
            "resolver_hash_hex": created["resolver_hash_hex"],
            "published_resolver_hash": published["resolver_hash"],
            "signature": resolved["signature"],
            "proof_hash_hex": verified["proof_hash_hex"],
            "public_inputs_hash_hex": verified["public_inputs_hash_hex"],
            "outcome": args.outcome,
            "signer_backend": args.signer_backend,
            "payer_pubkey": payer_pubkey,
            "payer_balance_lamports": payer_balance,
            "notary_pubkey": notary_pubkey,
            "signer_direct_smoke": signer_direct_smoke,
            "registry_health": registry_health,
            "signer_health": signer_health,
            "attester_health": attester_health,
            "artifacts_retained": bool(args.keep_artifacts),
        }
        if vault_bootstrap is not None:
            summary["vault_bootstrap"] = {
                "transit_mount": vault_bootstrap.get("transit_mount"),
                "vault_addr": vault_bootstrap.get("vault_addr"),
                "vault_namespace": vault_bootstrap.get("vault_namespace"),
                "keys": vault_bootstrap.get("keys"),
            }
        if args.keep_artifacts:
            summary["artifacts_dir"] = str(artifacts_dir)
        print(json.dumps(summary, indent=2, sort_keys=True))
        success = True
        return 0
    except Exception as exc:
        print(f"operated devnet failed: {exc}", file=sys.stderr)
        for service in services:
            print(f"\n[{service.name} log]\n{_tail(service.log_path)}", file=sys.stderr)
        print(f"\nArtifacts kept at: {temp_root}", file=sys.stderr)
        return 1
    finally:
        for service in reversed(services):
            service.stop()
        if success and not args.keep_artifacts:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
