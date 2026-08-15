#!/usr/bin/env python3
"""Fail-closed, no-broadcast preflight for the public-devnet runtime."""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "RPC_URL", "EXPECTED_CLUSTER", "EXPECTED_CLUSTER_GENESIS_HASH",
    "EXPECTED_PROPHET_PROGRAM_ID", "SIGNER_POLICY_VERSION",
    "MANAGED_SIGNER_A_PUBLIC_KEY", "MANAGED_SIGNER_B_PUBLIC_KEY",
    "ALERT_RECEIVER_CONFIGURED",
)

def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values

def rpc(url: str, method: str) -> object:
    request = urllib.request.Request(url, data=json.dumps({"jsonrpc":"2.0", "id":1, "method":method}).encode(), headers={"Content-Type":"application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.load(response)
    if payload.get("error"):
        raise RuntimeError(str(payload["error"]))
    return payload.get("result")

def main() -> int:
    path = Path(os.getenv("RUNTIME_ENV", "/etc/prophet/public-devnet/runtime.env"))
    if not path.exists():
        print(f"BLOCKED: runtime environment file missing: {path}")
        return 2
    values = load_env(path)
    errors = [f"missing {key}" for key in REQUIRED if not values.get(key)]
    errors += [f"unresolved {key}" for key in REQUIRED if values.get(key, "").startswith("REPLACE_")]
    if values.get("EXPECTED_CLUSTER") != "devnet": errors.append("EXPECTED_CLUSTER must be devnet")
    if "mainnet" in values.get("RPC_URL", "").lower(): errors.append("mainnet RPC prohibited")
    if values.get("MANAGED_SIGNER_A_PUBLIC_KEY") == values.get("MANAGED_SIGNER_B_PUBLIC_KEY"):
        errors.append("managed signer public keys must be distinct")
    if values.get("ALERT_RECEIVER_CONFIGURED") != "1": errors.append("real alert receiver is not configured")
    try:
        observed = rpc(values.get("RPC_URL", ""), "getGenesisHash")
        if observed != values.get("EXPECTED_CLUSTER_GENESIS_HASH"):
            errors.append(f"RPC genesis mismatch: {observed}")
    except Exception as exc:
        errors.append(f"RPC genesis query failed: {exc}")
    public = json.loads((ROOT / "deploy/environments/public-devnet.json").read_text())
    if public.get("expected_program_id") != values.get("EXPECTED_PROPHET_PROGRAM_ID"):
        errors.append("runtime program ID differs from public-devnet configuration")
    if errors:
        print("PUBLIC DEVNET RUNTIME PREFLIGHT BLOCKED")
        for error in errors: print(f"- {error}")
        return 2
    print("PUBLIC DEVNET RUNTIME PREFLIGHT PASSED")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
