#!/usr/bin/env python3
"""Fail-closed, no-broadcast preflight for the public-devnet runtime."""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "RPC_URL", "EXPECTED_CLUSTER", "EXPECTED_CLUSTER_GENESIS_HASH",
    "EXPECTED_PROPHET_PROGRAM_ID", "SIGNER_POLICY_VERSION",
    "MANAGED_SIGNER_A_PUBLIC_KEY", "MANAGED_SIGNER_B_PUBLIC_KEY",
    "ALERT_RECEIVER_CONFIGURED", "RESOLUTION_MODE",
    "DIRECT_ATTESTER_SETTLEMENT_ENABLED",
    "GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED",
    "VERIFIER_A_URL", "VERIFIER_B_URL",
    "VERIFIER_A_IDENTITY", "VERIFIER_B_IDENTITY",
    "VERIFIER_A_AUTH_REF", "VERIFIER_B_AUTH_REF",
    "VERIFIER_A_PROOF_BACKEND_URL", "VERIFIER_B_PROOF_BACKEND_URL",
    "COORDINATOR_URL", "COORDINATOR_SQLITE_PATH",
    "SIGNING_JOURNAL_PATH", "SUBMISSION_JOURNAL_PATH",
    "SIGNER_A_IDENTITY", "SIGNER_B_IDENTITY",
    "SIGNER_A_VAULT_KEY", "SIGNER_B_VAULT_KEY",
    "SIGNER_A_AUTH_REF", "SIGNER_B_AUTH_REF",
    "STRICT_SIGNER_COUNT",
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


def _persistent(value: str) -> bool:
    return bool(value and value != ":memory:" and Path(value).is_absolute())


def _compose_services(path: Path) -> set[str]:
    services: set[str] = set()
    in_services = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "services:":
            in_services = True
            continue
        if in_services and line and not line.startswith(" "):
            break
        if in_services and line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            services.add(line.strip()[:-1])
    return services


def topology_errors(values: dict[str, str], *, compose_path: Path) -> tuple[list[str], list[str]]:
    code: list[str] = []
    infra: list[str] = []
    for key in REQUIRED:
        if not values.get(key):
            (code if key in {"RESOLUTION_MODE", "DIRECT_ATTESTER_SETTLEMENT_ENABLED", "GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED", "VERIFIER_A_URL", "VERIFIER_B_URL", "VERIFIER_A_IDENTITY", "VERIFIER_B_IDENTITY", "VERIFIER_A_AUTH_REF", "VERIFIER_B_AUTH_REF", "VERIFIER_A_PROOF_BACKEND_URL", "VERIFIER_B_PROOF_BACKEND_URL", "COORDINATOR_URL", "COORDINATOR_SQLITE_PATH", "SIGNING_JOURNAL_PATH", "SUBMISSION_JOURNAL_PATH", "MANAGED_SIGNER_A_PUBLIC_KEY", "MANAGED_SIGNER_B_PUBLIC_KEY", "SIGNER_A_IDENTITY", "SIGNER_B_IDENTITY", "SIGNER_A_VAULT_KEY", "SIGNER_B_VAULT_KEY", "SIGNER_A_AUTH_REF", "SIGNER_B_AUTH_REF", "STRICT_SIGNER_COUNT"} else infra).append(f"missing {key}")
        elif values[key].startswith(("REPLACE_", "CONFIGURE_")):
            infra.append(f"unresolved {key}")
    if values.get("EXPECTED_CLUSTER") != "devnet":
        code.append("EXPECTED_CLUSTER must be devnet")
    if "mainnet" in values.get("RPC_URL", "").lower():
        code.append("mainnet RPC prohibited")
    if values.get("RESOLUTION_MODE") != "secure-coordinator":
        code.append("RESOLUTION_MODE must be secure-coordinator")
    if values.get("DIRECT_ATTESTER_SETTLEMENT_ENABLED") != "0":
        code.append("direct attester settlement must be disabled")
    if values.get("GENERIC_REMOTE_SIGNER_SETTLEMENT_ENABLED") != "0":
        code.append("generic remote signer settlement must be disabled")
    if values.get("STRICT_SIGNER_COUNT") != "2":
        code.append("strict 2/2 signer count required")
    if values.get("VERIFIER_A_URL", "").rstrip("/") == values.get("VERIFIER_B_URL", "").rstrip("/"):
        code.append("verifier A/B URLs must be distinct")
    if values.get("VERIFIER_A_IDENTITY") == values.get("VERIFIER_B_IDENTITY"):
        code.append("verifier A/B identities must be distinct")
    if values.get("VERIFIER_A_AUTH_REF") == values.get("VERIFIER_B_AUTH_REF"):
        code.append("verifier A/B auth references must be distinct")
    if values.get("VERIFIER_A_PROOF_BACKEND_URL", "").rstrip("/") == values.get("VERIFIER_B_PROOF_BACKEND_URL", "").rstrip("/"):
        code.append("verifier A/B proof backends must be distinct")
    if values.get("MANAGED_SIGNER_A_PUBLIC_KEY") == values.get("MANAGED_SIGNER_B_PUBLIC_KEY"):
        code.append("managed signer public keys must be distinct")
    if values.get("SIGNER_A_IDENTITY") == values.get("SIGNER_B_IDENTITY"):
        code.append("signer identities must be distinct")
    if values.get("SIGNER_A_VAULT_KEY") == values.get("SIGNER_B_VAULT_KEY"):
        code.append("Vault signer keys must be distinct")
    if values.get("SIGNER_A_AUTH_REF") == values.get("SIGNER_B_AUTH_REF"):
        code.append("Vault signer auth references must be distinct")
    for key in ("COORDINATOR_SQLITE_PATH", "SIGNING_JOURNAL_PATH", "SUBMISSION_JOURNAL_PATH"):
        if values.get(key) and not _persistent(values[key]):
            code.append(f"{key} must be a persistent absolute path")
    required_services = {"verifier-a", "verifier-b", "coordinator", "secure-settlement"}
    services = _compose_services(compose_path)
    for name in sorted(required_services - services):
        code.append(f"compose missing {name}")
    for name in ("oracle-attester", "remote-signer"):
        if name in services:
            code.append(f"legacy settlement service present in production compose: {name}")
    if values.get("ALERT_RECEIVER_CONFIGURED") != "1":
        infra.append("real alert receiver is not configured")
    return code, infra


def main() -> int:
    path = Path(os.getenv("RUNTIME_ENV", "/etc/prophet/public-devnet/runtime.env"))
    if not path.exists():
        print(f"BLOCKED: runtime environment file missing: {path}")
        return 2
    values = load_env(path)
    code, infra = topology_errors(
        values,
        compose_path=ROOT / "deploy/operated/public-devnet/docker-compose.yml",
    )
    try:
        observed = rpc(values.get("RPC_URL", ""), "getGenesisHash")
        if observed != values.get("EXPECTED_CLUSTER_GENESIS_HASH"):
            infra.append(f"RPC genesis mismatch: {observed}")
    except Exception as exc:
        infra.append(f"RPC genesis query failed: {exc}")
    public = json.loads((ROOT / "deploy/environments/public-devnet.json").read_text())
    if public.get("expected_program_id") != values.get("EXPECTED_PROPHET_PROGRAM_ID"):
        code.append("runtime program ID differs from public-devnet configuration")
    if code or infra:
        print("PUBLIC DEVNET RUNTIME PREFLIGHT BLOCKED")
        for error in code:
            print(f"- CODE/CONFIG: {error}")
        for error in infra:
            print(f"- INFRA: {error}")
        return 2
    print("PUBLIC DEVNET RUNTIME PREFLIGHT PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
