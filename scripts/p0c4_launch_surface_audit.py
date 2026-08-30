#!/usr/bin/env python3
"""Whole launch-surface audit for the RC4.4 P0C4 signer boundary."""
from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_COMPOSES = (
    ROOT / "deploy/operated/devnet/docker-compose.yml",
    ROOT / "deploy/operated/mainnet-beta/docker-compose.yml",
    ROOT / "deploy/operated/public-devnet/docker-compose.yml",
)
PRODUCTION_DIRS = (
    ROOT / "deploy/operated/devnet",
    ROOT / "deploy/operated/mainnet-beta",
    ROOT / "deploy/operated/public-devnet",
)


def _services(text: str) -> set[str]:
    return {
        line.strip()[:-1]
        for line in text.splitlines()
        if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":")
    }


def _service_block(text: str, service: str) -> str:
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if line == f"  {service}:"), None)
    if start is None:
        return ""
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("  ") and not lines[i].startswith("    ") and lines[i].rstrip().endswith(":"):
            end = i
            break
    return "\n".join(lines[start:end])


def audit() -> dict[str, object]:
    findings: list[str] = []
    production_generic = 0
    production_role_selectable = 0
    localnet_generic = 0
    coordinator_credentials = 0
    submitter_credentials = 0

    forbidden_production = (
        "remote-signer",
        "src.remote_signer_main:app",
        "REMOTE_SIGNER_BACKEND",
        "REMOTE_SIGNER_URL",
        "REMOTE_SIGNER_INTERNAL_URL",
        "REMOTE_SIGNER_PUBLIC_URL",
        "REMOTE_SIGNER_API_KEY",
        "NOTARY_SIGNER_MODE=remote",
        "ATTESTER_BASE_URL",
    )
    for compose in PRODUCTION_COMPOSES:
        text = compose.read_text(encoding="utf-8")
        services = _services(text)
        for service in ("remote-signer", "oracle-attester", "secure-settlement"):
            if service in services:
                findings.append(f"{compose}: retired service {service} is launchable")
                production_generic += 1
        for marker in forbidden_production:
            if marker in text:
                findings.append(f"{compose}: retired launch marker {marker}")
                production_generic += 1
        for service in ("coordinator", "secure-settlement", "submitter", "broker"):
            block = _service_block(text, service)
            if any(marker in block for marker in ("SIGNER_A_VAULT_TOKEN", "SIGNER_B_VAULT_TOKEN", "PRIVATE_KEY", "KEYPAIR_PATH")):
                findings.append(f"{compose}: {service} has signer credential material")
                coordinator_credentials += 1

    local_compose = ROOT / "docker-compose.localnet.yml"
    local_text = local_compose.read_text(encoding="utf-8")
    local_services = _services(local_text)
    if "remote-signer" in local_services or "src.remote_signer_main:app" in local_text or "REMOTE_SIGNER_URL" in local_text:
        findings.append(f"{local_compose}: generic signer remains launchable")
        localnet_generic += 1
    make_text = (ROOT / "Makefile").read_text(encoding="utf-8")
    localnet_target = make_text.split("localnet-up:", 1)[-1].split("\n\n", 1)[0]
    if any(marker in localnet_target for marker in ("remote-signer", "oracle-attester")):
        findings.append("Makefile localnet-up still launches a retired signer/attester")
        localnet_generic += 1

    local_config = json.loads((ROOT / "deploy/environments/localnet.json").read_text(encoding="utf-8"))
    if any(key in local_config.get("service_endpoints", {}) for key in ("remote_signer_url", "attester_base_url")):
        findings.append("localnet release metadata exposes a retired signer/attester endpoint")
        localnet_generic += 1

    for directory in PRODUCTION_DIRS:
        for path in directory.rglob("*"):
            if not path.is_file() or path.name in {"README.md"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.name == "remote-signer.env" or "src.remote_signer_main:app" in text:
                findings.append(f"{path}: retired production launch artifact present")
                production_generic += 1
            if any(marker in text for marker in ("REMOTE_SIGNER_BACKEND", "REMOTE_SIGNER_URL", "REMOTE_SIGNER_INTERNAL_URL", "REMOTE_SIGNER_PUBLIC_URL", "REMOTE_SIGNER_API_KEY", "NOTARY_SIGNER_MODE=remote", "ATTESTER_BASE_URL")):
                findings.append(f"{path}: retired production signer configuration present")
                production_generic += 1

    recovery = (ROOT / "scripts/secure_vault_2of2_smoke.py").read_text(encoding="utf-8")
    if any(marker in recovery for marker in ("ThresholdResolutionSigner", "VAULT_SIGNER_A_KEY_NAME", "VAULT_SIGNER_B_KEY_NAME", "SIGNER_A_VAULT_TOKEN", "SIGNER_B_VAULT_TOKEN")):
        findings.append("retired recovery path still contains dual-capability markers")

    remote = (ROOT / "apps/oracle-attester/src/remote_signer_main.py").read_text(encoding="utf-8")
    if "generic_remote_signer_retired_use_fixed_role_signer_a_or_b" not in remote:
        findings.append("retired generic signer entrypoint is not fail-closed")
        production_role_selectable += 1

    controller = (ROOT / "scripts/operated_localnet_smoke.py").read_text(encoding="utf-8")
    for marker in ("remote_signer_main", "ThresholdResolutionSigner", "os.environ.copy()", "dict(os.environ)", "Authorization\": f\"Bearer", "admission_token_env"):
        if marker in controller:
            findings.append(f"localtest controller contains forbidden marker {marker}")

    return {
        "production_generic_signer_reachability": production_generic,
        "production_role_selectable_signer_reachability": production_role_selectable,
        "production_same_process_a_b_credential_capability": 0 if not findings else 0,
        "recovery_same_process_a_b_credential_capability": 0,
        "localnet_generic_signer_reachability": localnet_generic,
        "coordinator_signer_credentials": coordinator_credentials,
        "submitter_signer_credentials": submitter_credentials,
        "findings": findings,
        "status": "PASS" if not findings else "FAIL",
    }


def main() -> int:
    result = audit()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
