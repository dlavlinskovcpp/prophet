#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ATTESTER_DIR = ROOT / "apps" / "oracle-attester"
if str(ATTESTER_DIR) not in sys.path:
    sys.path.insert(0, str(ATTESTER_DIR))

from src.runtime_config import parse_runtime_config
from src.vault_transit import VaultTransitConfig, bootstrap_vault_transit_keys
from src.vault_transit_signer_identity import VaultTransitSignerClient
from src.vault_transit_threshold_signer import ThresholdResolutionSigner


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def main() -> int:
    vault_addr = required("VAULT_ADDR")
    vault_token = required("VAULT_TOKEN")
    key_a = required("VAULT_SIGNER_A_KEY_NAME")
    key_b = required("VAULT_SIGNER_B_KEY_NAME")
    if key_a == key_b:
        raise SystemExit("Vault signer A/B key names must be distinct")

    mount = os.getenv("VAULT_TRANSIT_MOUNT", "transit").strip() or "transit"
    timeout_s = float(os.getenv("VAULT_TRANSIT_TIMEOUT_S", "5"))
    label = os.getenv("RC3_VAULT_SMOKE_LABEL", "initial").strip() or "initial"

    config = VaultTransitConfig(
        addr=vault_addr.rstrip("/"),
        namespace="",
        token=vault_token,
        mount=mount,
        timeout_s=timeout_s,
        cacert="",
        skip_verify=False,
        key_name="",
        key_map_path="",
    )
    bootstrap = bootstrap_vault_transit_keys(
        config=config,
        key_names=[key_a, key_b],
        create_missing=False,
    )
    keys = bootstrap["keys"]
    if len(keys) != 2:
        raise SystemExit("expected exactly two Vault Transit keys")

    by_name = {str(item["key_name"]): item for item in keys}
    a = by_name[key_a]
    b = by_name[key_b]
    if a["solana_pubkey"] == b["solana_pubkey"]:
        raise SystemExit("Vault signer A/B public identities collapsed")

    version_a = int(a["latest_version"])
    version_b = int(b["latest_version"])
    if version_a <= 0 or version_b <= 0:
        raise SystemExit("Vault signer key versions must be positive")

    raw = {
        "schema_version": 1,
        "environment": "localtest",
        "mode": "test",
        "solana": {
            "cluster": "localnet",
            "genesis_hash": "localnet-live-vault-smoke",
            "prophet_program_id": "11111111111111111111111111111111",
        },
        "resolver_v2": {"schema_version": 2},
        "verifier": {"implementation_id": "rc3-live-vault-smoke", "version": "1"},
        "allowed_adapters": ["pyth"],
        "limits": {"request_max_bytes": 1024, "request_timeout_seconds": 5},
        "freshness": {
            "default_max_evidence_age_seconds": 60,
            "default_max_verification_age_seconds": 60,
        },
        "internal_auth": {"token_env": "RC3_UNUSED_INTERNAL_TOKEN"},
        "signing": {
            "vault": {
                "address": vault_addr,
                "auth": {"token_env": "VAULT_TOKEN"},
                "transit_mount": mount,
                "request_timeout_seconds": max(1, int(timeout_s)),
                "backend": "vault-transit",
            },
            "signers": {
                "a": {
                    "signer_id": "signer-a",
                    "key_name": key_a,
                    "expected_public_key": str(a["solana_pubkey"]),
                    "expected_key_version": version_a,
                },
                "b": {
                    "signer_id": "signer-b",
                    "key_name": key_b,
                    "expected_public_key": str(b["solana_pubkey"]),
                    "expected_key_version": version_b,
                },
            },
        },
    }
    runtime = parse_runtime_config(raw)
    signer_a = VaultTransitSignerClient.from_runtime(runtime, slot="A")
    signer_b = VaultTransitSignerClient.from_runtime(runtime, slot="B")
    try:
        threshold = ThresholdResolutionSigner(signer_a=signer_a, signer_b=signer_b)
        label_bytes = label.encode("utf-8")
        message = (
            b"PROPHET_RC3_SECURE_VAULT_2OF2_SMOKE\0"
            + label_bytes
            + b"\0"
            + hashlib.sha256(label_bytes).digest()
        )
        bundle = threshold.sign_2_of_2(message)
        threshold.validate_bundle(bundle, message)
        if bundle.signer_a_public_key == bundle.signer_b_public_key:
            raise SystemExit("threshold bundle contains duplicate signer identities")
        print(f"label={label}")
        print(f"signer_a_pubkey={bundle.signer_a_public_key}")
        print(f"signer_a_key_version={bundle.signer_a_key_version}")
        print(f"signer_b_pubkey={bundle.signer_b_public_key}")
        print(f"signer_b_key_version={bundle.signer_b_key_version}")
        print(f"canonical_message_sha256={bundle.canonical_message_digest}")
        print("RC3_SECURE_VAULT_2OF2_SMOKE_PASSED")
        return 0
    finally:
        signer_a.close()
        signer_b.close()


if __name__ == "__main__":
    raise SystemExit(main())
