#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

# Allow `python scripts/...` to import the adjacent `src` package reliably.
SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from src.signer_ops import json_dumps, write_allowlist_file
from src.vault_transit import (
    build_vault_transit_config,
    bootstrap_vault_transit_keys,
    write_vault_key_map_file,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve Vault Transit Ed25519 keys into Prophet notary pubkeys."
    )
    parser.add_argument(
        "--vault-addr",
        default=os.getenv("VAULT_ADDR", ""),
        help="Vault base URL. Defaults to VAULT_ADDR.",
    )
    parser.add_argument(
        "--namespace",
        default=os.getenv("VAULT_NAMESPACE", ""),
        help="Optional Vault namespace. Defaults to VAULT_NAMESPACE.",
    )
    parser.add_argument(
        "--token",
        default="",
        help="Vault token. Prefer --token-file or VAULT_TOKEN_FILE for operators.",
    )
    parser.add_argument(
        "--token-file",
        default=os.getenv("VAULT_TOKEN_FILE", ""),
        help="Path to a file containing the Vault token. Defaults to VAULT_TOKEN_FILE.",
    )
    parser.add_argument(
        "--mount",
        default=os.getenv("VAULT_TRANSIT_MOUNT", "transit"),
        help="Transit mount path. Defaults to VAULT_TRANSIT_MOUNT or 'transit'.",
    )
    parser.add_argument(
        "--key-name",
        action="append",
        default=[],
        help="Vault Transit key name. Repeat for multiple keys.",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=float(str(os.getenv("VAULT_TRANSIT_TIMEOUT_S", "5")).strip()),
        help="Vault client timeout in seconds.",
    )
    parser.add_argument(
        "--cacert",
        default=os.getenv("VAULT_CACERT", ""),
        help="Optional custom CA bundle path for Vault TLS.",
    )
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        default=str(os.getenv("VAULT_SKIP_VERIFY", "")).strip().lower()
        in {"1", "true", "yes", "y", "on"},
        help="Disable Vault TLS certificate verification.",
    )
    parser.add_argument(
        "--create-missing",
        action="store_true",
        help="Create missing Vault Transit keys as type=ed25519 before resolving them.",
    )
    parser.add_argument(
        "--exportable",
        action="store_true",
        help="Create missing keys with exportable=true.",
    )
    parser.add_argument(
        "--allow-plaintext-backup",
        action="store_true",
        help="Create missing keys with allow_plaintext_backup=true.",
    )
    parser.add_argument(
        "--output-allowlist",
        default="",
        help="Optional path to write a normalized signer allowlist file.",
    )
    parser.add_argument(
        "--output-key-map",
        default="",
        help="Optional path to write the Vault Transit pubkey->key_name map JSON.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    key_names = args.key_name or [os.getenv("VAULT_TRANSIT_KEY_NAMES", "")]
    try:
        config = build_vault_transit_config(
            addr=str(args.vault_addr).strip(),
            namespace=str(args.namespace).strip(),
            token=str(args.token).strip(),
            token_file=str(args.token_file).strip(),
            mount=str(args.mount).strip() or "transit",
            timeout_s=float(args.timeout_s),
            cacert=str(args.cacert).strip(),
            skip_verify=bool(args.skip_verify),
        )

        payload = bootstrap_vault_transit_keys(
            config=config,
            key_names=key_names,
            create_missing=args.create_missing,
            exportable=args.exportable,
            allow_plaintext_backup=args.allow_plaintext_backup,
        )
        payload["ok"] = True

        if args.output_allowlist:
            payload["allowlist_written_to"] = args.output_allowlist
            payload["allowlist_pubkeys"] = write_allowlist_file(
                args.output_allowlist,
                payload["allowlist_pubkeys"],
            )
        if args.output_key_map:
            write_vault_key_map_file(args.output_key_map, payload["key_map"])
            payload["key_map_written_to"] = args.output_key_map

        print(json_dumps(payload))
        return 0
    except Exception as exc:
        print(json_dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
