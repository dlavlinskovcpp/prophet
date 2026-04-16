#!/usr/bin/env python3
import base64
import json
import sys
from pathlib import Path

# Allow `python scripts/...` to import the adjacent `src` package reliably.
SCRIPT_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from solders.pubkey import Pubkey

from src.vault_transit import (
    VaultTransitClient,
    VaultTransitConfig,
    resolve_vault_key_name,
)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:
        print(json.dumps({"error": f"invalid input json: {exc}"}), file=sys.stderr)
        return 2

    if not isinstance(payload, dict):
        print(json.dumps({"error": "input payload must be a JSON object"}), file=sys.stderr)
        return 2

    public_key = str(payload.get("public_key", "")).strip()
    message_b64 = str(payload.get("message_b64", "")).strip()
    if not public_key or not message_b64:
        print(json.dumps({"error": "public_key and message_b64 are required"}), file=sys.stderr)
        return 2

    try:
        normalized_pubkey = str(Pubkey.from_string(public_key))
    except Exception as exc:
        print(json.dumps({"error": f"invalid public_key: {exc}"}), file=sys.stderr)
        return 2

    try:
        message = base64.b64decode(message_b64, validate=True)
    except Exception as exc:
        print(json.dumps({"error": f"invalid message_b64: {exc}"}), file=sys.stderr)
        return 2

    try:
        config = VaultTransitConfig.from_env()
        with VaultTransitClient(config) as client:
            key_name = resolve_vault_key_name(
                normalized_pubkey,
                client=client,
                key_name=config.key_name,
                key_map_path=config.key_map_path,
            )
            signature = client.sign(key_name, message)
    except PermissionError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 3
    except Exception as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "public_key": normalized_pubkey,
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
