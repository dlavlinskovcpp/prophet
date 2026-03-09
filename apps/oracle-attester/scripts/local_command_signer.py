#!/usr/bin/env python3
import base64
import json
import sys
from typing import Dict

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from src.config import settings


def _load_signers() -> Dict[str, Keypair]:
    raw = (settings.NOTARY_KEYPAIR_PATHS or "").strip()
    if raw:
        sources = [item.strip() for item in raw.split(",") if item.strip()]
    else:
        sources = [settings.ORACLE_KEYPAIR_PATH]

    signers: Dict[str, Keypair] = {}
    for src in sources:
        kp = settings._load_keypair(src)
        if kp is None:
            continue
        signers[str(kp.pubkey())] = kp
    return signers


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
        pubkey = Pubkey.from_string(public_key)
    except Exception as exc:
        print(json.dumps({"error": f"invalid public_key: {exc}"}), file=sys.stderr)
        return 2

    try:
        message = base64.b64decode(message_b64, validate=True)
    except Exception as exc:
        print(json.dumps({"error": f"invalid message_b64: {exc}"}), file=sys.stderr)
        return 2

    signers = _load_signers()
    signer = signers.get(str(pubkey))
    if signer is None:
        print(json.dumps({"error": f"signer key unavailable for {pubkey}"}), file=sys.stderr)
        return 3

    signature = bytes(signer.sign_message(message))
    print(
        json.dumps(
            {
                "public_key": str(pubkey),
                "signature_b64": base64.b64encode(signature).decode("ascii"),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
