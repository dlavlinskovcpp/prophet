#!/usr/bin/env python3
"""Inspect an operated quote mint and fail closed on Token-2022/unknown programs."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from solana.rpc.api import Client
from solders.pubkey import Pubkey


LEGACY_TOKEN_PROGRAM = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
TOKEN_2022_PROGRAM = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuTb")


def _bytes(data: object) -> bytes:
    if isinstance(data, (list, tuple)) and data and isinstance(data[0], str):
        return base64.b64decode(data[0])
    if isinstance(data, str):
        return base64.b64decode(data)
    raise ValueError("unsupported RPC account encoding")


def inspect(rpc_url: str, mint: Pubkey) -> dict[str, object]:
    response = Client(rpc_url).get_account_info(mint, encoding="base64")
    if response.value is None:
        raise ValueError("quote mint account not found")
    owner = Pubkey.from_string(str(response.value.owner))
    raw = _bytes(response.value.data)
    if len(raw) < 82:
        raise ValueError("quote mint account data is too short")
    result = {
        "mint": str(mint),
        "program": str(owner),
        "program_class": "legacy-spl-token" if owner == LEGACY_TOKEN_PROGRAM else "token-2022" if owner == TOKEN_2022_PROGRAM else "unsupported",
        "decimals": raw[44],
        "mint_authority_present": int.from_bytes(raw[0:4], "little") != 0,
        "freeze_authority_present": int.from_bytes(raw[46:50], "little") != 0,
    }
    if owner != LEGACY_TOKEN_PROGRAM:
        raise ValueError(json.dumps(result, sort_keys=True))
    approved = os.getenv("PROPHET_APPROVED_QUOTE_MINT", "").strip()
    if approved and approved != str(mint):
        raise ValueError("quote mint is not the operated approved asset")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mint")
    parser.add_argument("--rpc-url", default=os.getenv("RPC_URL", "http://127.0.0.1:8899"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.rpc_url, Pubkey.from_string(args.mint))
    except Exception as exc:
        print(f"QUOTE MINT REJECTED: {exc}")
        return 1
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
