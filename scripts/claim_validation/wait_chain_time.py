#!/usr/bin/env python3
import base64
import sys
import time

from solana.rpc.api import Client
from solders.pubkey import Pubkey

CLOCK_SYSVAR = Pubkey.from_string("SysvarC1ock11111111111111111111111111111111")


def extract_account_bytes(account_data) -> bytes:
    if isinstance(account_data, (bytes, bytearray, memoryview)):
        return bytes(account_data)
    if isinstance(account_data, (list, tuple)):
        if len(account_data) >= 1 and isinstance(account_data[0], str):
            return base64.b64decode(account_data[0])
    if isinstance(account_data, str):
        return base64.b64decode(account_data)
    if hasattr(account_data, "decoded"):
        return extract_account_bytes(getattr(account_data, "decoded"))
    if hasattr(account_data, "data"):
        return extract_account_bytes(getattr(account_data, "data"))
    raise RuntimeError(f"Unknown account data format: {type(account_data)}")


def chain_now(rpc: Client) -> int:
    try:
        resp = rpc.get_account_info(CLOCK_SYSVAR)
        value = getattr(resp, "value", None)
        if value is not None and getattr(value, "data", None) is not None:
            raw = extract_account_bytes(value.data)
            if len(raw) >= 40:
                return int.from_bytes(raw[32:40], "little", signed=True)
    except Exception:
        pass
    return int(time.time())


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: wait_chain_time.py <rpc_url> <target_ts>", file=sys.stderr)
        return 2

    rpc_url = sys.argv[1]
    target = int(sys.argv[2])
    rpc = Client(rpc_url)

    for _ in range(120):
        now = chain_now(rpc)
        if now >= target:
            print(now)
            return 0
        time.sleep(1)

    print(f"timeout waiting for chain time >= {target}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
