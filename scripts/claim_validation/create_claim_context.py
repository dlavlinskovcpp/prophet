#!/usr/bin/env python3
import base64
import json
import os
import random
import time

from solana.rpc.commitment import Confirmed
from solders.pubkey import Pubkey

from prophet_sdk.client import ProphetClient
from prophet_sdk.pdas import derive_claim_pda

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


def chain_now(client_obj: ProphetClient) -> int:
    try:
        resp = client_obj.client.get_account_info(CLOCK_SYSVAR, commitment=Confirmed)
        value = getattr(resp, "value", None)
        data_obj = getattr(value, "data", None) if value is not None else None
        if data_obj is not None:
            raw = extract_account_bytes(data_obj)
            if len(raw) >= 40:
                return int.from_bytes(raw[32:40], "little", signed=True)
    except Exception:
        pass
    return int(time.time())


def get_token_balance_atoms(client_obj: ProphetClient, ata: Pubkey, label: str) -> int:
    last = None
    for _ in range(50):
        try:
            resp = client_obj.client.get_token_account_balance(ata, commitment=Confirmed)
            last = resp
            value = getattr(resp, "value", None)
            amount = getattr(value, "amount", None) if value is not None else None
            if amount is not None:
                return int(amount)
        except Exception as exc:
            last = exc
        time.sleep(0.2)
    raise SystemExit(
        f"Failed to read token balance for {label} ({ata}). Last response/error: {last}"
    )


def main() -> int:
    rpc_url = os.environ["RPC_URL"]
    program_id = os.environ["PROPHET_PROGRAM_ID"]
    wallet_path = os.environ["WALLET_PATH"]
    quote_mint = Pubkey.from_string(os.environ["QUOTE_MINT"])
    issuer_ata = Pubkey.from_string(os.environ["ISSUER_ATA"])
    fail_recipient = Pubkey.from_string(os.environ["FAIL_RECIPIENT_PUBKEY"])
    oracle_pubkey_token_ctx = Pubkey.from_string(os.environ["ORACLE_PUBKEY_TOKEN_CTX"])
    resolver_hash = bytes.fromhex(os.environ["RESOLVER_HASH"])
    bond_atoms = int(os.environ["BOND_ATOMS"])

    client = ProphetClient(rpc_url=rpc_url, payer_keypair_path=wallet_path, program_id=program_id)
    issuer = client.payer.pubkey()

    if issuer != oracle_pubkey_token_ctx:
        raise SystemExit(
            f"Oracle pubkey mismatch: wallet={issuer} token_ctx={oracle_pubkey_token_ctx}"
        )

    resolve_ts = chain_now(client) + 30

    def claim_matches(pubkey: Pubkey, cid: int) -> bool:
        acc = client.fetch_claim(pubkey)
        if acc is None:
            return False
        return (
            int(acc.claim_id) == int(cid)
            and acc.issuer == issuer
            and acc.quote_mint == quote_mint
            and int(acc.bond_atoms) == int(bond_atoms)
            and acc.resolver_hash == resolver_hash
        )

    claim_id = None
    expected_claim_pubkey = None
    for _ in range(16):
        candidate = random.getrandbits(64)
        pda, _ = derive_claim_pda(issuer, candidate, client.program_id)
        if client.fetch_claim(pda) is None:
            claim_id = candidate
            expected_claim_pubkey = pda
            break

    if claim_id is None or expected_claim_pubkey is None:
        raise SystemExit("Failed to allocate unique claim_id for test flow")

    balance_before_create = get_token_balance_atoms(client, issuer_ata, "issuer_ata_before_create")

    last_err = None
    claim_pubkey = None
    create_sig = None
    for _ in range(6):
        try:
            claim_pubkey, create_sig = client.create_claim(
                claim_id=claim_id,
                resolver_hash=resolver_hash,
                resolve_ts=resolve_ts,
                bond_atoms=bond_atoms,
                pass_recipient=issuer,
                fail_recipient=fail_recipient,
                quote_mint=quote_mint,
                oracle_authority=oracle_pubkey_token_ctx,
                notary_config=Pubkey.default(),
                issuer_quote_ata=issuer_ata,
            )
            break
        except Exception as exc:
            last_err = exc
            msg = str(exc)
            if "6022" in msg or "InvalidTimeRange" in msg:
                resolve_ts = chain_now(client) + 45
                time.sleep(0.4)
                continue
            # System/ATA custom(0) can occur when the first tx landed and
            # the retry hits account already in use.
            if (
                "InstructionErrorCustom(0)" in msg
                or "Custom(InstructionErrorCustom(0))" in msg
                or "custom(0)" in msg
            ):
                if claim_matches(expected_claim_pubkey, claim_id):
                    claim_pubkey = expected_claim_pubkey
                    create_sig = "already_created_on_chain"
                    break
            raise

    if claim_pubkey is None or create_sig is None:
        raise SystemExit(f"create_claim failed after retries: {last_err}")

    balance_after_create = get_token_balance_atoms(client, issuer_ata, "issuer_ata_after_create")

    if balance_before_create - balance_after_create != bond_atoms:
        raise SystemExit("SDK create_claim did not escrow expected bond amount")

    claim_acc = client.fetch_claim(claim_pubkey)
    if claim_acc is None:
        raise SystemExit("Claim account not found after create_claim")
    if claim_acc.pass_recipient != issuer:
        raise SystemExit("Claim pass_recipient mismatch")
    if claim_acc.fail_recipient != fail_recipient:
        raise SystemExit("Claim fail_recipient mismatch")
    if claim_acc.oracle_authority != oracle_pubkey_token_ctx:
        raise SystemExit("Claim oracle_authority mismatch")

    print(
        json.dumps(
            {
                "claim_pubkey": str(claim_pubkey),
                "claim_id": claim_id,
                "create_sig": create_sig,
                "resolve_ts": resolve_ts,
                "quote_mint": str(quote_mint),
                "issuer_ata": str(issuer_ata),
                "fail_recipient_pubkey": str(fail_recipient),
                "bond_atoms": bond_atoms,
                "oracle_pubkey": str(oracle_pubkey_token_ctx),
                "issuer_balance_before_create": balance_before_create,
                "issuer_balance_after_create": balance_after_create,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
