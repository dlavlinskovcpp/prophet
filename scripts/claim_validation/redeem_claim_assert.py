#!/usr/bin/env python3
import base64
import json
import os
import time

from solana.rpc.commitment import Confirmed
from solders.keypair import Keypair
from solders.pubkey import Pubkey

from prophet_sdk.client import ProphetClient
from prophet_sdk.types import ClaimStatus


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
    claim_pubkey = Pubkey.from_string(os.environ["CLAIM_PUBKEY"])
    claim_outcome = os.environ["CLAIM_OUTCOME"].upper()
    bond_atoms = int(os.environ["BOND_ATOMS"])

    issuer_ata = Pubkey.from_string(os.environ["ISSUER_ATA"])
    issuer_bal_before_create = int(os.environ["ISSUER_BAL_BEFORE_CREATE"])
    issuer_bal_after_create = int(os.environ["ISSUER_BAL_AFTER_CREATE"])

    fail_recipient = Pubkey.from_string(os.environ["FAIL_RECIPIENT_PUBKEY"])
    fail_ata = Pubkey.from_string(os.environ["FAIL_RECIPIENT_ATA"])
    fail_secret_b64 = os.environ["FAIL_RECIPIENT_SECRET_B64"]

    client = ProphetClient(rpc_url=rpc_url, payer_keypair_path=wallet_path, program_id=program_id)
    fail_signer = Keypair.from_bytes(base64.b64decode(fail_secret_b64))
    if fail_signer.pubkey() != fail_recipient:
        raise SystemExit("Fail recipient keypair/pubkey mismatch")

    before = client.fetch_claim(claim_pubkey)
    if before is None:
        raise SystemExit("Claim account not found before redeem_claim")
    if before.status != ClaimStatus.Resolved:
        raise SystemExit(f"Claim is not Resolved before redeem, status={before.status}")

    redeem_sig = None
    try:
        if claim_outcome == "PASS":
            redeem_sig = client.redeem_claim(claim_pubkey)
        elif claim_outcome in ("FAIL", "INVALID"):
            redeem_sig = client.redeem_claim(
                claim_pubkey,
                recipient_keypair=fail_signer,
                recipient_quote_ata=fail_ata,
            )
        else:
            raise SystemExit(f"Unsupported CLAIM_OUTCOME for validation: {claim_outcome}")
    except Exception as exc:
        msg = str(exc)
        # If first submit landed but client retried/timed out,
        # on-chain may already be redeemed.
        if "6042" in msg or "ClaimAlreadyRedeemed" in msg:
            redeem_sig = "already_redeemed_on_chain"
        else:
            raise

    after = client.fetch_claim(claim_pubkey)
    if after is None:
        raise SystemExit("Claim account not found after redeem_claim")
    if after.status != ClaimStatus.Redeemed:
        raise SystemExit(f"Claim is not Redeemed after redeem, status={after.status}")

    vault_balance = get_token_balance_atoms(client, after.quote_vault, "claim_quote_vault_after_redeem")
    issuer_balance = get_token_balance_atoms(client, issuer_ata, "issuer_ata_after_redeem")
    fail_balance = get_token_balance_atoms(client, fail_ata, "fail_recipient_ata_after_redeem")

    if claim_outcome == "PASS":
        expected_issuer_balance = issuer_bal_before_create
        expected_fail_balance = 0
    else:
        expected_issuer_balance = issuer_bal_after_create
        expected_fail_balance = bond_atoms

    if issuer_balance != expected_issuer_balance:
        raise SystemExit(
            f"Unexpected issuer ATA balance: got={issuer_balance} expected={expected_issuer_balance}"
        )
    if fail_balance != expected_fail_balance:
        raise SystemExit(
            f"Unexpected fail-recipient ATA balance: got={fail_balance} expected={expected_fail_balance}"
        )
    if vault_balance != 0:
        raise SystemExit(f"Claim vault not empty after redeem: {vault_balance}")

    print(
        json.dumps(
            {
                "redeem_sig": redeem_sig,
                "claim_pubkey": str(claim_pubkey),
                "claim_status_after": str(after.status),
                "claim_outcome_used": claim_outcome,
                "issuer_ata_balance_after": issuer_balance,
                "fail_recipient_ata_balance_after": fail_balance,
                "vault_balance_after": vault_balance,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
