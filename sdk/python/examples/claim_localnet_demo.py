import os
import time

from solders.pubkey import Pubkey

from prophet_sdk import ClaimOutcome, ProphetClient


def chain_time(client: ProphetClient) -> int:
    try:
        slot = client.client.get_slot().value
        bt = client.client.get_block_time(slot).value
        if bt is not None:
            return int(bt)
    except Exception:
        pass
    return int(time.time())


def main() -> None:
    rpc_url = os.getenv("RPC_URL", "http://127.0.0.1:8899")
    payer = os.getenv("PAYER_KEYPAIR_PATH", os.path.expanduser("~/.config/solana/id.json"))
    program_id = os.getenv("PROPHET_PROGRAM_ID", "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A")
    quote_mint_raw = os.getenv("QUOTE_MINT")
    if not quote_mint_raw:
        raise SystemExit("Set QUOTE_MINT to a token mint on localnet")

    client = ProphetClient(rpc_url=rpc_url, payer_keypair_path=payer, program_id=program_id)
    quote_mint = Pubkey.from_string(quote_mint_raw)
    issuer = client.payer.pubkey()

    now = chain_time(client)
    claim_id = int(time.time() * 1000) & ((1 << 64) - 1)
    resolve_ts = now + 5

    claim, create_sig = client.create_claim(
        claim_id=claim_id,
        resolver_hash=bytes([9] * 32),
        resolve_ts=resolve_ts,
        bond_atoms=1_000_000,
        pass_recipient=issuer,
        fail_recipient=issuer,
        quote_mint=quote_mint,
        oracle_authority=issuer,
    )
    print("create sig:", create_sig)
    print("claim:", claim)

    while chain_time(client) < resolve_ts:
        time.sleep(1)

    proof_hash = bytes([1] * 32)
    public_inputs_hash = bytes([2] * 32)
    resolve_sig = client.resolve_claim_signed(
        claim=claim,
        outcome=ClaimOutcome.Pass,
        proof_hash=proof_hash,
        public_inputs_hash=public_inputs_hash,
        oracle_keypair=client.payer,
    )
    print("resolve sig:", resolve_sig)

    redeem_sig = client.redeem_claim(claim)
    print("redeem sig:", redeem_sig)


if __name__ == "__main__":
    main()
