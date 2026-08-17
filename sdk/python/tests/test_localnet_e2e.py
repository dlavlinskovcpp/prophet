import os
import json
import time

import pytest
from prophet_sdk import ProphetClient, MarketOutcome, MarketStatus
from prophet_sdk.pdas import derive_market_pda, derive_notary_config_pda
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from solana.rpc.api import Client


def _write_keypair(path, kp: Keypair) -> None:
    path.write_text(json.dumps(list(bytes(kp))), encoding="utf-8")


def _airdrop(client: Client, pubkey: Pubkey, lamports: int) -> None:
    sig = client.request_airdrop(pubkey, lamports).value
    if not sig:
        raise RuntimeError(f"airdrop request failed for {pubkey}")

    for _ in range(30):
        bal = client.get_balance(pubkey).value or 0
        if bal >= lamports:
            return
        time.sleep(1)

    raise RuntimeError(f"airdrop not confirmed for {pubkey}")

@pytest.mark.parametrize(
    ("resolver_fill", "proof_fill", "pi_fill", "outcome"),
    [
        (0xCC, 0x01, 0x02, MarketOutcome.Yes),
        (0xCD, 0x03, 0x04, MarketOutcome.Invalid),
    ],
)
@pytest.mark.skipif(not os.getenv("RUN_LOCALNET"), reason="Skipping localnet e2e")
def test_localnet_resolve_flow(tmp_path, resolver_fill, proof_fill, pi_fill, outcome):
    rpc_url = os.getenv("RPC_URL", "http://localhost:8899")
    quote_mint = os.getenv("QUOTE_MINT")
    
    if not quote_mint:
        pytest.skip("Missing env vars for localnet test")

    payer = Keypair()
    oracle_kp = Keypair()
    payer_kp = tmp_path / "payer.json"
    _write_keypair(payer_kp, payer)

    rpc = Client(rpc_url)
    _airdrop(rpc, payer.pubkey(), 10_000_000_000)

    client = ProphetClient(rpc_url=rpc_url, payer_keypair_path=str(payer_kp))
    mint = Pubkey.from_string(quote_mint)

    resolver = bytes([resolver_fill] * 32)
    try:
        slot = client.client.get_slot().value
        now = client.client.get_block_time(slot).value or int(time.time())
    except: now = int(time.time())
    
    open_ts = now - 200
    lock_ts = now - 100
    resolve_ts = now - 50 

    notary_config, _ = derive_notary_config_pda(client.payer.pubkey(), client.program_id)
    client.initialize_notary_config(1, [oracle_kp.pubkey()])

    client.initialize_market_v2(
        resolver_hash=resolver,
        open_ts=open_ts,
        lock_ts=lock_ts,
        resolve_ts=resolve_ts,
        notary_config=notary_config,
        oracle_authority=oracle_kp.pubkey(),
        quote_mint=mint,
    )
    
    market, _ = derive_market_pda(resolver, open_ts, client.program_id)
    
    proof_hash = bytes([proof_fill] * 32)
    pi_hash = bytes([pi_fill] * 32)

    client.resolve_market_threshold(
        market=market,
        notary_config=notary_config,
        resolver_hash=resolver,
        open_ts=open_ts,
        resolve_ts=resolve_ts,
        outcome=outcome,
        proof_hash=proof_hash,
        public_inputs_hash=pi_hash,
        notary_keypairs=[oracle_kp],
        relayer_keypair=client.payer,
    )
    
    acct = client.fetch_market(market)
    assert acct is not None
    assert acct.status == MarketStatus.Resolved
    assert acct.outcome == outcome
    assert acct.proof_hash == proof_hash
    assert acct.public_inputs_hash == pi_hash
