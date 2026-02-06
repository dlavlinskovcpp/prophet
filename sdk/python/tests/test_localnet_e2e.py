import os
import pytest
from prophet_sdk import ProphetClient, MarketOutcome, MarketStatus
from prophet_sdk.pdas import derive_market_pda
from prophet_sdk.ata import ensure_ata
from solders.pubkey import Pubkey
from solders.keypair import Keypair
import json
import time

@pytest.mark.skipif(not os.getenv("RUN_LOCALNET"), reason="Skipping localnet e2e")
def test_localnet_resolve_flow():
    rpc_url = os.getenv("RPC_URL", "http://localhost:8899")
    payer_kp = os.getenv("PAYER_KEYPAIR_PATH")
    oracle_kp_path = os.getenv("ORACLE_KEYPAIR_PATH")
    quote_mint = os.getenv("QUOTE_MINT")
    
    if not (payer_kp and oracle_kp_path and quote_mint):
        pytest.skip("Missing env vars for localnet test")

    client = ProphetClient(rpc_url=rpc_url, payer_keypair_path=payer_kp)
    mint = Pubkey.from_string(quote_mint)
    
    with open(oracle_kp_path, 'r') as f:
        oracle_kp = Keypair.from_bytes(bytes(json.loads(f.read().strip())))

    ensure_ata(client.client, client.payer, client.payer.pubkey(), mint)

    resolver = bytes([0xCC]*32)
    try:
        slot = client.client.get_slot().value
        now = client.client.get_block_time(slot).value or int(time.time())
    except: now = int(time.time())
    
    open_ts = now - 200
    lock_ts = now - 100
    resolve_ts = now - 50 
    
    client.initialize_market(resolver_hash=resolver, open_ts=open_ts, lock_ts=lock_ts, resolve_ts=resolve_ts, oracle_authority=oracle_kp.pubkey(), quote_mint=mint)
    
    market, _ = derive_market_pda(resolver, open_ts, client.program_id)
    
    proof_hash = bytes([1]*32)
    pi_hash = bytes([2]*32)
    
    client.resolve_market_signed(market=market, resolver_hash=resolver, open_ts=open_ts, oracle_keypair=oracle_kp, outcome=MarketOutcome.Yes, proof_hash=proof_hash, public_inputs_hash=pi_hash, relayer_keypair=client.payer)
    
    acct = client.fetch_market(market)
    assert acct is not None
    assert acct.status == MarketStatus.Resolved
    assert acct.outcome == MarketOutcome.Yes
    assert acct.proof_hash == proof_hash
    assert acct.public_inputs_hash == pi_hash