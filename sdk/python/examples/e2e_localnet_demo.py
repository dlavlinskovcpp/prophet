import os
import time
import json
import urllib.request

from solders.pubkey import Pubkey
from solders.keypair import Keypair
from prophet_sdk import ProphetClient, OrderSide, MarketOutcome
from prophet_sdk.pdas import derive_market_pda, derive_order_pda, derive_position_pda, derive_associated_token_account
from prophet_sdk.ata import ensure_ata
from prophet_sdk.zktls.reclaim_client import ReclaimClient

def rpc_post(url: str, method: str, params: list, timeout_s: int = 2) -> dict:
    try:
        payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return json.load(resp)
    except Exception as e:
        return {"error": {"code": None, "message": str(e)}}

def warp_to_timestamp(rpc_url: str, client, target: int, max_iters: int = 20) -> bool:
    print(f"  Warping to {target}...")
    for _ in range(max_iters):
        try:
            slot = client.client.get_slot().value
            current = int(time.time())
            
            bt_resp = client.client.get_block_time(slot)
            if bt_resp.value:
                current = bt_resp.value
            
            if current >= target:
                print(f"  Reached time: {current}")
                return True
            
            resp = rpc_post(rpc_url, "warpSlot", [slot + 1000])
            
            if "error" in resp:
                err = resp["error"]
                code = err.get("code")
                msg = str(err.get("message", "")).lower()
                if code == -32601 or "method not found" in msg:
                    print(f"  [WARN] warpSlot unsupported")
                    return False
            
            time.sleep(0.5)
        except Exception as e:
            print(f"  Warp exception: {e}")
            time.sleep(1)
            
    return False

def get_token_balance(client, ata: Pubkey) -> int:
    try:
        resp = client.get_token_account_balance(ata)
        return int(resp.value.amount)
    except:
        return 0

def main():
    rpc_url = os.getenv("RPC_URL", "http://localhost:8899")
    payer_kp_path = os.getenv("PAYER_KEYPAIR_PATH")
    trader_b_kp_path = os.getenv("TRADER_B_KEYPAIR_PATH")
    quote_mint_str = os.getenv("QUOTE_MINT")
    oracle_kp_path = os.getenv("ORACLE_KEYPAIR_PATH")
    reclaim_proof_id = os.getenv("RECLAIM_PROOF_ID", "").strip()
    reclaim_api_endpoint = os.getenv("RECLAIM_API_ENDPOINT", "https://api.reclaimprotocol.org")
    reclaim_api_key = os.getenv("RECLAIM_API_KEY", "").strip() or None

    if not (payer_kp_path and trader_b_kp_path and quote_mint_str and oracle_kp_path):
        print("Missing required env vars: PAYER_KEYPAIR_PATH, TRADER_B_KEYPAIR_PATH, QUOTE_MINT, ORACLE_KEYPAIR_PATH")
        return
    if not reclaim_proof_id:
        print("Missing required env var: RECLAIM_PROOF_ID")
        return

    client_a = ProphetClient(rpc_url=rpc_url, payer_keypair_path=payer_kp_path)
    client_b = ProphetClient(rpc_url=rpc_url, payer_keypair_path=trader_b_kp_path)
    quote_mint = Pubkey.from_string(quote_mint_str)
    
    with open(oracle_kp_path, 'r') as f:
        oracle_kp = Keypair.from_bytes(bytes(json.loads(f.read().strip())))

    print(f"[E2E] A: {client_a.payer.pubkey()}")
    print(f"[E2E] B: {client_b.payer.pubkey()}")

    try:
        client_a.client.request_airdrop(client_a.payer.pubkey(), 10_000_000_000)
        client_a.client.request_airdrop(client_b.payer.pubkey(), 10_000_000_000)
        time.sleep(2)
    except:
        print("[WARN] Airdrop failed")

    ata_a = ensure_ata(client_a.client, client_a.payer, client_a.payer.pubkey(), quote_mint)
    ata_b = ensure_ata(client_b.client, client_b.payer, client_b.payer.pubkey(), quote_mint)

    bal_a = get_token_balance(client_a.client, ata_a)
    bal_b = get_token_balance(client_b.client, ata_b)
    
    if bal_a < 60 or bal_b < 20:
        print(f"[WARN] Insufficient quote tokens. A: {bal_a}/60, B: {bal_b}/20. Skipping trade flow.")
    else:
        print(f"[E2E] Balances sufficient. A: {bal_a}, B: {bal_b}")

    resolver_hash = bytes([0xAA] * 32)
    
    try:
        slot = client_a.client.get_slot().value
        now_ts = client_a.client.get_block_time(slot).value or int(time.time())
    except:
        now_ts = int(time.time())

    open_ts = now_ts - 10
    lock_ts = now_ts + 60
    resolve_ts = now_ts + 60
    
    print(f"\n[E2E] Creating Market (Resolve TS={resolve_ts})...")
    client_a.initialize_market(
        resolver_hash=resolver_hash,
        open_ts=open_ts,
        lock_ts=lock_ts,
        resolve_ts=resolve_ts,
        oracle_authority=oracle_kp.pubkey(),
        quote_mint=quote_mint
    )
    
    market_pda, _ = derive_market_pda(resolver_hash, open_ts, client_a.program_id)
    print(f"  Market: {market_pda}")

    if bal_a >= 60 and bal_b >= 20:
        print("\n[E2E] Placing Orders...")
        client_a.place_order(market_pda, 0, OrderSide.BuyYes, 60_000_000, 100, quote_mint)
        client_b.place_order(market_pda, 1, OrderSide.BuyNo, 60_000_000, 50, quote_mint)

        print("\n[E2E] Matching...")
        order_a, _ = derive_order_pda(market_pda, client_a.payer.pubkey(), 0, client_a.program_id)
        order_b, _ = derive_order_pda(market_pda, client_b.payer.pubkey(), 1, client_b.program_id)
        
        client_a.match_orders(
            market=market_pda,
            order_yes=order_a,
            order_no=order_b,
            owner_yes=client_a.payer.pubkey(),
            owner_no=client_b.payer.pubkey(),
            quote_mint=quote_mint,
            max_qty_atoms=50
        )

    # Warp & Resolve
    success = warp_to_timestamp(rpc_url, client_a.client, resolve_ts + 2)
    if not success:
        try:
            cur = client_a.client.get_block_time(client_a.client.get_slot().value).value
            if not cur or cur < resolve_ts:
                print(f"[WARN] Chain time {cur} < {resolve_ts}. Skipping resolve.")
                return
        except: return

    print("\n[E2E] Generating zkTLS Proof...")
    reclaim = ReclaimClient(api_endpoint=reclaim_api_endpoint, api_key=reclaim_api_key)
    proof_data = reclaim.fetch_proof(reclaim_proof_id)

    proof_hash = proof_data.proof_hash
    pi_hash = proof_data.public_inputs_hash
    print(f"  Proof Hash: {proof_hash.hex()}")
    print(f"  PI Hash:    {pi_hash.hex()}")

    print("\n[E2E] Resolving (Signed)...")
    try:
        client_a.resolve_market_signed(
            market=market_pda,
            resolver_hash=resolver_hash,
            open_ts=open_ts,
            oracle_keypair=oracle_kp,
            outcome=MarketOutcome.Yes,
            proof_hash=proof_hash,
            public_inputs_hash=pi_hash,
            relayer_keypair=client_a.payer
        )
        print(f"  Resolved!")
    except Exception as e:
        print(f"  Resolve Failed: {e}")
        return

    if bal_a >= 60:
        print("\n[E2E] Redeeming Trader A...")
        pos_a, _ = derive_position_pda(market_pda, client_a.payer.pubkey(), client_a.program_id)
        vault = derive_associated_token_account(market_pda, quote_mint)
        
        try:
            client_a.redeem(market_pda, pos_a, vault, ata_a, quote_mint)
            print(f"  Redeemed!")
        except Exception as e:
            print(f"  Redeem Failed: {e}")

    print("\n[E2E] Demo Complete!")

if __name__ == "__main__":
    main()
