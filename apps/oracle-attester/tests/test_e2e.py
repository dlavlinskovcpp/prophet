import os
import pytest
import base64
import hashlib
from solders.pubkey import Pubkey
from src.types import ResolveRequest, OutcomeEnum

@pytest.mark.asyncio
async def test_resolve_flow_e2e():
    market_str = os.getenv("MARKET_PUBKEY")
    if not market_str:
        pytest.skip("MARKET_PUBKEY not set. Skipping E2E test.")

    # Import runtime-bound components only when E2E is actually executed.
    from src.attester import service
    from src.solana_client import SolanaClient
    
    print(f"\n[E2E] Resolving market: {market_str}")
    
    # 1. Prepare Data
    proof_data = b"test_proof_data"
    pi_data = b"test_public_inputs"
    proof_b64 = base64.b64encode(proof_data).decode()
    pi_b64 = base64.b64encode(pi_data).decode()
    
    # Expected Hashes
    exp_proof_hash = hashlib.sha256(proof_data).digest()
    exp_pi_hash = hashlib.sha256(pi_data).digest()
    
    req = ResolveRequest(
        market=market_str,
        outcome=OutcomeEnum.YES,
        proof_bytes_b64=proof_b64,
        public_inputs_bytes_b64=pi_b64
    )
    
    # 2. Call Service Directly (In-Process)
    # If market is already resolved, we handle it as success-check or fail
    try:
        resp = await service.resolve_market(req)
        print(f"[E2E] Tx Signature: {resp.signature}")
        
        assert resp.signature is not None
        assert len(resp.signature) > 10
        assert resp.resolved_ts > 0
        assert resp.proof_hash_hex == exp_proof_hash.hex()
        assert resp.public_inputs_hash_hex == exp_pi_hash.hex()
        
    except ValueError as e:
        if "already resolved" in str(e):
             print("[E2E] Market already resolved, verifying on-chain state matches...")
        else:
             pytest.fail(f"Resolve failed with unexpected error: {e}")

    # 3. Verify On-Chain State Matches
    client = SolanaClient()
    final_state = client.get_market_state_full(Pubkey.from_string(market_str))
    
    assert final_state is not None
    assert final_state["status"] == 2 # Resolved
    assert final_state["proof_hash"] == exp_proof_hash
    assert final_state["public_inputs_hash"] == exp_pi_hash
    
    print("[E2E] On-Chain hashes verified successfully.")
