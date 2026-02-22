# Python SDK Quickstart (Claim Flow)

This SDK is the primary interface for issuer/attester automation.

## Install

```bash
cd sdk/python
pip install -e .
```

## Environment

```bash
export RPC_URL="http://127.0.0.1:8899"
export PROPHET_PROGRAM_ID="<your_program_id>"
export PAYER_KEYPAIR_PATH="$HOME/.config/solana/id.json"
```

## Claim Lifecycle API

`ProphetClient` claim-path methods:

- `create_claim(...)`
- `resolve_claim_signed(...)`
- `resolve_claim_threshold(...)`
- `redeem_claim(...)`
- `initialize_notary_config(...)`
- `update_notary_config(...)`

## Minimal Create + Redeem Example

```python
import os
import time
from solders.pubkey import Pubkey
from prophet_sdk import ProphetClient

client = ProphetClient(
    rpc_url=os.getenv("RPC_URL"),
    payer_keypair_path=os.getenv("PAYER_KEYPAIR_PATH"),
    program_id=os.getenv("PROPHET_PROGRAM_ID"),
)

quote_mint = Pubkey.from_string(os.environ["QUOTE_MINT"])
resolver_hash = bytes([9] * 32)
issuer = client.payer.pubkey()

claim_id = int(time.time() * 1000) & ((1 << 64) - 1)
resolve_ts = int(time.time()) + 120

claim, sig = client.create_claim(
    claim_id=claim_id,
    resolver_hash=resolver_hash,
    resolve_ts=resolve_ts,
    bond_atoms=1_000_000,
    pass_recipient=issuer,
    fail_recipient=issuer,  # use a different wallet for directional payout checks
    quote_mint=quote_mint,
)
print("create sig:", sig, "claim:", claim)

# resolve_claim_* is typically sent by oracle/attester process.
# after claim is resolved on-chain:
redeem_sig = client.redeem_claim(claim)
print("redeem sig:", redeem_sig)
```

## Full Validation Script

Use the integrated claim-stack validator:

```bash
bash scripts/validate_claim_stack.sh --skip-ts-test
```

This executes:

1. SDK smoke tests
2. program build/deploy
3. auto claim creation via SDK
4. attester `/resolve-claim`
5. SDK redeem and balance-direction assertions

For a minimal localnet SDK-only walkthrough (no attester), see:

```bash
python sdk/python/examples/claim_localnet_demo.py
```

## Legacy Market API

Market/CLOB SDK methods are still available for backward compatibility, but claim flow is the default development path.
