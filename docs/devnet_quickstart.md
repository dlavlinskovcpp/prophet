# Developer Devnet Preparation

This guide is for deterministic development and independent local/devnet
experimentation. It does not describe a currently live Prophet-operated public
devnet: the official public-devnet is paused, its Prophet program is not
deployed, and mainnet is blocked.

## Safest first steps

From the repository root:

```bash
make demo
make rc47-security-acceptance
```

`make demo` runs the deterministic agent-native Resolver V2 flow and its
conflict fail-closed case without a wallet, RPC, or deployment. The acceptance
target validates the checked-in RC4.7 security basis.

For the fixed-role localtest path:

```bash
make operated-smoke
```

This uses ephemeral developer infrastructure and proves the A/B admission and
settlement boundary locally. Its test keys are developer-only fixtures and are
not evidence of independent production compute, Vault, RPC, or administrative
domains.

## Localnet Market V2 flow

If you need an on-chain integration, use a local validator and two distinct
test notary keypairs. Market V2 accepts exactly 2-of-2; a one-key smoke path is
invalid.

Start the repository's local environment using the current target:

```bash
make localnet-up
```

Set the local RPC, program, payer, and quote-mint values for your environment:

```bash
export RPC_URL="http://127.0.0.1:8899"
export PROPHET_PROGRAM_ID="<local-program-id>"
export PAYER_KEYPAIR_PATH="$HOME/.config/solana/id.json"
export QUOTE_MINT="<local-quote-mint>"
```

The following uses the current `ProphetClient` API. The two notary keypairs
are intentionally distinct and are held only by this developer process:

```python
import os
import time

from solders.keypair import Keypair
from solders.pubkey import Pubkey

from prophet_sdk import ProphetClient, derive_market_pda, derive_notary_config_pda

client = ProphetClient(
    rpc_url=os.environ["RPC_URL"],
    payer_keypair_path=os.environ["PAYER_KEYPAIR_PATH"],
    program_id=os.environ["PROPHET_PROGRAM_ID"],
)
notary_a = Keypair()
notary_b = Keypair()
notary_keys = [notary_a.pubkey(), notary_b.pubkey()]

notary_config, _ = client.initialize_notary_config(2, notary_keys)
resolver_hash = bytes([7]) * 32
now = int(time.time())
open_ts = now - 5
lock_ts = now + 120
resolve_ts = now + 180
quote_mint = Pubkey.from_string(os.environ["QUOTE_MINT"])

client.initialize_market_v2(
    resolver_hash=resolver_hash,
    open_ts=open_ts,
    market_nonce=0,
    lock_ts=lock_ts,
    resolve_ts=resolve_ts,
    notary_config=notary_config,
    quote_mint=quote_mint,
)

market, _ = derive_market_pda(
    client.payer.pubkey(), resolver_hash, open_ts, 0, client.program_id
)
```

This is a developer example only. For an actual resolution, call
`resolve_market_threshold(...)` with both `notary_a` and `notary_b`, or use the
repository's fixed-role operated flow. Do not export these ephemeral private
keys or present them as production signer evidence.

## Independent developer deployment

An independent developer may deploy to a personal devnet environment after
reviewing the target environment and release workflow. Use the release tool
with an explicitly selected release tag and externally managed deployment
credentials; do not infer that this is the Prophet-operated public-devnet.

The release workflow and its credential boundary are documented in
[`release_runbook.md`](release_runbook.md). It intentionally keeps upgrade
authority and fee-payer credentials outside the repository and release bundle.

Before using a public RPC, verify the cluster and program identity. The current
operated public-devnet configuration points to
`https://api.devnet.solana.com`, but its `deployment_authorized` flag is false
and the Prophet program account is currently absent.

## What this guide proves

- deterministic Resolver V2 behavior through `make demo`;
- the local fixed-role A/B boundary through `make operated-smoke`; or
- local on-chain Market V2 initialization with two distinct test notaries when
  the local validator and quote mint are available.

It does not prove production independence, public-devnet readiness, external
audit completion, or mainnet safety. It also does not guarantee global
best-execution, strict price priority, strict time priority, or Sybil-resistant
matching: Prophet V1 is permissionless limit-order crossing.

## Related guides

- System architecture: [`architecture.md`](architecture.md)
- SDK API examples: [`sdk_quickstart.md`](sdk_quickstart.md)
- Resolver V2 schema: [`resolver_spec.md`](resolver_spec.md)
- Matching keeper: [`matching_keeper.md`](matching_keeper.md)
- Operated services: [`operated_devnet.md`](operated_devnet.md)
- Operations and recovery: [`ops_runbook.md`](ops_runbook.md)
- Release workflow: [`release_runbook.md`](release_runbook.md)
