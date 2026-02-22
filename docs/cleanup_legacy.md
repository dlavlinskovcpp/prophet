# Legacy Cleanup Plan

This is the safe cleanup sequence for removing legacy market/CLOB paths after claim-path cutover is stable.

## Remove Now (Low Risk)

- `sdk/python/examples/agent_place_order.py`
- `sdk/python/examples/keeper_match_once.py`
- `sdk/python/examples/keeper_match_loop.py`
- `sdk/python/examples/keeper_multi_market_logs.py`
- `sdk/python/examples/market_maker_basic.py`

Rationale: these examples are market-maker/CLOB specific and no longer represent default product flow.

## Remove After Claim CI Is Green For 2+ Releases

- `tests/prophet.ts`
- `tests/prophet_threshold.ts`
- market/CLOB sections in `docs/*` and README

Rationale: keep compatibility confidence while claim path hardens.

## Remove After Program Cutover Decision

- CLOB-only on-chain instructions and state:
  - `place_order`, `match_orders`, `cancel_order`, `claim_refunds`, `redeem` (market)
  - `Order`, `Position` account types
- legacy SDK methods wrapping these paths

Rationale: these are product-level removals and should be done with a migration release.
