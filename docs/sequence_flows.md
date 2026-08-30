# Prophet Sequence Flows

This document shows the main end-to-end flows in Prophet using text sequence diagrams.

## 1. Market Creation Flow

```text
Operator / SDK          Prophet Program           Solana Accounts
     |                        |                         |
     | initialize_notary_config/update_notary_config   |
     |----------------------->|                         |
     |                        | create/update           |
     |                        | NotaryConfig            |
     |                        |------------------------>|
     |                        |                         |
     | initialize_market_v2   |                         |
     |----------------------->|                         |
     |                        | create Market + vault   |
     |                        |------------------------>|
     |                        |                         |
     |<-----------------------| tx signature            |
```

## 2. Trading And Matching Flow

```text
Trader A / SDK         Trader B / SDK         Matching Keeper        Prophet Program
     |                      |                       |                       |
     | place_order YES      |                       |                       |
     |--------------------->|                       |                       |
     |                      |                       | store Order A         |
     |                      |                       |---------------------->|
     |                      |                       |                       |
     |                      | place_order NO        |                       |
     |                      |---------------------->|                       |
     |                      |                       | store Order B         |
     |                      |                       |---------------------->|
     |                      |                       |                       |
     |                      |                       | detect crossed book   |
     |                      |                       |---------------------> |
     |                      |                       | match_orders          |
     |                      |                       |---------------------->|
     |                      |                       | update orders,        |
     |                      |                       | positions, refunds,   |
     |                      |                       | fee accrual           |
     |                      |                       |                       |
     | claim_refunds        |                       |                       |
     |--------------------->|                       |                       |
     |                      |                       | transfer refunds      |
     |                      |                       |---------------------->|
```

## 3. Operated Resolution Flow

```text
Attester              Resolver Registry      Remote Signer       Prophet Program
   |                         |                    |                    |
   | load market state       |                    |                    |
   |--------------------------------------------------------------->   |
   |                         |                    |                    |
   | load resolver by hash   |                    |                    |
   |------------------------>|                    |                    |
   |<------------------------| canonical resolver |                    |
   |                         |                    |                    |
   | verify public inputs + zkTLS                 |                    |
   |                                               |                    |
   | build canonical v2 message                    |                    |
   |--------------------------------------------->| sign message       |
   |<---------------------------------------------| signature(s)       |
   |                                               |                    |
   | resolve_market_threshold                      |                    |
   |------------------------------------------------------------------>|
   |                                               | verify threshold   |
   |                                               | sigs, store hashes |
   |                                               | set outcome        |
```

## 4. Direct SDK Threshold Resolution Flow

This is the fast smoke-test path used in the devnet guide.

```text
Operator / SDK                         Prophet Program
     |                                       |
     | fetch market + notary config version  |
     |-------------------------------------->|
     |                                       |
     | build canonical v2 message            |
     | sign with local/demo notary keys      |
     | prepend Ed25519 verify instructions   |
     | resolve_market_threshold              |
     |-------------------------------------->|
     |                                       | verify threshold sigs
     |                                       | set resolved outcome
     |<--------------------------------------|
```

## 5. Redemption Flow

```text
Trader / SDK              Prophet Program            Solana Accounts
     |                         |                           |
     | redeem                  |                           |
     |------------------------>|                           |
     |                         | check resolved outcome    |
     |                         | compute payout            |
     |                         | transfer quote assets     |
     |                         |-------------------------->|
     |                         | zero redeemed shares      |
     |<------------------------| tx signature              |
```

## Notes

- Matching is on-chain in outcome, but off-chain in discovery and submission.
- Resolution is permissionless to submit, but depends on off-chain verifier and signer infrastructure.
- The direct SDK flow is useful for smoke testing; the attester path is the intended operated path.
- The resolver registry and fixed-role A/B signer services are part of the production trust and availability boundary, even though the final outcome is still committed on-chain.
