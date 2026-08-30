# Prophet Sequence Flows

This document shows the main end-to-end flows in Prophet using text sequence diagrams.

## 1. Market Creation Flow

```text
Operator / SDK          Prophet Program           Solana Accounts
     |                        |                         |
     | initialize_notary_config / rotate_notary_config |
     |----------------------->|                         |
     |                        | create immutable       |
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
Verifier A          Resolver Registry       Signer A       Prophet Program
   |                         |                 |                 |
   | load resolver by hash   |                 |                 |
   |------------------------>|                 |                 |
   |<------------------------| canonical def  |                 |
   | evaluate evidence       |                 |                 |
   | signed result + grant   |                 |                 |
   |-----------------------------------------> |                 |
   |                                           | read finalized   |
   |                                           | state via RPC A  |
   |                                           | G1/G2/P0C1/P0C2  |
   |                                           | sign 235 bytes   |

Verifier B performs the same work independently through Signer B, RPC B, its
own Vault/key domain, issuer, and durable journals. A credential-free
coordinator/broker may transport the untrusted request and signature bundle;
it cannot authorize either role.

Signer A + Signer B       Permissionless Submitter       Prophet Program
       |                            |                          |
       | identical signatures       |                          |
       |--------------------------->|                          |
       |                            | Ed25519 instructions   |
       |                            | + resolve_market_threshold
       |                            |------------------------->|
       |                            |                          | verify exact
       |                            |                          | 2-of-2 + bytes
       |                            |                          | store outcome
```

## 4. Direct SDK Threshold Resolution Flow

This is a developer-only smoke-test path. It is not the operated production
signer topology.

```text
Operator / SDK                         Prophet Program
     |                                       |
     | fetch market + notary config version  |
     |-------------------------------------->|
     |                                       |
     | build canonical v2 message            |
     | sign with two distinct demo notary keys|
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
- The direct SDK flow is useful for developer smoke testing; operated resolution uses independent Verifier A/B and fixed-role Signer A/B services.
- The resolver registry and fixed-role A/B signer services are part of the production trust and availability boundary, even though the final outcome is still committed on-chain.
