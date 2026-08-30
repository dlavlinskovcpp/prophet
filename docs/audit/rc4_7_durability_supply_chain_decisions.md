# RC4.7 durability and supply-chain decisions

RC4.7 preserves the current Prophet V1/V2 settlement protocol and adds
fail-closed durability and provenance controls.

## Invalid-outcome rounding

The deployed account layout retains `Market.invalid_payout_remainder`. The
current one-atom carry is intentionally retained: it makes aggregate payout
conservation exact when YES and NO claims are equal, but the individual atom
assignment is order-dependent. Redemption order is not an authority, relayer,
or signer input and cannot change aggregate collateral paid. A deterministic
pre-redemption allocation would require a material account/layout redesign and
is deferred. Adversarial redemption-order tests remain part of acceptance.

## Quote asset policy

The protocol accepts the legacy SPL Token program only. Token-2022 and unknown
token programs are explicitly unsupported and fail closed in operated tooling.
The mint inspection gate reports program, decimals, mint-authority presence, and
freeze-authority presence. An operated deployment may additionally set
`PROPHET_APPROVED_QUOTE_MINT` to require an exact approved mint. Issuer and
freeze authority remain an operational asset risk and are not silently treated
as protocol guarantees.

## Withdrawal and replay semantics

`claim_refunds(amount)` remains up-to semantics and never claims more than the
position balance. `withdraw_protocol_fees(amount)` is also up-to semantics for
backward compatibility. A position can be redeemed exactly once; a second
attempt is rejected before any transfer or event.

## Retired compatibility files

`tests/prophet.ts` is retained as a deliberately skipped compatibility marker
because the release-audit asset inventory names it. `programs/prophet/Xargo.toml`
was empty and unused and is removed in RC4.7.
