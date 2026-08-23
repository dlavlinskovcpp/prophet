# Resolver V2 signer authorization boundary

P0C1 is a read-only, per-signer authorization core. It validates two pinned
verifier attestations and finalized Solana state, then reconstructs the frozen
235-byte `PROPHET_RESOLVE_V2` message. It does not call Vault, sign, write a
journal, submit a transaction, or persist an authorization decision.

## Finalized-state rule

Authorization accepts only a shared Market and NotaryConfig account snapshot
returned at an explicit finalized RPC context slot. The core first obtains a
validated finalized-slot floor, performs a finalized Market probe only to find
the candidate NotaryConfig, and then uses a second shared-context read as its
sole authorization state. Each response must have an integer, non-negative
context slot at or above its requested minimum. The resolve-time check uses the
shared snapshot's context slot exclusively.

The RPC adapter owns `commitment=finalized`; callers cannot select another
commitment or a context-free account-read path.

## Model A RPC trust boundary

P0C1 uses Model A: signer A plus RPC domain A is one integrity domain, and
signer B plus RPC domain B is another. A malicious RPC A can fabricate a
finalized-looking view and may induce one bad A authorization or signature.
That is not sufficient for the required 2/2 quorum when the signer domains are
operated independently.

## P0C3 deployment gate

**REQUIRED IN P0C3 — REQUIRED BEFORE PUBLIC-DEVNET OPERATED 2/2 ACCEPTANCE —
REQUIRED BEFORE MAINNET:**

`RPC_A_DOMAIN != RPC_B_DOMAIN` means separate administrative/provider failure
domains, separate provider account/project/tenant where administration could
correlate them, separate credentials or service principals, separate
signer-side configuration, and separate operational failure domains.

Different URL strings alone are not sufficient. Two endpoints under the same
provider administration or credential are not sufficient. P0C1 does not
instantiate both signer services and therefore does not enforce this topology;
P0C3 must enforce it during production runtime and topology validation.
