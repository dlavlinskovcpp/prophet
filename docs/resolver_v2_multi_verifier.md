# Resolver V2 Multi-Verifier Resolution

Resolver V2 can require independently implemented verifiers over the same
canonical evidence. The primary adapter verifier and
`IndependentZkTlsVerifier` share schemas, hashes, evidence bytes, and protocol
constants only; proof parsing, claim checks, response traversal, and error
classification are separate implementations.

## Agreement

`AgreementPolicy` names required verifier IDs, required count, and minimum
agreement. `evaluate_agreement` compares normalized structured commitments:
verifier ID/version, definition hash, evidence hash, verification status,
canonical outcome, and validity. It never compares free-form error text.

For exact agreement, every required verifier must emit `VERIFIED`, reference
the same resolver definition and evidence hash, and have the same canonical
outcome. Missing verifiers, rejected outputs, differing evidence, outcomes,
resolver bindings, duplicate identities, and stale/fresh disagreement fail
closed. Signer policy consumes this result before authorizing a signature.

## Conflict state and reconciliation

`ConflictStateStore` persists an append-only open conflict for the resolution
domain `(market, resolver, cluster, notary config/version, nonce)`. The signing
gate rejects an open conflict, including retries. A conflict may clear only
with policy-approved operator override or a fresh evidence set different from
the recorded evidence. It has no on-chain governance effect.

## Equivocation

`EquivocationMonitor` records verifier and signer observations by identity and
resolution domain. A different outcome or bundle hash for the same identity and
domain raises a deterministic alert/audit record. It records no secrets.

## Operations and residual trust

`MultiVerifierCoordinator` writes all verifier identities, versions, result
statuses, and evidence hashes to JSONL audit records, opens conflicts, and
uses the existing metrics registry hooks for agreement rate, disagreement,
latency, stale-evidence rejection, equivocation, and conflict-open duration.
Operators investigate
source/proof/verifier divergence and either supply fresh evidence or use a
policy-approved override. Independent implementations reduce correlated bugs;
they do not remove the trust assumptions of the source, proof system, or
threshold signers.
