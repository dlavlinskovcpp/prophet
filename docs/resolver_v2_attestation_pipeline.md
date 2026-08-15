# Resolver V2 Attestation Pipeline

Resolver V2 is an off-chain, fail-closed pipeline that ends in the unchanged
`PROPHET_RESOLVE_V2` settlement message. It does not alter trading logic, the
program's threshold verification, or a legacy market's resolver hash.

## Stages and trust boundaries

```text
acquire -> normalize -> verify -> VerificationResultV2 -> bundle
        -> signer policy -> threshold signatures -> legacy submission
```

`EvidenceAcquirer.acquire(AcquisitionRequest)` may return raw bytes and source
metadata only. Its output is bound to the resolver ID, adapter digest, source
identity, acquisition time, and raw SHA-256. It cannot choose an outcome.

`normalize_evidence` deterministically produces `EvidenceEnvelopeV2`; its
evidence ID is derived from definition hash, raw-evidence hash, and source
commitment. The normalizer never parses or evaluates the raw payload.

`EvidenceVerifier.verify(definition, evidence, trust_model)` receives only
immutable, already-bound inputs. It returns a `VerificationReport`, which is
then committed to `VerificationResultV2`: decision, verification status,
confidence, verifier ID/version/digest, evidence hash, timestamps, checks, and
a deterministic failure code. Signers never rerun verification or inspect raw
evidence.

`ResolverV2Pipeline.build_bundle` accepts only VERIFIED reports with one common
outcome. It calls the shared canonical hashing library and validates the
resulting `ResolutionBundleV2` before it leaves the pipeline.

## Signer policy

`SignerPolicyEngine` is deterministic and allowlist-only. It checks resolver,
adapter digest, trust-model digest, verifier ID/version, market, cluster,
signer-set version, threshold, evidence age, verification age, emergency
denylist, deprecation status, canonical validity, and an optional expected
bundle hash. Unknown or unsupported values reject the request.

`ThresholdSigningGate` is the sole signer-facing boundary. A backend receives
only the canonical bundle bytes/hash, successful policy decision, and the
existing settlement message. It supports the existing local, command/remote,
and Vault Transit-compatible `SignerBackend.sign(pubkey, message, context)`
contract. Context includes commitments and policy identifiers, never raw source
bytes, proofs, headers, or secrets.

## Equivocation and retries

`EquivocationStore` durably records:

```json
{"key":"market:cluster:notary_config:version:nonce","outcome":"YES","bundle_hash":"..."}
```

The identical bundle is an idempotent retry. A different bundle for the same
domain is rejected; in particular a different outcome is
`equivocation_conflicting_outcome`. The record is appended before signing.

## Audit record

The gate writes structured JSONL records for authorization, rejection, and
signatures. They include resolver ID, market, evidence hashes, verifier
descriptor, verification statuses, bundle hash, signer-policy version and
decision, produced public keys, and rejection reason. Private keys, raw
evidence, request secrets, and authorization headers are never written.

## Legacy settlement compatibility

`build_legacy_settlement_message` is a byte-for-byte implementation of the
existing layout:

```text
"PROPHET_RESOLVE_V2" || program || market || notary_config || resolver_hash ||
open_ts:i64_le || resolve_ts:i64_le || config_version:u64_le || outcome:u8 ||
proof_hash || public_inputs_hash
```

V2 bundle metadata is not serialized into that message. Existing markets keep
their legacy resolver hashes; V2 use is strictly an attester-side metadata and
authorization layer until a future on-chain protocol change.
