# Security Review Scope

This note packages the scope and expectations for an external security/adversarial review.

## Components In Scope
- on-chain program `prophet` (v2 threshold-only surface)
- attester service (resolver load, zkTLS verification, resolve assembly)
- remote signer service (KMS/command backend, allowlist, audit)
- resolver registry service (publish/load/list APIs)
- matching keeper (order discovery, matching submissions)

## Core Invariants
- on-chain custody, fee accrual, lifecycle, and settlement are enforced by the program
- threshold resolution requires distinct notary signatures over the canonical resolve message
- resolver definitions are hashed; on-chain `resolver_hash` must match the off-chain definition used by attestation
- attester must not emit resolves unless proof/public inputs satisfy the resolver definition and zkTLS verifier
- remote signer must only sign for allowlisted notary keys

## Trust Assumptions
- Solana cluster trust and RPC honesty at the configured commitment
- attester honesty for zkTLS verification and resolver evaluation
- notary key custody is controlled (KMS/HSM/command backend)
- resolver registry integrity and availability
- operator controls env vars, API tokens, and network isolation

## Known Non-Goals / Out of Scope
- censorship resistance of attester/signer/registry
- proof verification on-chain (hashes only stored)
- economic analysis of oracle/notary collusion incentives
- MEV/mempool protection
- UI/UX correctness

## Operator-Controlled Risks
- misconfigured or stale `NotaryConfig` (threshold/signers) leading to failed or unsafe resolution
- running attester with mock or disabled zkTLS modes
- running remote signer without auth/allowlist/TLS
- unresolved resolver registry divergence from on-chain hash
- insufficient monitoring of attester/signer/registry/keeper health
- key leakage via logs or loose filesystem permissions

## Artifacts To Provide To Reviewers
- current release bundle (program.so, IDL, TS types, config, git sha)
- attester/registry/signer configs (with secrets redacted)
- sample resolver definitions and expected resolver_hash values
- sample proof/public-input pairs and expected attester outputs
- ops/rollback runbooks and monitoring dashboards
