# Resolver V2 signer key rotation

A logical signer ID is stable across Vault Transit key epochs. An epoch explicitly binds key version, pinned Ed25519 public key, activation time, and retirement time. Activation is inclusive; retirement is exclusive. Epochs are ordered, contiguous, non-overlapping, have unique increasing versions and unique public keys, and the final epoch remains active. Legacy `expected_key_version`/`expected_public_key` configuration is interpreted as one epoch active from time zero.

At first intent creation, `ThresholdResolutionSigner` selects one epoch for A and one for B using the intent creation time, validates both pinned Vault versions, and persists both selections with the canonical message binding. On restart, the journal selections—not current active epochs or wall clock—are used. A durable A version 1 with B pending therefore still requires B version 1. An uncertain version 1 operation also remains version 1; if that historical epoch is absent from configured policy or Vault metadata, recovery fails closed.

Vault is never asked to create or rotate a key. The policy does not accept a `latest` key version, does not mutate configuration, and does not change `PROPHET_RESOLVE_V2` bytes. Coordinator integration, automatic workers, transaction construction, and submission remain outside this phase.
