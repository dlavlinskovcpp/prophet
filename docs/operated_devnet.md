# Operated devnet signer acceptance smoke

Public-devnet remains paused. This tool does not deploy, settle, or start any
service. It is an acceptance controller which verifies that two already-running
fixed-role signer services independently accept the same authorization request
and produce a valid 2-of-2 signature bundle.

Before running it, operators must separately provision:

- signer A and signer B as independent, fixed-role services;
- role-local one-shot admission-grant issuer A and issuer B boundaries;
- the strict authorization request and the matching 235-byte settlement message;
- one grant for each signer, bound to the same acceptance run ID.

The controller receives only:

- signer A/B HTTPS endpoints and expected signer IDs/public keys;
- strict request JSON, canonical settlement-message bytes, and signed grant files;
- a fee-payer only in a future submission step, never signer or issuer credentials.

It must not receive Vault tokens, settlement private keys, issuer private keys,
or a legacy admission bearer. It starts no signer and has no generic-signer
fallback.

## Run

Generate or coordinate one 32-character lowercase hexadecimal acceptance run ID.
Give that ID plus the exact authorization request to the independently operated
A and B issuers. Each issuer returns one signed JSON grant artifact; grant IDs
remain issuer-generated and must differ.

Then run:

```bash
make operated-devnet ARGS="\
  --authorization-request-file /secure/input/request.json \
  --canonical-message-file /secure/input/settlement-message.bin \
  --acceptance-run-id <32-lowercase-hex> \
  --signer-a-endpoint https://signer-a.example \
  --signer-b-endpoint https://signer-b.example \
  --signer-a-id signer-a \
  --signer-b-id signer-b \
  --signer-a-public-key <A-public-key> \
  --signer-b-public-key <B-public-key> \
  --signer-a-grant-file /secure/input/grant-a.json \
  --signer-b-grant-file /secure/input/grant-b.json"
```

The controller sends the identical request bytes once to each endpoint, with its
role-local grant. It validates response role, signer ID, public key, 235-byte
message digest, and direct Ed25519 signature before emitting the bundle. Any
failure, swapped grant, wrong identity, timeout, or malformed result terminates
the run without a bundle; it never retries a consumed grant.

This proves only the external fixed-role signer admission boundary. It does not
prove physical or administrative independence, operational-evidence sufficiency,
or authorize public-devnet resumption.
