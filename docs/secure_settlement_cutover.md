# RC3 P-01/P-02 secure settlement cutover

Production/public-devnet settlement has one authorization path:

```text
verifier-a + verifier-b
        -> durable coordinator SQLite -> AGREED
        -> AgreedSettlementSigner
        -> durable SigningJournal SQLite
        -> signer A Vault policy + signer B Vault policy
        -> immutable 2/2 bundle
        -> existing deterministic transaction builder
        -> simulation
        -> durable submission/reconciliation journal
```

The production-shaped Compose manifests do not run `oracle-attester` or the
generic `remote-signer` as settlement services. `RESOLUTION_MODE=secure-coordinator`
also makes the retained `/resolve` compatibility endpoint fail closed, and the
generic `/sign` service cannot start in that mode. Those components remain only
for non-production compatibility tests and unrelated development workflows.

## Runtime authority boundaries

| component | creates settlement signatures | submits settlement | durable AGREED required | SigningJournal required | caller chooses signed bytes |
| --- | --- | --- | --- | --- | --- |
| verifier A | no | no | n/a | no | no |
| verifier B | no | no | n/a | no | no |
| coordinator | no | no | creates it | no | no |
| secure settlement API | triggers authorized 2/2 only | yes | yes | yes | no; job id only |
| legacy oracle-attester | legacy/test only | legacy/test only | no | no | n/a in production |
| generic remote signer | legacy/test only | no | no | no | disabled in production |

Coordinator job creation accepts evidence plus immutable settlement context, but
does not accept `state=AGREED`, signatures, signer identities, canonical message
bytes, or an outcome override. The coordinator persists A and B results itself.
Signing later accepts only `coordinator_job_id` and reloads the authoritative
job/context/runtime from SQLite.

## Independent verifier and signer domains

Verifier A uses the primary `bound-http` zkTLS proof-backend implementation.
Verifier B uses the separate `independent-bound-http` checker and independent
parser. Production preflight requires different verifier service URLs,
identities, auth references, and proof-backend URLs.

Settlement signer A and B have distinct signer identities, Vault key names,
public keys, and Vault token environment references. Secure startup additionally
rejects equal token values and rejects any configured value for the legacy
shared Vault token reference. The settlement API bearer token is also forbidden
from being either Vault token. An API caller can request execution of an already
durable AGREED job but cannot retrieve raw A/B signatures or choose bytes for
either signer.

## Durability and restart

Coordinator SQLite, SigningJournal SQLite, and the settlement submission journal
must all use persistent absolute paths. Existing recovery logic resumes durable
PARTIAL/AGREED/signing/submission states; there is no fallback to direct attester
or generic remote signing after restart. `CONFLICT` remains terminal and causes
zero signing, construction, simulation, or submission calls.

Mainnet execution keeps the existing Phase 6 settlement-executor restrictions.
If that executor is not enabled for mainnet, secure settlement stays unavailable
rather than falling back to the legacy path.

## Operator secrets

Verifier internal bearer tokens, the secure-settlement API token, signer A Vault
token, signer B Vault token, and the fee-payer keypair are external deployment
credentials. They are not release metadata and are provisioned through the
operator secret-management boundary.

This cutover does not change `PROPHET_RESOLVE_V2`, Resolver V2 canonical hashes,
the Ed25519 instruction layout, threshold settlement instruction, or the Anchor
program ABI.
