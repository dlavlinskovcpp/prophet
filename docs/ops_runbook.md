# Prophet Operations Runbook

This runbook covers mutable service state and operator checks. It does not
change protocol code, release tags, or deployment authorization.

## Service boundary

The operated topology consists of:

- Resolver V2 registry;
- independent Verifier A and Verifier B;
- fixed-role Signer A and Signer B;
- credential-free coordinator/broker;
- matching keeper;
- durable role-local journals; and
- private monitoring and alerting.

The coordinator, matching keeper, and transaction submitter do not hold signer
credentials. No production process may possess both role credentials. Public
devnet is currently paused and its Prophet program is not deployed.

## Local stack

The repository's local stack target is:

```bash
make localnet-up
```

It starts the local validator, resolver registry, matching keeper, Prometheus,
and Grafana. The local stack is developer infrastructure; it is not evidence
of public-devnet independence. The target does not provision production Vault,
issuer, RPC, TLS, or signer domains.

Useful local endpoints are:

- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000`
- Resolver V2 registry: `http://127.0.0.1:8200`
- Matching keeper: `http://127.0.0.1:8010`

Verifier, coordinator, and fixed-role signer services must be started through
their role-specific development targets or the localtest operated smoke path;
there is no generic production signer target.

## Monitoring

Validate the checked-in alert contract with:

```bash
make ops-validate-alerts
```

The monitoring stack should provide private signals for:

- Verifier A/B, Signer A/B, coordinator, resolver, keeper, and RPC health;
- Vault dependency failures and signer readiness;
- G1 rejection, G2 replay, P0C1 rejection, P0C2 `UNCERTAIN`, and verifier
  disagreement;
- resolution, submission, and reconciliation failures; and
- keeper websocket staleness, snapshot lag, and match backlog.

Metrics and alerts must never contain tokens, private keys, grants, or other
secret values.

## Signer and Vault operations

Signer A and Signer B are independently provisioned fixed-role services. Their
Vault keys, authentication principals, RPC credentials, admission issuers,
replay journals, and audit domains remain role-local. Follow
[`signer_vault_ops.md`](signer_vault_ops.md) for managed-key bootstrap and
rotation; record public identities and key versions, never private material.

The coordinator and keeper must not be supplied with Vault credentials, issuer
private keys, or signer key material. Cross-role grants and replayed grants
must reject before P0C1.

## Backup and restore

Create a mutable-state snapshot:

```bash
make ops-backup
```

Verify the repository backup/restore procedure:

```bash
make ops-verify-restore
```

For an operated deployment, back up and restore coordinator state, Resolver V2
registry data, matching-keeper state, G2 replay journals, P0C2
anti-equivocation state, and submission-attempt journals according to their
role-local ownership. A restore must preserve historical security state; it
must not regenerate identities or silently clear replay records.

## Incident checklist

1. Check private monitoring for service-down, dependency, and rejection alerts.
2. Check `/live`, `/ready`, and `/metrics` on the affected role without
   exposing request bodies or credentials.
3. Inspect the role-local audit and durable journal state.
4. For a verifier or registry issue, verify the canonical resolver hash and
   evidence freshness; do not substitute an unsupported definition.
5. For a signer issue, stop the affected role if key identity, grant binding,
   replay state, or Vault provenance is uncertain.
6. Treat ambiguous P0C2 or transaction submission state as `UNCERTAIN`; do not
   blindly retry a signing or broadcast attempt.
7. Restore only from an operator-approved backup after preserving evidence.

## Keeper operations

The matching keeper is an off-chain policy and submission service. Its
`MARKET_DISCOVERY_MODE`, durable SQLite `DB_PATH`, RPC/WebSocket endpoints,
market caps, and compute-unit-price bound must be explicit. Protect or disable
its operational endpoints and keep metrics private. It has no settlement
signer credentials.

Matching is permissionless limit-order crossing. Keeper best-price /
earliest-order selection is a policy convenience, not a consensus global
price-time guarantee.

## Drill cadence

- before each release: validate alerts and writable state ownership;
- weekly: `make ops-validate-alerts`;
- monthly: `make ops-verify-restore` and review dashboards; and
- before public-devnet authorization: rehearse independent signer restart,
  key-loss/liveness, grant replay, P0C2 ambiguity, and transaction
  reconciliation drills.
