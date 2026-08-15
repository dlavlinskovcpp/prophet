# Observability and response ownership

Use the existing Prometheus/alert configuration under `ops/monitoring/`; do
not consider a testnet launch complete until routing has been tested. The
on-call protocol operator owns P1/P2 acknowledgement; the release manager
owns P3 follow-up; the security lead owns any suspected key compromise.

| Condition | Severity | Detection / response |
|---|---|---|
| Failed settlement or unusual redemption failure | P1 | Transaction/event and attester metrics; halt automated submission, preserve evidence |
| Verifier disagreement or signer equivocation | P1 | Resolver V2 audit/metrics; conflict remains open, rotate/disable affected signer if needed |
| Vault imbalance or fee-accounting mismatch | P1 | Reconciliation against market/vault/events; stop withdrawals and investigate |
| Stale evidence, RPC failure, signer availability | P2 | Adapter/signer/RPC metrics; fail closed, fail over approved dependency |
| Keeper/order-matching failures | P2 | Keeper health and order-event backlog; restart/replace keeper, users retain direct path |
| Rate-limit or registry/attester failures | P3 | Service metrics/logs; scale or repair without bypassing policy |

Required alert coverage: failed settlements, verifier disagreement, signer
equivocation, stale evidence, RPC failures, keeper failures, matching failures,
vault imbalance, fee mismatch, and unusual redemption failures. Validate with
`python3 scripts/validate_alert_rules.py`; test alert delivery during each
testnet release.
