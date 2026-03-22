# Security Review Process

Use the generated review bundle as the handoff package for external auditors and for internal remediation tracking.

## Generate The Bundle

From the repo root:

```bash
make security-review-bundle ENV=devnet TAG=v0.2.3
```

That writes a bundle under `security-reviews/<tag>/<environment>/`.

The bundle contains:

- `release/`: current program binary, IDL, TS types, environment config, deployment templates, and release manifest
- `configs/redacted/`: redacted service and operated-stack config material
- `fixtures/`: sample resolver, proof, public-input, request, and expected attester-output fixtures
- `invariants/`: invariant mapping that ties the review scope back to code, docs, and tests
- `review_tracking/`: templates for findings and remediation status
- `reference/`: trust model, runbooks, and monitoring dashboards

## Reviewer Handoff

Send the generated bundle directory or archived copy to reviewers. The expected entrypoints are:

- `README.md`
- `release/manifest.json`
- `invariants/invariant_map.md`
- `review_tracking/audit_findings.md`

## Remediation Loop

1. Reviewers record each issue in `review_tracking/audit_findings.md`.
2. Maintainers mirror the finding ID into `review_tracking/remediation_log.md`.
3. Each remediation entry should capture:
   - owner
   - implementation PR or commit
   - validation evidence
   - close date
4. Keep accepted-risk decisions in the same log rather than deleting the finding.

## Scope

The authoritative review scope remains in `docs/security_review_scope.md`.
