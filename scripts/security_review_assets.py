from __future__ import annotations

REVIEW_FIXTURE_CASES = [
    {
        "slug": "threshold_yes",
        "description": "Resolver evaluates to YES with matching public inputs and placeholder proof bytes.",
        "resolver": {
            "url": "https://example.test/value",
            "method": "GET",
            "path": "data.answer",
            "predicate": "equals",
            "target_value": 42,
        },
        "proof_text": "prophet-security-review-proof-threshold-yes-v1",
        "public_inputs": {
            "data": {
                "answer": 42,
            }
        },
        "expected_outcome": "YES",
        "verifier_assumption": "Attester-side zkTLS verifier returns ok for this payload.",
    },
    {
        "slug": "threshold_invalid",
        "description": "Resolver evaluates to INVALID when the expected path is absent from public inputs.",
        "resolver": {
            "url": "https://example.test/value",
            "method": "GET",
            "path": "data.answer",
            "predicate": "equals",
            "target_value": 42,
        },
        "proof_text": "prophet-security-review-proof-threshold-invalid-v1",
        "public_inputs": {
            "data": {
                "unexpected": 7,
            }
        },
        "expected_outcome": "INVALID",
        "verifier_assumption": "Attester-side zkTLS verifier returns ok, but resolver evaluation forces INVALID.",
    },
]


INVARIANT_MAP = [
    {
        "id": "INV-001",
        "statement": "On-chain custody, lifecycle transitions, fee accrual, and settlement remain program-enforced.",
        "components": ["program"],
        "code_refs": [
            "programs/prophet/src/lib.rs",
            "programs/prophet/src/state.rs",
        ],
        "doc_refs": [
            "docs/trust_model.md",
            "docs/protocol.md",
        ],
        "test_refs": [
            "tests/prophet.ts",
            "tests/prophet_invariants.ts",
            "tests/prophet_governance.ts",
        ],
    },
    {
        "id": "INV-002",
        "statement": "Threshold resolution requires distinct notary signatures over the canonical V2 resolve message and current NotaryConfig version.",
        "components": ["program", "sdk", "attester"],
        "code_refs": [
            "programs/prophet/src/lib.rs",
            "sdk/python/prophet_sdk/client.py",
            "apps/oracle-attester/src/attester.py",
        ],
        "doc_refs": [
            "docs/attestation_format.md",
            "docs/trust_model.md",
        ],
        "test_refs": [
            "tests/prophet_threshold.ts",
            "sdk/python/tests/test_localnet_e2e.py",
            "apps/oracle-attester/tests/test_localnet_threshold_e2e.py",
            "apps/oracle-attester/tests/test_attester_threshold_integration.py",
        ],
    },
    {
        "id": "INV-003",
        "statement": "Resolver definitions are canonicalized and hashed; the off-chain resolver used for attestation must hash back to the market resolver_hash.",
        "components": ["resolver-registry", "attester", "sdk"],
        "code_refs": [
            "apps/oracle-attester/src/resolver.py",
            "apps/oracle-attester/src/resolver_registry.py",
            "apps/oracle-attester/src/resolver_registry_main.py",
            "sdk/python/prophet_sdk/resolver_hash.py",
        ],
        "doc_refs": [
            "docs/resolver_spec.md",
            "docs/security_review_scope.md",
        ],
        "test_refs": [
            "apps/oracle-attester/tests/test_resolver.py",
            "apps/oracle-attester/tests/test_resolver_registry.py",
            "apps/oracle-attester/tests/test_resolver_registry_main.py",
        ],
    },
    {
        "id": "INV-004",
        "statement": "The attester must not submit resolves unless proof/public inputs pass zkTLS verification and resolver evaluation for the requested outcome.",
        "components": ["attester"],
        "code_refs": [
            "apps/oracle-attester/src/attester.py",
            "apps/oracle-attester/src/zktls_verifier.py",
            "apps/oracle-attester/src/proof_fetcher.py",
        ],
        "doc_refs": [
            "docs/security_review_scope.md",
            "docs/attestation_format.md",
        ],
        "test_refs": [
            "apps/oracle-attester/tests/test_attester_threshold_integration.py",
            "apps/oracle-attester/tests/test_e2e.py",
            "apps/oracle-attester/tests/test_zktls_verifier.py",
            "apps/oracle-attester/tests/test_proof_fetcher.py",
        ],
    },
    {
        "id": "INV-005",
        "statement": "The remote signer only signs for loaded, allowlisted notary keys and exposes auditable failure modes when backends or allowlists are wrong.",
        "components": ["remote-signer"],
        "code_refs": [
            "apps/oracle-attester/src/remote_signer_main.py",
            "apps/oracle-attester/src/signer_backend.py",
            "apps/oracle-attester/src/signer_allowlist.py",
            "apps/oracle-attester/src/signer_ops.py",
        ],
        "doc_refs": [
            "docs/security_review_scope.md",
            "docs/signer_kms_ops.md",
        ],
        "test_refs": [
            "apps/oracle-attester/tests/test_remote_signer.py",
            "apps/oracle-attester/tests/test_signer_backend.py",
            "apps/oracle-attester/tests/test_signer_allowlist.py",
            "apps/oracle-attester/tests/test_signer_ops.py",
        ],
    },
    {
        "id": "INV-006",
        "statement": "The matching keeper should surface backlog and stale-snapshot conditions before they become silent liveness failures.",
        "components": ["matching-keeper", "ops"],
        "code_refs": [
            "apps/matching-keeper/src/service.py",
            "apps/matching-keeper/src/storage.py",
            "ops/monitoring/alerts.yml",
        ],
        "doc_refs": [
            "docs/ops_runbook.md",
            "docs/production_checklist.md",
        ],
        "test_refs": [
            "apps/matching-keeper/tests/test_service.py",
            "apps/matching-keeper/tests/test_storage.py",
            "apps/matching-keeper/tests/test_engine.py",
        ],
    },
]


TRACKER_FINDINGS_TEMPLATE = """# Audit Findings

Use one row per reviewer finding. Keep the `ID` stable across remediation.

| ID | Severity | Status | Component | Summary | Owner | Tracking Issue | Fix PR | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AUD-001 | TBD | Open | program | Example placeholder finding title | unassigned |  |  | Replace this row with real findings. |
"""


TRACKER_REMEDIATION_TEMPLATE = """# Remediation Log

Track each finding from acknowledgement through verification.

| Finding ID | Current State | Decision Date | Owner | Planned Fix | Verification Evidence | Closed Date |
| --- | --- | --- | --- | --- | --- | --- |
| AUD-001 | triage | YYYY-MM-DD | unassigned | Describe the intended change or accepted risk. | Link commit, PR, test run, or reviewer sign-off. |  |
"""


TRACKER_README_TEMPLATE = """# Review Workflow

1. Reviewers record each issue in `audit_findings.md`.
2. Maintainers copy the finding ID into `remediation_log.md`, assign an owner, and decide whether to fix, mitigate, or explicitly accept the risk.
3. Each remediation should link the implementation PR or commit plus the verification evidence used to close it.
4. Keep historical rows; do not delete closed findings.
"""
