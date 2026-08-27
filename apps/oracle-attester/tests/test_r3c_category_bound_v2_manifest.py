"""Integrity-only freeze for the replacement R3C V2 vector set."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "tests" / "vectors" / "r3c_category_bound_v2"
MANIFEST = VECTORS / "manifest.json"
EXPECTED_MANIFEST_SHA256 = "9e6dafc41c450a62d733b5bf5bef93fea8f1460641091edd8f818a6f507e254c"
MR_I1_REF = "bb9845b7099ba1620ce6ca09c2a3853c4c475f1b8776eb5cd1b84a205e7dd7ee"
V1_MANIFEST_SHA256 = "d1ec055d779e90db8b782827957a77dd4de4918643d4db5e01292fdd6c86666d"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_v2_manifest_and_all_constituents_are_immutable() -> None:
    assert _sha(MANIFEST) == EXPECTED_MANIFEST_SHA256
    manifest = json.loads(MANIFEST.read_text())
    assert manifest["vector_set_id"] == "PROPHET_R3C_CATEGORY_BOUND_CRYPTOGRAPHIC_VECTOR_SET_V2"
    assert manifest["constituent_count"] == 33
    rows = manifest["constituents"]
    assert len(rows) == len({row["vector_id"] for row in rows}) == len({row["relative_path"] for row in rows}) == 33
    for row in rows:
        path = ROOT.parent.parent / row["relative_path"]
        assert path.is_file()
        assert _sha(path) == row["sha256"]


def test_v2_binding_table_and_immutable_references_are_complete() -> None:
    manifest = json.loads(MANIFEST.read_text())
    table = manifest["binding_table"]
    assert len(table) == len({(row["signer_role"], row["evidence_category"]) for row in table}) == 28
    assert all(row["expected_evidence_source"] for row in table)
    failed = manifest["failed_candidate_supersession"]
    assert failed["manifest_sha256"] == V1_MANIFEST_SHA256
    assert failed["status"] == "FAILED IMMUTABLE CANDIDATE — SUPERSEDED BEFORE ACCEPTANCE"
    historical = manifest["historical_supersession"]
    assert _sha(ROOT.parent.parent / historical["historical_fixture"]) == historical["sha256"]
    d2 = manifest["still_active_unchanged"]["d2"]
    assert _sha(ROOT.parent.parent / d2["path"]) == d2["sha256"]
    assert manifest["still_active_unchanged"]["mr_i1"]["provenance_ref"] == MR_I1_REF


def test_v2_positive_inputs_match_their_package_targets() -> None:
    def package(name: str) -> list[dict]:
        return json.loads((VECTORS / "packages" / f"{name}.json").read_text())["unsigned_package"]["redaction_provenance"]["r3c_authorization_items"]

    primary = {(row["signer_role"], row["evidence_category"]): row for row in package("provider-primary")}
    manual = {(row["signer_role"], row["evidence_category"]): row for row in package("manual-review-alternative")}
    assert len(primary) == len(manual) == 28
    fields = ("signer_role", "evidence_category", "artifact_id", "raw_artifact_sha256", "redacted_artifact_sha256")
    for path, field in ((VECTORS / "provider-results", "unsigned_result"), (VECTORS / "vault-admin", "unsigned_attestation")):
        for vector_path in path.glob("*.json"):
            source = json.loads(vector_path.read_text())[field]
            target = primary[(source["signer_role"], source["evidence_category"])]
            assert tuple(source[name] for name in fields) == tuple(target[name] for name in fields)
            assert (source["environment"], source["git_sha"], source["evidence_set_id"]) == ("public-devnet", "af50c01f562b6cb1a0851fa0f59c45d820d595f8", "evidence-set-001")
    for vector_path in (VECTORS / "manual-review").glob("*.json"):
        source = json.loads(vector_path.read_text())["permit"]
        target = manual[(source["signer_role"], source["evidence_category"])]
        assert tuple(source[name] for name in fields) == tuple(target[name] for name in fields)
    a_journal = manual[("A", "journal_storage")]
    assert tuple(a_journal[name] for name in fields) == ("A", "journal_storage", "artifact-a-journal-001", "a" * 64, "b" * 64)
    assert a_journal["provenance_ref"] == MR_I1_REF
