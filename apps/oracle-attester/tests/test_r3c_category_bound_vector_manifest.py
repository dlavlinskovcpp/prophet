"""Integrity-only freeze for the R3C category-bound positive vector set."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "tests" / "vectors" / "r3c_category_bound_v1"
MANIFEST = VECTOR_ROOT / "manifest.json"
EXPECTED_MANIFEST_SHA256 = "d1ec055d779e90db8b782827957a77dd4de4918643d4db5e01292fdd6c86666d"
MR_I1_PROVENANCE_REF = "bb9845b7099ba1620ce6ca09c2a3853c4c475f1b8776eb5cd1b84a205e7dd7ee"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_category_bound_manifest_and_constituents_are_hash_pinned() -> None:
    assert _sha256(MANIFEST) == EXPECTED_MANIFEST_SHA256
    manifest = json.loads(MANIFEST.read_text())
    assert manifest["vector_set_id"] == "PROPHET_R3C_CATEGORY_BOUND_CRYPTOGRAPHIC_VECTOR_SET_V1"
    assert manifest["version"] == 1
    assert manifest["constituent_count"] == 32
    constituents = manifest["constituents"]
    assert len(constituents) == 32
    assert len({entry["vector_id"] for entry in constituents}) == 32
    assert len({entry["relative_path"] for entry in constituents}) == 32
    for entry in constituents:
        path = ROOT.parent.parent / entry["relative_path"]
        assert path.is_file()
        assert _sha256(path) == entry["sha256"]


def test_historical_and_still_active_vector_links_are_unchanged() -> None:
    manifest = json.loads(MANIFEST.read_text())
    historical = manifest["historical_supersession"]
    assert historical["marker"] == "SUPERSEDED BY R3C CATEGORY-BOUND CRYPTOGRAPHIC VECTOR SET"
    assert _sha256(ROOT.parent.parent / historical["historical_fixture"]) == historical["sha256"]
    d2 = manifest["still_active_unchanged"]["d2"]
    assert d2["state"] == "STILL_ACTIVE_UNCHANGED"
    assert _sha256(ROOT.parent.parent / d2["path"]) == d2["sha256"]
    mr_i1 = manifest["still_active_unchanged"]["mr_i1"]
    assert mr_i1["state"] == "STILL_ACTIVE_UNCHANGED"
    assert mr_i1["provenance_ref"] == MR_I1_PROVENANCE_REF


def test_complete_packages_bind_each_item_to_its_exact_positive_input() -> None:
    def load(relative_path: str) -> dict:
        return json.loads((ROOT.parent.parent / relative_path).read_text())

    provider = {}
    vault = {}
    manual = {("A", "journal_storage"): MR_I1_PROVENANCE_REF}
    for path in VECTOR_ROOT.glob("provider-results/*.json"):
        vector = json.loads(path.read_text())
        row = vector["unsigned_result"]
        provider[(row["signer_role"], row["evidence_category"])] = vector
    for path in VECTOR_ROOT.glob("vault-admin/*.json"):
        vector = json.loads(path.read_text())
        row = vector["unsigned_attestation"]
        vault[(row["signer_role"], row["evidence_category"])] = vector
    for path in VECTOR_ROOT.glob("manual-review/*.json"):
        vector = json.loads(path.read_text())
        row = vector["permit"]
        manual[(row["signer_role"], row["evidence_category"])] = vector["provenance_ref"]

    for package_path in VECTOR_ROOT.glob("packages/*.json"):
        package = json.loads(package_path.read_text())["unsigned_package"]
        items = package["authorization_items"]
        assert len(items) == 28
        targets = {(item["signer_role"], item["evidence_category"]) for item in items}
        assert len(targets) == 28
        assert len({item["artifact_id"] for item in items}) == 28
        assert len({(item["artifact_id"], item["raw_artifact_sha256"], item["redacted_artifact_sha256"]) for item in items}) == 28
        for item in items:
            target = (item["signer_role"], item["evidence_category"])
            fields = ("signer_role", "evidence_category", "artifact_id", "raw_artifact_sha256", "redacted_artifact_sha256")
            if item["provenance_kind"] == "provider_result":
                assert target in provider
                assert item["provenance_ref"] == provider[target]["preimage_sha256"]
                assert tuple(item[name] for name in fields) == tuple(provider[target]["unsigned_result"][name] for name in fields)
            elif item["provenance_kind"] == "vault_admin_attestation":
                if target == ("A", "vault_key_identity_version"):
                    assert item["provenance_ref"] == load("apps/oracle-attester/tests/vectors/r3c_category_bound_v1/manifest.json")["external_references"]["d2_a_vault_key_identity_version"]["preimage_sha256"]
                    d2 = load("apps/oracle-attester/tests/vectors/vault_admin_attestation_v1.json")["unsigned_attestation"]
                    assert tuple(item[name] for name in fields) == tuple(d2[name] for name in fields)
                else:
                    assert item["provenance_ref"] == vault[target]["preimage_sha256"]
                    assert tuple(item[name] for name in fields) == tuple(vault[target]["unsigned_attestation"][name] for name in fields)
            elif item["provenance_kind"] == "manual_review_permit":
                assert item["provenance_ref"] == manual[target]
            else:
                assert item["provenance_kind"] == "machine_verified"
                assert item["evidence_category"] == "worker_reload_concurrency"
