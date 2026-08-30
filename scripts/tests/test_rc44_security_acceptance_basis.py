"""Permanent harness regression for the manifest-backed RC4.4 acceptance basis."""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/audit/rc4_4_security_acceptance_basis.json"
VALIDATOR = ROOT / "scripts/validate_rc44_security_acceptance.py"


class RC44SecurityAcceptanceBasisTests(unittest.TestCase):
    def test_manifest_retired_metric_and_unique_lanes(self) -> None:
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(data["historical_metric"]["status"], "UNVERIFIABLE / RETIRED AS ACCEPTANCE EVIDENCE")
        self.assertEqual(data["historical_metric"]["arbitrary_numerical_reconstruction"], "FORBIDDEN")
        self.assertEqual(data["acceptance_basis_revision"], 4)
        self.assertEqual(data["supersession"]["previous_acceptance_basis"], "POST-R5")
        self.assertEqual(data["supersession"]["previous_manifest_sha256"], "2838481f58ea99c9c658dd59dac030984c4ea72b4b65d7b8c4938f3500bfcc89")
        self.assertEqual(data["supersession"]["current_acceptance_basis"], "POST-P0C4")
        self.assertEqual(data["supersession"]["reason"], "P0C4 fixed-role A/B production boundary and real localnet settlement")
        self.assertEqual(data["acceptance_semantics"], {
            "authority_root": "FRESH VERIFIED SIGNED PACKAGE + RAW EVIDENCE + TRUSTED CONTEXT ONLY",
            "package_deadline_source": "VERIFIED SIGNED PACKAGE.valid_until ONLY",
            "caller_package_deadline_authority": "NONE",
            "one_trusted_now_per_decision": True,
            "subordinate_containment_deadline": "SIGNED PACKAGE DEADLINE",
        })
        lanes = data["lanes"]
        self.assertEqual(len({lane["id"] for lane in lanes}), len(lanes))
        by_id = {lane["id"]: lane for lane in lanes}
        self.assertTrue(set(by_id) >= {"i4_r4", "i5_i2b", "r5", "p0c3e1", "oracle_attester", "p0c4_fixed_role", "p0c4_launch_surface", "rfc8785", "resolver_v2", "rust_frozen_layout"})
        self.assertEqual(by_id["i5_i2b"]["expected_passed"], 39)
        self.assertEqual(by_id["r5"]["expected_passed"], 20)
        self.assertEqual(by_id["p0c3e1"]["expected_passed"], 315)
        self.assertEqual(by_id["oracle_attester"]["expected_passed"], 1442)
        self.assertEqual(by_id["p0c4_fixed_role"]["expected_passed"], 105)
        self.assertEqual(by_id["oracle_attester"]["expected_skipped"], 3)
        self.assertEqual(data["supersession"]["lane_reconciliations"]["p0c3e1"], {"previous_passed": 315, "current_passed": 315, "delta_passed": 0})
        self.assertEqual(data["supersession"]["lane_reconciliations"]["oracle_attester"], {"previous_passed": 1320, "current_passed": 1442, "delta_passed": 122, "previous_skipped": 3, "current_skipped": 3, "delta_skipped": 0})
        self.assertEqual(data["supersession"]["lane_reconciliations"]["p0c4_fixed_role"], {"previous_passed": 0, "current_passed": 105, "delta_passed": 105})

    def test_manifest_collection_contract(self) -> None:
        result = subprocess.run([sys.executable, str(VALIDATOR), "--verify-collection"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RC4.4 acceptance collection contract: PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
