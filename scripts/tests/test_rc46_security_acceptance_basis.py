from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "docs/audit/rc4_6_security_acceptance_basis.json"
VALIDATOR = ROOT / "scripts/validate_rc46_security_acceptance.py"


class RC46SecurityAcceptanceBasisTests(unittest.TestCase):
    def test_revision_and_immutable_predecessor_are_explicit(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(data["acceptance_basis_revision"], 5)
        self.assertEqual(data["previous_manifest_sha256"], "a56bb5d2515839d003932b2a18036fc1483066a900d566a89278dc6e9812337b")
        self.assertEqual(data["immutable_crypto_vectors"]["g1"], "UNCHANGED")
        self.assertEqual(data["immutable_crypto_vectors"]["d2"], "UNCHANGED")
        self.assertEqual(data["lanes"][2]["expected_passed"], 1446)
        self.assertEqual(data["lanes"][2]["expected_skipped"], 3)

    def test_manifest_validator_accepts_basis_without_running_suites(self):
        result = subprocess.run([sys.executable, str(VALIDATOR)], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RC4.6 acceptance manifest: VALID", result.stdout)
