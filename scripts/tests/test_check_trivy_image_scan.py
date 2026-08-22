import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.check_trivy_image_scan import ScanPolicyError, main, validate


def report(*vulnerabilities):
    return {
        "Results": [
            {"Type": "debian", "Vulnerabilities": list(vulnerabilities)}
        ]
    }


def finding(identifier="CVE-1", package="base", version="1"):
    return {
        "VulnerabilityID": identifier,
        "PkgName": package,
        "InstalledVersion": version,
        "Severity": "HIGH",
        "Status": "affected",
    }


def exception():
    return {
        "schema_version": 1,
        "exceptions": [
            {
                "vulnerability_id": "CVE-1",
                "package": "base",
                "installed_version": "1",
                "ecosystem": "debian",
                "roles": ["oracle"],
                "disposition": "affected_with_temporary_exception",
                "reason": "No compatible fixed artifact.",
                "removal_assessment": "Required base dependency.",
                "compensating_controls": "Pinned base and expiry review.",
                "owner": "Security",
                "review_by": "2099-01-01",
                "expires_on": "2099-01-01",
            }
        ],
    }


class TrivyImageScanPolicyTests(unittest.TestCase):
    def test_exact_exception_allows_only_its_observed_finding(self):
        validate(report(finding()), exception(), "oracle")

    def test_unexplained_or_stale_finding_fails_closed(self):
        with self.assertRaises(ScanPolicyError):
            validate(report(finding(package="other")), exception(), "oracle")
        with self.assertRaises(ScanPolicyError):
            validate(report(), exception(), "oracle")

    def test_application_sbom_has_no_exception_path(self):
        validate(report(), None, "oracle")
        with self.assertRaises(ScanPolicyError):
            validate(report(finding()), None, "oracle")

    def test_empty_policy_is_valid_when_no_findings_exist(self):
        validate(report(), {"schema_version": 1, "exceptions": []}, "oracle")

    def test_malformed_expired_and_wildcard_policies_fail_closed(self):
        malformed = exception()
        malformed["schema_version"] = 2
        with self.assertRaises(ScanPolicyError):
            validate(report(), malformed, "oracle")
        expired = exception()
        expired["exceptions"][0]["expires_on"] = "2000-01-01"
        with self.assertRaises(ScanPolicyError):
            validate(report(finding()), expired, "oracle")
        wildcard = exception()
        wildcard["exceptions"][0]["package"] = "*"
        with self.assertRaises(ScanPolicyError):
            validate(report(finding()), wildcard, "oracle")

    def test_missing_configured_exception_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            report_path.write_text(json.dumps(report()), encoding="utf-8")
            with patch("sys.argv", [
                "check_trivy_image_scan.py",
                "--report", str(report_path),
                "--exceptions", str(Path(directory) / "missing.json"),
                "--role", "oracle",
            ]):
                self.assertEqual(main(), 1)
