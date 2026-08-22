import unittest

from scripts.check_trivy_image_scan import ScanPolicyError, validate


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
