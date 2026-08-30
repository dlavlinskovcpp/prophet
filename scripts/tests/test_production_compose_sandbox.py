"""Regression checks for the operated public-devnet/mainnet sandbox boundary."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENTS = ("public-devnet", "mainnet-beta")
APPLICATION_SERVICES = (
    "resolver-registry",
    "verifier-a",
    "verifier-b",
    "coordinator",
    "matching-keeper",
)
CONTROLS = (
    'user: "10001:10001"',
    "read_only: true",
    "cap_drop: [ALL]",
    "security_opt: [no-new-privileges:true]",
    "pids_limit: 256",
    "mem_limit: 512m",
    'cpus: "1.0"',
    'tmpfs: ["/tmp:rw,noexec,nosuid,size=64m,mode=1777"]',
    "restart: on-failure:5",
)


def _block(text: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\s*\n(.*?)(?=^  [a-z0-9-]+:\s*$|^networks:|\Z)",
        text,
    )
    if match is None:
        raise AssertionError(f"missing service {name}")
    return match.group(1)


class ProductionComposeSandboxTests(unittest.TestCase):
    def test_application_sandbox_and_secret_isolation(self) -> None:
        for environment in ENVIRONMENTS:
            text = (ROOT / "deploy" / "operated" / environment / "docker-compose.yml").read_text(encoding="utf-8")
            self.assertIn("control:\n    internal: true", text)
            self.assertIn("egress: {}", text)
            if environment == "public-devnet":
                self.assertIn("networks: [control]", _block(text, "vault"))
            for service in APPLICATION_SERVICES:
                block = _block(text, service)
                for control in CONTROLS:
                    self.assertIn(control, block, f"{environment}/{service}: {control}")
                self.assertNotIn("ports:", block, f"{environment}/{service} publishes a host port")

            keeper = _block(text, "matching-keeper")
            self.assertIn("/run/secrets/keeper-id.json:ro", keeper)
            self.assertIn("PAYER_KEYPAIR_PATH: /run/secrets/keeper-id.json", keeper)
            for service in ("resolver-registry", "verifier-a", "verifier-b", "coordinator", "matching-keeper"):
                self.assertNotIn("settlement-fee-payer.json", _block(text, service))
            for service in ("resolver-registry", "verifier-a", "verifier-b", "coordinator"):
                self.assertNotIn("keeper-id.json", _block(text, service))
            with self.assertRaises(AssertionError):
                _block(text, "secure-settlement")
            self.assertNotIn("settlement-fee-payer.json", text)
            coordinator = _block(text, "coordinator")
            for retired in ("PROPHET_VAULT_SIGNER_A_TOKEN", "PROPHET_VAULT_SIGNER_B_TOKEN", "SIGNER_A_AUTH_REF", "SIGNER_B_AUTH_REF"):
                self.assertNotIn(retired, coordinator)

    def test_sqlite_wal_mounts_are_distinct(self) -> None:
        for environment in ENVIRONMENTS:
            text = (ROOT / "deploy" / "operated" / environment / "docker-compose.yml").read_text(encoding="utf-8")
            coordinator = _block(text, "coordinator")
            root = f"/var/lib/prophet/{environment}"
            mount = f"/coordinator:{root}/coordinator"
            self.assertIn(mount, coordinator)
            with self.assertRaises(AssertionError):
                _block(text, "secure-settlement")
            self.assertNotIn(f"/signing:{root}/signing", text)
            self.assertNotIn(f"/submission:{root}/submission", text)

    def test_retired_dual_token_templates_are_absent(self) -> None:
        for environment in ("devnet", "public-devnet", "mainnet-beta"):
            base = ROOT / "deploy" / "operated" / environment
            self.assertFalse((base / "secure-settlement-runtime.example.yaml").exists())
            for template in base.glob("*.env.example"):
                text = template.read_text(encoding="utf-8")
                self.assertNotIn("SIGNER_A_AUTH_REF", text)
                self.assertNotIn("SIGNER_B_AUTH_REF", text)


if __name__ == "__main__":
    unittest.main()
