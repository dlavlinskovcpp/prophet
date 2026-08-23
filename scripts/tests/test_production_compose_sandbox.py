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
    "secure-settlement",
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

            settlement = _block(text, "secure-settlement")
            keeper = _block(text, "matching-keeper")
            self.assertIn("/run/secrets/settlement-fee-payer.json:ro", settlement)
            self.assertIn("PROPHET_SETTLEMENT_FEE_PAYER_KEYPAIR_PATH: /run/secrets/settlement-fee-payer.json", settlement)
            self.assertIn("/run/secrets/keeper-id.json:ro", keeper)
            self.assertIn("PAYER_KEYPAIR_PATH: /run/secrets/keeper-id.json", keeper)
            for service in ("resolver-registry", "verifier-a", "verifier-b", "coordinator", "matching-keeper"):
                self.assertNotIn("settlement-fee-payer.json", _block(text, service))
            for service in ("resolver-registry", "verifier-a", "verifier-b", "coordinator", "secure-settlement"):
                self.assertNotIn("keeper-id.json", _block(text, service))

    def test_sqlite_wal_mounts_are_distinct(self) -> None:
        for environment in ENVIRONMENTS:
            text = (ROOT / "deploy" / "operated" / environment / "docker-compose.yml").read_text(encoding="utf-8")
            coordinator = _block(text, "coordinator")
            settlement = _block(text, "secure-settlement")
            root = f"/var/lib/prophet/{environment}"
            mount = f"/coordinator:{root}/coordinator"
            self.assertIn(mount, coordinator)
            self.assertIn(mount, settlement)
            self.assertIn(f"/signing:{root}/signing", settlement)
            self.assertIn(f"/submission:{root}/submission", settlement)


if __name__ == "__main__":
    unittest.main()
