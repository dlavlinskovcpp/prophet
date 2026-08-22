#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from release_config import ConfigValidationError, validate_checked_in_environments, validate_environment_config


def public_config() -> dict:
    return json.loads((ROOT / "deploy/environments/public-devnet.json").read_text(encoding="utf-8"))


def reject(config: dict, message: str = "") -> None:
    try:
        validate_environment_config(
            config,
            env_name=config["environment"],
            root=ROOT,
            live=False,
            check_artifacts=False,
        )
    except ConfigValidationError:
        return
    raise AssertionError(message or "configuration unexpectedly validated")


class CheckedInReleaseConfigTests(unittest.TestCase):
    def test_repository_checked_in_configs_validate_without_rewrite(self):
        paths = [ROOT / "deploy/environments" / f"{name}.json" for name in ("localnet", "devnet", "public-devnet", "mainnet-beta")]
        before = {path: path.read_bytes() for path in paths}
        validate_checked_in_environments(ROOT)
        after = {path: path.read_bytes() for path in paths}
        self.assertEqual(before, after)

    def test_public_devnet_wrong_program_id_rejected(self):
        config = public_config(); config["expected_program_id"] = "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A"
        reject(config)

    def test_public_devnet_direct_attester_rejected(self):
        config = public_config(); config["secure_settlement"]["direct_attester_settlement_enabled"] = True
        reject(config)

    def test_generic_settlement_signer_rejected(self):
        config = public_config(); config["secure_settlement"]["generic_remote_signer_settlement_enabled"] = True
        reject(config)

    def test_equal_verifiers_rejected(self):
        config = public_config(); config["secure_settlement"]["verifier_b"] = copy.deepcopy(config["secure_settlement"]["verifier_a"])
        reject(config)

    def test_equal_signers_rejected(self):
        config = public_config(); config["secure_settlement"]["signer_b"] = copy.deepcopy(config["secure_settlement"]["signer_a"])
        reject(config)

    def test_non_persistent_journal_rejected(self):
        config = public_config(); config["secure_settlement"]["signing_journal_path"] = "./journal.sqlite"
        reject(config)

    def test_malformed_endpoint_rejected(self):
        config = public_config(); config["service_endpoints"]["coordinator_base_url"] = "not a url"
        reject(config)

    def test_live_authorized_example_endpoint_rejected(self):
        config = public_config()
        config["deployment_authorized"] = True
        config["wallet_path"] = "/run/secrets/deploy-authority.json"
        config["program_keypair_path"] = "/run/secrets/program-keypair.json"
        config["deployment_artifacts"] = {
            "compose_manifest": "deploy/operated/public-devnet/docker-compose.yml",
            "stack_values_template": "deploy/operated/public-devnet/docker-compose.yml",
            "resolver_registry_env_template": "deploy/operated/public-devnet/docker-compose.yml",
            "matching_keeper_env_template": "deploy/operated/public-devnet/docker-compose.yml",
        }
        config["service_endpoints"] = {
            "verifier_a_base_url": "https://verifier-a.prophet.invalid",
            "verifier_b_base_url": "https://verifier-b.prophet.invalid",
            "coordinator_base_url": "https://coordinator.example",
            "secure_settlement_base_url": "https://settlement.prophet.invalid",
            "resolver_registry_url": "https://registry.prophet.invalid/resolvers",
            "matching_keeper_base_url": "https://keeper.prophet.invalid",
        }
        with self.assertRaisesRegex(ConfigValidationError, "unresolved placeholder"):
            validate_environment_config(config, env_name="public-devnet", root=ROOT, live=True, check_artifacts=False)

    def test_mainnet_deploy_attempt_while_authorization_false_rejected(self):
        config = json.loads((ROOT / "deploy/environments/mainnet-beta.json").read_text(encoding="utf-8"))
        with self.assertRaises(ConfigValidationError):
            validate_environment_config(config, env_name="mainnet-beta", root=ROOT, live=True, check_artifacts=False)


if __name__ == "__main__":
    unittest.main()
