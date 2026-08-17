#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "render_operated_stack", ROOT / "scripts" / "render_operated_stack.py"
)
assert SPEC is not None and SPEC.loader is not None
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class SecureOperatedRendererTests(unittest.TestCase):
    def config(self):
        return {
            "environment": "devnet",
            "rpc_url": "https://api.devnet.solana.com",
            "expected_program_id": "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A",
            "service_endpoints": {
                "verifier_a_base_url": "https://verifier-a.example",
                "verifier_b_base_url": "https://verifier-b.example",
                "coordinator_base_url": "https://coordinator.example",
                "secure_settlement_base_url": "https://settlement.example",
                "resolver_registry_url": "https://registry.example/resolvers",
                "matching_keeper_base_url": "https://keeper.example",
            },
            "secure_settlement": {
                "resolution_mode": "secure-coordinator",
                "direct_attester_settlement_enabled": False,
                "generic_remote_signer_settlement_enabled": False,
                "coordinator_sqlite_path": "/var/lib/prophet/devnet/coordinator.sqlite",
                "signing_journal_path": "/var/lib/prophet/devnet/signing.sqlite",
                "submission_journal_path": "/var/lib/prophet/devnet/submission.sqlite",
                "required_signer_count": 2,
                "verifier_a": {"identity": "a", "backend_ref": "a-backend", "auth_ref": "a-auth"},
                "verifier_b": {"identity": "b", "backend_ref": "b-backend", "auth_ref": "b-auth"},
                "signer_a": {"identity": "sa", "vault_key_ref": "key-a", "auth_ref": "policy-a"},
                "signer_b": {"identity": "sb", "vault_key_ref": "key-b", "auth_ref": "policy-b"},
            },
        }

    def values(self):
        return {
            "VERIFIER_A_PROOF_BACKEND_URL": "https://proof-a.example/verify",
            "VERIFIER_B_PROOF_BACKEND_URL": "https://proof-b.example/verify",
            "RESOLVER_REGISTRY_SERVICE_API_KEY": "TEST_ONLY_registry_token",
        }

    def test_secure_renderer_accepts_only_secure_topology(self):
        values = renderer._final_values(
            env_name="devnet", env_config=self.config(), loaded=self.values(), generate_secrets=False
        )
        self.assertEqual(values["RESOLUTION_MODE"], "secure-coordinator")
        self.assertEqual(values["STRICT_SIGNER_COUNT"], "2")
        self.assertEqual(set(renderer.SERVICES), {"resolver-registry", "matching-keeper"})
        self.assertNotIn("remote-signer", renderer._service_replacements(values))
        self.assertNotIn("oracle-attester", renderer._service_replacements(values))

    def test_legacy_generic_signer_value_is_rejected(self):
        loaded = self.values()
        loaded["REMOTE_SIGNER_PUBLIC_URL"] = "https://legacy-signer.example/sign"
        with self.assertRaisesRegex(renderer.RenderError, "Legacy direct-attester/generic-signer"):
            renderer._final_values(
                env_name="devnet", env_config=self.config(), loaded=loaded, generate_secrets=False
            )

    def test_same_verifier_backend_is_rejected(self):
        loaded = self.values()
        loaded["VERIFIER_B_PROOF_BACKEND_URL"] = loaded["VERIFIER_A_PROOF_BACKEND_URL"]
        with self.assertRaisesRegex(renderer.RenderError, "proof backend"):
            renderer._final_values(
                env_name="devnet", env_config=self.config(), loaded=loaded, generate_secrets=False
            )

    def test_sync_writes_secure_metadata_and_removes_legacy_endpoints(self):
        values = renderer._final_values(
            env_name="devnet", env_config=self.config(), loaded=self.values(), generate_secrets=False
        )
        config = self.config()
        config["service_endpoints"]["attester_base_url"] = "https://legacy-attester.example"
        config["service_endpoints"]["remote_signer_url"] = "https://legacy-signer.example/sign"
        with tempfile.TemporaryDirectory(prefix="prophet-secure-render-") as temp:
            path = Path(temp) / "devnet.json"
            renderer._sync_environment_json(path, config, values)
            saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertNotIn("attester_base_url", saved["service_endpoints"])
        self.assertNotIn("remote_signer_url", saved["service_endpoints"])
        self.assertEqual(saved["service_endpoints"]["coordinator_base_url"], "https://coordinator.example")
        self.assertEqual(saved["secure_settlement"]["required_signer_count"], 2)
        self.assertFalse(saved["secure_settlement"]["direct_attester_settlement_enabled"])
        self.assertFalse(saved["secure_settlement"]["generic_remote_signer_settlement_enabled"])
        self.assertNotEqual(
            saved["secure_settlement"]["verifier_a"]["backend_ref"],
            saved["secure_settlement"]["verifier_b"]["backend_ref"],
        )


if __name__ == "__main__":
    unittest.main()
