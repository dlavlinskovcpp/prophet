#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import release as release_tool


PROGRAM_ID = "913Xp7ck53fMFTjGdKtjiwQXsBa4SfC9hce1SVGr3G9A"
CI_PROGRAM_ID = "3AUW4eLPigqyHmQNapcmv3JSYw6s8Aa5PPf87ayGT8kE"
TEST_KEYPAIR = list(range(64))


def _contains_solana_keypair_shape(value):
    if isinstance(value, list):
        if len(value) == 64 and all(
            type(item) is int and 0 <= item <= 255 for item in value
        ):
            return True
        return any(_contains_solana_keypair_shape(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_solana_keypair_shape(item) for item in value.values())
    return False


class ReleaseBundleSecretBoundaryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="prophet-p07-test-")
        self.root = Path(self._tmp.name)
        self.bundle_root = self.root / "bundles"
        self.env_dir = self.root / "deploy" / "environments"

        self._old_root = release_tool.ROOT
        self._old_env_dir = release_tool.ENVIRONMENTS_DIR
        self._old_bundle_root = release_tool.DEFAULT_BUNDLE_ROOT
        release_tool.ROOT = self.root
        release_tool.ENVIRONMENTS_DIR = self.env_dir
        release_tool.DEFAULT_BUNDLE_ROOT = self.bundle_root

        self._write_required_repo_files()

    def tearDown(self):
        release_tool.ROOT = self._old_root
        release_tool.ENVIRONMENTS_DIR = self._old_env_dir
        release_tool.DEFAULT_BUNDLE_ROOT = self._old_bundle_root
        self._tmp.cleanup()

    def _write(self, relative, data, *, binary=False):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path

    def _write_required_repo_files(self):
        self._write("programs/prophet/Cargo.toml", '[package]\nversion = "1.0.0"\n')
        self._write(
            "Anchor.toml",
            f'[toolchain]\nanchor_version = "1.0.1"\n[programs.localnet]\nprophet = "{PROGRAM_ID}"\n',
        )
        self._write("programs/prophet/src/lib.rs", f'anchor_lang::declare_id!("{PROGRAM_ID}");\n')
        self._write("sdk/python/pyproject.toml", '[tool.poetry]\nversion = "1.0.0"\n')
        self._write(
            "apps/oracle-attester/pyproject.toml",
            '[tool.poetry]\nversion = "1.0.0"\n',
        )
        self._write(
            "apps/matching-keeper/pyproject.toml",
            '[tool.poetry]\nversion = "1.0.0"\n',
        )
        self._write("package.json", '{"name":"prophet-test"}\n')
        self._write("target/deploy/prophet.so", b"TEST-SBF-BINARY", binary=True)
        self._write(
            "target/idl/prophet.json",
            json.dumps({"address": PROGRAM_ID}) + "\n",
        )
        self._write("target/types/prophet.ts", "export type Prophet = {};\n")

    def _config(self, **overrides):
        config = {
            "environment": "localnet",
            "cluster_name": "localnet",
            "anchor_cluster": "http://127.0.0.1:8899",
            "rpc_url": "http://127.0.0.1:8899",
            "wallet_path": str(self.root / "operator" / "deployment-authority.json"),
            "program_keypair_path": "target/deploy/prophet-keypair.json",
            "binary_path": "target/deploy/prophet.so",
            "idl_path": "target/idl/prophet.json",
            "ts_types_path": "target/types/prophet.ts",
            "expected_program_id": PROGRAM_ID,
            "program_identity_policy": "match-source",
            "deployment_authorized": True,
            "service_endpoints": {
                "attester_base_url": "http://127.0.0.1:8000",
                "remote_signer_url": "http://127.0.0.1:8100/sign",
                "resolver_registry_url": "http://127.0.0.1:8200/resolvers",
                "matching_keeper_base_url": "http://127.0.0.1:8010",
            },
        }
        config.update(overrides)
        return config

    def _bundle(self, config=None, *, release_tag="test-release"):
        config = config or self._config()
        env_path = self.env_dir / f"{config['environment']}.json"
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

        with mock.patch.object(release_tool, "_git_output", return_value="test-git"), mock.patch.object(
            release_tool, "_git_dirty", return_value=False
        ):
            manifest = release_tool._build_manifest(
                env_name=config["environment"],
                env_path=env_path,
                config=config,
                release_tag=release_tag,
            )

        bundle_dir = release_tool._bundle_release(
            manifest=manifest,
            env_path=env_path,
            config=config,
            bundle_root=self.bundle_root,
        )
        return manifest, bundle_dir

    def test_bundle_succeeds_with_public_program_identity_only(self):
        config = self._config(
            wallet_path=str(self.root / "missing-wallet.json"),
            program_keypair_path="target/deploy/missing-program-keypair.json",
        )

        manifest, bundle_dir = self._bundle(config)

        self.assertEqual(manifest["program"]["program_id"], PROGRAM_ID)
        self.assertEqual(
            (bundle_dir / "target/deploy/prophet.so").read_bytes(),
            b"TEST-SBF-BINARY",
        )
        self.assertTrue((bundle_dir / "target/idl/prophet.json").is_file())
        self.assertEqual(manifest["deployment"]["credential_boundary"], "external")

    def test_bundle_contains_no_program_deployment_or_fee_payer_keypairs(self):
        self._write(
            "target/deploy/prophet-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        self._write(
            "operator/deployment-authority-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        self._write(
            "operator/fee-payer-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )

        _, bundle_dir = self._bundle()

        names = [path.name.lower() for path in bundle_dir.rglob("*") if path.is_file()]
        self.assertFalse(any("keypair" in name for name in names))
        self.assertFalse(any("fee-payer" in name for name in names))

    def test_recursive_bundle_inspection_finds_no_solana_secret_key_array(self):
        self._write(
            "target/deploy/prophet-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        _, bundle_dir = self._bundle()

        for path in bundle_dir.rglob("*"):
            if not path.is_file():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            self.assertFalse(
                _contains_solana_keypair_shape(payload),
                f"secret-key-shaped JSON found in {path.relative_to(bundle_dir)}",
            )

    def test_real_looking_program_keypair_path_is_not_copied_or_read_by_bundle(self):
        keypair_path = self._write(
            "target/deploy/prophet-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )

        with mock.patch.object(
            release_tool,
            "_run",
            side_effect=AssertionError("pure bundle must not read deployment keypair"),
        ):
            manifest, bundle_dir = self._bundle()

        self.assertNotIn("program_keypair_path", manifest["program"])
        self.assertNotIn(str(keypair_path), json.dumps(manifest))
        self.assertFalse((bundle_dir / "target/deploy/prophet-keypair.json").exists())

    def test_external_secret_manager_references_are_not_materialized(self):
        program_ref = (
            "EXTERNAL_SECRET_MANAGER_REFERENCE:TEST_ONLY_PROGRAM_DEPLOYMENT_KEYPAIR"
        )
        wallet_ref = (
            "EXTERNAL_SECRET_MANAGER_REFERENCE:TEST_ONLY_DEPLOYMENT_AUTHORITY"
        )
        config = self._config(
            program_keypair_path=program_ref,
            wallet_path=wallet_ref,
        )

        manifest, bundle_dir = self._bundle(config)

        bundle_bytes = b"\n".join(
            path.read_bytes()
            for path in bundle_dir.rglob("*")
            if path.is_file()
        )
        self.assertNotIn(program_ref.encode(), bundle_bytes)
        self.assertNotIn(wallet_ref.encode(), bundle_bytes)
        self.assertNotIn("wallet_path", json.dumps(manifest))
        self.assertNotIn("program_keypair_path", json.dumps(manifest))

    def test_rollback_artifact_set_remains_usable_without_embedded_credential(self):
        keypair_path = self._write(
            "target/deploy/prophet-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        wallet_path = self._write(
            "operator/deployment-authority.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )

        manifest, bundle_dir = self._bundle()
        keypair_path.unlink()
        wallet_path.unlink()

        bundled_manifest = json.loads(
            (bundle_dir / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(bundled_manifest["program"]["program_id"], PROGRAM_ID)
        self.assertEqual(
            bundled_manifest["program"]["binary"]["sha256"],
            manifest["program"]["binary"]["sha256"],
        )
        self.assertEqual(
            bundled_manifest["program"]["idl"]["sha256"],
            manifest["program"]["idl"]["sha256"],
        )
        self.assertTrue((bundle_dir / "target/deploy/prophet.so").is_file())
        self.assertTrue((bundle_dir / "target/idl/prophet.json").is_file())

    def test_deployment_path_still_consumes_separately_supplied_credentials(self):
        program_keypair = self._write(
            "operator/program-deployment-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        wallet_path = self._write(
            "operator/deployment-authority.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        config = self._config(
            program_keypair_path=str(program_keypair),
            wallet_path=str(wallet_path),
        )

        calls = []

        def fake_run(argv, **kwargs):
            calls.append(argv)
            if argv[:3] == ["solana", "address", "-k"]:
                return subprocess.CompletedProcess(argv, 0, PROGRAM_ID + "\n", "")
            return subprocess.CompletedProcess(argv, 0, "", "")

        with mock.patch.object(release_tool, "_run", side_effect=fake_run):
            release_tool._validate_deployment_program_identity(config, PROGRAM_ID)
            release_tool._deploy_program(config, dry_run=False)

        self.assertIn(
            ["solana", "address", "-k", str(program_keypair.resolve())],
            calls,
        )
        self.assertTrue(
            any(
                call[:2] == ["anchor", "deploy"]
                and "--provider.wallet" in call
                and str(wallet_path.resolve()) in call
                for call in calls
            )
        )

    def test_ci_throwaway_program_keypair_remains_compatible_but_unbundled(self):
        self._write(
            "target/deploy/prophet-keypair.json",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        self._write(
            "target/idl/prophet.json",
            json.dumps({"address": CI_PROGRAM_ID}) + "\n",
        )
        self._write(
            "Anchor.toml",
            f'[toolchain]\nanchor_version = "1.0.1"\n[programs.localnet]\nprophet = "{CI_PROGRAM_ID}"\n',
        )
        self._write("programs/prophet/src/lib.rs", f'anchor_lang::declare_id!("{CI_PROGRAM_ID}");\n')
        config = self._config(expected_program_id=CI_PROGRAM_ID)

        manifest, bundle_dir = self._bundle(config, release_tag="ci-test")

        self.assertEqual(manifest["program"]["program_id"], CI_PROGRAM_ID)
        self.assertFalse((bundle_dir / "target/deploy/prophet-keypair.json").exists())

    def test_missing_deployment_secret_does_not_prevent_pure_bundle(self):
        config = self._config(
            wallet_path=str(self.root / "missing" / "wallet.json"),
            program_keypair_path=str(self.root / "missing" / "program-keypair.json"),
        )

        _, bundle_dir = self._bundle(config)

        self.assertTrue((bundle_dir / "manifest.json").is_file())

    def test_manifest_and_public_environment_snapshot_omit_secret_paths(self):
        secret_wallet_path = str(self.root / "very-secret" / "wallet.json")
        secret_program_path = str(
            self.root / "very-secret" / "prophet-keypair.json"
        )
        config = self._config(
            wallet_path=secret_wallet_path,
            program_keypair_path=secret_program_path,
        )

        manifest, bundle_dir = self._bundle(config)

        manifest_text = json.dumps(manifest, sort_keys=True)
        self.assertNotIn("wallet_path", manifest_text)
        self.assertNotIn("program_keypair_path", manifest_text)
        self.assertNotIn(secret_wallet_path, manifest_text)
        self.assertNotIn(secret_program_path, manifest_text)

        bundled_env = json.loads(
            (
                bundle_dir
                / "deploy"
                / "environments"
                / "localnet.json"
            ).read_text(encoding="utf-8")
        )
        self.assertNotIn("wallet_path", bundled_env)
        self.assertNotIn("program_keypair_path", bundled_env)
        self.assertEqual(bundled_env["expected_program_id"], PROGRAM_ID)

    def test_bundle_rebuild_removes_stale_keypair_from_older_bundle(self):
        stale_dir = self.bundle_root / "test-release" / "localnet" / "target" / "deploy"
        stale_dir.mkdir(parents=True, exist_ok=True)
        (stale_dir / "prophet-keypair.json").write_text(
            json.dumps(TEST_KEYPAIR) + "\n",
            encoding="utf-8",
        )

        _, bundle_dir = self._bundle()

        self.assertFalse((bundle_dir / "target/deploy/prophet-keypair.json").exists())

    def test_bundle_guard_rejects_renamed_secret_key_json(self):
        renamed_secret = self._write(
            "deploy/operated/test/public-artifact.dat",
            json.dumps(TEST_KEYPAIR) + "\n",
        )
        config = self._config(
            deployment_artifacts={
                "test_public_artifact": str(
                    renamed_secret.relative_to(self.root)
                )
            }
        )

        with self.assertRaises(release_tool.ReleaseError):
            self._bundle(config)


if __name__ == "__main__":
    unittest.main()
