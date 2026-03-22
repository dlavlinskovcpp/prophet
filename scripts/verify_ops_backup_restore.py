#!/usr/bin/env python3
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Dict, Iterable


ROOT = Path(__file__).resolve().parents[1]
MANAGED_PATHS = [
    "audit",
    "proof_store",
    "resolver_store",
    "apps/matching-keeper/state",
]
REFERENCE_COPIES = [
    "ops/monitoring",
    "docker-compose.localnet.yml",
    "apps/oracle-attester/.env.example",
    "apps/matching-keeper/.env.example",
]


def _write_fixture_tree(root: Path) -> None:
    for rel in MANAGED_PATHS:
        (root / rel).mkdir(parents=True, exist_ok=True)

    fixtures = {
        "audit/attester.jsonl": '{"event":"resolve_submitted","market":"m1"}\n',
        "audit/remote-signer.jsonl": '{"event":"sign_success","public_key":"pk1"}\n',
        "proof_store/proof-001.bin": "proof-bytes-001\n",
        "resolver_store/resolver-001.json": '{"resolver":"weather","version":1}\n',
        "apps/matching-keeper/state/matcher.db": "sqlite-fixture-placeholder\n",
        "apps/matching-keeper/state/cache/attempts.log": "attempt-1\nattempt-2\n",
    }
    for rel, content in fixtures.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    for rel in REFERENCE_COPIES:
        src = ROOT / rel
        if not src.exists():
            continue
        dst = root / rel
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def _tree_digest(root: Path, rel_paths: Iterable[str]) -> Dict[str, str]:
    snapshot: Dict[str, str] = {}
    for rel in rel_paths:
        target = root / rel
        snapshot[f"{rel}/"] = "dir" if target.is_dir() else "missing"
        if not target.exists():
            continue
        for path in sorted(target.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if path.is_dir():
                snapshot[f"{relative}/"] = "dir"
                continue
            snapshot[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def _run(command: list[str], *, env: Dict[str, str], expect_ok: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if expect_ok and proc.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    if not expect_ok and proc.returncode == 0:
        raise RuntimeError(f"Command unexpectedly succeeded: {' '.join(command)}")
    return proc


def _verify_checksum(archive_path: Path, checksum_path: Path) -> None:
    if not checksum_path.exists():
        raise RuntimeError(f"Missing checksum file: {checksum_path}")
    line = checksum_path.read_text(encoding="utf-8").strip()
    expected = line.split()[0]
    actual = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if expected != actual:
        raise RuntimeError(f"Checksum mismatch for {archive_path}: {expected} != {actual}")


def _verify_manifest(archive_path: Path) -> None:
    with tarfile.open(archive_path, "r:gz") as tar:
        manifest_members = [member for member in tar.getmembers() if member.name.endswith("/manifest.txt")]
        if len(manifest_members) != 1:
            raise RuntimeError(f"Expected exactly one manifest.txt in {archive_path}")
        manifest = tar.extractfile(manifest_members[0])
        if manifest is None:
            raise RuntimeError(f"Unable to read manifest from {archive_path}")
        content = manifest.read().decode("utf-8")
    required = [
        "created_at_utc=",
        "repo_root=",
        "included_paths=audit proof_store resolver_store apps/matching-keeper/state ops/monitoring docker-compose.localnet.yml",
    ]
    for needle in required:
        if needle not in content:
            raise RuntimeError(f"Manifest missing expected entry {needle!r}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="prophet-ops-verify-") as tmp:
        tmp_root = Path(tmp)
        fake_root = tmp_root / "workspace"
        fake_root.mkdir(parents=True, exist_ok=True)
        _write_fixture_tree(fake_root)

        expected_state = _tree_digest(fake_root, MANAGED_PATHS)

        archive_path = tmp_root / "ops-backup.tar.gz"
        checksum_path = Path(str(archive_path) + ".sha256")
        env = dict(os.environ)
        env["PROPHET_OPS_ROOT_DIR"] = str(fake_root)

        _run(["bash", "scripts/ops_backup.sh", str(archive_path)], env=env)
        if not archive_path.exists():
            raise RuntimeError(f"Backup archive was not created: {archive_path}")
        _verify_checksum(archive_path, checksum_path)
        _verify_manifest(archive_path)

        for rel in MANAGED_PATHS:
            target = fake_root / rel
            target.mkdir(parents=True, exist_ok=True)
            (target / "corrupted.txt").write_text("corrupted\n", encoding="utf-8")
        monitoring_sentinel = fake_root / "ops/monitoring/local-sentinel.txt"
        monitoring_sentinel.write_text("should survive restore\n", encoding="utf-8")

        failed_restore = _run(
            ["bash", "scripts/ops_restore.sh", str(archive_path)],
            env=env,
            expect_ok=False,
        )
        if "Refusing to restore over non-empty" not in failed_restore.stderr:
            raise RuntimeError("Restore safeguard did not reject overwrite without --force")

        _run(["bash", "scripts/ops_restore.sh", "--force", str(archive_path)], env=env)

        restored_state = _tree_digest(fake_root, MANAGED_PATHS)
        if restored_state != expected_state:
            raise RuntimeError("Managed ops state after restore does not match the backup fixture")
        if not monitoring_sentinel.exists():
            raise RuntimeError("Restore unexpectedly rewrote non-managed monitoring config")

        print("backup/restore verification passed")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
