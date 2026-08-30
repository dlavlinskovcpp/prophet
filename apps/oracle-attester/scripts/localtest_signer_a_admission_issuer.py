"""Localtest-only fixed issuer-A initializer and one-shot G1 issuer."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from solders.keypair import Keypair

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.fixed_role_admission_issuer import _issue_fixed_role_admission_grant


def _seed_path(state_dir: str) -> Path:
    path = Path(state_dir)
    if not path.is_absolute(): raise ValueError("localtest_issuer_state_path_invalid")
    path.mkdir(mode=0o700, parents=True, exist_ok=True); path.chmod(0o700)
    details = path.lstat()
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o077: raise ValueError("localtest_issuer_state_permissions_invalid")
    return path.resolve(strict=True) / "admission-issuer.seed"


def _key(path: Path) -> Keypair:
    if path.exists():
        details = path.lstat()
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or details.st_mode & 0o077 or details.st_size != 32 or (hasattr(os, "geteuid") and details.st_uid != os.geteuid()): raise ValueError("localtest_issuer_seed_invalid")
        seed = path.read_bytes()
    else:
        seed = secrets.token_bytes(32)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try: os.fchmod(descriptor, 0o600); os.write(descriptor, seed); os.fsync(descriptor)
        finally: os.close(descriptor)
    if len(seed) != 32: raise ValueError("localtest_issuer_seed_invalid")
    return Keypair.from_seed(seed)


def initialize_localtest_signer_a_issuer(state_dir: str, *, issuer_id: str, key_id: str) -> dict[str, object]:
    key = _key(_seed_path(state_dir))
    return {"schema": "PROPHET_LOCALTEST_ADMISSION_ISSUER_V1", "version": 1, "role": "A", "issuer_id": issuer_id, "key_id": key_id, "public_key": str(key.pubkey()), "ready": True}


def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--state-dir", required=True); parser.add_argument("--issuer-id", required=True); parser.add_argument("--key-id", required=True); parser.add_argument("--request-file"); parser.add_argument("--issuer-config-file"); parser.add_argument("--acceptance-run-id"); parser.add_argument("--grant-output")
    args = parser.parse_args()
    metadata = initialize_localtest_signer_a_issuer(args.state_dir, issuer_id=args.issuer_id, key_id=args.key_id)
    if args.request_file is None and args.issuer_config_file is None and args.acceptance_run_id is None and args.grant_output is None:
        print(json.dumps(metadata, separators=(",", ":"))); return
    if not all((args.request_file, args.issuer_config_file, args.acceptance_run_id, args.grant_output)):
        raise SystemExit("localtest_issuer_issue_arguments_required")
    config = json.loads(Path(args.issuer_config_file).read_text(encoding="utf-8"))
    key = _key(_seed_path(args.state_dir))
    if config.get("issuer_public_key") != str(key.pubkey()): raise SystemExit("localtest_issuer_public_key_mismatch")
    grant = _issue_fixed_role_admission_grant(fixed_role="A", config_value=config, raw_request=Path(args.request_file).read_bytes(), acceptance_run_id=args.acceptance_run_id, key_loader=lambda _: key)
    Path(args.grant_output).write_bytes(grant)
    print(json.dumps(metadata, separators=(",", ":")))


if __name__ == "__main__": main()
