#!/usr/bin/env python3
"""Build checksum-backed RC4.8 release provenance from build artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "docs/audit/rc4_8_security_acceptance_basis.json"
COMPOSE = ROOT / "deploy/operated/public-devnet/docker-compose.yml"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, str | int]:
    if not path.is_file():
        raise SystemExit(f"missing release artifact: {path}")
    return {"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--program", type=Path, required=True)
    parser.add_argument("--idl", type=Path, required=True)
    parser.add_argument("--sbom-dir", type=Path)
    args = parser.parse_args()
    commit = subprocess.check_output(["git", "rev-parse", args.commit_sha], cwd=ROOT, text=True).strip()
    if commit != args.commit_sha:
        raise SystemExit("release provenance commit did not resolve exactly")
    images = {}
    for image in re.findall(r"^\s*image:\s*([^\s#]+)", COMPOSE.read_text(encoding="utf-8"), re.MULTILINE):
        role = image.split("/")[-1].split("@")[0]
        images[role] = image
    sbom = []
    if args.sbom_dir is not None:
        sbom = [artifact(path) for path in sorted(args.sbom_dir.rglob("*")) if path.is_file()]
        if not sbom:
            raise SystemExit("SBOM directory is empty")
    payload = {
        "schema": "PROPHET_RC48_RELEASE_PROVENANCE_V1",
        "release": "v1.0.0-rc4.8",
        "source": {"commit_sha": commit},
        "artifacts": {"program_so": artifact(args.program), "idl": artifact(args.idl), "sbom": sbom},
        "acceptance_basis": {"revision": 7, "sha256": sha256(ACCEPTANCE)},
        "operated_images": images,
        "public_devnet": "PAUSED",
        "mainnet": "BLOCKED",
        "deployment": "NONE",
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output = args.output_dir / "rc4.8-provenance.json"
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (args.output_dir / "SHA256SUMS").write_text(f"{sha256(output)}  {output.name}\n", encoding="utf-8")
    print(output)
    print(args.output_dir / "SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
