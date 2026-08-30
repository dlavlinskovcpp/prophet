#!/usr/bin/env python3
"""Build checksum-backed RC4.7 release provenance from CI/local artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = ROOT / "docs/audit/rc4_7_security_acceptance_basis.json"
RISK = ROOT / "security/rc47_residual_risk.json"
REPRO = ROOT / "security/rc47_container_reproducibility.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def image_digest(image: str) -> dict[str, str]:
    image_id = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True
    ).strip()
    repo_digests = subprocess.check_output(
        ["docker", "image", "inspect", "--format", "{{json .RepoDigests}}", image], text=True
    ).strip()
    return {
        "image": image,
        "image_id": image_id.removeprefix("sha256:"),
        "repository_digests": json.loads(repo_digests),
    }


def artifact_record(path: Path) -> dict[str, str | int]:
    return {"path": str(path), "sha256": sha256(path), "bytes": path.stat().st_size}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--program", type=Path)
    parser.add_argument("--idl", type=Path)
    parser.add_argument("--sbom-dir", type=Path)
    parser.add_argument("--image", action="append", default=[], metavar="ROLE=IMAGE")
    args = parser.parse_args()

    commit_sha = args.commit_sha or git("rev-parse", "HEAD")
    if git("rev-parse", commit_sha) != commit_sha:
        raise SystemExit("commit SHA does not resolve locally")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, object] = {}
    for label, path in (("program_so", args.program), ("idl", args.idl)):
        if path is not None:
            if not path.is_file():
                raise SystemExit(f"missing artifact: {path}")
            artifacts[label] = artifact_record(path)

    if args.sbom_dir is not None:
        sbom_files = sorted(path for path in args.sbom_dir.rglob("*") if path.is_file())
        if not sbom_files:
            raise SystemExit(f"no SBOM files found under {args.sbom_dir}")
        artifacts["sbom"] = [artifact_record(path) for path in sbom_files]

    images: dict[str, object] = {}
    for spec in args.image:
        if "=" not in spec:
            raise SystemExit(f"image must be ROLE=IMAGE: {spec}")
        role, image = spec.split("=", 1)
        images[role] = image_digest(image)

    tracked = {
        "acceptance_manifest": artifact_record(ACCEPTANCE),
        "residual_risk_manifest": artifact_record(RISK),
        "container_reproducibility_manifest": artifact_record(REPRO),
    }
    payload = {
        "schema": "PROPHET_RC47_RELEASE_PROVENANCE_V1",
        "release": "v1.0.0-rc4.7",
        "source": {"commit_sha": commit_sha},
        "artifacts": artifacts,
        "images": images,
        "tracked_evidence": tracked,
        "acceptance_basis": json.loads(ACCEPTANCE.read_text(encoding="utf-8")),
        "toolchain": json.loads(ACCEPTANCE.read_text(encoding="utf-8"))["toolchain"],
        "residual_risk": json.loads(RISK.read_text(encoding="utf-8")),
    }
    output = args.output_dir / "rc4.7-provenance.json"
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum = args.output_dir / "SHA256SUMS"
    checksum.write_text(f"{sha256(output)}  {output.name}\n", encoding="utf-8")
    print(output)
    print(checksum)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
