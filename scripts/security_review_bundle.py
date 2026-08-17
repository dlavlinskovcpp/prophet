#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import release as release_tool
from security_review_assets import (
    INVARIANT_MAP,
    REVIEW_FIXTURE_CASES,
    TRACKER_FINDINGS_TEMPLATE,
    TRACKER_README_TEMPLATE,
    TRACKER_REMEDIATION_TEMPLATE,
)


ROOT = release_tool.ROOT
DEFAULT_REVIEW_ROOT = ROOT / "security-reviews"
REFERENCE_DOCS = [
    ROOT / "docs" / "security_review_scope.md",
    ROOT / "docs" / "security_review_process.md",
    ROOT / "docs" / "trust_model.md",
    ROOT / "docs" / "protocol.md",
    ROOT / "docs" / "attestation_format.md",
    ROOT / "docs" / "resolver_spec.md",
    ROOT / "docs" / "release_runbook.md",
    ROOT / "docs" / "ops_runbook.md",
    ROOT / "docs" / "production_checklist.md",
]
REFERENCE_DIRS = [
    ROOT / "ops" / "monitoring",
]
SECRET_KEYWORDS = ("TOKEN", "SECRET", "PASSWORD", "API_KEY")
PATH_KEYS = {
    "WALLET_PATH",
    "ORACLE_KEYPAIR_PATH",
    "RELAYER_KEYPAIR_PATH",
    "PAYER_KEYPAIR_PATH",
}
OPTIONAL_OPERATED_CONFIG_NAMES = (
    "stack.env",
    ".env",
    "oracle-attester.env",
    "remote-signer.env",
    "resolver-registry.env",
    "matching-keeper.env",
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _repo_rel(path: Path, *, fallback: str = "") -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT.resolve()))
    except ValueError:
        if fallback:
            return fallback
        return str(resolved)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: Dict[str, Any] | List[Any]) -> None:
    _write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _copy_tree_or_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dst)


def _canonical_json_bytes(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pretty_json_bytes(payload: Dict[str, Any]) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _compute_resolver_hash(definition: Dict[str, Any]) -> str:
    return _sha256_bytes(_canonical_json_bytes(definition))


def _extract_value(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _evaluate_resolver(definition: Dict[str, Any], public_inputs: Dict[str, Any]) -> str:
    actual = _extract_value(public_inputs, definition["path"])
    if actual is None:
        return "INVALID"

    target = definition["target_value"]
    predicate = definition["predicate"]
    if isinstance(target, (int, float)):
        try:
            actual = float(actual)
            target = float(target)
        except (TypeError, ValueError):
            return "INVALID"

    if predicate == "equals":
        matched = actual == target
    elif predicate == "contains":
        matched = str(target) in str(actual)
    elif predicate == "gt":
        matched = actual > target
    elif predicate == "gte":
        matched = actual >= target
    elif predicate == "lt":
        matched = actual < target
    elif predicate == "lte":
        matched = actual <= target
    else:
        return "INVALID"
    return "YES" if matched else "NO"


def _release_snapshot_paths(config: Dict[str, Any], _env_path: Path) -> List[Tuple[Path, str]]:
    paths = [
        (ROOT / config["binary_path"], _repo_rel(ROOT / config["binary_path"])),
        (ROOT / config["idl_path"], _repo_rel(ROOT / config["idl_path"])),
        (ROOT / config["ts_types_path"], _repo_rel(ROOT / config["ts_types_path"])),
        (ROOT / "Anchor.toml", _repo_rel(ROOT / "Anchor.toml")),
        (ROOT / "programs" / "prophet" / "Cargo.toml", _repo_rel(ROOT / "programs" / "prophet" / "Cargo.toml")),
        (ROOT / "sdk" / "python" / "pyproject.toml", _repo_rel(ROOT / "sdk" / "python" / "pyproject.toml")),
        (ROOT / "apps" / "oracle-attester" / "pyproject.toml", _repo_rel(ROOT / "apps" / "oracle-attester" / "pyproject.toml")),
        (ROOT / "apps" / "matching-keeper" / "pyproject.toml", _repo_rel(ROOT / "apps" / "matching-keeper" / "pyproject.toml")),
        (ROOT / "package.json", _repo_rel(ROOT / "package.json")),
    ]
    for path in release_tool._deployment_artifact_paths(config, env_name=config["environment"]).values():
        paths.append((path, _repo_rel(path)))

    deduped: List[Tuple[Path, str]] = []
    seen = set()
    for src, rel_dst in paths:
        if rel_dst in seen:
            continue
        seen.add(rel_dst)
        deduped.append((src, rel_dst))
    return deduped


def _redact_scalar(key: str, value: str) -> str:
    upper = key.upper()
    if any(token in upper for token in SECRET_KEYWORDS):
        return "<redacted>"
    if upper in PATH_KEYS or "KEYPAIR" in upper:
        return "<redacted-path>"
    return value


def _redact_json_value(value: Any, *, key_hint: str = "") -> Any:
    if isinstance(value, dict):
        return {key: _redact_json_value(child, key_hint=key) for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_json_value(item, key_hint=key_hint) for item in value]
    if isinstance(value, str):
        return _redact_scalar(key_hint, value)
    return value


def _is_env_style_file(path: Path) -> bool:
    name = path.name
    return (
        name.endswith(".env")
        or name == ".env"
        or name == "stack.env"
        or ".env." in name
    )


def _redact_env_text(raw: str) -> str:
    lines: List[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            lines.append(line)
            continue
        prefix = ""
        body = line
        if body.startswith("export "):
            prefix = "export "
            body = body[len(prefix) :]
        key, value = body.split("=", 1)
        redacted = _redact_scalar(key.strip(), value.strip())
        lines.append(f"{prefix}{key}={redacted}")
    return "\n".join(lines) + ("\n" if raw.endswith("\n") else "")


def _redact_file_contents(path: Path) -> str:
    raw = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        payload = json.loads(raw)
        return json.dumps(_redact_json_value(payload), indent=2, sort_keys=True) + "\n"
    if _is_env_style_file(path):
        return _redact_env_text(raw)
    return raw


def _config_sources(config: Dict[str, Any], env_path: Path) -> List[Tuple[str, Path, str]]:
    sources: List[Tuple[str, Path, str]] = [("environment", env_path, "release-environment")]
    deployment_artifacts = release_tool._deployment_artifact_paths(config, env_name=config["environment"])
    for key, path in deployment_artifacts.items():
        sources.append((key, path, "deployment-artifact"))

    operated_dir = next(iter(deployment_artifacts.values())).parent if deployment_artifacts else None
    if operated_dir is not None:
        for name in OPTIONAL_OPERATED_CONFIG_NAMES:
            candidate = operated_dir / name
            if candidate.exists():
                sources.append((name, candidate, "operated-live"))

    for extra in (
        ROOT / "apps" / "oracle-attester" / ".env.example",
        ROOT / "apps" / "matching-keeper" / ".env.example",
    ):
        if extra.exists():
            sources.append((extra.name, extra, "service-example"))

    deduped: List[Tuple[str, Path, str]] = []
    seen = set()
    for key, path, kind in sources:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append((key, resolved, kind))
    return deduped


def _render_invariant_markdown() -> str:
    sections = ["# Invariant Map", ""]
    for invariant in INVARIANT_MAP:
        sections.append(f"## {invariant['id']}")
        sections.append(invariant["statement"])
        sections.append("")
        sections.append(f"Components: {', '.join(invariant['components'])}")
        sections.append("")
        sections.append("Code Refs:")
        sections.extend([f"- `{item}`" for item in invariant["code_refs"]])
        sections.append("")
        sections.append("Doc Refs:")
        sections.extend([f"- `{item}`" for item in invariant["doc_refs"]])
        sections.append("")
        sections.append("Test Refs:")
        sections.extend([f"- `{item}`" for item in invariant["test_refs"]])
        sections.append("")
    return "\n".join(sections).rstrip() + "\n"


def _write_fixture_cases(fixtures_dir: Path) -> List[Dict[str, Any]]:
    manifests: List[Dict[str, Any]] = []
    for case in REVIEW_FIXTURE_CASES:
        case_dir = fixtures_dir / case["slug"]
        case_dir.mkdir(parents=True, exist_ok=True)

        resolver_payload = case["resolver"]
        public_inputs_payload = case["public_inputs"]
        proof_bytes = case["proof_text"].encode("utf-8")
        public_inputs_bytes = _pretty_json_bytes(public_inputs_payload)

        resolver_hash_hex = _compute_resolver_hash(resolver_payload)
        proof_hash_hex = _sha256_bytes(proof_bytes)
        public_inputs_hash_hex = _sha256_bytes(public_inputs_bytes)
        evaluated_outcome = _evaluate_resolver(resolver_payload, public_inputs_payload)
        if evaluated_outcome != case["expected_outcome"]:
            raise release_tool.ReleaseError(
                f"Fixture case {case['slug']} outcome mismatch: {evaluated_outcome} != {case['expected_outcome']}"
            )

        _write_json(case_dir / "resolver.json", resolver_payload)
        _write_text(case_dir / "public_inputs.json", public_inputs_bytes.decode("utf-8"))
        (case_dir / "proof.bin").write_bytes(proof_bytes)

        resolve_request = {
            "outcome": case["expected_outcome"],
            "proof_bytes_b64": base64.b64encode(proof_bytes).decode("ascii"),
            "public_inputs_bytes_b64": base64.b64encode(public_inputs_bytes).decode("ascii"),
        }
        _write_json(case_dir / "resolve_request.json", resolve_request)

        expected_attester_output = {
            "resolver_hash_hex": resolver_hash_hex,
            "proof_hash_hex": proof_hash_hex,
            "public_inputs_hash_hex": public_inputs_hash_hex,
            "expected_outcome": case["expected_outcome"],
            "verifier_assumption": case["verifier_assumption"],
            "description": case["description"],
        }
        _write_json(case_dir / "expected_attester_output.json", expected_attester_output)

        manifest = {
            "slug": case["slug"],
            "description": case["description"],
            "resolver_hash_hex": resolver_hash_hex,
            "proof_hash_hex": proof_hash_hex,
            "public_inputs_hash_hex": public_inputs_hash_hex,
            "expected_outcome": case["expected_outcome"],
            "verifier_assumption": case["verifier_assumption"],
            "files": {
                "resolver": "resolver.json",
                "public_inputs": "public_inputs.json",
                "proof": "proof.bin",
                "resolve_request": "resolve_request.json",
                "expected_attester_output": "expected_attester_output.json",
            },
        }
        _write_json(case_dir / "fixture_manifest.json", manifest)
        manifests.append(manifest)
    return manifests


def _write_tracker(tracker_dir: Path) -> None:
    _write_text(tracker_dir / "README.md", TRACKER_README_TEMPLATE)
    _write_text(tracker_dir / "audit_findings.md", TRACKER_FINDINGS_TEMPLATE)
    _write_text(tracker_dir / "remediation_log.md", TRACKER_REMEDIATION_TEMPLATE)


def _write_bundle_readme(
    bundle_dir: Path,
    *,
    manifest: Dict[str, Any],
    fixture_manifests: List[Dict[str, Any]],
    config_inventory: List[Dict[str, Any]],
) -> None:
    text = f"""# Prophet External Security Review Bundle

Generated at: {dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")}
Release tag: `{manifest["release_tag"]}`
Environment: `{manifest["environment"]}`
Program id: `{manifest["program"]["program_id"]}`
Git commit: `{manifest["git"]["commit"]}`

## Contents

- `release/`: current release snapshot (binary, IDL, TS types, environment config, deployment templates, manifest)
- `configs/redacted/`: redacted service and operated-stack config material
- `fixtures/`: sample resolver/proof/public-input fixtures and expected attester outputs
- `invariants/`: machine-readable and markdown invariant mapping for reviewer traceability
- `review_tracking/`: templates for findings and remediation status
- `reference/`: review scope, trust model, runbooks, and monitoring dashboards

## Notes

- Proof fixtures are placeholder bytes intended for payload-shape and hashing review, not for cryptographic zkTLS validation.
- The `expected_attester_output.json` files assume the zkTLS verifier returns `ok=true` and focus on resolver hashing, outcome evaluation, and attester request structure.
- Secrets are redacted in `configs/redacted/`, while public service endpoints and non-secret deployment metadata remain visible.

## Review Workflow

1. Reviewers log findings in `review_tracking/audit_findings.md`.
2. Maintainers mirror each finding into `review_tracking/remediation_log.md`, assign an owner, and track the chosen fix or accepted risk.
3. Close findings only after linking code changes and verification evidence.

## Generated Fixture Cases

"""
    for case in fixture_manifests:
        text += (
            f"- `{case['slug']}`: outcome `{case['expected_outcome']}`, "
            f"resolver `{case['resolver_hash_hex']}`, proof hash `{case['proof_hash_hex']}`\n"
        )

    text += "\n## Redacted Config Sources\n\n"
    for item in config_inventory:
        text += (
            f"- `{item['kind']}`: source `{item['source_path']}` -> redacted `{item['redacted_path']}`\n"
        )

    _write_text(bundle_dir / "README.md", text)


def _collect_bundle_hashes(bundle_dir: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(bundle_dir.rglob("*")):
        if path.is_dir():
            continue
        rows.append(
            {
                "path": str(path.relative_to(bundle_dir)),
                "sha256": _sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return rows


def _build_review_bundle(
    *,
    env_name: str,
    release_tag: str,
    review_root: Path,
) -> Path:
    env_path, config = release_tool._load_environment(env_name)
    manifest = release_tool._build_manifest(
        env_name=env_name,
        env_path=env_path,
        config=config,
        release_tag=release_tag,
    )

    bundle_dir = review_root / release_tag / env_name
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    release_dir = bundle_dir / "release"
    public_env_path = (
        release_dir
        / "deploy"
        / "environments"
        / f"{config['environment']}.json"
    )
    _write_json(
        public_env_path,
        release_tool._public_environment_snapshot(config),
    )
    for src, rel_dst in _release_snapshot_paths(config, env_path):
        dst = release_dir / rel_dst
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    _write_json(release_dir / "manifest.json", manifest)
    release_tool._assert_bundle_has_no_private_key_material(release_dir)

    config_inventory: List[Dict[str, Any]] = []
    redacted_dir = bundle_dir / "configs" / "redacted"
    for key, src, kind in _config_sources(config, env_path):
        source_rel = _repo_rel(
            src,
            fallback=(
                f"deploy/environments/{config['environment']}.json"
                if key == "environment"
                else src.name
            ),
        )
        rel_dst = Path(source_rel)
        dst = redacted_dir / rel_dst
        _write_text(dst, _redact_file_contents(src))
        config_inventory.append(
            {
                "key": key,
                "kind": kind,
                "source_path": source_rel,
                "redacted_path": str(dst.relative_to(bundle_dir)),
            }
        )
    _write_json(bundle_dir / "configs" / "inventory.json", config_inventory)

    fixtures_dir = bundle_dir / "fixtures"
    fixture_manifests = _write_fixture_cases(fixtures_dir)
    _write_json(fixtures_dir / "manifest.json", fixture_manifests)

    invariants_dir = bundle_dir / "invariants"
    invariants_dir.mkdir(parents=True, exist_ok=True)
    _write_json(invariants_dir / "invariant_map.json", INVARIANT_MAP)
    _write_text(invariants_dir / "invariant_map.md", _render_invariant_markdown())

    tracker_dir = bundle_dir / "review_tracking"
    _write_tracker(tracker_dir)

    reference_dir = bundle_dir / "reference"
    for path in REFERENCE_DOCS:
        _copy_tree_or_file(path, reference_dir / "docs" / path.name)
    for path in REFERENCE_DIRS:
        _copy_tree_or_file(path, reference_dir / _repo_rel(path))

    _write_bundle_readme(
        bundle_dir,
        manifest=manifest,
        fixture_manifests=fixture_manifests,
        config_inventory=config_inventory,
    )

    review_manifest = {
        "schema_version": 1,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "release_tag": release_tag,
        "environment": env_name,
        "program_id": manifest["program"]["program_id"],
        "git_commit": manifest["git"]["commit"],
        "contents": _collect_bundle_hashes(bundle_dir),
    }
    _write_json(bundle_dir / "review_manifest.json", review_manifest)
    return bundle_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an external security review bundle")
    parser.add_argument("--environment", required=True, help="Environment config name from deploy/environments")
    parser.add_argument("--release-tag", default="", help="Release tag for the generated review bundle")
    parser.add_argument(
        "--review-root",
        default=str(DEFAULT_REVIEW_ROOT),
        help="Directory where review bundles are written",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional path to write the generated review_manifest.json",
    )
    args = parser.parse_args()

    release_tag = release_tool._normalize_tag(args.release_tag or None)
    review_root = release_tool._resolve_repo_path(args.review_root)

    try:
        bundle_dir = _build_review_bundle(
            env_name=args.environment,
            release_tag=release_tag,
            review_root=review_root,
        )
        if args.output:
            src = bundle_dir / "review_manifest.json"
            dst = Path(args.output)
            if not dst.is_absolute():
                dst = (ROOT / dst).resolve()
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        print(f"security-review-bundle: environment={args.environment} tag={release_tag}")
        print(f"bundle_dir: {bundle_dir}")
        return 0
    except release_tool.ReleaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
