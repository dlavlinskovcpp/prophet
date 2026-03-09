#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict


ROOT = Path(__file__).resolve().parent.parent
ENVIRONMENTS_DIR = ROOT / "deploy" / "environments"
DEFAULT_BUNDLE_ROOT = ROOT / "releases"
TAG_RE = re.compile(r"^[A-Za-z0-9._-]+$")


class ReleaseError(RuntimeError):
    pass


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReleaseError(f"Missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReleaseError(f"Invalid JSON in {path}: {exc}") from exc


def _read_toml_scalar(path: Path, section: str, key: str) -> str:
    current = ""
    header = f"[{section}]"
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line
            continue
        if current != header:
            continue
        if "=" not in line:
            continue
        lhs, rhs = line.split("=", 1)
        if lhs.strip() != key:
            continue
        value = rhs.strip().split("#", 1)[0].strip()
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        if value.startswith("'") and value.endswith("'"):
            return value[1:-1]
        return value
    raise ReleaseError(f"Could not find {key} in section {section} of {path}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT.resolve()))


def _expand_path(raw: str) -> Path:
    return Path(os.path.expandvars(os.path.expanduser(raw))).resolve()


def _resolve_repo_path(raw: str) -> Path:
    path = Path(os.path.expandvars(os.path.expanduser(raw)))
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _load_environment(name: str) -> tuple[Path, Dict[str, Any]]:
    path = ENVIRONMENTS_DIR / f"{name}.json"
    if not path.exists():
        raise ReleaseError(f"Unknown environment '{name}'. Expected {path}")
    config = _read_json(path)
    if config.get("environment") != name:
        raise ReleaseError(
            f"Environment config mismatch: file {path} declares {config.get('environment')!r}"
        )
    return path, config


def _artifact_metadata(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise ReleaseError(f"Required artifact missing: {path}")
    return {
        "path": _rel(path),
        "sha256": _sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _run(
    argv: list[str],
    *,
    cwd: Path = ROOT,
    check: bool = True,
    capture_output: bool = False,
    dry_run: bool = False,
) -> subprocess.CompletedProcess[str]:
    if dry_run:
        print("+", " ".join(argv))
        return subprocess.CompletedProcess(argv, 0, "", "")

    try:
        return subprocess.run(
            argv,
            cwd=str(cwd),
            check=check,
            capture_output=capture_output,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ReleaseError(f"Required command not found: {argv[0]}") from exc
    except subprocess.CalledProcessError as exc:
        stdout = exc.stdout.strip() if exc.stdout else ""
        stderr = exc.stderr.strip() if exc.stderr else ""
        details = stderr or stdout or str(exc)
        raise ReleaseError(f"Command failed ({' '.join(argv)}): {details}") from exc


def _git_output(argv: list[str]) -> str:
    try:
        proc = _run(["git", *argv], capture_output=True, check=True)
    except ReleaseError:
        return ""
    return proc.stdout.strip()


def _git_dirty() -> bool:
    return bool(_git_output(["status", "--short"]))


def _default_release_tag() -> str:
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    short_sha = _git_output(["rev-parse", "--short", "HEAD"]) or "nogit"
    return f"manual-{ts}-{short_sha}"


def _resolve_program_id(config: Dict[str, Any], idl_path: Path, keypair_path: Path) -> str:
    candidates: list[str] = []

    if keypair_path.exists():
        try:
            proc = _run(["solana", "address", "-k", str(keypair_path)], capture_output=True)
            if proc.stdout.strip():
                candidates.append(proc.stdout.strip())
        except ReleaseError:
            pass

    if idl_path.exists():
        idl = _read_json(idl_path)
        if isinstance(idl.get("address"), str) and idl["address"].strip():
            candidates.append(idl["address"].strip())

    expected = str(config.get("expected_program_id", "")).strip()
    if expected:
        candidates.append(expected)

    unique = []
    for value in candidates:
        if value not in unique:
            unique.append(value)

    if not unique:
        raise ReleaseError(
            "Unable to resolve program id. Provide expected_program_id in the environment config "
            "or ensure target/idl/prophet.json / target/deploy/prophet-keypair.json exist."
        )

    if len(unique) > 1:
        raise ReleaseError(f"Program id mismatch across sources: {unique}")

    return unique[0]


def _collect_versions() -> Dict[str, str]:
    return {
        "program": _read_toml_scalar(ROOT / "programs" / "prophet" / "Cargo.toml", "package", "version"),
        "anchor": _read_toml_scalar(ROOT / "Anchor.toml", "toolchain", "anchor_version"),
        "sdk_python": _read_toml_scalar(ROOT / "sdk" / "python" / "pyproject.toml", "tool.poetry", "version"),
        "oracle_attester": _read_toml_scalar(
            ROOT / "apps" / "oracle-attester" / "pyproject.toml", "tool.poetry", "version"
        ),
        "matching_keeper": _read_toml_scalar(
            ROOT / "apps" / "matching-keeper" / "pyproject.toml", "tool.poetry", "version"
        ),
    }


def _build_manifest(
    *,
    env_name: str,
    env_path: Path,
    config: Dict[str, Any],
    release_tag: str,
) -> Dict[str, Any]:
    binary_path = (ROOT / config["binary_path"]).resolve()
    idl_path = (ROOT / config["idl_path"]).resolve()
    ts_types_path = (ROOT / config["ts_types_path"]).resolve()
    keypair_path = (ROOT / config["program_keypair_path"]).resolve()
    wallet_path = _expand_path(config["wallet_path"])

    versions = _collect_versions()
    program_id = _resolve_program_id(config, idl_path, keypair_path)

    manifest = {
        "schema_version": 1,
        "release_tag": release_tag,
        "environment": env_name,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "deployment": {
            "cluster_name": config["cluster_name"],
            "anchor_cluster": config["anchor_cluster"],
            "rpc_url": config["rpc_url"],
            "wallet_path": str(wallet_path),
            "service_endpoints": config.get("service_endpoints", {}),
        },
        "git": {
            "commit": _git_output(["rev-parse", "HEAD"]),
            "branch": _git_output(["rev-parse", "--abbrev-ref", "HEAD"]),
            "dirty": _git_dirty(),
        },
        "versions": versions,
        "program": {
            "name": "prophet",
            "program_id": program_id,
            "program_keypair_path": _rel(keypair_path),
            "binary": _artifact_metadata(binary_path),
            "idl": _artifact_metadata(idl_path),
            "ts_types": _artifact_metadata(ts_types_path),
        },
        "sources": {
            "environment_config": _rel(env_path),
            "anchor_toml": _rel(ROOT / "Anchor.toml"),
            "program_cargo_toml": _rel(ROOT / "programs" / "prophet" / "Cargo.toml"),
            "sdk_pyproject": _rel(ROOT / "sdk" / "python" / "pyproject.toml"),
            "oracle_attester_pyproject": _rel(ROOT / "apps" / "oracle-attester" / "pyproject.toml"),
            "matching_keeper_pyproject": _rel(ROOT / "apps" / "matching-keeper" / "pyproject.toml"),
            "package_json": _rel(ROOT / "package.json"),
        },
    }
    return manifest


def _bundle_release(
    *,
    manifest: Dict[str, Any],
    env_path: Path,
    config: Dict[str, Any],
    bundle_root: Path,
) -> Path:
    bundle_dir = bundle_root / manifest["release_tag"] / manifest["environment"]
    bundle_dir.mkdir(parents=True, exist_ok=True)

    copy_paths = [
        ROOT / config["binary_path"],
        ROOT / config["idl_path"],
        ROOT / config["ts_types_path"],
        ROOT / config["program_keypair_path"],
        env_path,
        ROOT / "Anchor.toml",
        ROOT / "programs" / "prophet" / "Cargo.toml",
        ROOT / "sdk" / "python" / "pyproject.toml",
        ROOT / "apps" / "oracle-attester" / "pyproject.toml",
        ROOT / "apps" / "matching-keeper" / "pyproject.toml",
        ROOT / "package.json",
    ]

    for src in copy_paths:
        if not src.exists():
            raise ReleaseError(f"Cannot bundle missing file: {src}")
        dst = bundle_dir / src.resolve().relative_to(ROOT.resolve())
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)

    manifest_path = bundle_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return bundle_dir


def _write_manifest(manifest: Dict[str, Any], output_path: str) -> None:
    if output_path == "-":
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return

    path = Path(output_path)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _ensure_clean_for_deploy(allow_dirty: bool) -> None:
    if _git_dirty() and not allow_dirty:
        raise ReleaseError("Refusing to deploy from a dirty git tree. Commit or pass --allow-dirty.")


def _build_program(*, dry_run: bool) -> None:
    _run(["anchor", "build"], dry_run=dry_run)


def _deploy_program(config: Dict[str, Any], *, dry_run: bool) -> None:
    wallet_path = _expand_path(config["wallet_path"])
    cluster = str(config["anchor_cluster"])
    if not wallet_path.exists() and not dry_run:
        raise ReleaseError(f"Wallet not found: {wallet_path}")

    _run(
        [
            "anchor",
            "deploy",
            "--provider.cluster",
            cluster,
            "--provider.wallet",
            str(wallet_path),
        ],
        dry_run=dry_run,
    )


def _sync_idl(config: Dict[str, Any], program_id: str, *, dry_run: bool) -> None:
    wallet_path = _expand_path(config["wallet_path"])
    cluster = str(config["anchor_cluster"])
    idl_path = str((ROOT / config["idl_path"]).resolve())
    init_cmd = [
        "anchor",
        "idl",
        "init",
        "--provider.cluster",
        cluster,
        "--provider.wallet",
        str(wallet_path),
        "--filepath",
        idl_path,
        program_id,
    ]
    upgrade_cmd = [
        "anchor",
        "idl",
        "upgrade",
        "--provider.cluster",
        cluster,
        "--provider.wallet",
        str(wallet_path),
        "--filepath",
        idl_path,
        program_id,
    ]

    if dry_run:
        _run(init_cmd, dry_run=True)
        _run(upgrade_cmd, dry_run=True)
        return

    init_proc = subprocess.run(init_cmd, cwd=str(ROOT), capture_output=True, text=True)
    if init_proc.returncode == 0:
        return

    upgrade_proc = subprocess.run(upgrade_cmd, cwd=str(ROOT), capture_output=True, text=True)
    if upgrade_proc.returncode != 0:
        stderr = upgrade_proc.stderr.strip() or init_proc.stderr.strip() or upgrade_proc.stdout.strip()
        raise ReleaseError(f"Failed to sync IDL: {stderr}")


def _post_deploy_verify(config: Dict[str, Any], program_id: str, *, dry_run: bool) -> None:
    _run(
        ["solana", "program", "show", "-u", str(config["rpc_url"]), program_id],
        dry_run=dry_run,
    )


def _normalize_tag(raw: str | None) -> str:
    tag = raw or _default_release_tag()
    if not TAG_RE.fullmatch(tag):
        raise ReleaseError(
            f"Invalid release tag {tag!r}. Use only letters, digits, '.', '_' and '-'."
        )
    return tag


def _build_or_bundle(
    *,
    action: str,
    env_name: str,
    release_tag: str,
    output_path: str | None,
    bundle_root: str | None,
) -> tuple[Dict[str, Any], Path | None]:
    env_path, config = _load_environment(env_name)
    manifest = _build_manifest(
        env_name=env_name,
        env_path=env_path,
        config=config,
        release_tag=release_tag,
    )

    if output_path:
        _write_manifest(manifest, output_path)

    bundle_dir = None
    if bundle_root:
        bundle_dir = _bundle_release(
            manifest=manifest,
            env_path=env_path,
            config=config,
            bundle_root=_resolve_repo_path(bundle_root),
        )

    if output_path != "-":
        print(f"{action}: environment={env_name} tag={release_tag}")
        print(f"program_id: {manifest['program']['program_id']}")
        print(f"binary_sha256: {manifest['program']['binary']['sha256']}")
        if bundle_dir is not None:
            print(f"bundle_dir: {bundle_dir}")
    return manifest, bundle_dir


def main() -> int:
    parser = argparse.ArgumentParser(description="Prophet release/deploy helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_arguments(subparser: argparse.ArgumentParser) -> None:
        subparser.add_argument("--environment", required=True, help="Environment config name from deploy/environments")
        subparser.add_argument("--release-tag", default="", help="Release tag for manifest/bundle naming")
        subparser.add_argument("--output", default="", help="Write manifest JSON to this path ('-' for stdout)")

    plan_parser = subparsers.add_parser("plan", help="Generate a release manifest from existing artifacts")
    add_common_arguments(plan_parser)

    bundle_parser = subparsers.add_parser("bundle", help="Archive release artifacts and manifest into releases/")
    add_common_arguments(bundle_parser)
    bundle_parser.add_argument(
        "--bundle-root",
        default=str(DEFAULT_BUNDLE_ROOT),
        help="Directory where release bundles are written",
    )

    deploy_parser = subparsers.add_parser("deploy", help="Build, deploy, sync IDL, verify, and archive a release bundle")
    add_common_arguments(deploy_parser)
    deploy_parser.add_argument(
        "--bundle-root",
        default=str(DEFAULT_BUNDLE_ROOT),
        help="Directory where release bundles are written",
    )
    deploy_parser.add_argument("--allow-dirty", action="store_true", help="Allow deploying from a dirty git tree")
    deploy_parser.add_argument("--skip-post-verify", action="store_true", help="Skip solana program show verification")
    deploy_parser.add_argument("--dry-run", action="store_true", help="Print deploy commands without executing them")
    deploy_parser.add_argument(
        "--yes",
        action="store_true",
        help="Required for mainnet-beta deploys to avoid accidental execution",
    )

    args = parser.parse_args()
    release_tag = _normalize_tag(args.release_tag or None)

    try:
        if args.command == "plan":
            _build_or_bundle(
                action="plan",
                env_name=args.environment,
                release_tag=release_tag,
                output_path=args.output or "-",
                bundle_root=None,
            )
            return 0

        if args.command == "bundle":
            _build_or_bundle(
                action="bundle",
                env_name=args.environment,
                release_tag=release_tag,
                output_path=args.output or "",
                bundle_root=args.bundle_root,
            )
            return 0

        env_path, config = _load_environment(args.environment)
        if args.environment == "mainnet-beta" and not args.yes:
            raise ReleaseError("Mainnet deploy requires --yes.")

        _ensure_clean_for_deploy(args.allow_dirty)
        _build_program(dry_run=args.dry_run)
        program_id = _resolve_program_id(
            config,
            (ROOT / config["idl_path"]).resolve(),
            (ROOT / config["program_keypair_path"]).resolve(),
        )
        _deploy_program(config, dry_run=args.dry_run)
        _sync_idl(config, program_id, dry_run=args.dry_run)
        if not args.skip_post_verify:
            _post_deploy_verify(config, program_id, dry_run=args.dry_run)

        manifest = _build_manifest(
            env_name=args.environment,
            env_path=env_path,
            config=config,
            release_tag=release_tag,
        )
        if args.output:
            _write_manifest(manifest, args.output)
        bundle_dir = _bundle_release(
            manifest=manifest,
            env_path=env_path,
            config=config,
            bundle_root=_resolve_repo_path(args.bundle_root),
        )
        print(f"deploy: environment={args.environment} tag={release_tag}")
        print(f"program_id: {program_id}")
        print(f"bundle_dir: {bundle_dir}")
        return 0

    except ReleaseError as exc:
        print(f"release error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
