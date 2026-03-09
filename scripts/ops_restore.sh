#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

force="0"
archive_path=""

for arg in "$@"; do
  case "${arg}" in
    --force)
      force="1"
      ;;
    *)
      archive_path="${arg}"
      ;;
  esac
done

if [ -z "${archive_path}" ]; then
  echo "Usage: bash scripts/ops_restore.sh [--force] <archive.tar.gz>" >&2
  exit 1
fi

if [ ! -f "${archive_path}" ]; then
  echo "Archive not found: ${archive_path}" >&2
  exit 1
fi

for path in audit proof_store resolver_store apps/matching-keeper/state; do
  if [ -e "${path}" ] && [ "$(find "${path}" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')" -gt 0 ] && [ "${force}" != "1" ]; then
    echo "Refusing to restore over non-empty ${path}. Re-run with --force to overwrite." >&2
    exit 1
  fi
done

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT

tar -xzf "${archive_path}" -C "${tmpdir}"
snapshot_root="$(find "${tmpdir}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [ -z "${snapshot_root}" ]; then
  echo "Unable to locate extracted snapshot root in ${archive_path}" >&2
  exit 1
fi

for path in audit proof_store resolver_store apps/matching-keeper/state; do
  rm -rf "${ROOT_DIR:?}/${path}"
  mkdir -p "$(dirname "${ROOT_DIR}/${path}")"
  cp -R "${snapshot_root}/${path}" "${ROOT_DIR}/${path}"
done

echo "Restored ops state from ${archive_path}"
