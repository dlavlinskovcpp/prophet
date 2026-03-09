#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

timestamp="$(date -u +"%Y%m%dT%H%M%SZ")"
archive_path="${1:-ops/backups/prophet-ops-${timestamp}.tar.gz}"
archive_dir="$(dirname "${archive_path}")"
archive_base="$(basename "${archive_path}")"

mkdir -p "${archive_dir}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}"' EXIT
snapshot_root="${tmpdir}/${archive_base%.tar.gz}"
mkdir -p "${snapshot_root}" "${snapshot_root}/ops" "${snapshot_root}/apps/oracle-attester" "${snapshot_root}/apps/matching-keeper"

copy_dir_or_empty() {
  local src="$1"
  local dest="$2"
  if [ -d "${src}" ]; then
    cp -R "${src}" "${dest}"
  else
    mkdir -p "${dest}"
  fi
}

manifest="${snapshot_root}/manifest.txt"
cat >"${manifest}" <<EOF
created_at_utc=${timestamp}
repo_root=${ROOT_DIR}
included_paths=audit proof_store resolver_store apps/matching-keeper/state ops/monitoring docker-compose.localnet.yml
EOF

copy_dir_or_empty "${ROOT_DIR}/audit" "${snapshot_root}/audit"
copy_dir_or_empty "${ROOT_DIR}/proof_store" "${snapshot_root}/proof_store"
copy_dir_or_empty "${ROOT_DIR}/resolver_store" "${snapshot_root}/resolver_store"
copy_dir_or_empty "${ROOT_DIR}/apps/matching-keeper/state" "${snapshot_root}/apps/matching-keeper/state"
cp -R "${ROOT_DIR}/ops/monitoring" "${snapshot_root}/ops/monitoring"
cp "${ROOT_DIR}/docker-compose.localnet.yml" "${snapshot_root}/docker-compose.localnet.yml"
cp "${ROOT_DIR}/apps/oracle-attester/.env.example" "${snapshot_root}/apps/oracle-attester/.env.example"
cp "${ROOT_DIR}/apps/matching-keeper/.env.example" "${snapshot_root}/apps/matching-keeper/.env.example"

tar -czf "${archive_path}" -C "${tmpdir}" "${archive_base%.tar.gz}"

if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "${archive_path}" > "${archive_path}.sha256"
elif command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${archive_path}" > "${archive_path}.sha256"
fi

echo "Created ops backup: ${archive_path}"
if [ -f "${archive_path}.sha256" ]; then
  echo "Checksum: ${archive_path}.sha256"
fi
