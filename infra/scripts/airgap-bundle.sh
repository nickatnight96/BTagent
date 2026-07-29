#!/usr/bin/env bash
# Build a transfer bundle for an air-gapped BTagent install — Sovereign Pack (#502).
#
# Run this on the CONNECTED side. It resolves every container image to an
# immutable digest, saves the image layers to a tarball, copies the offline
# deployment assets, and writes a manifest with SHA-256 checksums. The output
# directory is what crosses the boundary.
#
# What it does NOT do (on purpose):
#   * It does not download model weights. Those are large, licence-bearing
#     binaries and this repository does not vendor them — see the "Model
#     bundle" section of docs/deployment/air-gap.md for the `ollama pull` +
#     volume-export procedure.
#   * It does not fetch the MITRE ATT&CK STIX bundle. That is a separate,
#     independently-refreshed artifact; see "Offline reference data".
#   * It does not sign anything. Signing/verification is whatever the
#     receiving environment already mandates; the manifest gives you the
#     digests to sign.
#
# Usage:
#   infra/scripts/airgap-bundle.sh [OUTPUT_DIR]
#
# Environment overrides (defaults match infra/docker-compose.yml):
#   BACKEND_IMAGE, FRONTEND_IMAGE, POSTGRES_IMAGE, REDIS_IMAGE,
#   MINIO_IMAGE, OLLAMA_IMAGE, NGINX_IMAGE

set -euo pipefail

OUT_DIR="${1:-./btagent-airgap-bundle}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

BACKEND_IMAGE="${BACKEND_IMAGE:-ghcr.io/nickatnight96/btagent-backend:latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-ghcr.io/nickatnight96/btagent-frontend:latest}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-pgvector/pgvector:pg16}"
REDIS_IMAGE="${REDIS_IMAGE:-redis:7-alpine}"
MINIO_IMAGE="${MINIO_IMAGE:-minio/minio:latest}"
OLLAMA_IMAGE="${OLLAMA_IMAGE:-ollama/ollama:latest}"
NGINX_IMAGE="${NGINX_IMAGE:-nginx:alpine}"

IMAGES=(
  "IMAGE_BACKEND=${BACKEND_IMAGE}"
  "IMAGE_FRONTEND=${FRONTEND_IMAGE}"
  "IMAGE_POSTGRES=${POSTGRES_IMAGE}"
  "IMAGE_REDIS=${REDIS_IMAGE}"
  "IMAGE_MINIO=${MINIO_IMAGE}"
  "IMAGE_OLLAMA=${OLLAMA_IMAGE}"
  "IMAGE_NGINX=${NGINX_IMAGE}"
)

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }

mkdir -p "${OUT_DIR}/images" "${OUT_DIR}/deploy"

DIGEST_ENV="${OUT_DIR}/images.env"
: > "${DIGEST_ENV}"

resolved_refs=()

for entry in "${IMAGES[@]}"; do
  var="${entry%%=*}"
  ref="${entry#*=}"
  echo ">> pulling ${ref}"
  docker pull --quiet "${ref}" >/dev/null

  # RepoDigests is the registry-canonical, immutable identity. Prefer it over
  # the local image Id: the Id is a config-blob hash that differs from what the
  # registry serves, so it cannot be used to pull on the far side.
  repo_digest="$(docker image inspect --format '{{ index .RepoDigests 0 }}' "${ref}" 2>/dev/null || true)"
  if [ -z "${repo_digest}" ]; then
    echo "!! no RepoDigest for ${ref} (locally-built image never pushed?)." >&2
    echo "   Push it to a registry first, or the far side cannot verify what it runs." >&2
    exit 1
  fi

  echo "${var}=${repo_digest}" >> "${DIGEST_ENV}"
  resolved_refs+=("${repo_digest}")
  echo "   ${repo_digest}"
done

echo ">> saving image layers (this is the large step)"
docker save "${resolved_refs[@]}" -o "${OUT_DIR}/images/btagent-images.tar"

echo ">> copying deployment assets"
cp "${REPO_ROOT}/infra/docker-compose.airgap.yml" "${OUT_DIR}/deploy/"
cp "${REPO_ROOT}/infra/.env.airgap.example"       "${OUT_DIR}/deploy/"
cp -R "${REPO_ROOT}/infra/nginx"                  "${OUT_DIR}/deploy/nginx"
cp -R "${REPO_ROOT}/infra/helm"                   "${OUT_DIR}/deploy/helm"
cp "${REPO_ROOT}/docs/deployment/air-gap.md"      "${OUT_DIR}/deploy/"

# SBOMs, when the CI artifact has been downloaded next to this script's cwd.
if [ -d "./sbom" ]; then
  echo ">> including SBOMs from ./sbom"
  cp -R ./sbom "${OUT_DIR}/sbom"
else
  echo ">> no ./sbom directory found — download the 'sbom-cyclonedx' CI artifact"
  echo "   and re-run, or copy it into the bundle by hand."
fi

echo ">> writing manifest"
{
  echo "# BTagent air-gap bundle manifest"
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# git commit: $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo 'unknown')"
  echo
  echo "## Images (digest-pinned)"
  cat "${DIGEST_ENV}"
  echo
  echo "## File checksums (sha256)"
} > "${OUT_DIR}/MANIFEST.txt"

if command -v shasum >/dev/null 2>&1; then
  HASH_CMD=(shasum -a 256)
else
  HASH_CMD=(sha256sum)
fi
( cd "${OUT_DIR}" && find . -type f ! -name MANIFEST.txt -print0 \
    | sort -z | xargs -0 "${HASH_CMD[@]}" ) >> "${OUT_DIR}/MANIFEST.txt"

cat <<EOF

Bundle written to: ${OUT_DIR}

Next steps (see docs/deployment/air-gap.md):
  1. Add model weights   -> ${OUT_DIR}/models/
  2. Add the ATT&CK STIX bundle -> ${OUT_DIR}/reference/enterprise-attack.json
  3. Re-run the checksum section of MANIFEST.txt after adding those, then
     transfer the directory and verify checksums on arrival.
EOF
