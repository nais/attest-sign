#!/bin/bash
set -euo pipefail

IMAGE_REF="${INPUT_IMAGE_REF}"
SBOM="${INPUT_SBOM}"
TRIVY_JAVA_DB_REPOSITORIES="${INPUT_TRIVY_JAVA_DB_REPOSITORIES}"

# Validate image ref
if [[ "${IMAGE_REF}" != *@sha256:* ]]; then
  echo "Image must be in the form of <image>@<digest>"
  exit 1
fi

# Validate SBOM input
if [ -z "${SBOM}" ]; then
  echo "SBOM input is empty. Please provide a valid SBOM for attestation."
  exit 1
elif [[ ! "${SBOM}" =~ ^[a-zA-Z0-9._/-]+$ ]]; then
  echo "Invalid SBOM filename or path: ${SBOM}"
  exit 1
else
  echo "SBOM input is provided and valid: ${SBOM}"
fi

# Start signing in background while trivy runs in parallel
cosign sign --yes "${IMAGE_REF}" > /tmp/cosign-sign.log 2>&1 &
SIGN_PID=$!
trap 'kill "$SIGN_PID" 2>/dev/null; wait "$SIGN_PID" 2>/dev/null || true' EXIT

# Generate SBOM with Trivy if not provided
if [ "${SBOM}" = "auto-generate-for-me-please.json" ]; then
  echo "Generating SBOM with Trivy..."

  TRIVY_SKIP_DB_UPDATE=true \
  TRIVY_JAVA_DB_REPOSITORY="${TRIVY_JAVA_DB_REPOSITORIES}" \
  trivy image \
    --format cyclonedx \
    --output "auto-generate-for-me-please.json" \
    --cache-dir ".trivy" \
    "${IMAGE_REF}"

  echo "=== SBOM file info ==="
  ls -lh auto-generate-for-me-please.json

  echo "=== CycloneDX metadata ==="
  jq '{bomFormat, specVersion, metadata: {timestamp, tools}}' auto-generate-for-me-please.json

  echo "=== Component count ==="
  jq '.components | length' auto-generate-for-me-please.json

  echo "=== First 2 components ==="
  jq '.components[:2]' auto-generate-for-me-please.json
fi

echo "Using SBOM file: ${SBOM}"

# Wait for background sign to complete; propagates non-zero exit under set -e
wait $SIGN_PID
echo "=== cosign sign output ==="
cat /tmp/cosign-sign.log
trap - EXIT
cosign attest --yes --predicate "${SBOM}" --type cyclonedx "${IMAGE_REF}"
