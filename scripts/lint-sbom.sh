#!/usr/bin/env bash
#
# Validate a CycloneDX SBOM and lint it for problems strict consumers reject that
# JSON-schema validation misses: dangling dependency-graph refs and components
# sharing a purl. Also flags CycloneDX spec versions the checks below have not
# been reviewed against, so schema drift is visible instead of silently passing.
#
# Read-only; run scripts/normalize-sbom.sh first to fix what can be fixed.
#
# Usage: lint-sbom.sh <sbom.json> [error|warn|off]
#   warn (default) - report problems, exit zero
#   error          - exit non-zero on any schema or lint problem
#   off            - do nothing

set -euo pipefail

# CycloneDX versions the field assumptions below (bom-ref, dependencies[].ref /
# dependsOn / provides, purl) have been checked against.
REVIEWED_SPEC_VERSIONS="1.2 1.3 1.4 1.5 1.6"

sbom="${1:?usage: lint-sbom.sh <sbom.json> [error|warn|off]}"
mode="${2:-warn}"

case "$mode" in
  error | warn) ;;
  off) exit 0 ;;
  *)
    echo "lint-sbom: invalid mode '$mode' (expected error, warn or off)" >&2
    exit 1
    ;;
esac

if [ ! -f "$sbom" ]; then
  echo "lint-sbom: file not found: $sbom" >&2
  exit 1
fi

problems=0

if ! cyclonedx validate --input-file "$sbom" --input-format json --fail-on-errors; then
  problems=1
fi

spec_version=$(jq -r '.specVersion // "unknown"' "$sbom")
case " $REVIEWED_SPEC_VERSIONS " in
  *" $spec_version "*) ;;
  *)
    echo "LINT: CycloneDX $spec_version is outside the reviewed set [$REVIEWED_SPEC_VERSIONS]; re-check bom-ref / dependencies / purl handling"
    problems=1
    ;;
esac

mapfile -t dangling < <(jq -r '
  ([.. | objects | select(has("bom-ref")) | ."bom-ref"] | unique) as $known
  | [ .dependencies[]? | (.ref, (.dependsOn[]?), (.provides[]?)) ]
  | map(select(. != null)) | unique
  | map(select(. as $r | ($known | index($r)) | not)) | .[]' "$sbom")
if [ "${#dangling[@]}" -gt 0 ]; then
  echo "LINT: dependency graph references unknown bom-ref(s):"
  printf '  - %s\n' "${dangling[@]}"
  problems=1
fi

mapfile -t dupe_purls < <(jq -r '
  [.components[]? | select(has("purl")) | .purl]
  | group_by(.) | map(select(length > 1) | .[0]) | .[]' "$sbom")
if [ "${#dupe_purls[@]}" -gt 0 ]; then
  echo "LINT: multiple components share a purl:"
  printf '  - %s\n' "${dupe_purls[@]}"
  problems=1
fi

if [ "$problems" -eq 0 ]; then
  echo "lint-sbom: valid and lint-clean"
  exit 0
fi

if [ "$mode" = "error" ]; then
  echo "lint-sbom: problems found (mode: error)"
  exit 1
fi

echo "lint-sbom: problems found (mode: warn, not failing the build)"
