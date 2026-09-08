#!/usr/bin/env bash
# Lint a CycloneDX SBOM for problems strict consumers reject but JSON-schema
# validation misses: duplicate bom-refs, dangling dependency refs, shared purls.
# Usage: lint-sbom.sh <sbom.json> [warn|error]

set -euo pipefail

sbom="${1:?usage: lint-sbom.sh <sbom.json> [warn|error]}"
mode="${2:-warn}"

if [ ! -f "$sbom" ]; then
  echo "lint-sbom: file not found: $sbom" >&2
  exit 1
fi

problems=0

mapfile -t dupe_refs < <(jq -r '
  [.. | objects | select(has("bom-ref")) | ."bom-ref"]
  | group_by(.) | map(select(length > 1) | .[0]) | .[]' "$sbom")
if [ "${#dupe_refs[@]}" -gt 0 ]; then
  echo "ERROR: duplicate bom-ref(s) (violates CycloneDX uniqueness, breaks BOM graph resolution):"
  printf '  - %s\n' "${dupe_refs[@]}"
  problems=1
fi

mapfile -t dangling < <(jq -r '
  ([.. | objects | select(has("bom-ref")) | ."bom-ref"] | unique) as $known
  | [.dependencies[]? | (.ref, (.dependsOn[]?), (.provides[]?))] | map(select(. != null)) | unique
  | map(select(. as $r | ($known | index($r)) | not)) | .[]' "$sbom")
if [ "${#dangling[@]}" -gt 0 ]; then
  echo "ERROR: dependency graph references unknown bom-ref(s):"
  printf '  - %s\n' "${dangling[@]}"
  problems=1
fi

mapfile -t dupe_purls < <(jq -r '
  [.. | objects | select(has("purl")) | .purl]
  | group_by(.) | map(select(length > 1) | .[0]) | .[]' "$sbom")
if [ "${#dupe_purls[@]}" -gt 0 ]; then
  label="WARN"
  [ "$mode" = "error" ] && label="ERROR"
  echo "${label}: multiple components share a purl (Trivy duplicate-component pattern):"
  printf '  - %s\n' "${dupe_purls[@]}"
  [ "$mode" = "error" ] && problems=1
fi

if [ "$problems" -ne 0 ] && [ "$mode" = "error" ]; then
  echo "SBOM lint failed (sbom_lint: error)."
  exit 1
fi

if [ "$problems" -ne 0 ]; then
  echo "SBOM lint found problems (sbom_lint: warn - not failing the build)."
else
  echo "SBOM lint passed."
fi
