#!/usr/bin/env bash
# Lint a CycloneDX SBOM for problems strict consumers reject but JSON-schema
# validation misses: duplicate bom-refs, dangling dependency refs, shared purls.
# Usage: lint-sbom.sh <sbom.json> [warn|error]

set -euo pipefail

# CycloneDX versions the field assumptions below (bom-ref, dependencies[].ref /
# dependsOn / provides, purl) have been reviewed against. A newer SBOM is
# reported so schema drift is visible instead of silently passing.
REVIEWED_SPEC_VERSIONS="1.2 1.3 1.4 1.5 1.6"

sbom="${1:?usage: lint-sbom.sh <sbom.json> [warn|error]}"
mode="${2:-warn}"

if [ ! -f "$sbom" ]; then
  echo "lint-sbom: file not found: $sbom" >&2
  exit 1
fi

bom_format=$(jq -r '.bomFormat // "unknown"' "$sbom")
spec_version=$(jq -r '.specVersion // "unknown"' "$sbom")

if [ "$bom_format" != "CycloneDX" ]; then
  echo "lint-sbom: not a CycloneDX BOM (bomFormat: $bom_format)" >&2
  exit 1
fi

problems=0

case " $REVIEWED_SPEC_VERSIONS " in
  *" $spec_version "*) ;;
  *)
    msg="field assumptions reviewed for CycloneDX [$REVIEWED_SPEC_VERSIONS], SBOM is $spec_version - re-check bom-ref/dependencies/purl handling"
    if [ "$mode" = "error" ]; then
      echo "ERROR: $msg"
      problems=1
    else
      echo "WARN: $msg"
    fi
    ;;
esac

echo "lint-sbom: CycloneDX $spec_version, $(jq '[.. | objects | select(has("bom-ref"))] | length' "$sbom") bom-refs, $(jq '[.dependencies[]?] | length' "$sbom") dependency nodes"

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
