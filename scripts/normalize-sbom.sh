#!/usr/bin/env bash
#
# Normalize a CycloneDX SBOM in place, then validate and lint it.
#
# Trivy can emit one package as several components sharing a single bom-ref when
# the package is present in more than one image layer. That produces duplicate
# entries in `dependencies` and `dependencies[].dependsOn`, which CycloneDX 1.6
# requires to be unique, so Dependency-Track rejects the attestation with a
# schema-validation error and the affected workload never gets a vulnerability
# report. See https://github.com/aquasecurity/trivy/discussions/7532
#
# Normalization (always applied): collapse duplicate components by bom-ref,
# de-duplicate the dependency graph by ref (unioning dependsOn), and de-duplicate
# each dependsOn array.
#
# Validation + lint (mode-controlled): CycloneDX schema validation plus checks
# for problems strict consumers reject that the schema misses -- dangling
# dependency-graph refs and components sharing a purl.
#
# Usage: normalize-sbom.sh <sbom.json> [error|warn|off]
#   error (default) - fail the build on any schema or lint problem
#   warn            - report problems but do not fail
#   off             - normalize only, skip validation and lint

set -euo pipefail

# CycloneDX versions the field assumptions below (bom-ref, dependencies[].ref /
# dependsOn / provides, purl) have been checked against. A newer SBOM is reported
# so schema drift is visible instead of silently passing every check.
REVIEWED_SPEC_VERSIONS="1.2 1.3 1.4 1.5 1.6"

sbom="${1:?usage: normalize-sbom.sh <sbom.json> [error|warn|off]}"
mode="${2:-error}"

case "$mode" in
  error | warn | off) ;;
  *)
    echo "normalize-sbom: invalid mode '$mode' (expected error, warn or off)" >&2
    exit 1
    ;;
esac

if [ ! -f "$sbom" ]; then
  echo "SBOM file does not exist: $sbom" >&2
  exit 1
fi

if [ "$(jq -r '.bomFormat // "unknown"' "$sbom")" != "CycloneDX" ]; then
  echo "normalize-sbom: not a CycloneDX BOM" >&2
  exit 1
fi

# --- Normalization -----------------------------------------------------------

normalized="$(mktemp)"
trap 'rm -f "$normalized"' EXIT

jq '
  (if has("components") then
    .components |= ( [ .[] | . as $c
        | ($c["bom-ref"] // $c.purl // ($c.name + "@" + ($c.version // ""))) as $k
        | {k: $k, c: $c} ]
      | reduce .[] as $e ({seen: {}, out: []};
          if .seen[$e.k] then . else .seen[$e.k] = true | .out += [$e.c] end)
      | .out )
  else . end)
  | (if has("dependencies") then
    .dependencies |= ( group_by(.ref)
      | map( .[0] + { dependsOn: ( [ (.[].dependsOn // [])[] ] | unique ) } ) )
  else . end)
' "$sbom" > "$normalized"

mv "$normalized" "$sbom"
trap - EXIT

spec_version=$(jq -r '.specVersion // "unknown"' "$sbom")
echo "normalize-sbom: CycloneDX $spec_version, $(jq '(.components // []) | length' "$sbom") components, $(jq '(.dependencies // []) | length' "$sbom") dependency nodes"

if [ "$mode" = "off" ]; then
  exit 0
fi

# --- Validation + lint -------------------------------------------------------

problems=0

if ! cyclonedx validate --input-file "$sbom" --input-format json --fail-on-errors; then
  problems=1
fi

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
  echo "normalize-sbom: SBOM is valid and lint-clean"
  exit 0
fi

if [ "$mode" = "error" ]; then
  echo "normalize-sbom: SBOM has problems (mode: error)"
  exit 1
fi

echo "normalize-sbom: SBOM has problems (mode: warn, not failing the build)"