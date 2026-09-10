#!/usr/bin/env bash
#
# Make a Trivy CycloneDX SBOM ingestible by strict consumers (Dependency-Track),
# in place. A Trivy image scan produces output that fails CycloneDX schema
# validation, after which DT rejects the attestation and the workload never gets
# a vulnerability report. Two causes:
#
#   1. a package present in multiple image layers becomes multiple components
#      sharing one `bom-ref` (must be unique), which in turn repeats
#      `dependencies` entries and `dependsOn` items (both `uniqueItems`)
#   2. the spec version is whatever Trivy's newest is - 1.7 since Trivy 0.71,
#      with no flag to choose it (aquasecurity/trivy#10850); DT <= 4.14 and much
#      of the ecosystem only ingest <= 1.6
#
# See https://github.com/aquasecurity/trivy/discussions/7532
#
# The work happens in a temp file that is renamed over the SBOM once, at the end,
# so a failure leaves the original intact. JSON formatting is rewritten and
# arrays are reordered.
#
# Usage: normalize-sbom.sh <sbom.json>

set -euo pipefail

sbom="${1:?usage: normalize-sbom.sh <sbom.json>}"

if [ ! -f "$sbom" ]; then
  echo "SBOM file does not exist: $sbom" >&2
  exit 1
fi

if [ "$(jq -r '.bomFormat // ""' "$sbom")" != "CycloneDX" ]; then
  echo "normalize-sbom: not a CycloneDX BOM" >&2
  exit 1
fi

# Both rewrites below - the jq dedup and the optional down-convert - land in a
# temp file beside the SBOM; a single `mv` at the end is the only thing that
# touches $sbom, so any failure leaves the original intact. mktemp beside it
# keeps that `mv` a same-filesystem rename rather than a copy.
work="$(mktemp "${sbom}.normalize.XXXXXX")"
converted="$(mktemp "${sbom}.normalize.XXXXXX")"
trap 'rm -f "$work" "$converted"' EXIT

jq '
  # Fold each bom-ref group down to its first component, carrying over only
  # `properties` from the rest (unioned) - that is where Trivy puts the per-layer
  # data (LayerDigest, ...). `properties` is an unordered name/value bag so
  # merging it stays schema-valid; unioning richer fields (licenses, hashes)
  # might not. Components with no bom-ref are left alone.
  def fold_properties($dup):
    if ($dup.properties | type) == "array"
    then .properties = (((.properties // []) + $dup.properties) | unique)
    else . end;
  def dedupe_components:
    ( [ .[] | select(."bom-ref" != null) ]
      | group_by(."bom-ref")
      | map(reduce .[1:][] as $dup (.[0]; fold_properties($dup))) )
    + [ .[] | select(."bom-ref" == null) ];

  # Merge entries that share a ref, unioning each edge array (dependsOn, and
  # provides when present) - Trivy repeats both the entry and items within them.
  # A non-array edge is malformed and contributes nothing rather than aborting
  # the run. Entries with no ref pass through.
  def merge_edge($group; $field):
    if any($group[]; has($field))
    then { ($field): ( [ $group[] | (.[$field] | if type == "array" then .[] else empty end) ] | unique ) }
    else {} end;
  def dedupe_dependencies:
    ( [ .[] | select(.ref != null) ]
      | group_by(.ref)
      | map(.[0] + merge_edge(.; "dependsOn") + merge_edge(.; "provides")) )
    + [ .[] | select(.ref == null) ];

  (if (.components | type) == "array" then .components |= dedupe_components else . end)
  | (if (.dependencies | type) == "array" then .dependencies |= dedupe_dependencies else . end)
' "$sbom" > "$work"

# Down-convert only 1.7 and newer (see header). 1.6 and older pass through - an
# older BOM is left for lint-sbom.sh to flag, not silently rewritten. Only a
# "1.<minor>" version triggers conversion; a missing or odd version is left as is.
spec_version="$(jq -r '.specVersion // ""' "$work")"
case "$spec_version" in
  1.[0-9] | 1.[0-9][0-9]) minor="${spec_version#1.}" ;;
  *)                      minor=0 ;;
esac
if [ "$minor" -ge 7 ]; then
  cyclonedx convert --input-file "$work" --input-format json \
    --output-file "$converted" --output-format json --output-version v1_6
  mv "$converted" "$sbom"
  echo "normalize-sbom: down-converted CycloneDX $spec_version -> 1.6"
else
  mv "$work" "$sbom"
fi

# Summary line, read back from the written file. Counts are type-safe:
# `"components": true` in a malformed BOM must not fail the script here, after
# the SBOM has already been replaced.
final_version="$(jq -r '.specVersion // "?"' "$sbom")"
components="$(jq '.components | if type == "array" then length else 0 end' "$sbom")"
dependencies="$(jq '.dependencies | if type == "array" then length else 0 end' "$sbom")"
echo "normalize-sbom: CycloneDX $final_version, $components components, $dependencies dependency nodes"
