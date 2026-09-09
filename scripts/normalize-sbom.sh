#!/usr/bin/env bash
#
# Collapse Trivy's duplicate CycloneDX output in place.
#
# Trivy can emit one package as several components sharing a single bom-ref when
# the package is present in more than one image layer. That produces duplicate
# entries in `dependencies` and `dependencies[].dependsOn`, which CycloneDX 1.6
# requires to be unique, so Dependency-Track rejects the attestation with a
# schema-validation error and the affected workload never gets a vulnerability
# report. See https://github.com/aquasecurity/trivy/discussions/7532
#
# What it normalizes (note: rewrites JSON formatting and may reorder arrays):
#   - components: drop entries after the first that share a `bom-ref` (bom-ref
#     must be unique per spec; components without a bom-ref are left untouched)
#   - dependencies: merge entries that share a `ref`, unioning their `dependsOn`
#   - dependsOn: de-duplicate each array
#
# Writes via a temp file, so a jq failure leaves the original SBOM untouched.
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

# Keep the temp file on the same filesystem as the SBOM so the final mv is an
# atomic rename, not a copy that could partially overwrite the SBOM on failure.
normalized="$(mktemp "${sbom}.normalized.XXXXXX")"
trap 'rm -f "$normalized"' EXIT

jq '
  # Keep every component that has no bom-ref, or is the first occurrence of its
  # bom-ref. Only exact bom-ref collisions (already invalid per spec) are dropped.
  def dedupe_components:
    reduce .[] as $c ({seen: {}, out: []};
      ($c["bom-ref"]) as $ref
      | if $ref != null and (.seen[$ref] // false)
        then .
        else (if $ref != null then .seen[$ref] = true else . end) | .out += [$c]
        end)
    | .out;

  # Merge dependency entries that share a ref (union of dependsOn); pass through
  # any malformed entry that has no ref.
  def dedupe_dependencies:
    ( [ .[] | select(.ref != null) ]
      | group_by(.ref)
      | map( .[0] + { dependsOn: ( [ (.[].dependsOn // [])[] ] | unique ) } ) )
    + [ .[] | select(.ref == null) ];

  (if (.components | type) == "array" then .components |= dedupe_components else . end)
  | (if (.dependencies | type) == "array" then .dependencies |= dedupe_dependencies else . end)
' "$sbom" > "$normalized"

mv "$normalized" "$sbom"
trap - EXIT

echo "normalize-sbom: CycloneDX $(jq -r '.specVersion // "?"' "$sbom"), $(jq '(.components // []) | length' "$sbom") components, $(jq '(.dependencies // []) | length' "$sbom") dependency nodes"
