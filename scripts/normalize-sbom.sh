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
# Collapses duplicate components by bom-ref, de-duplicates the dependency graph
# by ref (unioning dependsOn), and de-duplicates each dependsOn array.
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

echo "normalize-sbom: CycloneDX $(jq -r '.specVersion // "?"' "$sbom"), $(jq '(.components // []) | length' "$sbom") components, $(jq '(.dependencies // []) | length' "$sbom") dependency nodes"