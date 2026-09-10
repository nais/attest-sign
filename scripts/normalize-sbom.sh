#!/usr/bin/env bash
#
# Collapse Trivy's duplicate CycloneDX output in place.
#
# Scanning a multi-layer image, Trivy emits a package that appears in several
# layers as several components with the same `bom-ref`, one duplicated
# `dependencies` entry per repeat, and repeated items inside `dependsOn`. All
# three must be unique per the CycloneDX spec, so the raw BOM fails schema
# validation and Dependency-Track rejects the attestation - the affected
# workload then never gets a vulnerability report.
# See https://github.com/aquasecurity/trivy/discussions/7532
#
# What it normalizes (note: rewrites JSON formatting and reorders arrays):
#   - components: fold entries that share a `bom-ref` into one, unioning their
#     `properties` so the per-layer metadata Trivy records there (LayerDigest,
#     ...) is kept; every other field takes the first occurrence's value.
#     Components with no `bom-ref` are left untouched.
#   - dependencies: merge entries that share a `ref`, unioning and de-duplicating
#     their `dependsOn`. Entries with no `ref` pass through.
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
  # Fold each group of components that share a bom-ref down to one, unioning
  # `properties` across the group (that is where Trivy records the per-layer data
  # - LayerDigest, LayerDiffID, ... - that differs between the copies). Every
  # other field is taken from the first component in the group. Only `properties`
  # is merged: it is an unordered name/value bag, so combining and sorting it
  # stays schema-valid, whereas unioning fields like `licenses` or `hashes` could
  # produce a combination the CycloneDX schema rejects.
  def fold_properties($dup):
    if ($dup.properties | type) == "array"
    then .properties = (((.properties // []) + $dup.properties) | unique)
    else . end;
  def dedupe_components:
    ( [ .[] | select(."bom-ref" != null) ]
      | group_by(."bom-ref")
      | map(reduce .[1:][] as $dup (.[0]; fold_properties($dup))) )
    + [ .[] | select(."bom-ref" == null) ];

  # Merge dependency entries that share a ref, unioning and de-duplicating their
  # dependsOn (Trivy repeats both the entry and items within dependsOn). Entries
  # with no ref are malformed but passed through rather than dropped.
  def merge_dependsOn($group):
    if any($group[]; has("dependsOn"))
    then { dependsOn: ( [ $group[] | .dependsOn // empty | .[] ] | unique ) }
    else {} end;
  def dedupe_dependencies:
    ( [ .[] | select(.ref != null) ]
      | group_by(.ref)
      | map(.[0] + merge_dependsOn(.)) )
    + [ .[] | select(.ref == null) ];

  (if (.components | type) == "array" then .components |= dedupe_components else . end)
  | (if (.dependencies | type) == "array" then .dependencies |= dedupe_dependencies else . end)
' "$sbom" > "$normalized"

mv "$normalized" "$sbom"
trap - EXIT

echo "normalize-sbom: CycloneDX $(jq -r '.specVersion // "?"' "$sbom"), $(jq '(.components // []) | length' "$sbom") components, $(jq '(.dependencies // []) | length' "$sbom") dependency nodes"
