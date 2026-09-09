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
#   - components: fold entries that share a `bom-ref` into the first occurrence,
#     unioning their `properties` so the per-layer metadata Trivy records there
#     (LayerDigest, ...) is kept; every other field takes the first value (bom-ref
#     must be unique per spec; components without a bom-ref are left untouched)
#   - dependencies: merge entries that share a `ref`, unioning `dependsOn` and
#     `provides`
#   - dependsOn / provides: de-duplicate each array, on merged and passthrough
#     entries alike
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
  # Fold every component that shares a bom-ref into its first occurrence. Only
  # exact bom-ref collisions (already invalid per spec) are folded; a component
  # with no bom-ref is always kept as-is. `properties` from every duplicate are
  # unioned, since that is where Trivy records the per-layer data that differs
  # between the copies (LayerDigest, FilePath, PkgID, ...); every other field
  # takes its value from the first occurrence. Only `properties` is merged: it is
  # an unordered name/value bag, so combining and sorting it stays schema-valid,
  # whereas blindly unioning fields like `licenses` or `hashes` could produce a
  # combination the CycloneDX schema rejects.
  def merge_component($extra):
    if ($extra.properties | type) == "array"
    then .properties = (((.properties // []) + $extra.properties) | unique)
    else . end;
  def dedupe_components:
    reduce .[] as $c ({seen: {}, out: []};
      ($c["bom-ref"]) as $ref
      | if $ref == null then .out += [$c]
        elif (.seen | has($ref) | not)
        then .seen[$ref] = (.out | length) | .out += [$c]
        else (.seen[$ref]) as $i | .out[$i] |= merge_component($c)
        end)
    | .out;

  # Merge dependency entries that share a ref, unioning the graph-edge arrays
  # (dependsOn, and provides when any entry carries it) so nothing is lost when
  # the merge keeps only non-array fields from the first entry. Malformed
  # entries with no ref pass through, still with their edge arrays de-duplicated.
  #
  # A malformed edge value (Trivy has emitted a bare string instead of an array)
  # is coerced rather than crashing the whole normalization; anything else
  # non-array becomes empty.
  def as_edge_array: if type == "array" then . elif type == "string" then [.] else [] end;
  def dedupe_edges:
    ( if has("dependsOn") then .dependsOn = (.dependsOn | as_edge_array | unique) else . end )
    | ( if has("provides") then .provides = (.provides | as_edge_array | unique) else . end );
  def union_edge($group; $field):
    if any($group[]; has($field))
    then { ($field): ( [ $group[] | .[$field] | as_edge_array | .[] ] | unique ) }
    else {} end;
  def dedupe_dependencies:
    ( [ .[] | select(.ref != null) ]
      | group_by(.ref)
      | map(
          .[0]
          + union_edge(.; "dependsOn")
          + union_edge(.; "provides") ) )
    + [ .[] | select(.ref == null) | dedupe_edges ];

  (if (.components | type) == "array" then .components |= dedupe_components else . end)
  | (if (.dependencies | type) == "array" then .dependencies |= dedupe_dependencies else . end)
' "$sbom" > "$normalized"

mv "$normalized" "$sbom"
trap - EXIT

echo "normalize-sbom: CycloneDX $(jq -r '.specVersion // "?"' "$sbom"), $(jq '(.components // []) | length' "$sbom") components, $(jq '(.dependencies // []) | length' "$sbom") dependency nodes"
