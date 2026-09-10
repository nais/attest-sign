#!/usr/bin/env bash
#
# Tests for scripts/normalize-sbom.sh.
#
#   duplicate-sbom.json - Trivy-shaped BOM with two components sharing a bom-ref
#                         (differing only in per-layer properties), a component
#                         with no bom-ref, a dependency entry that appears twice,
#                         and a repeated item inside dependsOn.
#   cdx17-sbom.json     - CycloneDX 1.7 (what Trivy 0.71+ emits); must be
#                         down-converted to 1.6 and deduplicated.

set -euo pipefail

# shellcheck source=test/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sbom="$work/sbom.json"
cp "$here/duplicate-sbom.json" "$sbom"

if cyclonedx validate --input-file "$sbom" --input-format json --fail-on-errors >/dev/null 2>&1; then
  fail "duplicate-sbom.json unexpectedly passed schema validation before normalization"
fi

bash "$repo/scripts/normalize-sbom.sh" "$sbom"

assert_eq "duplicate component collapsed" "$(jq '.components | length' "$sbom")" "3"
assert_eq "component bom-refs unique" \
  "$(jq '[.components[]."bom-ref" | select(. != null)] | (length) - (unique | length)' "$sbom")" "0"
assert_eq "single certifi component kept" \
  "$(jq '[.components[] | select(."bom-ref" == "pkg:pypi/certifi@2026.6.17")] | length' "$sbom")" "1"
assert_eq "LayerDigest properties from both certifi duplicates unioned" \
  "$(jq -c '[.components[] | select(."bom-ref" == "pkg:pypi/certifi@2026.6.17")
            | .properties[] | select(.name == "aquasecurity:trivy:LayerDigest") | .value]
            | sort' "$sbom")" \
  '["sha256:aaaa","sha256:bbbb"]'
assert_eq "component without a bom-ref left untouched" \
  "$(jq '[.components[] | select(.name == "no-bom-ref-lib")] | length' "$sbom")" "1"
assert_eq "duplicate dependency entry merged" "$(jq '.dependencies | length' "$sbom")" "3"
assert_eq "dependency refs unique" \
  "$(jq '[.dependencies[].ref] | unique | length' "$sbom")" "3"
assert_eq "dependsOn items de-duplicated" \
  "$(jq '[.dependencies[] | (.dependsOn | length) - (.dependsOn | unique | length)] | add' "$sbom")" "0"
assert_eq "merged dependency entry keeps its dependsOn" \
  "$(jq -c '.dependencies[] | select(.ref == "pkg:pypi/requests@2.34.2") | .dependsOn' "$sbom")" \
  '["pkg:pypi/certifi@2026.6.17"]'

cyclonedx validate --input-file "$sbom" --input-format json --fail-on-errors >/dev/null \
  || fail "normalized SBOM does not pass schema validation"

# CycloneDX 1.7 input is down-converted to 1.6 and still deduplicated.
sbom17="$work/cdx17.json"
cp "$here/cdx17-sbom.json" "$sbom17"
bash "$repo/scripts/normalize-sbom.sh" "$sbom17"
assert_eq "1.7 down-converted to 1.6" "$(jq -r '.specVersion' "$sbom17")" "1.6"
assert_eq "1.7 fixture components deduplicated" "$(jq '.components | length' "$sbom17")" "1"
cyclonedx validate --input-file "$sbom17" --input-format json --input-version v1_6 --fail-on-errors >/dev/null \
  || fail "down-converted SBOM does not pass 1.6 schema validation"

# A malformed (non-array) dependsOn on a duplicated ref must not abort the run.
malformed="$work/malformed.json"
jq '.dependencies = [
      {"ref": "r", "dependsOn": "oops-a-string"},
      {"ref": "r", "dependsOn": ["pkg:pypi/requests@2.34.2"]}
    ]' "$here/duplicate-sbom.json" > "$malformed"
bash "$repo/scripts/normalize-sbom.sh" "$malformed" >/dev/null \
  || fail "a non-array dependsOn should not abort normalization"
assert_eq "the two 'r' entries merged into one" \
  "$(jq '[.dependencies[] | select(.ref == "r")] | length' "$malformed")" "1"
assert_eq "malformed dependsOn contributes nothing, valid item kept" \
  "$(jq -c '.dependencies[] | select(.ref == "r") | .dependsOn' "$malformed")" \
  '["pkg:pypi/requests@2.34.2"]'

echo "PASS: normalize-sbom.sh tests"