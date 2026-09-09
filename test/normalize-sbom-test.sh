#!/usr/bin/env bash
#
# Tests for scripts/normalize-sbom.sh, using test/duplicate-sbom.json: a
# Trivy-shaped BOM with duplicate components sharing a bom-ref, a duplicated
# dependency entry (one copy carrying an extra `provides`, one with a malformed
# scalar `dependsOn`), and a repeated dependsOn ref.

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
assert_eq "dependsOn entries unique" \
  "$(jq '[.dependencies[] | (.dependsOn | length) - (.dependsOn | unique | length)] | add' "$sbom")" "0"
assert_eq "provides preserved from a later merged duplicate" \
  "$(jq -c '.dependencies[] | select(.ref == "pkg:pypi/requests@2.34.2") | .provides' "$sbom")" \
  '["pkg:pypi/certifi@2026.6.17"]'
assert_eq "a scalar dependsOn is coerced to an array, not crashed on" \
  "$(jq -c '.dependencies[] | select(.ref == "pkg:pypi/requests@2.34.2") | .dependsOn' "$sbom")" \
  '["pkg:pypi/certifi@2026.6.17"]'

cyclonedx validate --input-file "$sbom" --input-format json --fail-on-errors >/dev/null \
  || fail "normalized SBOM does not pass schema validation"

echo "PASS: normalize-sbom.sh tests"