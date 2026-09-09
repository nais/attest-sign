#!/usr/bin/env bash
#
# Regression test for scripts/normalize-sbom.sh.
#
# Uses test/duplicate-sbom.json, a CycloneDX BOM shaped like Trivy output for an
# image that carries the same package in multiple layers: duplicate components
# sharing a bom-ref, a duplicated dependency entry, and a repeated dependsOn ref.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
fixture="$here/duplicate-sbom.json"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sbom="$work/sbom.json"
cp "$fixture" "$sbom"

fail() { echo "FAIL: $1"; exit 1; }
assert_eq() { [ "$2" = "$3" ] || fail "$1: expected '$3', got '$2'"; }

# The raw fixture must be rejected by the CycloneDX schema, otherwise it is not
# exercising the bug this script fixes.
if cyclonedx validate --input-file "$sbom" --input-format json --fail-on-errors >/dev/null 2>&1; then
  fail "fixture $fixture unexpectedly passed schema validation"
fi

bash "$repo/scripts/normalize-sbom.sh" "$sbom"

components=$(jq '.components | length' "$sbom")
dependencies=$(jq '.dependencies | length' "$sbom")
uniq_bomref=$(jq '[.components[]."bom-ref"] | unique | length' "$sbom")
uniq_depref=$(jq '[.dependencies[].ref] | unique | length' "$sbom")
dependson_dupes=$(jq '[.dependencies[] | (.dependsOn | length) - (.dependsOn | unique | length)] | add' "$sbom")
certifi_kept=$(jq '[.components[] | select(."bom-ref" == "pkg:pypi/certifi@2026.6.17")] | length' "$sbom")

assert_eq "duplicate component collapsed" "$components" "2"
assert_eq "component bom-refs unique" "$uniq_bomref" "$components"
assert_eq "single certifi component kept" "$certifi_kept" "1"
assert_eq "duplicate dependency entry merged" "$dependencies" "3"
assert_eq "dependency refs unique" "$uniq_depref" "$dependencies"
assert_eq "dependsOn entries unique" "$dependson_dupes" "0"

echo "PASS: normalize-sbom.sh regression test"