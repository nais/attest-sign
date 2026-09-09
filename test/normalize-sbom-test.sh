#!/usr/bin/env bash
#
# Tests for scripts/normalize-sbom.sh.
#
# Fixtures:
#   duplicate-sbom.json   - Trivy-shaped: duplicate components sharing a bom-ref,
#                           a duplicated dependency entry, a repeated dependsOn ref.
#   dangling-ref-sbom.json - dependsOn points at a bom-ref that no component declares.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"
norm="$repo/scripts/normalize-sbom.sh"

fail() { echo "FAIL: $1"; exit 1; }
assert_eq() { [ "$2" = "$3" ] || fail "$1: expected '$3', got '$2'"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- duplicate components / dependency graph are collapsed -------------------

sbom="$work/dup.json"
cp "$here/duplicate-sbom.json" "$sbom"

if cyclonedx validate --input-file "$sbom" --input-format json --fail-on-errors >/dev/null 2>&1; then
  fail "duplicate-sbom.json unexpectedly passed schema validation before normalization"
fi

bash "$norm" "$sbom" error

assert_eq "duplicate component collapsed" "$(jq '.components | length' "$sbom")" "2"
assert_eq "component bom-refs unique" \
  "$(jq '[.components[]."bom-ref"] | unique | length' "$sbom")" "2"
assert_eq "single certifi component kept" \
  "$(jq '[.components[] | select(."bom-ref" == "pkg:pypi/certifi@2026.6.17")] | length' "$sbom")" "1"
assert_eq "duplicate dependency entry merged" "$(jq '.dependencies | length' "$sbom")" "3"
assert_eq "dependency refs unique" \
  "$(jq '[.dependencies[].ref] | unique | length' "$sbom")" "3"
assert_eq "dependsOn entries unique" \
  "$(jq '[.dependencies[] | (.dependsOn | length) - (.dependsOn | unique | length)] | add' "$sbom")" "0"

# --- dangling dependency-graph refs -----------------------------------------

sbom="$work/dangling.json"

cp "$here/dangling-ref-sbom.json" "$sbom"
if bash "$norm" "$sbom" error >/dev/null 2>&1; then
  fail "dangling-ref-sbom.json should fail normalize-sbom.sh in error mode"
fi

cp "$here/dangling-ref-sbom.json" "$sbom"
bash "$norm" "$sbom" warn >/dev/null || fail "warn mode should not fail on dangling refs"

cp "$here/dangling-ref-sbom.json" "$sbom"
bash "$norm" "$sbom" off >/dev/null || fail "off mode should not run lint"

echo "PASS: normalize-sbom.sh tests"
