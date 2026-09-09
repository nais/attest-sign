#!/usr/bin/env bash
#
# Tests for scripts/lint-sbom.sh.
#
#   dangling-ref-sbom.json - dependsOn points at a bom-ref no component declares.
#   npm-sbom.json          - clean, schema-valid, lint-clean.
#   null-purl-sbom.json    - several components with an empty/absent purl; must
#                            not be flagged as sharing a purl.

set -euo pipefail

# shellcheck source=test/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
lint="$repo/scripts/lint-sbom.sh"

# Clean SBOM passes in every mode.
bash "$lint" "$here/npm-sbom.json" error >/dev/null || fail "clean SBOM should pass lint in error mode"

# Components with an empty or absent purl are not "sharing a purl".
bash "$lint" "$here/null-purl-sbom.json" error >/dev/null || fail "empty/absent purls should not be flagged as duplicates"

# Dangling dependency-graph ref: fails in error, reported but not fatal in warn,
# untouched in off.
if bash "$lint" "$here/dangling-ref-sbom.json" error >/dev/null 2>&1; then
  fail "dangling-ref-sbom.json should fail lint in error mode"
fi
bash "$lint" "$here/dangling-ref-sbom.json" warn >/dev/null || fail "warn mode should not fail on dangling refs"
bash "$lint" "$here/dangling-ref-sbom.json" off >/dev/null || fail "off mode should be a no-op"

# Default mode is warn.
bash "$lint" "$here/dangling-ref-sbom.json" >/dev/null || fail "default mode should be warn (non-fatal)"

# A schema-invalid SBOM fails error mode but never fails warn mode.
if bash "$lint" "$here/duplicate-sbom.json" error >/dev/null 2>&1; then
  fail "schema-invalid SBOM should fail lint in error mode"
fi
bash "$lint" "$here/duplicate-sbom.json" warn >/dev/null || fail "warn mode should not fail on a schema-invalid SBOM"

# Invalid mode is rejected.
if bash "$lint" "$here/npm-sbom.json" bogus >/dev/null 2>&1; then
  fail "invalid mode should be rejected"
fi

echo "PASS: lint-sbom.sh tests"
