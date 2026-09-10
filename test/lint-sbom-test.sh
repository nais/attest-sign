#!/usr/bin/env bash
#
# Tests for scripts/lint-sbom.sh.
#
#   dangling-ref-sbom.json - dependsOn points at a bom-ref no component declares.
#   npm-sbom.json          - clean, schema-valid, lint-clean.
#   null-purl-sbom.json    - two components with purl "" plus two with no purl
#                            key. Empty-string purl is schema-valid (CycloneDX
#                            purl has no minLength) and is the case that a naive
#                            `has("purl")` grouping wrongly flags as a duplicate;
#                            the no-purl pair is the never-broken control.
#   shared-purl-sbom.json  - two schema-valid components with the same purl and
#                            different bom-refs (real Trivy output); a NOTE, not
#                            a build failure.

set -euo pipefail

# shellcheck source=test/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
lint="$repo/scripts/lint-sbom.sh"

# Clean SBOM passes in every mode.
bash "$lint" "$here/npm-sbom.json" error >/dev/null || fail "clean SBOM should pass lint in error mode"

# The empty/absent-purl fixture is itself schema-valid ...
cyclonedx validate --input-file "$here/null-purl-sbom.json" --input-format json --fail-on-errors >/dev/null 2>&1 \
  || fail "null-purl-sbom.json is not schema-valid (empty-string purl rejected?)"
# ... and empty or absent purls are not flagged as a shared purl, in any mode.
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

# Components sharing a purl (different bom-refs) are a NOTE, not a PROBLEM:
# valid Trivy output must pass error mode, but the note must still be printed.
purl_out=$(bash "$lint" "$here/shared-purl-sbom.json" error 2>&1) \
  || fail "shared-purl SBOM should pass error mode (purl sharing is a NOTE)"
case "$purl_out" in
  *"NOTE: multiple components share a purl"*) ;;
  *) fail "shared-purl SBOM should still emit the purl NOTE" ;;
esac

# Invalid mode is rejected.
if bash "$lint" "$here/npm-sbom.json" bogus >/dev/null 2>&1; then
  fail "invalid mode should be rejected"
fi

echo "PASS: lint-sbom.sh tests"
