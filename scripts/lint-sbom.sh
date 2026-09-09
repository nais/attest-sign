#!/usr/bin/env bash
#
# Validate a CycloneDX SBOM and lint it for problems strict consumers reject that
# JSON-schema validation misses: dangling dependency-graph refs and components
# sharing a purl. Also flags CycloneDX spec versions the checks below have not
# been reviewed against, so schema drift is visible instead of silently passing.
#
# Read-only; run scripts/normalize-sbom.sh first to fix what can be fixed.
#
# Usage: lint-sbom.sh <sbom.json> [error|warn|off]
#   warn (default) - report problems, exit zero
#   error          - exit non-zero on any schema or lint problem
#   off            - do nothing

set -euo pipefail

# CycloneDX versions the field assumptions below (bom-ref, dependencies[].ref /
# dependsOn / provides, purl) have been checked against.
REVIEWED_SPEC_VERSIONS="1.2 1.3 1.4 1.5 1.6"

sbom="${1:?usage: lint-sbom.sh <sbom.json> [error|warn|off]}"
mode="${2:-warn}"

case "$mode" in
  error | warn) ;;
  off) exit 0 ;;
  *)
    echo "lint-sbom: invalid mode '$mode' (expected error, warn or off)" >&2
    exit 1
    ;;
esac

if [ ! -f "$sbom" ]; then
  echo "lint-sbom: file not found: $sbom" >&2
  exit 1
fi

problems=0

spec_version=$(jq -r '.specVersion // "unknown"' "$sbom")
[ -n "$spec_version" ] || spec_version="unknown"

# Validate against the schema the SBOM declares, not cyclonedx-cli's newest
# default (currently v1.7).
validate_args=(--input-file "$sbom" --input-format json --fail-on-errors)
case "$spec_version" in
  1.*) validate_args+=(--input-version "v${spec_version//./_}") ;;
esac
if ! cyclonedx validate "${validate_args[@]}"; then
  problems=1
fi

# check VAR LABEL PROGRAM: run a jq check and store its newline-separated output
# in VAR (in this shell, so `problems` updates stick - `mapfile < <(jq ...)` is
# avoided on purpose: it is bash 4+, and a process substitution hides jq's exit
# status). A failure of jq itself counts as a problem rather than a silent pass.
check() {
  local __var=$1 label=$2 program=$3 out
  if out=$(jq -r "$program" "$sbom" 2>&1); then
    printf -v "$__var" '%s' "$out"
  else
    echo "LINT: $label check could not run: $out" >&2
    problems=1
    printf -v "$__var" '%s' ''
  fi
}

# report_lines HEADING LINES: if LINES is non-empty, print HEADING then each
# line bulleted, and count it as a problem.
report_lines() {
  local heading=$1 lines=$2 line
  [ -n "$lines" ] || return 0
  echo "$heading"
  while IFS= read -r line; do
    [ -n "$line" ] && echo "  - $line"
  done <<< "$lines"
  problems=1
}

case " $REVIEWED_SPEC_VERSIONS " in
  *" $spec_version "*) ;;
  *)
    echo "LINT: CycloneDX $spec_version is outside the reviewed set [$REVIEWED_SPEC_VERSIONS]; re-check bom-ref / dependencies / purl handling"
    problems=1
    ;;
esac

dangling='' dupe_purls=''

# shellcheck disable=SC2016  # the single-quoted strings are jq programs, not shell
check dangling "dangling-ref" '
  ([.. | objects | select(has("bom-ref")) | ."bom-ref"] | unique) as $known
  | [ .dependencies[]? | (.ref, (.dependsOn[]?), (.provides[]?)) ]
  | map(select(. != null)) | unique
  | map(select(. as $r | ($known | index($r)) | not)) | .[]'
report_lines "LINT: dependency graph references unknown bom-ref(s):" "$dangling"

# shellcheck disable=SC2016
check dupe_purls "shared-purl" '
  [.components[]? | .purl | select(type == "string" and . != "")]
  | group_by(.) | map(select(length > 1) | .[0]) | .[]'
report_lines "LINT: multiple components share a purl:" "$dupe_purls"

if [ "$problems" -eq 0 ]; then
  echo "lint-sbom: valid and lint-clean"
  exit 0
fi

if [ "$mode" = "error" ]; then
  echo "lint-sbom: problems found (mode: error)"
  exit 1
fi

echo "lint-sbom: problems found (mode: warn, not failing the build)"
