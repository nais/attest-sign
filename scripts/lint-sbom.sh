#!/usr/bin/env bash
#
# Validate a CycloneDX SBOM and lint it before attestation.
#
# Two tiers of finding:
#   PROBLEM - makes the BOM invalid or the dependency graph broken; fails the
#             build in error mode (schema validation, dangling dependency refs).
#   NOTE    - real Trivy output legitimately produces these; reported for
#             visibility but never fails the build (multiple components sharing
#             a purl, which Trivy emits for packages with more than one parent
#             and which strict consumers such as Dependency-Track may reject;
#             CycloneDX spec versions this script has not been vetted against).
#
# Read-only; run scripts/normalize-sbom.sh first to fix what can be fixed.
#
# Usage: lint-sbom.sh <sbom.json> [error|warn|off]
#   warn (default) - report findings, exit zero
#   error          - exit non-zero on any PROBLEM (NOTEs never fail)
#   off            - do nothing

set -euo pipefail

# CycloneDX versions the field assumptions here (bom-ref, dependencies[].ref /
# dependsOn / provides, purl) have been checked against. Trivy has emitted 1.4
# through 1.6 across its releases; normalize-sbom.sh down-converts anything newer.
REVIEWED_SPEC_VERSIONS="1.4 1.5 1.6"

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

# Don't let a malformed file exit here under `set -e` - `cyclonedx validate`
# below records it as a problem, and warn mode must still finish.
spec_version=$(jq -r '.specVersion // "unknown"' "$sbom" 2>/dev/null) || spec_version="unknown"
[ -n "$spec_version" ] || spec_version="unknown"

reviewed=no
case " $REVIEWED_SPEC_VERSIONS " in
  *" $spec_version "*) reviewed=yes ;;
esac

# Validate against the version the SBOM declares; for an unreviewed one let
# cyclonedx-cli pick its own default and leave a NOTE - a newer spec is not a
# defect.
validate_args=(--input-file "$sbom" --input-format json --fail-on-errors)
if [ "$reviewed" = yes ]; then
  validate_args+=(--input-version "v${spec_version//./_}")
fi
if ! cyclonedx validate "${validate_args[@]}"; then
  problems=1
fi
if [ "$reviewed" != yes ]; then
  echo "NOTE: CycloneDX $spec_version is outside the reviewed set [$REVIEWED_SPEC_VERSIONS]; bom-ref / dependencies / purl handling not re-verified for it"
fi

# check VAR LABEL PROGRAM: run jq and store its newline-separated output in VAR.
# Not `mapfile < <(jq ...)`: that is bash 4+, and the process substitution would
# hide a jq failure - which here must count as a problem, not a silent pass.
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

# report_lines SEVERITY HEADING LINES: if LINES is non-empty, print HEADING then
# each line bulleted. SEVERITY 'problem' also counts toward the error-mode exit;
# 'note' is informational only.
report_lines() {
  local severity=$1 heading=$2 lines=$3 line
  [ -n "$lines" ] || return 0
  echo "$heading"
  while IFS= read -r line; do
    [ -n "$line" ] && echo "  - $line"
  done <<< "$lines"
  if [ "$severity" = problem ]; then
    problems=1
  fi
}

dangling='' dupe_purls=''

# graph refs (ref / dependsOn / provides) that no object declares as a bom-ref
# shellcheck disable=SC2016  # single-quoted strings are jq programs, not shell
check dangling "dangling-ref" '
  ([.. | objects | select(has("bom-ref")) | ."bom-ref"] | unique) as $known
  | [ .dependencies[]? | (.ref, (.dependsOn[]?), (.provides[]?)) ]
  | map(select(. != null)) | unique
  | map(select(. as $r | ($known | index($r)) | not)) | .[]'
report_lines problem "LINT: dependency graph references unknown bom-ref(s):" "$dangling"

# shellcheck disable=SC2016
check dupe_purls "shared-purl" '
  [.components[]? | .purl | select(type == "string" and . != "")]
  | group_by(.) | map(select(length > 1) | .[0]) | .[]'
report_lines note "NOTE: multiple components share a purl (Trivy emits these for multi-parent packages; strict consumers such as Dependency-Track may reject them):" "$dupe_purls"

if [ "$problems" -eq 0 ]; then
  echo "lint-sbom: no problems (mode: $mode)"
  exit 0
fi

if [ "$mode" = "error" ]; then
  echo "lint-sbom: problems found (mode: error)"
  exit 1
fi

echo "lint-sbom: problems found (mode: warn, not failing the build)"
