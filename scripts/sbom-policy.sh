#!/usr/bin/env bash

SBOM_CHECK_MODES="warn error off"
SBOM_REVIEWED_SPEC_VERSIONS="1.4 1.5 1.6 1.7"

sbom_check_mode_valid() {
  local allowed
  for allowed in $SBOM_CHECK_MODES; do
    [ "$1" = "$allowed" ] && return 0
  done
  return 1
}

sbom_spec_supported_for_merge() {
  case "$1" in
    1.[0-7]) return 0 ;;
    *) return 1 ;;
  esac
}

sbom_spec_reviewed_for_lint() {
  local reviewed
  for reviewed in $SBOM_REVIEWED_SPEC_VERSIONS; do
    [ "$1" = "$reviewed" ] && return 0
  done
  return 1
}
