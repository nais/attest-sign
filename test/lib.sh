# Shared setup for the SBOM script tests. Source it:
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
#
# Provides: $here (this test directory), $repo (repo root), fail(), assert_eq().

# shellcheck disable=SC2034  # here and repo are consumed by the sourcing script
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(dirname "$here")"

fail() { echo "FAIL: $1"; exit 1; }
assert_eq() { [ "$2" = "$3" ] || fail "$1: expected '$3', got '$2'"; }
