#!/usr/bin/env bash
#
# Install the pinned Trivy release from GitHub Releases and add it to GITHUB_PATH
# (Linux x64 / arm64). The version and hashes live in trivy-release.sh.

set -euo pipefail

# shellcheck source=scripts/trivy-release.sh
source "$(dirname "${BASH_SOURCE[0]}")/trivy-release.sh"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    asset="trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz"
    expected_sha="$TRIVY_SHA256_AMD64"
    ;;
  Linux/aarch64 | Linux/arm64)
    asset="trivy_${TRIVY_VERSION#v}_Linux-ARM64.tar.gz"
    expected_sha="$TRIVY_SHA256_ARM64"
    ;;
  *)
    echo "install-trivy: unsupported platform $(uname -s)/$(uname -m); need Linux x86_64 or arm64" >&2
    exit 1
    ;;
esac

install_dir="$(mktemp -d "${RUNNER_TEMP:?}/trivy.XXXXXX")"
trap 'rm -rf "$install_dir"' EXIT
archive="$install_dir/$asset"
download_url="https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${asset}"

echo "Installing Trivy ${TRIVY_VERSION} from GitHub Releases"
curl -fsSL --retry 3 --retry-connrefused --retry-delay 2 --connect-timeout 10 --max-time 180 \
  "$download_url" -o "$archive"
if ! echo "${expected_sha}  ${archive}" | sha256sum --check --status; then
  echo "install-trivy: SHA-256 verification failed for ${asset}" >&2
  exit 1
fi

mkdir "$install_dir/bin"
tar --no-same-owner -xzf "$archive" -C "$install_dir/bin" trivy contrib
"$install_dir/bin/trivy" --version
rm -f "$archive"
printf '%s\n' "$install_dir/bin" >> "${GITHUB_PATH:?}"
# Later workflow steps run Trivy from here, so keep it after this script exits.
trap - EXIT
