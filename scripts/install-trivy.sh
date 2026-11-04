#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/trivy-release.sh
source "$(dirname "${BASH_SOURCE[0]}")/trivy-release.sh"
version="$TRIVY_VERSION"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    asset="trivy_${version#v}_Linux-64bit.tar.gz"
    expected_sha="$TRIVY_SHA256_AMD64"
    ;;
  Linux/aarch64 | Linux/arm64)
    asset="trivy_${version#v}_Linux-ARM64.tar.gz"
    expected_sha="$TRIVY_SHA256_ARM64"
    ;;
  *)
    echo "install-trivy: unsupported platform $(uname -s)/$(uname -m); need Linux x86_64 or arm64" >&2
    exit 1
    ;;
esac

tmp="$(mktemp -d "${RUNNER_TEMP:?}/trivy.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
archive="$tmp/$asset"
download_url="https://github.com/aquasecurity/trivy/releases/download/${version}/${asset}"

echo "Installing Trivy ${version} from GitHub Releases"
curl -fsSL --retry 3 --retry-connrefused --retry-delay 2 --connect-timeout 10 --max-time 180 \
  "$download_url" -o "$archive"
if ! echo "${expected_sha}  ${archive}" | sha256sum --check --status; then
  echo "install-trivy: SHA-256 verification failed for ${asset}" >&2
  exit 1
fi

mkdir "$tmp/bin"
tar --no-same-owner -xzf "$archive" -C "$tmp/bin" trivy contrib
"$tmp/bin/trivy" --version
rm -f "$archive"
printf '%s\n' "$tmp/bin" >> "${GITHUB_PATH:?}"
trap - EXIT
