#!/usr/bin/env bash
set -euo pipefail

version='v0.74.0'

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)
    asset='trivy_0.74.0_Linux-64bit.tar.gz'
    expected_sha='2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a'
    ;;
  Linux/aarch64 | Linux/arm64)
    asset='trivy_0.74.0_Linux-ARM64.tar.gz'
    expected_sha='b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5'
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
