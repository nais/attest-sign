#!/usr/bin/env bash
#
# Install a pinned cyclonedx-cli to /usr/local/bin/cyclonedx (Linux x64 / arm64).

set -euo pipefail

version='v0.33.1'

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)          asset='cyclonedx-linux-x64'   expected_sha='bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746' ;;
  Linux/aarch64 | Linux/arm64) asset='cyclonedx-linux-arm64' expected_sha='b2e9fdf9665ef49868a2ec012171c6e785dcd69745bc5869e53e4f4bfb096a5f' ;;
  *)
    echo "install-cyclonedx-cli: unsupported platform $(uname -s)/$(uname -m); need Linux x86_64 or arm64" >&2
    exit 1
    ;;
esac
download_url="https://github.com/CycloneDX/cyclonedx-cli/releases/download/${version}/${asset}"

dest='/usr/local/bin/cyclonedx'

tmp="$(mktemp)"
# Stage the final file next to the destination so the install is an atomic
# rename, not a copy that could leave a half-written binary on failure.
staged="$(sudo mktemp "${dest}.XXXXXX")"
trap 'rm -f "$tmp"; sudo rm -f "$staged"' EXIT

curl -fsSL --retry 3 --retry-connrefused --retry-delay 2 "$download_url" -o "$tmp"
echo "${expected_sha}  ${tmp}" | sha256sum --check --status
sudo cp "$tmp" "$staged"
sudo chmod 0755 "$staged"
sudo mv "$staged" "$dest"

trap - EXIT
rm -f "$tmp"

cyclonedx --version
