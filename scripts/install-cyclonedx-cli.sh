#!/usr/bin/env bash
#
# Install a pinned cyclonedx-cli (linux/amd64) to /usr/local/bin/cyclonedx.

set -euo pipefail

version='v0.33.1'
download_url="https://github.com/CycloneDX/cyclonedx-cli/releases/download/${version}/cyclonedx-linux-x64"
expected_sha='bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746'

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
