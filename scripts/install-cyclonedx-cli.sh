#!/usr/bin/env bash
#
# Install a pinned cyclonedx-cli (linux/amd64) to /usr/local/bin/cyclonedx.

set -euo pipefail

version='v0.33.1'
download_url="https://github.com/CycloneDX/cyclonedx-cli/releases/download/${version}/cyclonedx-linux-x64"
expected_sha='bfc8b2538da86fe239bc53658bbb63c1c8c510a293c1e6891aa5bea5d3c58746'

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsSL "$download_url" -o "$tmp"
echo "${expected_sha}  ${tmp}" | sha256sum --check --status
chmod +x "$tmp"
sudo mv "$tmp" /usr/local/bin/cyclonedx
trap - EXIT

cyclonedx --version
