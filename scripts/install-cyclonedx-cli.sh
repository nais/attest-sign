#!/usr/bin/env bash
#
# Install a pinned cyclonedx-cli (linux/amd64) to /usr/local/bin/cyclonedx.

set -euo pipefail

version='v0.32.0'
download_url="https://github.com/CycloneDX/cyclonedx-cli/releases/download/${version}/cyclonedx-linux-x64"
expected_sha='454879e6a4a405c8a13bff49b8982adcb0596f3019b26b0811c66e4d7f0783e1'

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsSL "$download_url" -o "$tmp"
echo "${expected_sha}  ${tmp}" | sha256sum --check --status
chmod +x "$tmp"
sudo mv "$tmp" /usr/local/bin/cyclonedx
trap - EXIT

cyclonedx --version
