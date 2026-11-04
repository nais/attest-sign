#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=test/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/mock-bin" "$work/fixture/contrib" "$work/runner"

cat > "$work/fixture/trivy" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo executed >> "$TEST_EXECUTIONS"
if [ "$TEST_MODE" = version-failure ]; then exit 1; fi
echo 'Version: 0.74.0'
EOF
printf 'template\n' > "$work/fixture/contrib/html.tpl"
chmod +x "$work/fixture/trivy"
tar -czf "$work/fixture.tar.gz" -C "$work/fixture" trivy contrib

cat > "$work/mock-bin/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -s) echo "$TEST_OS" ;;
  -m) echo "$TEST_ARCH" ;;
  *) exit 1 ;;
esac
EOF

cat > "$work/mock-bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
while [ "$#" -gt 0 ]; do
  case "$1" in
    https://*) echo "$1" >> "$TEST_DOWNLOADS"; shift ;;
    -o) output="$2"; shift 2 ;;
    *) shift ;;
  esac
done
cp "$TEST_ARCHIVE" "$output"
if [ "$TEST_MODE" = download-failure ]; then exit 6; fi
if [ "$TEST_MODE" = checksum-failure ]; then echo corrupt >> "$output"; fi
EOF

cat > "$work/mock-bin/sha256sum" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
read -r expected archive
[ "$expected" = "$TEST_EXPECTED_SHA" ]
cmp -s "$archive" "$TEST_ARCHIVE"
EOF

cat > "$work/mock-bin/trivy" <<'EOF'
#!/usr/bin/env bash
echo 'Version: pre-existing'
EOF
chmod +x "$work/mock-bin/"*

export PATH="$work/mock-bin:$PATH"
export RUNNER_TEMP="$work/runner"
export GITHUB_PATH="$work/github-path"
export TEST_ARCHIVE="$work/fixture.tar.gz"
export TEST_EXECUTIONS="$work/executions"
export TEST_DOWNLOADS="$work/downloads"
export TEST_OS=Linux TEST_MODE=success

for TEST_ARCH in x86_64 aarch64 arm64; do
  export TEST_ARCH
  case "$TEST_ARCH" in
    x86_64)
      asset='trivy_0.74.0_Linux-64bit.tar.gz'
      export TEST_EXPECTED_SHA='2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a'
      ;;
    *)
      asset='trivy_0.74.0_Linux-ARM64.tar.gz'
      export TEST_EXPECTED_SHA='b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5'
      ;;
  esac
  : > "$GITHUB_PATH"
  : > "$TEST_DOWNLOADS"
  bash "$repo/scripts/install-trivy.sh"
  installed="$(cat "$GITHUB_PATH")"
  [ -x "$installed/trivy" ] || fail "$TEST_ARCH binary not installed"
  [ -f "$installed/contrib/html.tpl" ] || fail "$TEST_ARCH contrib not installed"
  assert_eq "$TEST_ARCH download URL" "$(cat "$TEST_DOWNLOADS")" \
    "https://github.com/aquasecurity/trivy/releases/download/v0.74.0/$asset"
  assert_eq "$TEST_ARCH PATH precedence" "$(PATH="$installed:$PATH" trivy --version)" 'Version: 0.74.0'
  [ ! -f "$(dirname "$installed")/$asset" ] || fail "archive not cleaned up"
  rm -rf "$(dirname "$installed")"
done

export TEST_ARCH=x86_64
export TEST_EXPECTED_SHA='2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a'
for TEST_MODE in download-failure checksum-failure version-failure unsupported; do
  export TEST_MODE
  export TEST_OS=Linux
  if [ "$TEST_MODE" = unsupported ]; then export TEST_OS=Darwin; fi
  : > "$GITHUB_PATH"
  : > "$TEST_EXECUTIONS"
  : > "$TEST_DOWNLOADS"
  if bash "$repo/scripts/install-trivy.sh" > "$work/output" 2>&1; then
    fail "$TEST_MODE unexpectedly succeeded"
  fi
  [ ! -s "$GITHUB_PATH" ] || fail "$TEST_MODE exposed a failed installation on PATH"
  [ -z "$(ls -A "$RUNNER_TEMP")" ] || fail "$TEST_MODE left installation files behind"
  if [ "$TEST_MODE" != version-failure ]; then
    [ ! -s "$TEST_EXECUTIONS" ] || fail "$TEST_MODE executed an unverified binary"
  fi
  if [ "$TEST_MODE" = unsupported ]; then
    [ ! -s "$TEST_DOWNLOADS" ] || fail "unsupported platform downloaded an archive"
  fi
  if [ "$TEST_MODE" = checksum-failure ]; then
    grep -q 'SHA-256 verification failed' "$work/output" || fail "missing checksum diagnostic"
  fi
done

echo "install-trivy tests passed"
