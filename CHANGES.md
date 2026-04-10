# Changes

## What changed and why

Third-party GitHub Actions (`sigstore/cosign-installer`, `oras-project/setup-oras`,
`aquasecurity/trivy-action`) are a supply-chain risk. A compromised action can
exfiltrate secrets or tamper with builds. We replaced them with a self-contained
Docker image that installs the tools directly from upstream releases.

## What's new

- **`Dockerfile`** (repo root): Alpine-based image with pinned versions of
  cosign v3.0.5, trivy v0.69.3, and oras v1.3.1.
- **`entrypoint.sh`**: runs input validation, SBOM generation (trivy), signing
  and attestation (cosign).
- **`action.yml`**: rewritten as a composite action that handles caching via
  `actions/cache` and runs the Docker image via `docker run`. All third-party
  `uses:` steps removed.
- **`.github/workflows/main.yml`**: builds and pushes the action Docker image to
  GHCR (`ghcr.io/nais/attest-sign`) before the integration test. The test image
  continues to go to GAR via `nais/docker-build-push`. Note: after the first
  push, the GHCR package visibility must be set to **public** manually in GitHub
  package settings (one-time step) so consumers can pull without authentication.
- **`.github/dependabot.yml`**: added Dockerfile tracking for the root
  Dockerfile.
- **`README.md`**: documents the new architecture.

## What's kept

- `actions/cache` (first-party GitHub action) — still used for the trivy-java-db
  cache.
- The same inputs/outputs interface — callers don't need to change anything.
