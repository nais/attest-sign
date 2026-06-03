# nais/attest-sign

A GitHub Action that generates a Software Bill of Materials (SBOM), creates attestations, and signs Docker images using container signing best practices.

## Overview

This action automates container image supply chain security by:
- Generating SBOMs in CycloneDX format with Trivy
- Signing images with cosign
- Creating attestations for vulnerability scanning results
- Caching database artifacts for performance optimization

**Prerequisites:** You must be authenticated to the registry where attestations and signatures are uploaded.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `image_ref` | ✅ Yes | - | Full image reference in the form `<image>@<digest>` (e.g., `europe-north1-docker.pkg.dev/nais-io/nais/images/app@sha256:abc123...`) |
| `sbom` | ❌ No | `auto-generate-for-me-please.json` | Path to existing SBOM in CycloneDX format. If not provided, SBOM is auto-generated from the image manifest. |
| `trivy_java_db_repositories` | ❌ No | `europe-north1-docker.pkg.dev/nais-io/github-ptc/aquasecurity/trivy-java-db:1,public.ecr.aws/aquasecurity/trivy-java-db,ghcr.io/aquasecurity/trivy-java-db:1` | Comma-separated list of container registries to use for Trivy Java DB mirror fallback |

## Outputs

| Output | Description |
|--------|-------------|
| `sbom` | Path to the generated or provided SBOM in CycloneDX JSON format |

## Usage

### Basic Example

```yaml
env:
  registry: "some.registry/images"
  image: "myimage"

jobs:
  build_push_sign:
    runs-on: "ubuntu-latest"
    steps:
      - name: "Checkout"
        uses: actions/checkout@v4

      - name: "Authenticate to Google Cloud"
        # ... your authentication step ...

      - name: "Login to registry"
        # ... your registry login step ...

      - name: "Build and push"
        id: "build_push"
        # ... your build and push step ...
        # Must output 'digest' (e.g., sha256:abc123...)

      - name: "Attest and sign"
        uses: nais/attest-sign@v1.x.x
        with:
          image_ref: ${{ env.registry }}/${{ env.image }}@${{ steps.build_push.outputs.digest }}
```

### With Pre-generated SBOM

```yaml
- name: "Attest and sign"
  uses: nais/attest-sign@v1.x.x
  with:
    image_ref: ${{ env.registry }}/${{ env.image }}@${{ steps.build_push.outputs.digest }}
    sbom: ./sbom.json
```

## How It Works

1. **Validation**: Ensures the image reference is in the correct format (`<image>@<digest>`)
2. **Trivy Java DB Caching**: Fetches and caches the Trivy Java database using multiple repository mirrors to avoid rate limiting
3. **SBOM Generation**: Uses Trivy (v0.71.0) to scan the image and generate a CycloneDX SBOM unless one is provided
4. **Security Signing**: Uses cosign (v3.0.6) to sign the image and create attestations with the SBOM
5. **Output**: Returns the SBOM path for downstream use

### Performance Optimization

- **Multi-mirror Java DB**: Automatically falls back through multiple registries if the primary source is unavailable or rate-limited
- **Database Caching**: Caches the Trivy Java DB between runs to significantly reduce scan time
- **Cache Key Strategy**: Uses the Trivy Java DB digest as cache key to automatically update when the database is refreshed (weekly)

## Technical Details

- **SBOM Format**: CycloneDX 1.x JSON
- **Trivy Version**: v0.71.0
- **Cosign Version**: v3.0.6
- **Requires**: Bash, Docker/container runtime, authenticated registry access

## Security Considerations

- Image references must include a digest (`@sha256:...`) for reproducibility
- SBOM input path is validated to prevent directory traversal
- All dependencies (cosign, Trivy, ORAS) are pinned to specific versions
- Signatures and attestations are stored in the container registry alongside the image

## Caching Strategy

The action caches the `trivy-java-db` artifact which is updated weekly by the Trivy project. For optimal security updates:
- Cache is automatically invalidated when the database digest changes
- No manual cache management is required
- Significantly reduces GitHub API rate limiting impact on subsequent runs
