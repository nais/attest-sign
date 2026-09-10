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
| `additional_sboms` | ❌ No | `''` | Newline-separated list of extra CycloneDX SBOM files to merge with the primary SBOM before attestation. Missing files fail the action. |
| `sbom_check` | ❌ No | `warn` | How the SBOM is normalized and checked before attestation: `warn` normalizes it and reports CycloneDX schema / lint problems without failing the build, `error` normalizes it and fails the build on any schema error or lint problem, `off` skips normalization and checking entirely (SBOM merge still runs if `additional_sboms` is set). |
| `trivy_java_db_repositories` | ❌ No | `europe-north1-docker.pkg.dev/nais-io/github-ptc/aquasecurity/trivy-java-db:1,public.ecr.aws/aquasecurity/trivy-java-db,ghcr.io/aquasecurity/trivy-java-db:1` | Comma-separated list of container registries to use for Trivy Java DB mirror fallback |

## Outputs

| Output | Description |
|--------|-------------|
| `sbom` | Path to the generated, provided, or merged SBOM in CycloneDX JSON format |

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

### With merged SBOMs

```yaml
- name: "Attest and sign"
  uses: nais/attest-sign@v1.x.x
  with:
    image_ref: ${{ env.registry }}/${{ env.image }}@${{ steps.build_push.outputs.digest }}
    sbom: auto-generate-for-me-please.json
    additional_sboms: |
      frontend-sbom.json
      backend-sbom.json
```

Use this when you want one combined CycloneDX SBOM with both image dependencies and application dependencies. `byosbom` still accepts one file, so this action merges the SBOMs before attestation.

## How It Works

1. **Validation**: Ensures the image reference is in the correct format (`<image>@<digest>`)
2. **Trivy Java DB Caching**: Fetches and caches the Trivy Java database using multiple repository mirrors to avoid rate limiting
3. **SBOM Generation**: Uses Trivy (v0.70.0) to scan the image and generate a CycloneDX SBOM unless one is provided
4. **SBOM Merge**: Merges the primary SBOM with any extra CycloneDX SBOM files if `additional_sboms` is set
5. **SBOM Normalization**: Unless `sbom_check: off`:
   - folds duplicate components (exact same `bom-ref`) into one, unioning their `properties`, and de-duplicates / merges `dependencies` and `dependsOn` entries. Trivy emits a package as several components sharing one `bom-ref` when it is present in multiple image layers, which makes the BOM invalid and causes downstream consumers such as Dependency-Track to reject the attestation.
   - down-converts anything newer than CycloneDX 1.6 to 1.6. Trivy emits its newest supported spec version (1.7 as of Trivy 0.71) with no flag to choose, and Dependency-Track (≤ 4.14.x) and much of the ecosystem only ingest ≤ 1.6.

   In `warn` mode a normalization failure is logged and the SBOM is attested as-is; in `error` mode it fails the build.
6. **SBOM Validation**: Unless `sbom_check: off`, runs CycloneDX schema validation and lint checks on the normalized SBOM. Findings come in two tiers: **problems** (schema-invalid BOM, or a dependency graph that references an unknown `bom-ref`) fail the build under `sbom_check: error`; **notes** (multiple components sharing a `purl` — which Trivy emits for multi-parent packages and which strict consumers such as Dependency-Track may reject — and CycloneDX spec versions outside the reviewed range 1.4–1.6) are reported for visibility but never fail the build. `warn` reports both tiers without failing.
7. **Security Signing**: Uses cosign (v3.0.6) to sign the image and create attestations with the final SBOM
8. **Output**: Returns the final SBOM path for downstream use

### Performance Optimization

- **Multi-mirror Java DB**: Automatically falls back through multiple registries if the primary source is unavailable or rate-limited
- **Database Caching**: Caches the Trivy Java DB between runs to significantly reduce scan time
- **Cache Key Strategy**: Uses the Trivy Java DB digest as cache key to automatically update when the database is refreshed (weekly)

## Security Considerations

- Image references must include a digest (`@sha256:...`) for reproducibility
- Provided SBOM files must exist before the action runs, except `auto-generate-for-me-please.json`
- Missing files in `additional_sboms` fail the action immediately
- All dependencies (cosign, Trivy, ORAS) are pinned to specific versions
- Signatures and attestations are stored in the container registry alongside the image

## Caching Strategy

The action caches the `trivy-java-db` artifact which is updated weekly by the Trivy project. For optimal security updates:
- Cache is automatically invalidated when the database digest changes
- No manual cache management is required
- Significantly reduces GitHub API rate limiting impact on subsequent runs
