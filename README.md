# nais/attest-sign

A GitHub Action that generates a Software Bill of Materials (SBOM), creates attestations, and signs Docker images.

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `image_ref` | ✅ Yes | - | Full image reference in the form `<image>@<digest>` |
| `sbom` | ❌ No | `auto-generate-for-me-please.json` | Path to existing SBOM in CycloneDX format |
| `trivy_java_db_repositories` | ❌ No | see action.yml | Comma-separated Trivy Java DB mirror list |

## Outputs

| Output | Description |
|--------|-------------|
| `sbom` | Path to the generated or provided SBOM in CycloneDX JSON format |

## Usage

### Basic: SBOM + sign only

```yaml
- uses: nais/attest-sign@v2
  with:
    image_ref: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
```

### With SLSA provenance (optional add-on job)

Add a separate job to your workflow. Deploy does not wait for it.

```yaml
jobs:
  build:
    outputs:
      image: ${{ steps.build.outputs.image }}
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: nais/docker-build-push@v0
        id: build
        with:
          team: myteam

      - uses: nais/attest-sign@v2
        with:
          image_ref: ${{ steps.build.outputs.image_ref }}

  deploy:
    needs: [build]
    steps:
      - uses: nais/deploy/actions/deploy@v2
        env:
          IMAGE: ${{ needs.build.outputs.image }}

  slsa_provenance:
    needs: [build]
    permissions:
      actions: read
      id-token: write
      packages: write
    uses: nais/attest-sign/.github/workflows/slsa-provenance.yml@v2 # ratchet:nais/attest-sign/.github/workflows/slsa-provenance.yml@v2
    with:
      image: ${{ needs.build.outputs.image }}
      digest: ${{ needs.build.outputs.digest }}
      workload_identity_provider: ${{ vars.NAIS_WORKLOAD_IDENTITY_PROVIDER }}
      service_account: ${{ vars.GCP_SERVICE_ACCOUNT || vars.NAIS_SERVICE_ACCOUNT }}
```

SLSA failure emits a warning and does not block deploy.

Note: set either `GCP_SERVICE_ACCOUNT` or `NAIS_SERVICE_ACCOUNT` repository variable.

### With pre-generated SBOM

```yaml
- uses: nais/attest-sign@v2
  with:
    image_ref: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
    sbom: ./sbom.json
```

## How It Works

1. Validates image reference is in `<image>@<digest>` form
2. Caches Trivy Java DB for performance
3. Generates CycloneDX SBOM with Trivy (unless one is provided)
4. Signs image and attests SBOM with cosign (keyless, Sigstore)

## Technical Details

- SBOM is produced in CycloneDX JSON format.
- The action uses Trivy for SBOM generation and cosign for signing and attestation.
- Signatures and attestations are stored in the OCI registry alongside the image
## Security Considerations

- Image reference must include a digest (`@sha256:...`) for reproducibility
- All dependencies pinned to specific versions
- SBOM input path validated to prevent directory traversal
