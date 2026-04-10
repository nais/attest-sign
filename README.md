# nais/attest-sign

This action generates an SBOM, attests and signs the image.

It assumes that you are already authenticated to the registry where attestations and signatures are uploaded.

## Usage

```yaml
env:
  registry: "some.registry/images"
  image: "myimage"

jobs:
  build_push_sign:
    runs-on: "ubuntu-latest"
    steps:
    - name: "Checkout"
      ...
    - name: "Authenticate to Google Cloud"
      ...
    - name: "Login to registry"
      ...
    - name: "Docker metadata"
      ...
    - name: "Build and push"
      id: "build_push"
      ...
    - name: "Attest and sign"
      uses: 'nais/attest-sign@v1.x.x'
      with:
        image_ref: ${{ env.registry }}/${{ env.image }}@${{ steps.build_push.outputs.digest }}
        sbom: # By default, the SBOM is generated with Trivy from the image manifest. Can be overridden with a pre-generated SBOM.
```

## Functionality

The action uses Trivy to generate an SBOM and cosign to sign it.
It implements caching of the `trivy-java-db` and multiple "mirrors/repositories" to avoid being rate-limited by Github and significantly reduce the time used on subsequent runs.
The [trivy-java-db](https://github.com/aquasecurity/trivy-java-db/pkgs/container/trivy-java-db) is updated weekly so the cache should be updated at least as often.

## Architecture

The action is a **composite action** with a Docker inner runner:

- The outer `action.yml` (composite) handles caching (`actions/cache`) and outputs.
- All heavy lifting — Trivy SBOM generation, `cosign sign`, and `cosign attest` — runs inside a
  Docker container built from the `Dockerfile` at the repo root.
- Tools installed in the Docker image (pinned versions):
  - [cosign](https://github.com/sigstore/cosign) v3.0.5
  - [trivy](https://github.com/aquasecurity/trivy) v0.69.3
  - [oras](https://github.com/oras-project/oras) v1.3.1
- The only external GitHub Action used is `actions/cache` (first-party).
