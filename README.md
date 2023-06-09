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
```
