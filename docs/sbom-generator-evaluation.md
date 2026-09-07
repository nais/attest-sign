# SBOM generator evaluation: Trivy vs Syft

Status: **parked**. Trivy stays the SBOM generator.

## Context

`nais/attest-sign` generates the image SBOM with Trivy. NAIS teams hit
"SBOM processing failed" in DependencyTrack (test environment), suspected
Trivy's known duplicate-component issues, and asked whether switching to
Syft would help.

## What this branch added

- `sbom_generator` input (`trivy` default, `syft` alternative).
- `sbom_lint` input + `scripts/lint-sbom.sh`: warns or fails on SBOM
  problems that strict CycloneDX consumers reject but JSON-schema
  validation misses (duplicate `bom-ref`s, dangling dependency refs,
  components sharing a `purl`). Trivy's duplication is visible here.
- CI jobs that build, attest and deploy both a Trivy- and a
  Syft-generated image so both SBOMs reach DependencyTrack.

## Result: Syft is not a drop-in replacement

Tested with syft 1.51.1 / trivy 0.74.0 against `alpine:3.24.1`, CycloneDX 1.6:

|                                              | Trivy | Syft     |
| -------------------------------------------- | ----- | -------- |
| root component present in the dependency graph | yes   | no       |
| connected graph (image -> OS -> packages)    | yes   | no       |
| orphan components                            | 0     | 79 / 95  |

Syft's CycloneDX for a container image emits only package-to-package
edges and never links them to `metadata.component`, so most components
have no path from the root. DependencyTrack imports the components and
still matches vulnerabilities by `purl`, but cannot resolve the
dependency graph. Trivy emits a graph rooted at the image, which is what
DependencyTrack needs.

Syft's purls also carry `distro=alpine-3.24.1` where Trivy uses
`distro=3.24.1`, which can additionally weaken OS-package vulnerability
matching.

## Decision

Keep Trivy. "SBOM processing failed" has to be solved on the Trivy path -
deduplicating Trivy's duplicate components before attestation, or on the
DependencyTrack side - not by switching generators. This branch is left
as a record of the evaluation.
