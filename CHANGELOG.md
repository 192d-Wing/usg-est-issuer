# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-07-30

### Added

- Publish a multi-platform container image for Linux AMD64 and ARM64.
- Verify both required architectures are present in the registry manifest
  before signing, attesting, and creating the GitHub Release.

## [0.2.0] - 2026-07-30

### Added

- A tag-driven GHCR release pipeline gated by Rust, Helm, and end-to-end
  Kubernetes EST checks.
- High and critical vulnerability scanning before publication.
- SPDX and OCI SBOM generation, BuildKit and GitHub provenance attestations,
  keyless Cosign signing, and GitHub Release creation.
- Container build-context exclusions for local build output, vendored test
  dependencies, repository metadata, logs, and local environment files.
- Negative tests for non-P-384 public keys and mismatched common names.

### Security

- Enforce the CSR SubjectPublicKeyInfo algorithm and named curve so only
  ECDSA P-384 (`secp384r1`) public keys are accepted.
- Require a CSR common name, when present, to match one of its validated DNS
  subject alternative names and reject multiple common names.

### Changed

- Make the standard CI and Kubernetes integration workflows reusable release
  gates.
- Publish production images by immutable digest with synchronized Cargo,
  Helm chart, application, and default image versions.

[0.2.1]: https://github.com/192d-Wing/usg-est-issuer/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/192d-Wing/usg-est-issuer/releases/tag/v0.2.0
