# Kasumi v0.19.2

This release adds an overwrite guard to `kasumi key`, adds a vulnerability reporting policy (`SECURITY.md`), and aligns documentation with current CLI behavior and release verification.

## Highlights

- **Key overwrite protection (`kasumi key`, `kasumi config`).** `set_profile_key`, `kasumi key <profile>`, and `[k] Key` in `kasumi config` now compare any existing stored master key using constant-time `crypto_verify32` before writing. Re-entering the same key stays idempotent and missing or corrupt local keys remain recoverable, while attempting to overwrite a different valid key fails with `ProfileErrorCode::AlreadyExists` in the application API and requires explicit confirmation (defaulting to No) in interactive CLI flows.
- **Security policy (`SECURITY.md`).** Added a root `SECURITY.md` documenting Kasumi's pre-1.0 support scope (security fixes target only the latest `0.x` release on `main`) and private vulnerability reporting through GitHub Security Advisories.
- **Documentation and release verification updates.** Clarified that `kasumi key` updates only the local key without re-encrypting remote data, removed stale `--non-interactive` and managed package-manager references, documented the official binary baselines (`windows-2022` `/MT` and `ubuntu-latest` GCC 14 with dynamic `glibc`), and added `gh attestation verify` instructions alongside a note on current OS code-signing status.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4 and `state.db` schema v2 (`v0.19.0` and `v0.19.1` vaults open directly). See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.19.2/docs/best-practices.md#upgrading-kasumi).
- Download the archive for your platform (`kasumi-windows-x86_64.zip` or `kasumi-linux-x86_64.tar.gz`), verify its SHA-256 checksum and GitHub build provenance attestation (`gh attestation verify`), and replace the executable manually.
