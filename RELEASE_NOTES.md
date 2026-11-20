# Kasumi v0.18.1

This release fixes repeated `:back` navigation hints in the interactive `kasumi config` profile wizard.

## Highlights

- **Single `:back` hint per wizard action.** `kasumi config` now displays the `Type :back to return to the menu.` hint once when starting a profile action instead of repeating it before every subsequent field prompt and validation retry.

## Compatibility and installation

- Existing Protocol v3 vaults open directly with v0.18.1. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.18.1/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
