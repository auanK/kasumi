# Kasumi v0.23.1

This patch release adopts versioned download filenames across all installers and portable archives, makes every native installer upgrade-aware with clear version feedback, clarifies multi-device (`multi-master`) terminology, and eliminates compiler warnings while accelerating CI builds and tests.

## Highlights

- **Versioned package filenames (`kasumi-v0.23.1-...`).** Release downloads now include the version in the outer package name (`kasumi-v0.23.1-windows-x86_64.msi`, `kasumi-v0.23.1-windows-x86_64.zip`, `kasumi-v0.23.1-linux-x86_64.pkg.tar.zst`, `kasumi-v0.23.1-linux-x86_64.deb`, `kasumi-v0.23.1-linux-x86_64.rpm`, and `kasumi-v0.23.1-linux-x86_64.tar.gz`) while keeping the internal executable names simple (`kasumi` / `kasumi.exe`).
- **Upgrade-aware installers with visible version feedback.**
  - **Windows (`.msi`)**: displays `Kasumi v0.23.1` across setup screens, detects prior installations (`InstalledVersion` + `WIX_UPGRADE_DETECTED`) for patch, minor, or major updates, preserves existing profiles and `PATH`, and skips redundant directory prompts on updates.
  - **Linux (`.pkg.tar.zst`, `.deb`, `.rpm`)**: adds install/upgrade lifecycle hooks reporting the installed or upgraded version while preserving local configuration.
- **Build & CI improvements.** Eliminates the unused `-fstack-clash-protection` compiler warning for Clang on Windows and remaining `-Wsign-conversion` warnings, updates GitHub Actions workflows to Node 24-compatible versions, and adds `KASUMI_FETCHCONTENT_CACHE_DIR`, a prebuilt non-root GHCR Ubuntu CI container, `MSVC` `Ninja`+`ccache` (`/Z7`), `/MP` for Visual Studio generators, `lld`, and parallel `ctest`.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x`–`v0.23.0` vaults and local databases. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.23.1/docs/best-practices.md#upgrading-kasumi).
- Upgrade in-place with the native installer for your platform (`kasumi-v0.23.1-windows-x86_64.msi`, `sudo pacman -U kasumi-v0.23.1-linux-x86_64.pkg.tar.zst`, `sudo apt install ./kasumi-v0.23.1-linux-x86_64.deb`, or `sudo dnf install --nogpgcheck ./kasumi-v0.23.1-linux-x86_64.rpm`), or extract the portable `.zip` / `.tar.gz` archive. Verify checksums (`SHA256SUMS.txt` / `.sha256`) and GitHub build provenance (`gh attestation verify`) before installing.
