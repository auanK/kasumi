# Kasumi v0.27.1

## Highlights

- **Faster Release & Windows MSVC CI Pipelines**:
  - Switched Windows Release builds from MSBuild (`Visual Studio 17 2022`) to `Ninja` + `ccache` (`2G` cache reusing CI MSVC Release artifacts) and updated single-config packaging paths.
  - Added FetchContent and `ccache` caching to Linux Release builds.
  - Parallelized Windows MSVC CI into separate `Debug` and `Release` matrix jobs with dedicated caches.

## Compatibility

100% compatible with repositories and state created by `v0.19.x`–`v0.27.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`, and `config.toml`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version`, or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.27.1-linux-x86_64.tar.gz` or `kasumi-v0.27.1-windows-x86_64.zip`).
