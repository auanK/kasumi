# Kasumi v0.29.1

## Fixed

- **Linux Boot `kwalletd6` / `kwalletd5` Coredump Prevention**: Guarded D-Bus activation of `org.kde.kwalletd6`, `org.kde.kwalletd5`, and `org.kde.ksecretd` in `src/runtime/vault.cpp` so `kasumi-daemon` does not trigger D-Bus activation of Qt GUI wallet daemons before a graphical session exports `WAYLAND_DISPLAY`, `DISPLAY`, or `QT_QPA_PLATFORM`. Already-running wallet daemons are still discovered immediately via D-Bus `NameHasOwner`, allowing automatic unlock recovery once the desktop session starts `kwalletd` cleanly.

## Compatibility

100% compatible with repositories, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.29.0` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the archive or package for your platform, extract it, verify the binary with `kasumi --version` (or `kasumi version`), or validate the release checksums via `SHA256SUMS.txt` (for example `kasumi-v0.29.1-linux-x86_64.tar.gz` or `kasumi-v0.29.1-windows-x86_64.zip`).
