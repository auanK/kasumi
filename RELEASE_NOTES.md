# Kasumi v0.22.0

This release introduces native OS installers and package formats alongside the portable archives, making installation, system `PATH` setup, and in-place upgrades automatic across Windows, Arch Linux, Debian/Ubuntu, and Fedora/RHEL.

## Highlights

- **Windows installer (`kasumi-windows-x86_64.msi`).** Installs into `C:\Program Files\Kasumi`, adds the directory to the system `PATH`, and performs automatic in-place upgrades (`MajorUpgrade`) without duplicating `PATH` entries or touching existing `%APPDATA%\kasumi` profiles.
- **Arch Linux package (`kasumi-linux-x86_64.pkg.tar.zst` + `PKGBUILD`).** Install or upgrade directly with `sudo pacman -U kasumi-linux-x86_64.pkg.tar.zst` (or build locally with `makepkg -si` from [packaging/arch/PKGBUILD](https://github.com/auanK/kasumi/blob/v0.22.0/packaging/arch/PKGBUILD)).
- **Debian/Ubuntu (`.deb`) and Fedora/RHEL (`.rpm`).** Install or upgrade with `sudo apt install ./kasumi-linux-x86_64.deb` or `sudo dnf install --nogpgcheck ./kasumi-linux-x86_64.rpm`.
- **Verified release pipeline.** Every installer and portable archive ships with matching `.sha256` sidecars, a consolidated `SHA256SUMS.txt`, and GitHub build provenance attestations (`gh attestation verify`).

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x`–`v0.21.2` vaults and local databases. Existing profiles and configurations are preserved on upgrade. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.22.0/docs/best-practices.md#upgrading-kasumi).
- Portable archives (`kasumi-windows-x86_64.zip` and `kasumi-linux-x86_64.tar.gz`) remain available alongside the native installers. Verify downloads with `sha256sum` / `Get-FileHash` and `gh attestation verify` before installing.
