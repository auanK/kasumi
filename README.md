# Kasumi

[![GitHub Release](https://img.shields.io/github/v/release/auanK/kasumi)](https://github.com/auanK/kasumi/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C.svg)](CMakeLists.txt)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows-informational.svg)](https://github.com/auanK/kasumi/releases)
[![CI Ubuntu](https://github.com/auanK/kasumi/actions/workflows/ci-ubuntu.yml/badge.svg)](https://github.com/auanK/kasumi/actions/workflows/ci-ubuntu.yml)
[![CI Windows](https://github.com/auanK/kasumi/actions/workflows/ci-windows.yml/badge.svg)](https://github.com/auanK/kasumi/actions/workflows/ci-windows.yml)

**Client-side encrypted, multi-master bidirectional file synchronization over local paths, network shares, or [rclone](https://rclone.org/)-compatible shared storage — with no dedicated server.**

Written in C++23 for **Linux and Windows**, Kasumi lets every machine synchronize independently through passive shared storage — no dedicated server, background daemon, or simultaneous online connection required.

```text
Machine A ───┐
             │   XChaCha20-Poly1305 + Zstd + Immutable DAG
Machine B ───┼──────────────────────────────────────────────▶ Shared Storage
             │   (Local path, SMB/NFS share, or rclone remote)
Machine C ───┘
```

> **Project status:** Pre-1.0 (`0.x`). Actively developed and covered by an extensive automated test suite across Linux and Windows, without guaranteed cross-release migration yet — use the same release on all devices and keep independent backups.

---

## How It Compares

| Capability | **Kasumi** | **Syncthing** | **`rclone bisync`** | **`restic` / `borg`** |
|---|---|---|---|---|
| **Primary model** | Multi-master bidirectional sync | Multi-master P2P sync | 2-path bidirectional sync | Snapshot backup & restore |
| **Syncs when devices are offline at different times** | Yes (passive shared storage) | No (peers must be online together) | Yes (rclone remotes) | Yes (passive storage) |
| **Multi-device (`3+` clients) reconciliation** | Yes (immutable Commit DAG) | Yes (P2P sync protocol) | Not designed for it (pairwise state) | N/A (backup snapshots) |
| **Built-in client-side AEAD encryption** | Yes (XChaCha20-Poly1305) | TLS in transit; optional untrusted device | Optional via separate `crypt` remote | Yes |
| **Content-defined chunking & deduplication** | Yes (FastCDC + Micro-Packs) | Block-level delta transfer | No | Yes |
| **Crash-safe transaction recovery** | Yes (encrypted local journal) | Continuous daemon reconciliation | No (`--resync` after interrupted state) | Append-only repo transactions |
| **Background daemon required** | No (on-demand / cron) | Yes | No (on-demand / cron) | No (on-demand / cron) |

*Each tool excels at its own model — Kasumi specifically targets encrypted, on-demand multi-device synchronization over passive storage without a dedicated server.*

---

## Highlights

- **Multi-master sync & conflict tooling**: Independent clients reconcile via an immutable Commit DAG without a central server or global sync lock; conflicting edits are preserved and easily inspected via `kasumi conflicts`, and older retained versions can be queried or restored via `kasumi remote stat/get --commit <id>`.
- **Adaptive encrypted storage**: Combines loose objects, `KPAK\x01` Micro-Packs (`<= 256 KiB`), and FastCDC chunking (`> 8 MiB`) with Zstandard compression, **XChaCha20-Poly1305** AEAD, Argon2id key derivation, and a persistent BLAKE3 hash cache.
- **Flexible key storage (`vault`, `file`, `memory`)**: Persist derived keys in Windows Credential Manager / Linux Secret Service & KWallet, local `key.bin`, or stateless RAM-only derivation.
- **Crash-resilient & auditable**: Encrypted local transaction journals safely recover interrupted runs; built-in `diagnostics`, `sync --repair`, `fsck`, `repack`, `resolve-missing`, and hardened `gc` (6h remote-clock-clamped grace period, `remote_busy` backoff, multi-barrier checks, periodic mid-`Apply` revalidation) keep vaults healthy.
- **Automation-ready CLI**: Non-interactive `kasumi profile ...` lifecycle commands, `kasumi completion <shell>`, live terminal progress, `--json` (`schema_version: 1` with stable `error.code`), `--quiet`, `--log-file <path>` (text or NDJSON), and `--full`.

---

## Quick Start

Create a profile named `work`, preview the plan, and synchronize:

```bash
kasumi config
kasumi status work
kasumi sync work
```

```text
$ kasumi sync work
Synchronizing "work"...
[1/5] Observing local and remote state...
[2/5] Calculating changes...
  3 changes | ↑ 2 (1.42 MiB) | ↓ 1 (312.0 KiB)
[3/5] Applying changes...
[4/5] Publishing new state...
[5/5] Finalizing...
Synchronization completed.
Wire upload 684.5 KiB (2 objects) | wire download 198.2 KiB (1 object) | locally reused 0 B
Duration: 1.842 s
```

On a second machine, run `kasumi config` with the same shared storage and **exact same Password and Password Salt**, then run `kasumi sync work`. See [Getting Started](docs/getting-started.md) for the complete two-machine walkthrough and download verification steps.

---

## Installation

Official x86_64 installers and portable archives (`kasumi-v<version>-...`) are published on [GitHub Releases](https://github.com/auanK/kasumi/releases) with `.sha256` checksums and GitHub build provenance attestations (`gh attestation verify`).

| Platform | Package / Archive | Install |
|---|---|---|
| **Windows (Installer)** | `kasumi-v<version>-windows-x86_64.msi` | Run installer (adds to `PATH`, supports in-place upgrades) |
| **Windows (Portable)** | `kasumi-v<version>-windows-x86_64.zip` | Extract to a folder on `PATH` |
| **Arch Linux** | `kasumi-v<version>-linux-x86_64.pkg.tar.zst` | `sudo pacman -U kasumi-v<version>-linux-x86_64.pkg.tar.zst` ([PKGBUILD](packaging/arch/PKGBUILD)) |
| **Debian / Ubuntu** | `kasumi-v<version>-linux-x86_64.deb` | `sudo apt install ./kasumi-v<version>-linux-x86_64.deb` |
| **Fedora / RHEL** | `kasumi-v<version>-linux-x86_64.rpm` | `sudo dnf install --nogpgcheck ./kasumi-v<version>-linux-x86_64.rpm` |
| **Linux (Portable)** | `kasumi-v<version>-linux-x86_64.tar.gz` | Extract and place `kasumi` on `PATH` |

**Build from source** (CMake 3.28+, Git, Ninja, Python 3, C++23 compiler — see [Build and Test](docs/build-and-test.md)):

```bash
cmake --preset default && cmake --build --preset default
```

---

## Command Overview

| Command | Purpose |
|---|---|
| `kasumi config` | Interactive wizard (with `rclone` remote hints) to manage profiles and key storage |
| `kasumi profile <subcommand>` | Non-interactive profile management (`create`, `edit`, `clone`, `storage`, `rename`, `delete`) |
| `kasumi status <profile>` | Preview synchronization changes read-only (`sync --dry-run`) |
| `kasumi sync <profile> [--repair]` | Synchronize bidirectionally or re-upload missing remote objects |
| `kasumi conflicts <profile>` | Scan local folder read-only and group preserved `.kasumiconflict_*` artifacts |
| `kasumi diagnostics [<profile>]` | Inspect local environment, `rclone >= v1.60.0`, disk space, and profile health |
| `kasumi fsck <profile>` | Download and cryptographically audit every referenced payload |
| `kasumi repack <profile> [--dry-run]` | Consolidate fragmented `KPAK\x01` Micro-Packs locally without remote downloads/deletions |
| `kasumi gc <profile> [--dry-run] [--min-age <hours>]` | Reclaim eligible orphans, expired commits, redundant variants, and old activities |
| `kasumi resolve-missing <profile> [--dry-run \| --confirm]` | Explicitly resolve permanently missing remote content as logical deletions |
| `kasumi remote <subcommand> <profile>` | Read-only inspection (`summary`, `heads`, `tree`, `stat`/`get [--commit]`, `writers`, `health`, ...) |
| `kasumi completion <shell>` | Output shell completion script (`bash`, `zsh`, `fish`, `powershell`) |

Run `kasumi --help` or `kasumi <command> --help` for full syntax and options.

---

## Documentation

- [Getting Started](docs/getting-started.md) — download verification, first profile, and two-machine setup.
- [Configuration and Usage](docs/configuration-and-usage.md) — complete CLI reference, `--json`/`--log-file`, `.kasumiignore`, and exit codes.
- [Best Practices](docs/best-practices.md) — scheduling, backups, upgrades, and maintenance cadence.
- [Troubleshooting](docs/troubleshooting.md) — diagnosis and safe recovery procedures.
- [Security](docs/security.md) — threat model, cryptography, and local key storage trade-offs.
- [Architecture](docs/architecture.md) — system map, protocols, and component invariants.
- [Build and Test](docs/build-and-test.md) — source builds, formatting, sanitizers, and test suites.
- [Changelog](CHANGELOG.md) & [Release Notes](RELEASE_NOTES.md) — version history and upgrade notes.

> [!IMPORTANT]
> - **Protect your credentials:** If all copies of the key and Password/Password Salt are lost, the vault cannot be recovered. Use full-disk encryption on sensitive devices ([Security](docs/security.md)).
> - **Sync is not a backup:** Synchronization propagates deletions; keep independent backups. Exit code `2` indicates **partial synchronization** with pending materializations ([Exit Codes](docs/configuration-and-usage.md#exit-codes)).

---

## Contributing & Security

Bug reports and pull requests are welcome on [GitHub Issues](https://github.com/auanK/kasumi/issues); see [Build and Test](docs/build-and-test.md) for local setup and formatting checks. To report a security vulnerability privately, follow [SECURITY.md](SECURITY.md).

## License

Kasumi is released under the [MIT License](LICENSE). Third-party components retain their respective licenses; see [Third-Party Notices](THIRD_PARTY_NOTICES.md).
