# Kasumi

[![GitHub Release](https://img.shields.io/github/v/release/auanK/kasumi)](https://github.com/auanK/kasumi/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-00599C.svg)](CMakeLists.txt)
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows-informational.svg)](https://github.com/auanK/kasumi/releases)
[![CI Ubuntu](https://github.com/auanK/kasumi/actions/workflows/ci-ubuntu.yml/badge.svg)](https://github.com/auanK/kasumi/actions/workflows/ci-ubuntu.yml)
[![CI Windows](https://github.com/auanK/kasumi/actions/workflows/ci-windows.yml/badge.svg)](https://github.com/auanK/kasumi/actions/workflows/ci-windows.yml)

**Client-side encrypted, multi-master bidirectional file synchronization over local paths, network shares, or [rclone](https://rclone.org/)-compatible shared storage — with no dedicated server.**

Written in C++23 for **Linux and Windows**, Kasumi lets every machine synchronize independently through passive shared storage — with no dedicated server or simultaneous online connection required, either on demand from the CLI or continuously via its built-in background daemon.

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
| **Syncs when devices are offline at different times** | Yes (passive shared storage) | No (requires an online peer / always-on node) | Yes (rclone remotes) | Yes (passive storage) |
| **Multi-device (`3+` clients) reconciliation** | Yes (immutable Commit DAG) | Yes (P2P sync protocol) | Not designed for it (pairwise state) | N/A (backup snapshots) |
| **Built-in client-side AEAD encryption** | Yes (XChaCha20-Poly1305) | TLS in transit; optional untrusted device | Optional via separate `crypt` remote | Yes |
| **Content-defined chunking & deduplication** | Yes (FastCDC + Micro-Packs) | Block-level delta transfer | No | Yes |
| **Crash-safe transaction recovery** | Yes (encrypted local journal) | Continuous daemon reconciliation | No (`--resync` after interrupted state) | Append-only repo transactions |
| **Execution mode** | Optional (real-time daemon or on-demand CLI) | Required (continuous daemon) | On-demand / external scheduler | On-demand / external scheduler |

*Each tool excels at its own model — Kasumi specifically targets encrypted multi-device synchronization over passive storage without a dedicated server, either on demand or via its built-in real-time daemon.*

---

## Highlights

- **Multi-master sync & conflict tooling**: Independent clients reconcile via an immutable Commit DAG without a central server or global sync lock; conflicting edits are preserved, listed via `kasumi conflicts`, and resolved in-place via `kasumi conflicts resolve`, while older retained versions can be queried with `kasumi remote log` and restored individually or in bulk via `kasumi remote get/restore --commit <id>`.
- **Adaptive encrypted storage**: Combines loose objects, `KPAK\x01` Micro-Packs (`<= 256 KiB`), and FastCDC chunking (`> 8 MiB`) with Zstandard compression, **XChaCha20-Poly1305** AEAD, Argon2id key derivation, and a persistent BLAKE3 hash cache.
- **Flexible key storage (`vault`, `file`, `memory`)**: Persist derived keys in Windows Credential Manager / Linux Secret Service & KWallet, local `key.bin`, or stateless RAM-only derivation (kept pinned in non-swappable OS memory pages while unlocked in `kasumi daemon`).
- **Continuous multi-profile daemon (`kasumi daemon`)**: Native file watchers (`ReadDirectoryChangesW` / `inotify`) with debounce and self-mutation suppression, warm `rclone` transport sessions, staggered startup and per-remote concurrency limits, zero-walk remote fast polling, user-session autostart, and authenticated loopback IPC.
- **Crash-resilient & auditable**: Encrypted local transaction journals safely recover interrupted runs; built-in `diagnostics`, `sync --repair`, `fsck`, `repack`, `resolve-missing`, and hardened `gc` (6h remote-clock-clamped grace period, `remote_busy` backoff, multi-barrier checks, periodic mid-`Apply` revalidation) keep vaults healthy.
- **Automation-ready CLI**: Non-interactive `kasumi profile ...` lifecycle commands, `kasumi daemon ...` service controls, `kasumi completion <shell>`, live terminal progress, `--json` (`schema_version: 1` with stable `error.code`), `--quiet`, `--log-file <path>` (text or NDJSON), and `--full`.

---

## Quick Start

1. **Set up your shared storage remote** — for cloud storage (Google Drive, OneDrive, S3, Dropbox, SFTP, etc.), configure a remote in `rclone` first (skip this step if syncing over a local folder or mounted SMB/NFS share):

```bash
rclone config            # create a remote (e.g. named "gdrive")
rclone listremotes       # confirm it is listed (e.g. gdrive:)
```

2. **Create your first profile** linking a local folder to that remote:

```bash
kasumi config
# Choose [n] New -> name: work
# Local path:  ~/Work (or D:/Work)
# Remote path: gdrive:kasumi/work (or a local/SMB path like /mnt/share/kasumi/work)
# Then set your Password and Password Salt
```

3. **Run your first sync** to initialize the encrypted vault on the remote and verify everything works:

```bash
kasumi sync work
```

4. *(Optional)* **Enable continuous real-time sync** in the background and inspect status or live logs at any time:

```bash
kasumi start --autostart
kasumi
kasumi logs -f
```

```text
$ kasumi
Daemon: running (autostart on)

work [Ready]
  Last sync:   2026-04-15 14:20 +00:00 (no changes)
  Last change: 2026-04-15 13:55 +00:00 by desktop-1

Run 'kasumi --full' for detailed daemon metrics and paths.
```

On a second machine, run `kasumi config` with the same shared storage and **exact same Password and Password Salt**, run `kasumi sync work`, and optionally enable the background daemon with `kasumi start --autostart`. See [Getting Started](docs/getting-started.md) for the complete two-machine walkthrough and download verification steps.

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

**Build from source** (CMake 3.28+, Git, Ninja, Python 3, C++23 compiler, plus Node.js 22+ to embed the Web UI — see [Build and Test](docs/build-and-test.md)):

```bash
cd web && npm ci && npm run build && cd ..
cmake --preset default && cmake --build --preset default
```

---

## Command Overview

| Command | Purpose |
|---|---|
| `kasumi [--full]` | Show unified local overview of daemon, profiles, last sync, and problems (`--full` expands details) |
| `kasumi start [--autostart]` | Start the background daemon in one command (optionally install login autostart) |
| `kasumi stop` | Stop the background daemon |
| `kasumi logs [<profile>] [-f]` | Show recent daemon logs (or stream live updates with `-f` / `--follow`) |
| `kasumi pause <profile \| --all>` | Pause automatic daemon sync for one profile or all profiles |
| `kasumi resume <profile \| --all>` | Resume automatic daemon sync for one profile or all profiles |
| `kasumi sync <profile> [--repair]` | Run manual bidirectional sync (or re-upload missing remote objects) |
| `kasumi status <profile>` | Preview synchronization changes against remote storage read-only |
| `kasumi show <profile> [--full]` | Inspect profile settings, last complete sync, and recent history (`--full` expands details) |
| `kasumi config` | Interactive profile wizard (`rclone` remote hints, paths, keys, and sync schedule) |
| `kasumi web [--no-open]` | Open the embedded Web UI (or `kasumi web set-password` to set the login password) |
| `kasumi conflicts <profile>` | Scan local folder read-only or `resolve <profile> <path>` preserved conflicts |
| `kasumi diagnostics [<profile>]` | Inspect local environment, `rclone >= v1.60.0`, disk space, and profile health |
| `kasumi remote <subcommand> <profile>` | Read-only inspection & restore (`summary`, `heads`, `tree`, `log`, `stat`/`get`/`restore`, `writers`) |

Advanced maintenance & scripting commands (`profile`, `daemon`, `key`, `ignore`, `fsck`, `repack`, `gc`, `resolve-missing`, `completion`) are documented in `kasumi help --all` (or `kasumi --help --all`) and [Configuration and Usage](docs/configuration-and-usage.md).

Run `kasumi help`, `kasumi help --all`, `kasumi help <command>` (or `--help`), and `kasumi version` (or `--version`) for syntax, options, and version info.

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
