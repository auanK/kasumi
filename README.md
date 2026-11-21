# Kasumi

Kasumi is multi-client bidirectional file synchronization with client-side encryption
over local or rclone-compatible shared storage, without a dedicated server.

Written in C++23 for **Linux and Windows**, it works with local filesystems,
network shares, and configured rclone remotes. Each machine synchronizes
independently; no dedicated Kasumi server or simultaneous connection is required.

```text
Machine A ───┐
             │
Machine B ───┼──> Shared Storage
             │
Machine C ───┘
```

Interactive runs show live progress on one terminal line. Sync reports physical transfer bytes and object counts alongside its logical plan summary.

## Features

- **Bidirectional, multi-client sync** across independently operated machines.
- **Client-side encryption, authentication, and in-memory Zstandard compression** for file contents, Micro-Packs, chunks, and history.
- **Adaptive storage layout** combining loose objects, `KPAK\x01` Micro-Packs for small files (`<= 256 KiB`), and FastCDC content-defined chunking (`> 8 MiB`) with block-level delta uploads and downloads.
- **Configurable key storage (`vault`, `file`, `memory`)** supporting OS credential vaults (Windows Credential Manager, Linux Secret Service / KWallet), local `key.bin`, or stateless in-memory key derivation.
- **Shared storage** through local paths, network shares, or rclone remotes.
- **Immutable history and conflict handling** with `KCOM` v4 commit authorship (`origin`, persistent installation identity, and machine name) that preserve divergent file versions.
- **Offline and shared operational traceability** recording local execution outcomes and accepted commit provenance in `db.sqlite`, plus immutable `KACT` v1 maintenance records (`fsck`, `gc`, writer/barrier removal) inspectable via `show [--full]`, `config`, `remote heads`/`commits`, and `remote summary [--full]` with zero extra remote requests during `sync`.
- **Interrupted-operation recovery** through an authenticated transaction journal.
- **Persistent BLAKE3 hash cache** shared by sync and read-only plan observation.
- **Integrity and maintenance tools** to audit referenced content, packs, and chunks (`fsck`), consolidate fragmented Micro-Packs locally without remote downloads or deletions (`repack`), and directly remove authenticated orphan physical objects and redundant CommitVariants (`gc`).

## Quick Start

Create a profile named `work`, preview its changes, then synchronize:

```bash
kasumi config
kasumi status work
kasumi sync work
```

The wizard asks for the local folder, shared storage destination, key storage mode (`vault` by default, `file`, or `memory`), Password, and
Password Salt. Configure the next machine with the same storage and exactly the
same two credentials. Follow [Getting Started](docs/getting-started.md) for the
complete setup, download verification, and first synchronization on two machines.

Keep a secure record of your credentials and local key. Depending on the profile's `key_storage` setting, the derived master key is stored in the OS credential vault (`vault`), in `key.bin` with reversible masking and filesystem permissions (`file`), or derived on demand in RAM without persistence (`memory`); protect sensitive devices with disk encryption.
See [Security](docs/security.md) for the protection limits and key-loss risks.

## Download and Documentation

Official x86_64 binaries: [GitHub Releases](https://github.com/auanK/kasumi/releases).
For source builds, see [Build and Test](docs/build-and-test.md).

- [Getting Started](docs/getting-started.md) — first profile and two-machine setup.
- [Configuration and Usage](docs/configuration-and-usage.md) — commands, options, and exit codes.
- [Best Practices](docs/best-practices.md) — synchronization, backups, and maintenance.
- [Troubleshooting](docs/troubleshooting.md) — diagnosis and safe recovery procedures.
- [Security](docs/security.md) — threats, cryptography, and local key protection.
- [Architecture](docs/architecture.md) — components and their responsibilities.
- [Changelog](CHANGELOG.md) and [Release Notes](RELEASE_NOTES.md) — changes and upgrade requirements.

Use the same release on all clients; read the
[upgrade precautions](docs/best-practices.md#upgrading-kasumi) before replacing binaries.
Synchronization propagates deletions; keep independent backups. A sync that exits
with code `2` is only partially complete; see
[Exit Codes](docs/configuration-and-usage.md#exit-codes).

## License

Kasumi is released under the [MIT License](LICENSE). Third-party components retain
their respective licenses; see [Third-Party Notices](THIRD_PARTY_NOTICES.md).
