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

## Features

- **Bidirectional, multi-client sync** across independently operated machines.
- **Client-side encryption and authentication** for file contents and history.
- **Shared storage** through local paths, network shares, or rclone remotes.
- **Immutable history and conflict handling** that preserve divergent file versions.
- **Interrupted-operation recovery** through an authenticated transaction journal.
- **Persistent BLAKE3 hash cache** shared by sync and read-only plan observation.
- **Integrity and maintenance tools** to audit referenced content and directly remove authenticated orphan Content and redundant CommitVariants.

## Quick Start

Create a profile named `work`, preview its changes, then synchronize:

```bash
kasumi config
kasumi status work
kasumi sync work
```

The wizard asks for the local folder, shared storage destination, Password, and
Password Salt. Configure the next machine with the same storage and exactly the
same two credentials. Follow [Getting Started](docs/getting-started.md) for the
complete setup, download verification, and first synchronization on two machines.

Keep a secure record of your credentials and local key. `key.bin` uses reversible
masking and filesystem permissions; protect sensitive devices with disk encryption.
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
- [Provider Certification](docs/provider-certification.md) — provider requirements and certification procedure.
- [Changelog](CHANGELOG.md) and [Release Notes](RELEASE_NOTES.md) — changes and upgrade requirements.

Use the same release on all clients; read the
[upgrade precautions](docs/best-practices.md#upgrading-kasumi) before replacing binaries.
Synchronization propagates deletions; keep independent backups. A sync that exits
with code `2` is only partially complete; see
[Exit Codes](docs/configuration-and-usage.md#exit-codes).

## License

Kasumi is released under the [MIT License](LICENSE). Third-party components retain
their respective licenses; see [Third-Party Notices](THIRD_PARTY_NOTICES.md).
