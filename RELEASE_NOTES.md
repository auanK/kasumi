# Kasumi v0.7.0

## Overview

Kasumi is multi-client bidirectional file synchronization with client-side encryption
over local or rclone-compatible shared storage, without a dedicated server.
This release unifies local file observation and strengthens checks before
overwriting, deleting, or moving local content.

## Highlights

- One scanner on both platforms, using native file identities and persistent
  SQLite fingerprints to reuse unchanged files' BLAKE3 hashes between syncs.
- Independent content verification before destructive local operations, with
  safe replanning or an error when the observed target has changed.
- Windows timestamp and metadata fixes, plus broader cross-platform regression
  coverage and verified MSYS2 UCRT64 toolchain selection.
- A concise project overview and a dedicated [Getting Started](https://github.com/auanK/kasumi/blob/v0.7.0/docs/getting-started.md) tutorial.

## Important Changes

Every observation still walks the local tree and checks metadata. Hash reuse
reduces content reads; it does not eliminate enumeration or remote history work.
`status` and `sync --dry-run` use full hashing. Unsupported native file identity
forces hashing instead of cache reuse.

NTFS USN Change Journal observation has been removed. Kasumi's encrypted
**transaction journal** remains responsible for interrupted-operation recovery.
The release workflow classifies `v0.7.0` as stable; tags containing `-` are prereleases.

## Upgrade Notes

Kasumi is pre-1.0. No compatibility, migration, downgrade, or cross-version
client synchronization is guaranteed between 0.x releases. A newer release may
require a new profile, configuration, or remote namespace. Reconstruct state
only from files and credentials preserved independently; do not treat the
synchronized vault as a backup.

The binary updater replaces only the executable and does not migrate profile,
database, journal, credential, or remote data. Before changing versions, finish
pending recovery where the current executable supports it and preserve the old
profile, configuration, credentials, local files, and remote data independently.
Do not delete incompatible state or assume that downgrading will work. See the
[pre-1.0 precautions](https://github.com/auanK/kasumi/blob/v0.7.0/docs/best-practices.md#upgrading-kasumi).

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

The [release workflow](https://github.com/auanK/kasumi/blob/v0.7.0/.github/workflows/release.yml) also publishes each archive's
individual `.sha256` file and generates GitHub build provenance attestations for
both archives and `SHA256SUMS.txt`. Follow
[download verification](https://github.com/auanK/kasumi/blob/v0.7.0/docs/getting-started.md#verify-downloads) before extracting.

See the [v0.7.0 changelog](https://github.com/auanK/kasumi/blob/v0.7.0/CHANGELOG.md#070) for the full change summary.
