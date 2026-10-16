# Kasumi v0.7.0

## Overview

Kasumi synchronizes files bidirectionally between independent Windows and Linux
clients through local or rclone-compatible shared storage. File contents and
history are encrypted and authenticated on the client; no dedicated Kasumi
server or simultaneous client connection is required.

Version 0.7.0 consolidates local observation, transaction durability, recovery,
and concurrent-history handling. Real Google Drive validation exercised two
clients, exposed a sibling-head observation defect, and verified convergence
after its correction. Operational validation, hosted CI, and publication are
separate gates; this document prepares the release.

## Highlights

- Authenticated multi-head history and deterministic conflict preservation,
  including corrected ancestry validation for cached history anchors.
- Incremental authenticated transaction journal with confirmed replay and
  restart-safe retirement, plus verified staging and rollback backups.
- One scanner on Windows and Linux, with persistent BLAKE3 hash reuse in Sync,
  Preview, and Status and independent content checks before destructive effects.
- Windows timestamp, file-identity, path-length diagnostics, and manifest fixes,
  with regression coverage across five toolchains.
- Simplified Windows binary update permissions: removed fragile internal UAC
  elevation handoff; non-elevated runs fail fast instructing to run as administrator.

## Synchronization and Concurrency

Clients can publish immutable sibling Commits and separate HEAD markers
concurrently. Multiple HEADs are normal input to reconciliation; a later Sync
combines independent edits, preserves conflicting variants, and can publish a
multi-parent merge. An ambiguous best common ancestor stops resolution rather
than selecting an arbitrary branch. Ordinary writers do not take a global lock.

Scoped history observation now proves that all loaded branches link to the
accepted `cached_anchor` before using it as a frontier. A sibling publication
may descend from its parent instead, invalidating that shortcut. Loading then
retries without the cached anchor to recover the required common ancestry.

Sync reobserves local and remote inputs before effects and validates the
materialized publication tree afterward. Commit bytes are verified before HEAD
publication; accepted SQLite state advances after the required remote checks.
Transport uncertainty and contradictory publication evidence remain explicit
recovery errors.

## Data Integrity and Recovery

The private `transaction.bin.enc/` directory contains an encrypted snapshot,
chained encrypted deltas, authenticated confirmation of the durable log prefix,
and an authenticated retirement proof during cleanup. An in-memory Session
accelerates verified checkpoints; persisted confirmed bytes remain authority.
Unconfirmed tails do not govern replay. Missing confirmed bytes, invalid
authentication, incompatible formats, or missing required backups stop recovery
and preserve evidence.

Local downloads authenticate/decrypt content and verify BLAKE3 and size before
installation. Destructive targets receive independent content checks; rollback
uses verified backups. Sync, Fsck, ordinary GC, and `resolve-missing` evaluate
pending Sync recovery before their own work. Preview, Status, and remote
inspection do not run that recovery path. A partial Sync still exits with code
`2` when accepted files remain pending materialization.

## Local Observation and Performance

Every observation enumerates the managed tree and reads native metadata. SQLite
persists BLAKE3 hashes with path, type, size, nanosecond mtime, and complete native
identity: Windows volume/full file ID or Linux device/inode. Matching fingerprints
allow hash reuse without a time-based expiry. Cache misses, changed files, or
insufficient identity require content hashing; an effective ignore projection
differing from local rules uses full hashing.

`status` and `sync --dry-run` reuse eligible fingerprints **read-only** and never
save cache deltas or advance accepted state. Sync persists cache updates at
successful finalization and separately verifies destructive targets. A warm cache
does not skip enumeration or remote observation. Ignore matching and journal
preparation/checkpoint work were also optimized; no universal speedup is promised.

The Windows NTFS USN scanner was removed. It is unrelated to the authenticated
transaction journal, which remains responsible for interrupted-operation recovery.

## Windows and Linux Improvements

Native timestamp conversion, Windows 100-nanosecond timestamp equivalence,
physical identity handling, timestamp-preserving backups, and local mutation
recovery received portability fixes. Windows binaries and tests embed a
`longPathAware` manifest. Long Win32 paths also require the host's
`LongPathsEnabled` policy; internal staging paths can exceed the source path's
length. Shorter profile roots remain useful on hosts enforcing legacy limits.

Regression coverage includes observation, cache persistence, local mutation,
journal confirmation/retirement, interruption recovery, and concurrent heads.
CI configures Debug and Release on MSVC 2022, MSYS2 UCRT64 GCC, MSYS2 Clang64,
Ubuntu GCC 14, and Ubuntu Clang 19. Results belong to their exact commit.

## Breaking Changes and Upgrade Precautions

**Kasumi provides no backward compatibility between 0.x releases.** There is no
automatic migration of old SQLite, journals, configuration, credentials, or remote
formats; clients on different releases have no interoperability contract and
downgrade is not a supported recovery procedure. Obsolete fixed-layout and
custody-recovery paths were removed; unsupported artifacts remain preserved.

The updater replaces only the executable. Before changing versions, finish
pending recovery with the compatible executable and independently preserve the
old executable, complete profile, credentials, local files, and remote data.
Do not delete `db.sqlite`, accepted history, journals, or backups to force a new
initialization. A new profile or namespace may be necessary; this is not an
in-place migration procedure.

## Validation

Real Google Drive/rclone testing used Windows 11 and Ubuntu WSL2/ext4 with two
independent profiles. It covered bidirectional create/update/rename/delete,
Unicode, initial 1/10/100 MiB transfers, a 100 MiB update, conflicts, simultaneous
publication, abrupt process exits, transport/connectivity failure and subsequent
recovery, remote inspection, Fsck, and a 100-file workload. The interrupted
large-file case used **10 MiB**. Cross-client BLAKE3 and SHA-256 matched after
convergence.

GC refused observed abandoned writers. After operational checks and removal of
six writer markers, it completed with **zero candidates and zero purged objects**;
subsequent Fsck passed. Quarantine stayed empty, so these runs do not demonstrate
eligible-object purge, quarantine restoration, or corruption repair.

The campaign began at `913317f`; post-fix local binaries exercised the ancestry
correction later committed in `e1a0ce3`. They are distinct source states. Hosted
Ubuntu and Windows CI passed for that corrected SHA, including Debug/Release
builds and tests on all five toolchains, as checked on 2026-10-16.
See [Provider Certification](https://github.com/auanK/kasumi/blob/refactor/durability-recovery-070/docs/provider-certification.md) for source
identities, CI links, audit scope, and historical backend evidence. No RC, tag,
or release publication is asserted here.

## Known Limitations and Security

- Kasumi supplies no atomic filesystem snapshot. Final validation and the
  following syscall are separate; an external writer racing that interval can
  still lose an edit, including during rollback. Metadata-preserving edits can
  evade hash-cache reuse checks.
- Journal and SQLite durability depend on OS, filesystem, and hardware behavior.
  SQLite uses WAL with `synchronous=NORMAL`; the latest committed state can roll
  back on power loss. Process-kill tests do not simulate that failure; restoring
  a complete older valid local authority bundle is outside journal detection.
- Provider consistency and availability remain external dependencies. Historical
  eleven-backend validation is not a fresh certification of every backend on
  this build. A visibility probe cannot certify provider-wide LIST/PRESENCE.
- Stop Sync on every client and serialize GC, purge, repair, and writer-marker
  maintenance. The cooperative barrier is not distributed exclusion. Retention
  and GC can permanently remove the last vault copy; keep independent backups.
- **`key.bin` is not password-encrypted.** It uses reversible XOR masking and
  filesystem permissions. Same-user processes can read it; disk encryption and
  protection of the local account remain necessary for sensitive devices.

See [Security](https://github.com/auanK/kasumi/blob/refactor/durability-recovery-070/docs/security.md) and [Best Practices](https://github.com/auanK/kasumi/blob/refactor/durability-recovery-070/docs/best-practices.md) for
the complete operating boundaries and upgrade precautions.

## Downloads

When published through the [release workflow](https://github.com/auanK/kasumi/blob/refactor/durability-recovery-070/.github/workflows/release.yml),
the [GitHub Releases page](https://github.com/auanK/kasumi/releases) provides:

- `kasumi-linux-x86_64.tar.gz` and `kasumi-linux-x86_64.tar.gz.sha256`
- `kasumi-windows-x86_64.zip` and `kasumi-windows-x86_64.zip.sha256`
- `SHA256SUMS.txt`

Both archives contain the executable, `LICENSE`, and `THIRD_PARTY_NOTICES.md`.
The workflow generates GitHub build provenance attestations for both archives
and `SHA256SUMS.txt`; this does not imply executable code signing. Follow
[download verification](https://github.com/auanK/kasumi/blob/refactor/durability-recovery-070/docs/getting-started.md#verify-downloads) before extraction
or execution. See the [changelog](https://github.com/auanK/kasumi/blob/refactor/durability-recovery-070/CHANGELOG.md#070) for the complete change list.
