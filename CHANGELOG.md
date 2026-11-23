# Changelog

## [0.25.0]

### Added

- **Historical Inspection & Recovery**:
  - `kasumi remote log <profile> <path> [--full]` to inspect per-file commit history on the encrypted remote repository.
  - `--commit <id>` support on `kasumi remote stat` and `kasumi remote get` to inspect metadata or extract encrypted files at a specific historical commit.
  - `kasumi remote restore <profile> [<prefix>] <dst> [--commit <id>] [--dry-run]` to restore a subtree or full repository state locally without altering the active remote state.
- **Conflict Discovery & Atomic Resolution**:
  - `kasumi conflicts <profile>` to list active conflict artifacts on a profile.
  - `kasumi conflicts resolve <profile> <path> (--keep-canonical | --keep <artifact>) [--dry-run]` to atomically resolve conflicts by keeping either the canonical file or a chosen conflict artifact.
- **Non-Interactive Profile Management & Onboarding**:
  - `kasumi profile <create|edit|clone|storage|rename|delete>` for scriptable, non-interactive profile and storage configuration.
  - `rclone listremotes` discovery hints and warnings in `kasumi config`.
- **Shell Completions & Automation Output**:
  - `kasumi completion <bash|zsh|fish|powershell>` for shell autocompletion.
  - Expanded `--json` structured output across `profile`, `conflicts`, `conflicts resolve`, and `remote stat|get|log|restore`, alongside `--quiet` and `--log-file` support.

### Fixed

- Fixed concurrent Linux OS vault access in `src/runtime/vault.cpp` by rechecking KDE Wallet folder creation (`hasFolder` after `createFolder`) and entry deletion (`hasEntry` after `removeEntry`) across concurrent processes, and serializing intra-process D-Bus / `libsecret` vault calls.
- Fixed `run_rclone_readonly_cli` EOF handling in `src/transport/rclone/session.cpp` by checking `read_err` before converting `reproc_read` counts to `size_t` and clamping buffer appends.
- Fixed a dangling `std::string_view` lifetime issue in `src/cli/presenter.cpp`.

### Documentation

- Updated `README.md`, `docs/getting-started.md`, `docs/configuration-and-usage.md`, `docs/best-practices.md`, `docs/troubleshooting.md`, `docs/architecture.md`, and `docs/architecture/*.md` for historical inspection, restore workflows, conflict resolution, non-interactive profile commands, and shell completions.

### Upgrade Notes

- 100% compatible with existing `v0.19.x`–`v0.24.0` encrypted repositories and local state (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`, and `config.toml`).

## [0.24.0]

### Added

- Add multi-barrier GC control layout (`<history-ns>/<gc-ns>/<version-ns>/<barriers-ns>/<32-hex-token>`) with a post-publish settle window (`2000 ms` in CLI runs), exclusivity verification, and full backward read/removal compatibility with legacy `v0.23.x` single barriers (`<barrier-id>`).
- Add fail-closed remote-clock grace clamping (`effective_now = min(local_now, remote_now)`) for GC `--min-age > 0` using the newly published barrier's remote `ModTime`, protecting recent uploads from local clock skew while retaining the default `6`-hour / `5`-commit retention policy.
- Add periodic mid-`Apply` exclusivity revalidation during GC (every `16` batches / `128` objects or `30s`) checking writers, competing barriers, legacy barriers, and own barrier integrity, stopping unstarted batches cleanly with `NotAttempted` while preserving `confirmed_removed`.
- Add diagnostic-only metadata (`started_at`, `pid`, `machine`) inside writer and barrier marker payloads (never auto-expired by time), surfaced in `kasumi remote writers <profile>` (text and `--json`).
- Add optional `[<barrier-id>]` target selection (full identifier or 32-hex token) to `kasumi gc remove-barrier <profile> [<barrier-id>] --confirm-abandoned` with remaining-barriers reporting, and enable `--json` output for both `remote writers` and `gc remove-barrier`.

### Documentation

- Redesign [README.md](README.md) with release/CI badges, pre-1.0 status notice, tool comparison matrix, CLI output preview, installation table, and command overview.
- Update [garbage-collection.md](docs/architecture/garbage-collection.md), [remote-layout.md](docs/architecture/remote-layout.md), [remote-maintenance-inspection.md](docs/architecture/remote-maintenance-inspection.md), [remote-storage-and-maintenance.md](docs/architecture/remote-storage-and-maintenance.md), [configuration-and-usage.md](docs/configuration-and-usage.md), [troubleshooting.md](docs/troubleshooting.md), [best-practices.md](docs/best-practices.md), [security.md](docs/security.md), [build-and-test.md](docs/build-and-test.md), and architecture docs to cover `v0.24.0` GC concurrency hardening, `--json` commands, and Linux Clang `lld` / `run_with_linux_vault.py` workflows.

### Upgrade Notes

- Protocol and local storage formats remain unchanged (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`), staying 100% compatible with `v0.19.x`–`v0.23.1`. No re-sync is required; existing `v0.23.x` legacy barriers remain recognized and removable.

## [0.23.1]

### Added

- Use versioned release package filenames (`kasumi-v0.23.1-windows-x86_64.{msi,zip}` and `kasumi-v0.23.1-linux-x86_64.{pkg.tar.zst,deb,rpm,tar.gz}`) while keeping internal executable names simple (`kasumi` / `kasumi.exe`).
- Make all native installers upgrade-aware with visible version reporting:
  - **Windows `.msi`**: display target version (`v0.23.1`) on setup dialogs, detect existing installations across patch/minor/major updates (`WIX_UPGRADE_DETECTED` + `InstalledVersion` registry tracking), preserve profiles/configuration, and skip re-prompting for license/directory on updates.
  - **Arch Linux `.pkg.tar.zst` / `PKGBUILD`**, **Debian/Ubuntu `.deb`**, and **Fedora/RHEL `.rpm`**: include `.INSTALL` / `postinst` / `post.sh` lifecycle hooks reporting clean installs vs in-place version upgrades with preserved profiles.
- Add `KASUMI_FETCHCONTENT_CACHE_DIR` in [CMakeLists.txt](CMakeLists.txt) to reuse downloaded third-party dependency sources across Debug/Release builds without sharing build directories.

### Fixed

- Guard `-fstack-clash-protection` in [CMakeLists.txt](CMakeLists.txt) so Clang builds on Windows no longer emit unused compiler argument warnings, and fix remaining `-Wsign-conversion` warnings in `durability.cpp`, `local/storage.cpp`, `test_private_storage.cpp`, and `test_soak_and_benchmark.cpp`.
- Upgrade GitHub Actions workflows ([ci-ubuntu.yml](.github/workflows/ci-ubuntu.yml), [ci-windows.yml](.github/workflows/ci-windows.yml), [release.yml](.github/workflows/release.yml)) to Node 24-compatible action versions (`actions/checkout@v7`, `actions/cache@v6`, `actions/upload-artifact@v7`, `actions/download-artifact@v8`, `softprops/action-gh-release@v3`).
- Accelerate and harden CI builds and tests with a prebuilt non-root GHCR Ubuntu image ([ci-ubuntu.Dockerfile](.github/docker/ci-ubuntu.Dockerfile), [ci-image.yml](.github/workflows/ci-image.yml)), `MSVC` `Ninja`+`ccache` (`/Z7`), `/MP` for Visual Studio generators, non-LTO test binaries, `lld`, `FetchContent` source caching, workflow `concurrency`, resilient Ubuntu APT mirror retries, and parallel `ctest`.

### Documentation

- Update [README.md](README.md), [getting-started.md](docs/getting-started.md), [configuration-and-usage.md](docs/configuration-and-usage.md), and package metadata to document versioned package names, upgrade-aware installers, `multi-device` (`multi-master`) sync terminology, and exclusive `gc` barrier behavior.

### Upgrade Notes

- Protocol and local storage formats remain unchanged (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`), staying 100% compatible with `v0.19.x`–`v0.23.0`.

## [0.23.0]

### Added

- Add safe, automatable garbage collection with a default fail-closed grace period (`--min-age <hours>`, `0..8760`, defaulting to the profile's `min_history_age_hours` = 6h) that defers freshly uploaded orphan blobs and unreachable commits while enforcing a floor on `KACT` activity retention, plus dual-clock (`ModTime` + authenticated `created_at`) pruning of expired commits behind Epoch boundaries.
- Add single-pass `transport::list_metadata` across local storage and `rclone` (`operations/list` with `noModTime: false` and `FastList: true`) for object sizes and RFC3339 timestamps, batched Epoch and HEAD marker prefetch during history reachability, pre-barrier read-only busy detection (`remote_busy` JSON error code and `[BUSY]` log tag without mutating the remote barrier), zero-candidate fast path skipping the consistency probe, and granular GC live progress reporting (sub-stages, commit counts, reclaimable/removed bytes, rate, ETA, and deferred counts).
- Expand binary codec fuzzing across `KCOM`, `KPAK`, `KACT`, `Epoch`, `Transaction`, and AEAD envelopes (10-seed deterministic corpus plus 6 libFuzzer harnesses under `KASUMI_BUILD_FUZZERS=ON`), and add randomized multi-client soak, transport fault-injection, and sync throughput benchmark integration tests.

### Changed

- Refactor `src/application/sync/coordinator.cpp` into focused internal translation units (`coordinator_workspace.cpp`, `coordinator_uploads.cpp`, `coordinator_downloads.cpp`, and `coordinator_detail.hpp`) with zero external behavior or performance regression.

### Documentation

- Document safe automatable GC, `--min-age`, expired commit pruning, `remote_busy` / `[BUSY]` automation logs, `list_metadata`, and granular GC progress across [garbage-collection.md](docs/architecture/garbage-collection.md), [history-and-concurrency.md](docs/architecture/history-and-concurrency.md), [remote-layout.md](docs/architecture/remote-layout.md), [transport.md](docs/architecture/transport.md), [best-practices.md](docs/best-practices.md), [configuration-and-usage.md](docs/configuration-and-usage.md), [troubleshooting.md](docs/troubleshooting.md), and [README.md](README.md).

### Upgrade Notes

- Protocol and local storage formats remain unchanged (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`), staying 100% compatible with `v0.19.x`–`v0.22.0`.

## [0.22.0]

### Added

- Add Windows x86_64 `.msi` installer ([packaging/wix/kasumi.wxs](packaging/wix/kasumi.wxs), WiX v5) that installs into `C:\Program Files\Kasumi`, adds the installation directory to the system `PATH`, and supports automatic in-place major upgrades via a fixed `UpgradeCode` with custom install-folder persistence.
- Add native Arch Linux `.pkg.tar.zst` package builder ([scripts/build_arch_package.py](scripts/build_arch_package.py)) and Arch [PKGBUILD](packaging/arch/PKGBUILD) for `pacman -U` / `makepkg -si` installation and upgrades under `/usr/bin/kasumi`.
- Configure CPack DEB and RPM packaging rules in [CMakeLists.txt](CMakeLists.txt) to build `kasumi-linux-x86_64.deb` and `kasumi-linux-x86_64.rpm` alongside the portable `.zip` and `.tar.gz` archives.
- Add packaging contract tests ([tests/architecture/test_packaging.py](tests/architecture/test_packaging.py)) and automated release-gate live install, in-place upgrade/reinstall, and clean removal verification across Windows MSI, Ubuntu `.deb`, Arch Linux `.pkg.tar.zst`, and Fedora `.rpm`, publishing SHA-256 sidecars, `SHA256SUMS.txt`, and GitHub build provenance attestations for all 6 packages.

### Documentation

- Document native installer installation, SHA-256 / `gh attestation verify` verification, and in-place upgrade instructions across [README.md](README.md), [getting-started.md](docs/getting-started.md), and [configuration-and-usage.md](docs/configuration-and-usage.md).

### Upgrade Notes

- Protocol and local storage formats remain unchanged (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`), staying 100% compatible with `v0.19.x`–`v0.21.2`.

## [0.21.2]

### Fixed

- Report actively locked profiles (e.g. during `sync`, `gc`, `fsck`, or `repack`) as `Running` (annotated with the active operation such as `Running (gc)` when recorded in local activity) rather than `Problem` across `kasumi config`, `kasumi show`, and `kasumi diagnostics`, while keeping malformed, symlinked, or unreadable lock files reported as `Problem`.
- Keep `kasumi diagnostics` healthy (`overall_ok: true`, `"running"` / `"running (<op>)"` detail) when an active execution holds a valid lock or writes its active `transaction.bin.enc` journal, and stop setting `lock_busy = true` on corrupt/unreadable lock errors.
- Enrich `lock_busy` / `LockFailure` messages across `execute`, `config` mutations, and `kasumi key` with `(running <op>)` when an `InProgress` local operation is present.
- Expose `"state": "running"`, `"lock_active"`, and `"active_operation"` in `kasumi show --json` and `"active_operation"` in `kasumi diagnostics --json`.

### Documentation

- Document the `Running` local profile state, JSON `running` / `lock_active` / `active_operation` fields, and lock-busy operation reporting across [profile-management.md](docs/architecture/profile-management.md), [configuration-and-usage.md](docs/configuration-and-usage.md), and [troubleshooting.md](docs/troubleshooting.md).

### Upgrade Notes

- Protocol and local storage formats remain unchanged (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`), staying 100% compatible with `v0.19.x`–`v0.21.1`.

## [0.21.1]

### Changed

- Enrich `--log-file <path>` non-JSON text logs with local timestamps (`±HH:MM`), explicit status tags (`[OK]`, `[WARN]`, `[PARTIAL]`, `[LOCKED]`, `[CANCELLED]`, `[ERROR]`), language-independent compact operational summaries with human-readable transfer sizes, elapsed duration (`(<seconds> s)`), and indented detail lines (pending paths, warnings, unhealthy diagnostics), written in a single atomic append per command.

### Added

- Add top-level UTC ISO-8601 `timestamp` (`YYYY-MM-DDTHH:MM:SSZ`) to every `--json` response envelope (`schema_version: 1`) and `kasumi ... --json --log-file <path>` NDJSON line.
- Add concise language-independent `data.summary` strings across `--json` operation, plan, diagnostics, and inspection payloads alongside all existing raw structured fields.

### Documentation

- Document enriched `--log-file` text format, `--json` `timestamp`, and `data.summary` in [configuration-and-usage.md](docs/configuration-and-usage.md).

### Upgrade Notes

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x` and `v0.21.0`. Existing `--json` raw numeric/array/error fields are unchanged (`timestamp` and `data.summary` are additive).

## [0.21.0]

### Added

- Add `kasumi sync <profile> --repair` for fast missing-object recovery via a single physical listing across the effective `StorageManifest` (loose objects, `KPAK\x01` Micro-Packs, and FastCDC chunks), re-uploading missing payloads from verified local copies without downloading payloads (`fsck`) or publishing a new Commit when no logical changes occur (`data.repaired` in `--json`; incompatible with `--dry-run` and `--initial`).
- Add preflight checks before remote transfers: local free disk-space verification ahead of `sync` downloads (`error.code: "insufficient_disk_space"`) and minimum `rclone` version (`v1.60.0`) validation via `core/version` and `probe_rclone_installation`.
- Add read-only `kasumi diagnostics [<profile>] [--json] [--quiet]` to inspect OS, data/config status, disk space, `rclone` availability/version, profile local states, active locks, pending journals, and key accessibility without contacting remotes or exposing secrets.
- Add `--log-file <path>` (`--log-file=<path>`) on non-interactive commands to append UTC-timestamped UTF-8 plain-text logs without ANSI escape sequences, or NDJSON lines when combined with `--json`, with upfront path validation (`error.code: "io_error"` in `--json`) and no file creation on `--help`.

### Documentation

- Document `sync --repair`, disk-space and `rclone >= v1.60.0` preflight checks, `kasumi diagnostics`, `--log-file`, `insufficient_disk_space`, and `io_error` across [configuration-and-usage.md](docs/configuration-and-usage.md), [synchronization.md](docs/architecture/synchronization.md), [transport.md](docs/architecture/transport.md), [troubleshooting.md](docs/troubleshooting.md), and [README.md](README.md).

### Upgrade Notes

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, maintaining full drop-in compatibility with `v0.19.x` and `v0.20.0` vaults and local databases.

## [0.20.0]

### Added

- Add `kasumi gc <profile> --dry-run` to inspect local transaction journals read-only, check maintenance barrier and active writer preconditions, and report eligible candidate counts (`candidate_content_objects`, `candidate_commit_variants`, `candidate_activities`) without establishing a barrier, deleting remote objects, or publishing a `KACT` activity record.
- Add `--dry-run` preview and interactive confirmation guards (`[y/N]` / `[s/N]`) with `--confirm` automation bypass to `kasumi resolve-missing <profile>`.
- Add `--quiet` flag on non-interactive CLI commands to suppress banners, live progress, `Duration:` lines, and non-error operational stdout while keeping query output and error/partial diagnostics visible.
- Add `--json` structured output (`schema_version: 1`, language-independent keys and `error.code` values, empty `stderr`) across `list`, `show`, `status`, `sync`, `fsck`, `gc`, `repack`, `resolve-missing`, and `remote summary`, including `lock_busy` and `confirmation_required` distinction.

### Changed

- `kasumi resolve-missing <profile>` now previews eligible pending paths and requires explicit confirmation before publishing logical deletions (when pending paths exist); non-interactive scripts must pass `--confirm` (or run read-only with `--dry-run`).

### Documentation

- Document `gc --dry-run`, `resolve-missing [--dry-run | --confirm]`, `--quiet`, and `--json` (`schema_version: 1` and stable `error.code` reference) across [configuration-and-usage.md](docs/configuration-and-usage.md), [garbage-collection.md](docs/architecture/garbage-collection.md), [best-practices.md](docs/best-practices.md), and [README.md](README.md).

### Upgrade Notes

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, and `config.toml`, staying compatible with `v0.19.x` vaults and local databases. Automated scripts invoking `kasumi resolve-missing <profile>` when pending paths exist must pass `--confirm`.

## [0.19.2]

### Added

- Add root `SECURITY.md` defining Kasumi's pre-1.0 support policy and private vulnerability reporting via GitHub Security Advisories.

### Fixed

- Guard `set_profile_key`, `kasumi key <profile>`, and `kasumi config` `[k] Key` against silently overwriting a different persisted master key (`ProfileErrorCode::AlreadyExists` unless explicitly confirmed/allowed; constant-time `crypto_verify32` comparison keeps identical key re-entry idempotent and still permits recovery of missing or corrupt local keys).

### Documentation

- Clarify that `kasumi key` performs local key entry/replacement rather than vault re-encryption, remove stale `--non-interactive` and managed package-manager claims, document `windows-2022` (`/MT`) and `ubuntu-latest` (GCC 14 / dynamic `glibc`) release baselines, and add `gh attestation verify` verification steps.

## [0.19.1]

### Removed

- Remove the `--trust-existing-content` option from `kasumi sync --initial`, along with its unverified remote content trust bypass (`trusted_remote_content_objects`, `SyncCompleted::trusted_content_reused`, and associated warning/CLI paths). Initial bootstrap continues to verify pre-existing loose objects via AEAD decryption and plaintext BLAKE3 verification before reuse.

## [0.19.0]

### Added

- Add persistent installation machine identity (`machine.id` paired with the automatically detected OS hostname) and local human-readable timestamp formatting (`YYYY-MM-DD HH:MM:SS ±HH:MM`).
- Add immutable, encrypted, authenticated `KACT` v1 operational activity records under a dedicated keyed remote namespace (`FilePurpose::Activity`, `KeyPurpose::Activity`), published best-effort by `fsck`, `gc`, `gc remove-writer`, and `gc remove-barrier`.
- Add `state.db` schema v2 tables (`local_executions`, `accepted_commit_meta`, `remote_activity_cache`) to persist local execution attempts and results (including no-op and download-only syncs), offline accepted-commit provenance, and cached remote maintenance summaries.
- Display commit authorship (`sync`, `repack`, `resolve-missing` and publishing machine) and readable timestamps in `remote heads`, `remote commits`, and `remote commit`, shared operational maintenance activity in `remote summary [--full]`, offline traceability in `show <profile> [--full]`, and a concise last-sync column in `config`.

### Changed

- Upgrade the encrypted commit wire format to `KCOM` v4 with embedded commit authorship (`origin_operation`, persistent `machine_id`, and historical hostname at publication time) while keeping zero extra remote objects or requests during `sync`.
- Extend `kasumi gc` to retain and prune `KACT` v1 activity records using the vault's `min_history_depth` and `min_history_age_hours` policy while preserving the newest successful record per `(machine_id, operation)` and failing closed on invalid activity objects.

### Upgrade Notes

- Pre-1.0 breaking format change: `v0.19.0` requires `KCOM` v4 commits and `state.db` schema v2 and rejects legacy v3 vaults and v1 local databases without automatic migration. Complete pending recovery on `v0.18.x`, back up data, upgrade all clients to `v0.19.0`, and initialize fresh vaults and local state.

## [0.18.2]

### Changed

- Accelerate x86-64 SHA-256 physical hashing (`sha256_update`, `sha256_finish`, and `hash_file`) with runtime-detected SHA-NI instructions on both Windows and Linux, preserving automatic fallback to software SHA-256 (and Windows CNG `BCrypt` for `hash_file`) when SHA-NI is unavailable.
- Raise `bulk_list_probe_threshold` from `64` to `256` physical objects and remove the `>= 8` chunked-object exception during content availability checks so small incremental syncs prioritize `control_read_batch` or batched `presence` probes instead of full remote directory listings.

## [0.18.1]

### Fixed

- Print the `:back` navigation hint once per action in `kasumi config` instead of repeating it on every subsequent field prompt and validation retry.

## [0.18.0]

### Added

- Add `kasumi repack <profile> [--dry-run] [--reclaim-dirty] [--full]` (`Operation::Repack`, `RepackCompleted`, `ErrorCode::RepackFailure`) to consolidate loose small files (`<= 256 KiB`) and fragmented `KPAK\x01` Micro-Packs directly from verified local files without downloading remote payloads or deleting remote objects.
- Add a deterministic Micro-Pack repack planner (`repack::plan`) that detects dead blobs inside existing packs by recomputing the canonical live-member pack hash with zero I/O, consolidates loose small blobs and underfilled packs (`< 2 MiB`) into `4 MiB` target packs by default, and reclaims large dirty packs (`>= 2 MiB` live bytes with dead blobs) when `--reclaim-dirty` is passed.
- Stage, upload, verify, and clean up consolidated Micro-Packs in bounded 16-pack windows (`~64 MiB` per window) under cooperative writer registration before publishing a single tree-preserving `KCOM` v3 Commit with the updated `StorageManifest`.

### Fixed

- Poll interactive POSIX terminal input before reading lines in `kasumi config` so a `SIGINT` delivered between flushing the prompt and entering input read is observed promptly instead of blocking in `getline`.

## [0.17.4]

### Fixed

- Project the observed local tree against the persisted base tree before triggering speculative writer registration during sync observation, avoiding unnecessary remote writer marker creation and cleanup on no-op syncs when local directories contain only ignored files.
- Sort `file_cache` rows loaded from SQLite using segment-wise `path_less` order to match the local scanner, preventing false dirty-cache writes on no-op syncs when paths trigger ASCII vs. path-segment ordering inversions (such as `.` vs. `/`).

## [0.17.3]

### Changed

- Use a single remote listing instead of batched per-object presence probes when checking availability for 64 or more physical objects (outside storage audits), speeding up `initial-sync` and large non-chunked syncs while keeping automatic fallback to batched presence checks.
- Send explicit raw file lists (`FilesFromRaw`) with `NoTraverse`, `NoCheckDest`, and `NoUpdateModTime` in rclone batch downloads so each download window fetches only the requested objects without traversing the remote root.
- Stream FastCDC chunk decryption and verification directly into the temporary destination file, eliminating the `chunk-plain` plaintext staging directory during large-file downloads.

### Fixed

- Ensure storage object audits always probe remote presence directly instead of substituting bulk listing results, and avoid quadratic scanning when ordering storage repair operations.

## [0.17.2]

### Changed

- Stream verified FastCDC chunks directly into the temporary destination file, avoiding an intermediate plaintext copy. Reuse verified slices from files already installed in the same sync.
- Download Micro-Packs in bounded windows with per-window checkpoints and install authenticated members directly, eliminating the intermediate extraction directory during sync and recovery.

### Fixed

- Remove leftover temporary download files before replaying pending downloads during roll-forward recovery, and reject non-regular files or links during candidate cleanup.
- Restore immediate rclone process termination after `core/quit` is acknowledged, removing the extra shutdown wait at the end of rclone sessions.

## [0.17.1]

### Added

- Show the number of confirmed changes out of the current plan in Sync and Resolve Missing. Show the active file's progress when it can be measured separately, or show the batch's bytes, speed, and ETA when available.
- Show live progress while comparing local and remote snapshots, checking remote content availability, and preparing changes. Interactive terminals show elapsed time during operations with no reliable ETA.

### Changed

- Include encoded upload and download bytes, physical object counts, and local reuse in the default Sync summary. The `--full` option keeps per-activity details and lists every plan item and pending path.
- Show FSCK audit totals, verified plaintext, wire downloads, and reassembled files. Show garbage collection inventory size, candidates, confirmed removals, and removal rate. Keep stage messages and periodic progress updates readable when redirecting output.

### Fixed

- Count completed audit checks even when they find invalid or missing content. Keep transfer summaries under Applying changes and report publication and finalization as they happen.

## [0.17.0]

### Removed

- Removed the `kasumi update` command, the built-in updater, and its private installer commands. Update portable installations manually from the official release archives. Update managed installations through the package manager that installed Kasumi.

### Changed

- Stage and upload Micro-Packs in bounded batches with checkpoints. Extract packs into separate workspaces so packs that share a blob can be processed concurrently.
- Bound rclone removal batches by the expected response size, and stop reading oversized listings without retrying them.

### Fixed

- Verify remote payloads before reusing upload checkpoints. Replan paused uploads when local files or remote history change, so synchronization can continue before the pending transaction expires.
- Recover interrupted local copies and partially initialized journals. Clean up owned temporary files on destination conflicts and release the remote writer marker if missing-content resolution fails.
- Keep GC, remote health, and inventory audits working after Epoch pruning. Clear old pending materializations when advancing to a new Epoch.
- Reconcile file-to-directory and directory-to-file changes in diff and plan, including three-way conflicts. Accept timestamps rounded to the destination filesystem's precision.
- Verify that rclone batch downloads produced every requested object, report missing packs as missing content, and replace stale downloads even when file size and modification time match.
- Preserve useful diagnostics for rclone server errors and uncertain writes. Bound async job polling, confirm termination when possible, and allow the child process to quit during cancellation.
- Find trusted rclone executables on `PATH` from filesystem roots and home directories, recognize Windows child-process exit statuses correctly, and isolate temporary hash manifests.
- Preserve local copies from read-only sources as writable on Windows, and report permission failures during storage enumeration.
- Initialize SQLite databases atomically, recover interrupted WAL state, protect WAL sidecars before commit, and prune legacy file-cache rows. Reject redirected database files and sidecars.
- Open only regular crypto inputs without following symlinks or reparse points. Bound Micro-Pack reads and wipe plaintext buffers before reuse.
- Reject duplicate profile names and support renames that only change capitalization. Fix profile setup when the Linux configuration directory does not yet exist.
- Improve Windows Credential Manager retries and diagnostics, handle Linux D-Bus disconnects without terminating the process, and improve cancellation and UTF-8 in the Windows console. Sanitize control characters in remote reports.
- Harden Windows file replacement, profile locks, and cleanup of extended-length paths. Use native macOS change timestamps and exclusive renames.

## [0.16.0]

### Changed

- Select FastCDC chunk sizes by file size, with chunks up to 32 MiB, and plan chunk layouts for independent files in parallel.
- Stage FastCDC transfers in windows of up to 64 chunks and 256 MiB of plaintext. Reuse verified local and staged slices across download windows and files, and hash the assembled file as it is written.
- Reuse chunks from interrupted uploads after authenticating their contents, including on the first upload of a new file.
- Stream chunk encryption in 1 MiB frames and skip Zstandard temporarily after consecutive frames yield negligible savings.

### Fixed

- Resolve Windows extended-length paths before applying permissions to quarantined workspace files.

### Upgrade Notes

- Existing Protocol v3 vaults open directly with `v0.16.0`. Upgrade every client sharing a vault before publishing with `v0.16.0`. Clients on `v0.15.1` and earlier reject manifests containing FastCDC chunks larger than 4 MiB.

## [0.15.1]

### Changed

- Keep default Sync terminal output concise by erasing transient non-transfer progress lines, aggregating transfer waves into one live Applying line, hiding empty staging metrics and directory-only install counts, and moving the wire summary and per-stage progress history behind `--full`.
- Report average, minimum, and maximum transfer speeds below completed byte-transfer lines (`sync`, `fsck`, `remote`, and `update`).

### Fixed

- Re-prompt directly on `>` after an invalid menu option in `kasumi config` instead of reprinting the full profile list and menu.

## [0.15.0]

### Added

- Show live, single-line terminal progress for synchronization, planning, integrity checks, garbage collection, remote inspection, and update downloads. Redirected output keeps readable stage lines.
- Report physical content bytes and object counts for uploads and downloads alongside the logical sync totals. Include bytes reused through FastCDC seeds and deduplication.
- Report scanner discovery, cache hits and hashing, plus staging, transfer, verification, installation, and reobservation phases during sync.

### Changed

- Measure transfers using rclone job statistics and streamed local copies. Cancel active rclone jobs on Ctrl+C and preserve batched copies and the no-op sync fast path.

### Upgrade Notes

- `v0.15.0` uses the same Protocol v3 vault format, flat commit layout, transaction journal v10, and profile configuration as `v0.14.2`.

## [0.14.2]

### Fixed

- Restore the exact Pack ID when a required probe finds a missing Micro-Pack and verified local sources can reproduce it. A sync that already publishes a commit can replace an incomplete pack mapping when the remaining sources are available.
- Verify the BLAKE3 and size of each FastCDC file in `fsck` by streaming its authenticated chunks in manifest order.
- Assemble FastCDC downloads directly from verified local slices and remove downloaded plaintext chunks after their last use.
- Apply the reachability limit to distinct physical object IDs and avoid accumulating repeated reference details during GC and remote inspection.
- End the rclone child process immediately after it acknowledges `core/quit` and the RC pool closes.

### Upgrade Notes

- `v0.14.2` uses the same Protocol v3 remote layout, transaction journal v10, and profile configuration schema as `v0.14.1`.

## [0.14.1]

### Fixed

- Show the `vault`, `file`, and `memory` key storage modes before asking for credentials when creating a profile. Pressing Enter selects the operating system credential vault.
- Offer New and Quit when there are no profiles. Type `:back` at profile, path, and key storage prompts to return to the menu.
- Resolve GCC and Clang build warnings in platform code and the GCC LTO warning from Zstandard's assembler flags.

### Upgrade Notes

- Scripts that drive `kasumi config` via standard input must supply a storage mode or an empty line after the remote destination when creating a profile.

## [0.14.0]

### Added

- Added Protocol v3 (`KASUMI\x03\x00`, `FILE_HEADER_SIZE = 57`) stream encryption with per-chunk in-memory Zstandard (`zstd` level 1) compression over `1 MiB` plaintext chunks (`CHUNK_SIZE = 1 MiB`), authenticated `FilePurpose` (`Content`, `History`, `Pack`) header binding, and a 5-byte chunk prefix (`CHUNK_PREFIX_SIZE = 5`) inside each XChaCha20-Poly1305 AEAD envelope.
- Added Micro-Packs (`KPAK\x01`) under domain-separated `KeyPurpose::Pack` and `IdentifierPurpose::Pack`, packing small upload files (`<= 256 KiB`, excluding `.kasumiignore`) into deterministic content-addressed pack blobs up to `4 MiB` (`PACK_TARGET_MAX_SIZE`).
- Added content-defined chunking (FastCDC) using a normalized 64-bit Gear rolling hash (`256 KiB` minimum, `1 MiB` average, `4 MiB` maximum chunk size) for files larger than `8 MiB` (`FASTCDC_FILE_THRESHOLD`), enabling block-level deduplication and delta transfers on both uploads and downloads (including client-side seed chunk reuse from the existing local file or local move/copy donors).
- Added canonical `StorageManifest` metadata (`packed_blobs` and `chunked_files`, bounded to `16 MiB` per packed blob and `4 MiB` per chunk slice) to `Commit` (`KCOM` v3), deterministic manifest merging across DAG branches, and persistence in `db.sqlite` (`StoredState.storage_manifest`).

### Changed

- Flattened remote Commit variant storage paths to `<history-ns>/<commits-ns>/<commit-id>_<ciphertext-id>` so commit discovery completes in a single directory listing instead of per-commit prefix listings.
- Updated `sync`, `fsck`, `gc`, `remote get`, and `remote contents [--audit]` to resolve, prefetch in parallel, deduplicate, audit, reassemble, and garbage-collect physical Pack IDs and FastCDC chunk Content IDs alongside loose Content objects, using single-call `transport::list` presence checks when probing batches containing chunked objects (`>= 8` physical IDs).
- Optimized local and remote runtime execution with `rclone rcd` HTTP keep-alive connection pooling (`RcRuntime`), Windows BCrypt hardware-accelerated SHA-256 physical hashing, Win32 `FindFirstFileExW` bulk directory enumeration, parallel local file hashing and upload/download staging, and tuned SQLite WAL/mmap/cache PRAGMAs.
- Hardened transport, platform vault (`dlopen` root/permission checks and D-Bus reply validation), SQLite statement lifecycles, manifest deserialization bounds, and TOCTOU `FileIdentity` checks across FastCDC slice reads and private temporary reassembly files.
- Removed legacy format compatibility paths (`KASUMI\x02\x00` stream decoding, `KCOM` v2 commits, transaction journal format 9, and `config.toml` profiles omitting `key_storage`).

### Fixed

- Fixed timestamp conversion on Windows builds using libc++ so sync can restore file and directory modification times.

### Upgrade Notes

- `0.14.0` uses Protocol v3 remote objects (`KASUMI\x03\x00`), `KPAK\x01` Micro-Packs, `KCOM` v3 commits, flat remote commit paths (`<commit-id>_<ciphertext-id>`), transaction journal format 10, and explicit `key_storage` entries in `config.toml`, without backward-compatibility fallbacks for earlier pre-1.0 formats. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.12.0]

### Added

- Added configurable per-profile `key_storage` modes (`vault`, `file`, and `memory`), defaulting new profiles to the OS credential vault (`vault`: Windows Credential Manager on Windows; Freedesktop Secret Service / GNOME Keyring and KDE KWallet via on-demand `dlopen` on Linux).
- Added `kasumi key <profile>` and `[k] Key` / `[s] Storage` actions in `kasumi config` to change key storage modes and re-enter profile keys (password and salt).

### Changed

- Profiles in `config.toml` without an explicit `key_storage` field load as `file`, preserving existing `key.bin` installations across upgrades. Switching a profile's `key_storage` removes the previous persisted key and requires `kasumi key <profile>` when moving to `vault` or `file`.

### Development

- Added isolated Linux D-Bus vault test runner (`scripts/run_with_linux_vault.py`) covering GNOME Keyring, KDE KWallet, and headless `file`/`memory` portability in CI and release checks.

### Upgrade Notes

- Existing profiles without `key_storage` in `config.toml` continue using `key.bin` (`file` mode) automatically. Remote formats, encryption schemes, SQLite schema, and supported journal formats remain unchanged from v0.11.0. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.11.2]

### Fixed

- Omitted the final `Duration` / `Duração` line from `kasumi config`, keeping elapsed-time reporting limited to sync, maintenance, remote, and update operations.

### Upgrade Notes

- Remote formats, SQLite schema, and supported journal formats remain unchanged from v0.11.0. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.11.1]

### Changed

- Scoped rclone batch SHA-256 verification (`FilesFromRaw` and `NoTraverse`) to the requested objects instead of listing unrelated remote Content and history, and overlapped scoped HEAD discovery with Epoch listing and read on batch-capable backends.
- Configured rclone uploads to skip redundant copy-layer destination checks (`NoCheckDest`) while keeping provider PUT semantics and post-upload physical verification unchanged.
- Reused authenticated physical Commit variant addresses during in-command stabilization reobservation when HEAD markers and Epoch are unchanged, reading ancestors in bounded batches without per-ancestor prefix listings.

### Fixed

- Reduced redundant Argon2id derivations in the CLI process integration test so ASan/UBSan runs complete reliably within subprocess timeouts.

### Upgrade Notes

- Remote formats, SQLite schema, and supported journal formats remain unchanged from v0.11.0. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.11.0]

### Added

- Added `kasumi list` for profile names and `kasumi show <profile>` for settings, retention, local state, and inspection diagnostics, without contacting remote storage or displaying credentials.

### Changed

- Simplified the profile wizard with a compact list, grouped credential prompts, and per-field validation that preserves accepted input.
- Profile deletion and path edits require explicit confirmation, defaulting to No. Path edits show the old and new destinations and explain that files are not moved or remote data migrated.
- Status and dry-run plans use translated action descriptions that distinguish local and remote changes, files and directories, and disposable ignored files.

### Development

- Added Ubuntu CI coverage with AddressSanitizer and UndefinedBehaviorSanitizer using the existing test suite.

### Upgrade Notes

- Update scripted wizard input for the new confirmations. `list` and `show` omit duration lines and send errors to stderr.
- Remote formats, SQLite schema, and supported journal formats remain unchanged from v0.10.0. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.10.0]

### Changed

- Consolidated duplicated Sync, recovery, history, storage, cryptography, and CLI code.
- Replaced runtime translation-catalog parsing with generated compile-time tables.

### Fixed

- Hardened local file access, credential-buffer cleanup, and rclone identifier filters.

### Removed

- Removed auxiliary Fsck checkpoints and the persistent remote-inspection history cache. Fsck still downloads and authenticates every referenced payload.
- Removed standalone benchmark and provider-certification runners and reduced performance tracing.

### Upgrade Notes

- Remote formats, SQLite schema, and supported journal formats remain unchanged from v0.9.4. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.9.4]

### Added

- Added opt-in disposable ignore rules with the `(?d)` modifier in `.kasumiignore` (such as `(?d)*.bak`). Disposable classification applies exclusively to regular ignored files; unsupported modifier combinations and negated disposable rules fail closed during parsing.
- Added transactional `DeleteIgnoredLocalFile` (action ID 11) to safely remove eligible disposable ignored files when reconciliation authorizes the removal of their containing previously managed directory tree.
- Upgraded transaction journal writer to format 10 with backward-compatible reading of formats 9 and 10; wire action IDs 0–10 are preserved.

### Changed

- Reconciled directory tree removals allow pruned managed subtrees to be deleted when all descendants are either managed removals or eligible disposable files, while preserving subtrees containing protected ignored files. Independently eligible nested subdirectories remain candidate for removal.
- `kasumi status <profile>` and `kasumi sync <profile> --dry-run` display planned `DeleteIgnoredLocalFile` operations and directory removals without performing physical deletions.

### Fixed

- Hardened disposable file disposal with pre-removal verification of native filesystem identity, size, and BLAKE3 hash against durable staged transaction backups, with authenticated rollback and recovery support.
- Enforced fail-closed conflict handling if a disposable source disappears without verified removal by Kasumi or if external file replacement is detected during execution.
- Isolated provider certification test temporary files using unique dedicated workspaces (`kasumi::test::make_temp_workspace`), preventing race conditions and readback corruption under parallel CTest execution while maintaining strict byte validation.

## [0.9.3]

### Fixed

- Fixed synchronization failures when remote directory deletions or renames left locally ignored files behind. Managed files are synchronized while ignored content and its required parent directories remain intact.
- Prevented directories containing only ignored content from being republished as local additions or repeatedly scheduled for removal, while preserving normal synchronization of empty directories.
- Corrected reconciliation and final publication-tree validation to account for transient physical ignore evidence, including files that were synchronized before becoming ignored.
- Preserved fail-closed local observation for invalid regular-file metadata and unsupported non-regular entries. Unexpected filesystem changes continue to produce explicit conflicts instead of being silently discarded.
- Kept directory-removal planning consistent with updated physical evidence during stabilization, and verified convergence after interrupted v0.9.2 transactions without requiring manual removal of recovery state.

## [0.9.2]

### Added

- Added `MoveLocal` to reuse verified local files for eligible remote file moves and renames, including files relocated within directories, avoiding Content downloads.
- Added `CopyLocal` to materialize new paths from local bytes matching the expected BLAKE3 hash and size, preserving the source and refusing occupied destinations.

### Changed

- Local file and directory moves reuse matching accepted remote Content, avoiding redundant uploads.

### Fixed

- Preserved operation dependencies during execution and recovery, including interrupted repairs; strengthened staging ownership and rollback checks to preserve detected external replacements and retain recovery evidence on failure.
- Fixed missing remote Content detection during `CopyLocal`. Repair uses verified local bytes, preserves local materialization, and reports repair failures; physical-only repair publishes no new Commit or HEAD.

## [0.9.1]

### Fixed

- Fixed downloads directly beneath a trailing-slash symlink synchronization root without permitting symlink traversal inside the synchronized tree.

## [0.9.0]

### Added

- Added profile cloning in `kasumi config`, reusing settings and the master key with a new empty SQLite database.
- Added local profile-state indicators in the configuration wizard without contacting remote storage or modifying persistent profile data.
- Added explicit recovery of abandoned maintenance barriers with `gc remove-barrier --confirm-abandoned`.

### Changed

- Standardized CLI argument validation, contextual help, elapsed-time reporting, and cancellation at safe operation boundaries.
- GC revalidates barrier ownership before deletion and reports acknowledged removals and uncertain effects separately.

### Fixed

- Reconciled histories with multiple best common ancestors, preserving independent changes, conflict variants, and later deletions within authenticated history limits.
- Serialized configuration mutations and corrected concurrent configuration reads, atomic replacement, permissions, and profile-lock handling on Windows.
- Hardened profile-clone rollback and interrupted Sync cleanup with filesystem identity and ownership checks.
- Preserved native Unicode command-line arguments on Windows independently of the system ANSI code page.

### Performance

- Reduced GC remote I/O by classifying orphan Content through authenticated reachability without payload auditing and applying candidate deletions in bounded batches.

## [0.8.4]

### Added

- Added support for `sync --initial` to enroll an uninitialized client into an existing authenticated remote vault.
- Added `--trust-existing-content` parameter for `sync --initial` to reuse orphan Content during bootstrap without verification downloads or redundant uploads.

### Fixed

- Hardened SQLite database validation by rejecting symlinks and non-regular files, while safely reusing empty databases left by interrupted initial operations.
- Validated remote history authentication before creating or updating the local SQLite database.
- Protected against concurrent modifications during bootstrap and enrollment, failing closed if remote history is observed concurrently.

### Performance

- Reduced redundant remote presence queries during trusted bootstrap by reusing the initial storage listing.
- Preserved zero network request overhead for normal sync and no-op operations.

## [0.8.3]

### Fixed

- Made file encryption and decryption transactional: output is written to isolated temporary files with private permissions and published atomically, preserving preexisting destinations when operations fail before publication.
- Protected against alias and destination corruption by rejecting empty paths, identical source/destination paths, directory/symlink targets, and hardlinked aliases of the input file.
- Fixed a double-close vulnerability in private file handling and strengthened RAII ownership of Windows handles and POSIX file descriptors.
- Made temporary file cleanup safe by validating physical `FileIdentity` before unlinking, preventing accidental removal of colliding or replaced files.

### Performance

- Sized encryption and decryption scratch buffers according to payload size up to chunk limits, reducing memory consumption and wipe work for small files.
- Optimized BLAKE3 file hashing with a 64 KiB buffer and RAII memory wiping via `BufferWipeGuard`.

## [0.8.2]

### Performance

- Sync checks remote Content availability only for its current work. No-op and small runs avoid a global presence scan; unrelated missing objects are not discovered or repaired automatically.

### Added

- Added the opt-in `kasumi sync <profile> --audit-inventory` command to report referenced, present, missing, and orphan Content across reachable history, plus unknown physical objects. A clean complete run returns `0`, findings or partial Sync return `2`, and audit failure returns `1`.

### Limitations

- The structural audit does not download or authenticate Content payloads, repair or delete objects, or provide an atomic snapshot. It rejects detected writers, barriers, and changes between its two physical listings. If audit fails after Sync publishes, that publication remains.

## [0.8.1]

### Fixed

- Stopped duplicate progress messages during `kasumi gc`.
- CLI rejects completion payloads that do not match their operation, preventing incorrect success messages.

## [0.8.0]

### Changed

- Replaced quarantine-based GC with direct removal of authenticated orphan Content and redundant CommitVariants, using one authenticated observation and a globally validated plan.
- GC applies sequential removals, reports partial and uncertain results, and preserves ownership checks during barrier cleanup.
- Sync checks required remote Content even on no-op runs and repairs missing objects from authenticated local bytes without publishing unnecessary history. Unavailable content remains pending instead of becoming a logical deletion.
- Added explicit `sync --initial` to initialize a missing local database only when local transaction evidence and current remote history are absent; compatible Content can be reused.
- Expanded maintenance, repair, and process-crash regressions and the release-critical gate; corrected Windows GCC/MSYS2 fixtures, crash-helper linkage, and crash-test signaling.

### Removed

- Quarantine and the `gc purge-quarantine`, `gc repair-quarantine`, and `remote quarantine` commands. GC deletions are permanent.

### Upgrade Notes

- Use the same release on all clients. See [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi) for compatibility and backup requirements.
- See [Release Notes](RELEASE_NOTES.md) for user-facing changes and [Transport and Provider Capabilities](docs/architecture/transport.md) for current requirements and limitations.

## [0.7.0]

### Highlights

- Strengthened bidirectional Windows/Linux synchronization, concurrent-history observation, local mutation checks, and recovery of interrupted operations.
- Replaced full-record journal rewrites with an incremental authenticated journal and validated confirmed-session cache.
- Unified local scanning and persistent BLAKE3 hash reuse across Sync, Preview, and Status.

### Added

- Native metadata observation with Windows volume/full 128-bit file identity and Linux device/inode identity, explicit filesystem errors, and checked nanosecond timestamp conversion.
- Incremental journal snapshots and chained encrypted deltas, authenticated confirmation of the durable log prefix, and authenticated retirement for restart-safe cleanup. Incompatible, truncated, or contradictory confirmed state stops recovery and retains evidence.
- Journal preparation batching, confirmed Record/Tip caching with artifact and key checks, deterministic fault injection in separate test builds, and operational preparation/recovery benchmarks.
- Windows `longPathAware` manifests for the CLI and test executables, plus diagnostics identifying rejected internal staging paths and their lengths.

### Changed

- Windows and Linux use one scanner. Every observation enumerates the managed tree and reads metadata; hash reuse requires matching logical path, regular-file type, size, nanosecond mtime, and every native identity component.
- SQLite persists the uniform hash-cache representation without time-based expiration. `status` and `sync --dry-run` reuse eligible fingerprints read-only, hash cache misses or unreliable identities, and never save cache deltas. A differing authenticated ignore projection uses full hashing; a warm cache does not skip enumeration or remote observation.
- Existing profile configuration and SQLite state are validated before application operations open transport. Unknown profile fields, missing required values, and missing/corrupt/incompatible databases are rejected without migration, recreation, or accepted-base reset.
- Optimized ignore-rule matching and added regressions for anchored and wildcard patterns.
- Expanded Debug/Release CI to five toolchains: MSVC 2022, MSYS2 UCRT64 GCC, MSYS2 Clang64, Ubuntu GCC 14, and Ubuntu Clang 19; Windows MSYS2 jobs verify tool paths. Cleaned up test/benchmark namespaces and development-phase identifiers.
- Stable tags are no longer classified as prereleases solely for having major version zero; tags containing `-` are prereleases. Windows version resources derive from CMake's project version.
- Consolidated user guides, architecture, maintenance safety limits, and release documentation around the current implementation.
- Simplified Windows self-update permissions: replaced internal UAC helper elevation (`runas`, process ACL manipulation, nested helper processes) with a direct write-permission check. Non-elevated sessions fail fast with an explicit administrator requirement, while elevated or user-writable sessions install directly.

### Fixed

- Scoped history observation now verifies ancestry linkage across all loaded branches before trusting `cached_anchor`. Concurrent sibling HEADs invalidate the shortcut and trigger loading without that anchor, restoring the common ancestry needed for reconciliation. Includes the regression discovered during real Google Drive validation (`DEFECT-P36-01`).
- Destructive download, deletion, and conflict-rename targets are verified by content independently of cached hashes. A mismatch invalidates the cache row and triggers reconciliation; unexpected disappearance, non-regular replacement, or an occupied destination fails closed.
- Preserved cache invalidations and freshly reobserved fingerprints through finalization and across executions, including observations following confirmed local renames.
- Restored normal Linux local mutations and hardened verified staging, no-overwrite installation/rename, backup restoration, and rollback after interruptions. Detected pre-effect destination conflicts preserve completed peer effects for a fresh Sync; ambiguous recovery retains the journal and required backups.
- Hardened Commit/HEAD publication and recovery checks around confirmed local progress. Commit upload alone is not publication; exact marker/Commit/Epoch and accepted-state contradictions stop recovery rather than silently selecting rollback or success.
- Corrected Windows native timestamp reads, checked FILETIME conversion, 100-nanosecond timestamp equivalence, and timestamp preservation in synchronization and rollback backups.
- Corrected native metadata error handling and unsupported-identity fallback. Reworked the file-identity regression to avoid assuming that a filesystem cannot immediately reuse an identifier, and made the Windows sharing-violation retry regression deterministic.

### Removed

- Windows NTFS USN Change Journal scanning, observation checkpoints, directory-lineage machinery, and selective tree patching. The authenticated **transaction journal** remains in use.
- Obsolete fixed remote-layout readers/helpers, former custody-artifact replay/cleanup, and unused APIs/tests tied to those implementations. Unknown objects and unsupported custody artifacts are preserved rather than adopted or deleted.
- Windows self-update UAC elevation helper mode (`--kasumi-update-elevated`), `launch_elevated_windows`, and process query-access grants.

### Breaking Changes

- Kasumi provides **no backward compatibility between 0.x releases**. There is no automatic SQLite, journal, configuration, credential, or remote-format migration, no cross-version client interoperability contract, and no supported downgrade procedure.
- Current SQLite validation, fingerprint encoding, journal codec/envelopes, and key-derived remote layout must not be treated as an in-place upgrade path from older releases. The updater replaces only the executable. Preserve incompatible state and independent copies of files/credentials; do not delete `db.sqlite` or recovery evidence to force synchronization. See [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).

## [0.6.1]

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed rclone job/batch timeouts during large content presence checks by splitting requests into bounded concurrent batches.

## [0.6.0]

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Highlights

- **Partial Materialization & Exit Code 2**: Gracefully handles missing remote payloads during synchronization by recording unresolved entries as pending materializations in local state and exiting with status code 2, allowing synchronization to proceed safely without failing the entire transaction.
- **Reconciliation & DAG Correctness**: Strictly selects merge bases by ancestry in the commit DAG, ensures state commits are independent of remote head ordering, preserves remote conflict copies in shared state when local changes win, and prevents data loss during concurrent file-and-directory branch collisions.
- **Fail-Closed Transaction Safety**: Strengthens recovery invariants to abort and fail closed if transaction journals encounter conflicting remote publications or missing rollback evidence, while keeping read-only commands strictly isolated from recovery side effects.
- **Concurrent Integrity Audits**: Parallelizes `kasumi fsck` payload validation with bounded workers controlled by `KASUMI_CONTENT_CONCURRENCY`, backed by crash-safe authenticated local checkpoint metadata and localized progress displays.
- **Garbage Collection Efficiency**: Adds verified same-storage copy for quarantine staging, batches metadata publications and purge operations through rclone, verifies maintenance barrier ownership via remote physical hash, and adds live staged progress tracking.
- **Storage Provider Certification**: Provider-neutral transport and application certification runner with ownership-safe cleanup.

### Added

- Added partial materialization support in `kasumi sync`: missing remote payloads are persisted in local state (`pending_materializations`), reported to the user, and signaled via exit code 2.
- Added parallel payload verification in `kasumi fsck` using bounded workers configured by `KASUMI_CONTENT_CONCURRENCY` (defaults to 8, capped at 16).
- Added crash-safe authenticated local checkpoint persistence (`fsck_checkpoint.bin.enc`) for tracking audit progress metadata across interruptions.
- Added real-time localized progress and summary metrics for `kasumi fsck` (reporting stages, verified object counts, percentage, and plaintext byte volume).
- Added staged, localized progress indicators for `kasumi gc`, reporting preparation, quarantine verification, analysis, application, and finalization stages.
- Added same-storage native copy support for quarantine staging during garbage collection, with automatic fallback to verified client-mediated copy.
- Added batched quarantine copy, batched metadata publication, and batched source deletion via rclone job/batch execution in garbage collection.
- Added explicit manual quarantine maintenance commands: `kasumi gc purge-quarantine <profile> --confirm-permanent-loss` and `kasumi gc repair-quarantine <profile> --confirm-permanent-loss`. These are intentionally separate from normal retention-aware garbage collection; purge can permanently remove content even when it is still needed.
- Added `kasumi resolve-missing <profile>` for explicitly accepting eligible missing remote content as deletions when the original payload cannot be restored. This changes logical history and should be used only after recovery options have been exhausted.
- Added support for Windows extended-length paths (`\\?\`) exceeding `MAX_PATH` (260 characters) across workspace and private profile paths.
- Added overlapped concurrent reading for independent remote history objects (markers, commits, epochs) during observation.
- Added comprehensive modular production architecture documentation covering runtime, data models, state storage, reconciliation, transactions, garbage collection, fsck, and transport.
- Added `kasumi update` for official Windows and Linux x86_64 releases. It verifies the package's SHA-256 checksum, replaces only the Kasumi executable, and requests elevated privileges when required. See [Updating Kasumi](docs/configuration-and-usage.md#updating-kasumi).

### Changed

- Reused the observed physical namespace snapshot during history loading and fsck to eliminate redundant remote listings.
- Enforced strict remote root path containment for all rclone storage operations.
- Classified unsupported remote physical hash types (such as backends lacking SHA-256) as optional capabilities rather than errors, utilizing verified client-side fallback paths.
- Disabled redundant destination modification time updates during rclone batch uploads.
- Isolated read-only commands (`status`, `sync --dry-run`, and remote inspection) from invoking transaction recovery.
- Standardized provider certification suites and test targets across all supported storage backends.

### Fixed

- Fixed conflict omission during reconciliation by preserving remote conflict files in shared state when local modifications take precedence.
- Fixed non-deterministic reconciliation by making state commits independent of remote logical head iteration order.
- Fixed concurrent file and directory branch resolution, preserving both entries when a file and a directory are created concurrently at the same path.
- Fixed multi-party conflict preservation across three concurrent modifications and preserved modified descendants during parent directory deletions.
- Fixed first-sync composition mismatches by evaluating `.kasumiignore` patterns against remote state before fresh-client reconciliation.
- Fixed merge-base resolution to select bases strictly by ancestry in the commit DAG, correctly handling unequal-height and ambiguous branching.
- Fixed history loading and inspection to strictly reject untrusted non-zero DAG roots.
- Fixed transaction recovery to fail closed on ambiguous publication states or missing rollback workspaces, preventing evidence loss.
- Fixed cross-platform timestamp precision by canonically preserving nanosecond-resolution modification times in history and local state.
- Fixed path status resolution on POSIX platforms by properly handling `ENOTDIR` errors during path traversals.
- Fixed causal error masking during `kasumi fsck` worker drain, ensuring the root hard failure is preserved and surfaced.
- Fixed portable handling of unspecified modification timestamps during file materialization.
- Fixed MSVC compilation of embedded localization catalogs by generating bounded C++ string fragments, with deterministic delimiter handling and byte-for-byte preservation of locale source content (including CRLF).

### Upgrade Notes

- **Breaking change — Local state compatibility:** v0.6.0 is incompatible with v0.5.5 local SQLite databases and unfinished transaction journals. Complete all synchronizations using v0.5.5 and verify local and remote state before upgrading. Back up the complete profile and synchronized files; preserve `key.bin` and `config.toml`. After verifying the existing state, rebuild the incompatible local database and synchronize again with v0.6.0. Rebuilding discards the previous local accepted-history and Epoch rollback checkpoint, so deployments that require preserving that checkpoint should not use this procedure. No automatic migration is provided. `kasumi update` replaces the executable only and does not migrate this state.
- **Automation Handling of Exit Code 2**: `kasumi sync` exits with status code 2 when synchronization completes partially with pending materializations (accepted metadata, but missing remote payloads). Automated workflows should treat exit code 2 as a non-fatal partial synchronization. Pending materializations can be downloaded or repaired by a later synchronization once the required payloads are available.
- **Fsck Checkpoint Metadata**: `kasumi fsck` creates authenticated local checkpoint and progress metadata (`fsck_checkpoint.bin.enc`) in the profile directory to track audit progress across interruptions. Checkpoint metadata does not allow referenced payloads to skip cryptographic verification: every referenced payload is still downloaded and authenticated during audit runs.
- **Manual Data-Loss Operations**: `gc purge-quarantine` intentionally bypasses normal quarantine retention/reachability safeguards and can permanently remove the only remaining copy of referenced encrypted content. `gc repair-quarantine` removes eligible orphaned quarantine metadata, not missing payloads. Both require `--confirm-permanent-loss` and must not be treated as routine GC. `resolve-missing` publishes logical deletions for eligible unresolved content. Read the operational documentation before using any of them.

## [0.5.5] - 2026-09-19

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed a `Composition Mismatch` caused by modification-time drift on pre-existing equivalent files when publication is not required. Timestamps are now aligned during metadata restoration without triggering false-positive local divergence.

### Tests

- Added unit, integration, and end-to-end regression tests validating pre-existing equivalent file modification-time drift without publication, while preserving strict rejection of concurrent modifications.

## [0.5.4] - 2026-09-19

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Breaking Changes

- Overhauled remote history storage layout and protocol with privacy-preserving key-derived namespaces and canonical extensionless object identifiers. Backward compatibility with pre-0.5.4 remote layouts is not maintained and synchronization must be freshly re-initialized on all client machines.

### Added

- Isolated remote history objects (markers, commits, epochs, active writers, and maintenance barriers) within deterministic namespaces derived from the vault master key via HKDF/BLAKE3 to prevent unauthorized observation of commit graphs and activity cadences on shared storage.
- Added staged execution tracking (`Reconciling`, `Staging`, `Transferring`, `Finalizing`) and automated plan truncation for large file sets in `kasumi sync` and `kasumi status`.
- Added full English and Brazilian Portuguese (`pt-BR`) localization for remote health reports, marker validation, epoch verification, and orphan detection in `kasumi inspect`.

### Changed

- Eliminated plaintext file extensions (`.kcom`, `.head`, `.epoch`, `.writer`, `.probe`) across all remote storage operations in favor of canonical extensionless object naming.
- Standardized all internal error descriptions, assertion messages, and runtime diagnostic logging in English across the engine.
- Removed legacy directory fallback scans (`history/gc/v1/writers`), reducing round-trip remote listing overhead during garbage collection and epoch maintenance.

### Tests

- Added unit and integration test suites validating key-derived layout isolation, canonical object parsing, and concurrent GC barriers under partitioned namespaces.
- Updated all end-to-end sync, coordinator, and inspection tests, achieving a 100% pass rate across all 811 tests.

## [0.5.3] - 2026-09-10

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed a `Composition Mismatch` when synchronizing profiles where remote storage contains entries matching `.kasumiignore` (such as `desktop.ini`, `node_modules/`, `*.tmp`). Reconciler and diff now systematically evaluate ignore patterns, preserving local files while purging excluded paths from the shared remote namespace.

### Changed

- Decoupled payload auditing from garbage collection reachability analysis, avoiding redundant payload downloads and significantly reducing GC duration. Cryptographic payload integrity verification is performed exclusively by `fsck`.
- Added pre-destructive remote listing verification before quarantine and purge in garbage collection to prevent races against concurrent modifications.

### Tests

- Added unit and end-to-end regression tests validating ignore pattern evaluation in 3-way reconciliation, remote cleanup of excluded entries, and composition consistency across Linux, MSYS2, and MSVC.
- Added unit, integration, and operational live benchmarks validating garbage collection reachability, quarantine staging, and retention policies.

## [0.5.2] - 2026-09-08

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

### Fixed

- Fixed a `Composition Mismatch` caused by modification-time drift on equivalent files. Shared rows are now synchronized with the current local tree before reconciliation, allowing unrelated changes to be published.
- Prevented hybrid scanner rows containing metadata from one file state and content from another when a file changes during hashing.
- Retried unstable local observations and safely aborted synchronization after repeated concurrent changes, without publishing partial state.

### Tests

- Added scanner, synchronization, and end-to-end regressions for concurrent file mutation and equivalent-file modification-time drift across Linux, MSYS2, and MSVC.

## [0.5.1] - 2026-09-05

Patch release of Kasumi.

### Fixed

- Fixed Windows path handling issues that could cause incorrect filesystem path processing.
- Improved Unicode path handling on Windows.
- Improved cross-platform path normalization behavior.

## [0.5.0] - 2026-09-04

Initial public release of Kasumi.

### Added

- Multi-master bidirectional synchronization across multiple machines through shared storage without a dedicated Kasumi coordination server.
- Immutable history commits stored in a DAG, allowing concurrent publications to form branches that are reconciled deterministically without an exclusive global synchronization lock.
- Client-side authenticated encryption via XChaCha20-Poly1305 (Monocypher) with per-vault master keys.
- Blinded remote identifiers preventing original file paths and filenames from being used directly as remote object identifiers.
- Storage backends for local filesystems, network shares, and rclone-compatible remotes.
- Encrypted transaction journal for tracking and recovering interrupted synchronization operations.
- Epoch-based retention and maintenance protocol for history lifecycle and garbage-collection coordination.
- `kasumi fsck` for remote and history integrity verification, and `kasumi gc` for garbage collection with quarantine staging.
- Incremental file observation using persisted fingerprints, cached BLAKE3 hashes, and NTFS USN Change Journal integration on Windows.
- CLI commands for profile configuration, synchronization, inspection, maintenance, and dry-run simulation, with English and Portuguese localization and external JSON locale catalogs.
- Native builds for Linux and Windows.
- CMake install target for local installation.
