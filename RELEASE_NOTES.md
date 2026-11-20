# Kasumi v0.18.0

This release adds `kasumi repack` for local-first `KPAK\x01` Micro-Pack consolidation without downloading remote payloads or deleting remote objects.

## Highlights

- **Local-first Micro-Pack consolidation (`kasumi repack <profile>`).** Consolidates loose small files (`<= 256 KiB`) and underfilled Micro-Packs (`< 2 MiB`) into `4 MiB` target packs directly from verified local files, publishing a tree-preserving Commit with an updated `StorageManifest` under cooperative writer registration. Other enrolled clients fast-forward cleanly without re-downloading unchanged files, and fresh `sync --initial` clients enroll directly into the consolidated packs.
- **Zero-I/O dead-space detection and opt-in large-pack reclamation (`--reclaim-dirty`).** The repack planner detects dead (deleted or overwritten) members inside immutable remote packs by recomputing the canonical pack hash over remaining live members. Large fragmented packs (`>= 2 MiB` live bytes with dead blobs) are reported and skipped by default to avoid upload amplification, and are rewritten when `--reclaim-dirty` is passed.
- **Dry-run preview, detailed inventory (`--full`), and bounded staging windows.** `--dry-run` previews the consolidation plan read-only (refusing pending Sync journals without mutating state), `--full` displays the pack inventory breakdown and published commit details, and execution stages, uploads, verifies, and cleans up new packs in bounded 16-pack windows (`~64 MiB` per window). Replaced packs remain protected by history retention until removed later by `kasumi gc <profile>`.
- **Prompt POSIX `SIGINT` handling in `kasumi config`.** Interactive terminal line reads now poll `STDIN_FILENO` with bounded timeouts so an interrupt arriving immediately after prompt flush exits cleanly with status `130`.

## Compatibility and installation

- Existing Protocol v3 vaults open directly with v0.18.0. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.18.0/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
