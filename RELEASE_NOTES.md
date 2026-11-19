# Kasumi v0.17.1

This release makes it easier to see what Kasumi is doing during planning, synchronization, and maintenance.

## Highlights

- **Planning shows what is happening.** Sync, Status, and dry-run show the current planning step. In Sync, this includes checking remote content availability and preparing changes. The terminal shows counts when the total is known and elapsed time when an ETA is unavailable.
- **Sync tracks the whole plan.** Sync and Resolve Missing show the number of confirmed changes out of the current plan. A second line shows the active file when its progress can be measured separately. Shared transfers show batch bytes, speed, and ETA when available. A checkpoint can confirm multiple changes together. Transfer metrics stay under Applying changes. Publication and finalization are displayed as they begin.
- **The default summary includes transfers.** Sync reports encoded upload and download bytes, physical object counts, and data reused locally. Use `--full` to retain more per-activity detail and list every plan item and pending path.
- **Audits and cleanup show meaningful totals.** FSCK reports verified plaintext and the bytes and objects downloaded. Garbage collection reports the size of the remote listing, candidates found, and confirmed removals with their rate. Remote content audit progress counts completed checks that find invalid or missing content.

## Compatibility and installation

- Existing Protocol v3 vaults open directly with v0.17.1. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.17.1/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
