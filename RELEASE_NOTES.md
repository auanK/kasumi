# Kasumi v0.15.1

Cleaner interactive terminal progress, transfer speed summaries, and streamlined profile wizard prompts.

## Highlights

- Default `sync` keeps only one aggregated transfer line under `[3/5] Applying changes...` (no repeated per-batch lines or empty staging metrics), erases transient scan progress on completion, and shows `Speed: avg | min | max` right below finished transfers.
- `--full` restores per-stage progress lines across all stages and prints the physical `Wire upload | wire download | locally reused` summary at the end of Sync.
- `fsck`, `gc`, `status`, `remote`, and `update` keep real-time progress during long operations, with average/min/max speeds reported after completed byte transfers.
- Entering an invalid menu choice in `kasumi config` re-prompts directly on `>` instead of reprinting the entire profile table.

## Compatibility

- `v0.15.1` uses the same Protocol v3 vault format, flat commit layout, transaction journal v10, and profile configuration as `v0.15.0`. Follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).
