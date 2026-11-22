# Kasumi v0.21.1

This patch release refines persistent `--log-file` and structured `--json` outputs introduced in `v0.21.0`, making both human-readable logs and lightweight automation scripts work cleanly out of the box without any protocol or storage format changes.

## Highlights

- **Readable, complete `--log-file` entries.** Plain-text logs now use local timestamps with explicit UTC offset, clear status tags (`[OK]`, `[WARN]`, `[PARTIAL]`, `[LOCKED]`, `[CANCELLED]`, `[ERROR]`), ANSI-free compact summaries (`Everything in sync`, `3 changes | ↑ 2 (2 KB) | ↓ 1 (512 bytes)`, `4 objects verified (1 MB)`), execution duration, and indented detail lines (pending paths, warnings, unhealthy diagnostic details) written atomically per command.
- **Additive `timestamp` and `data.summary` in `--json`.** Every `--json` envelope (`schema_version: 1`) and NDJSON log entry now includes an RFC 3339 UTC `timestamp`, and command `data` payloads include a language-independent `summary` string alongside all existing raw byte counts, object metrics, and arrays.

## Compatibility and installation

- Protocol and local state formats remain `KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` schema v2, `transaction.bin.enc`, and `config.toml`, staying 100% compatible with `v0.19.x` and `v0.21.0` vaults and local databases. Existing `--json` schemas remain backwards-compatible (`timestamp` and `data.summary` are purely additive). See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.21.1/docs/best-practices.md#upgrading-kasumi).
- Download the archive for your platform (`kasumi-windows-x86_64.zip` or `kasumi-linux-x86_64.tar.gz`), verify its SHA-256 checksum and GitHub build provenance attestation (`gh attestation verify`), and replace the executable manually.
