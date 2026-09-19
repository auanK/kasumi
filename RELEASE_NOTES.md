# Kasumi v0.5.4

Feature and protocol release of Kasumi.

Kasumi - Multi-client bidirectional file synchronization with client-side encryption over any cloud storage, without a dedicated server.

## Breaking Changes

- **Protocol Change — Synchronization Must Be Redone:** v0.5.4 introduces obfuscated, key-derived remote history namespaces and canonical extensionless storage objects (`.kcom`, `.head`, and `.epoch` have been removed). Because Kasumi is in pre-1.0 and does not carry legacy compatibility layers, **all client machines must re-synchronize (re-initialize profiles)** against remote storage.

## Highlights

- **Key-Derived Namespaces (Metadata Privacy):** Remote history objects (markers, commits, epochs, writers, GC barriers) are now partitioned and hashed under namespaces derived cryptographically from the vault master key, hiding commit frequency, graph topology, and marker identities from unauthorized observers on cloud storage.
- **Canonical Extensionless Protocol:** Completely removed plaintext file extensions and legacy directory fallbacks across remote layouts, eliminating technical debt and simplifying object discovery.
- **Staged CLI Progress & Plan Summarization:** Modernized `kasumi sync` and `kasumi status` with staged visual progress (`Reconciling` -> `Staging` -> `Transferring` -> `Finalizing`) and automated plan truncation for clean terminal output.
- **Internationalized Remote Inspection:** Full English and Brazilian Portuguese (`pt-BR`) support for remote health reports, marker validation, epoch checks, and orphan detection, alongside standardized internal engine diagnostics in English.

## Downloads

- `kasumi-linux-x86_64.tar.gz`
- `kasumi-windows-x86_64.zip`
- `SHA256SUMS.txt`

Individual SHA-256 checksum files are also provided for each archive.

GitHub artifact attestations are generated for the release archives and
`SHA256SUMS.txt`.

See `CHANGELOG.md` for the complete v0.5.4 change summary.
