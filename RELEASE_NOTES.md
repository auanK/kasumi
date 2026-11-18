# Kasumi v0.14.0

Storage protocol v3 and performance release introducing in-memory Zstandard chunk compression, `KPAK\x01` Micro-Packs for small files, FastCDC content-defined chunking with block-level delta uploads and downloads for large files, flat single-list remote commit discovery, and runtime/security hardening.

## Highlights

- **Protocol v3 (`KASUMI\x03\x00`) with Zstandard compression:** Stream encryption splits payloads into `1 MiB` chunks, compresses each chunk in RAM with Zstandard (`zstd` level 1) before XChaCha20-Poly1305 encryption when compression reduces size by more than 32 bytes, binds a 1-byte `FilePurpose` (`Content`, `History`, `Pack`) into the authenticated 57-byte header, and authenticates a 5-byte chunk prefix (`flags` + wire size).
- **Micro-Packs (`KPAK\x01`) and `StorageManifest` (`KCOM` v3):** Small uploaded files (`<= 256 KiB`, excluding `.kasumiignore`) are grouped into encrypted, content-addressed Micro-Packs up to `4 MiB` under domain-separated `Pack` subkeys and identifiers, eliminating small-file remote request bottlenecks. Commits use `KCOM` v3 and carry a canonical `StorageManifest` mapping logical file hashes to physical Pack IDs or chunk slices.
- **FastCDC content-defined chunking and delta transfers:** Files larger than `8 MiB` are segmented with a normalized Gear rolling hash (`256 KiB`–`4 MiB`, `1 MiB` average). Only modified chunks are uploaded or downloaded; downloading clients automatically seed unchanged chunks from the local target file or local rename/copy donors before fetching missing chunks in parallel.
- **Flat remote commit layout and runtime acceleration:** Remote commits are published at `<history-ns>/<commits-ns>/<commit-id>_<ciphertext-id>` for single-listing discovery, accompanied by `rclone rcd` HTTP keep-alive connection pooling, single-list chunk presence probing, Windows BCrypt SHA-256 acceleration, Win32 bulk directory scans, parallel hashing and staging, and TOCTOU/manifest security hardening.

## Compatibility

- Kasumi does not guarantee cross-release backward compatibility prior to `1.0`. `v0.14.0` requires Protocol v3 (`KASUMI\x03\x00`), `KCOM` v3 commits, flat `<commit-id>_<ciphertext-id>` commit paths, transaction journal format 10, and an explicit `key_storage` field (`vault`, `file`, or `memory`) on every profile in `config.toml`.
- Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi). `kasumi update` replaces only the executable and does not migrate data or guarantee cross-release compatibility.
