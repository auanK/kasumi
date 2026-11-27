# Kasumi v0.30.4

## Highlights

- **Remote Vault Thumbnails & Preview-Saved Cache**:
  - Added remote raster image thumbnail fallback (up to `5 MiB` in icon grids and `32 MiB` when clicked to preview) backed by a bounded per-profile in-memory LRU `RemoteThumbnailCache` (`24 MiB` / `512` thumbnails, cleared on profile lock or key/remote change) and throttled remote fetches (max `2` concurrent overall, `1` per profile, plus max `2` concurrent unseen items in the Web UI grid).
  - Clicking to preview a remote image or video saves its `160px` thumbnail into the cache (server-side for raster images and client canvas frame upload via `POST /v1/remote/{profile}/thumbnail` for videos), updating the explorer icon immediately.
- **Epoch & Head Marker Caching (`CommitCache`)**:
  - Added in-memory verified epoch caching (`max_epoch_entries = 128`) plus sealed `KEPA\x01` encrypted disk caching (re-authenticated via `epoch::open` with automatic corruption self-healing), RAM caching of validated head marker IDs (`max_validated_markers = 512`), and automatic pruning of deleted commits from daemon RAM on complete `commits/` listings.
- **Instant Historical Snapshots & Diffs from Daemon RAM**:
  - Served historical `/v1/remote/{profile}/tree?commit=...` and `/v1/remote/{profile}/diff?from=...&to=...` directly from already authenticated commits in daemon RAM `CommitCache` with zero cloud calls, while supporting `?refresh=1` for explicit live revalidation.

## Compatibility

100% compatible with repositories, CLI commands, `--json` contracts, `config.toml`, and local/remote state created by `v0.19.x`–`v0.30.3` (`KCOM` v4, `KACT` v1, `KPAK\x01`, `state.db` v2, `transaction.bin.enc`).

## Installation

Download the installer or portable archive for your platform (`kasumi-v0.30.4-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
