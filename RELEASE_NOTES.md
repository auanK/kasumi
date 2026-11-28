# Kasumi v0.32.0

## Highlights

- **Periodic GC reclaims superseded history**:
  - GC can advance retention once replaced versions pass both the configured depth and age (five generations and six hours by default). It preserves current files, shared chunks and merge bases needed by concurrent branches. Use `kasumi gc <profile> --dry-run` to preview reclamation. [Garbage collection](docs/architecture/garbage-collection.md)
- **Concurrent Sync with a defined first-writer rule**:
  - Initialize an empty destination on one device. Once that device finishes, other devices can enroll and publish concurrent changes. Overlapping writes on an established vault can produce separate heads and preserved conflict files.
- **Stronger continuity checks during recovery and GC**:
  - An empty remote Epoch listing cannot erase an accepted checkpoint. GC stops when the remote inventory contradicts the collector's accepted history. Recovery can finish an already committed transaction after a peer legitimately prunes its old HEAD.
- **Safer local operations**:
  - Verified profile creation checks connectivity and credentials before the profile becomes visible. An interrupted deletion reserves the name until cleanup finishes. Restore preserves a file that appears at the destination during installation and identifies partial progress.
- **More predictable background operation**:
  - The daemon keeps watcher events received during Sync, detects a busy listener before advertising its address, and ends waiting requests when a profile is paused before dispatch.

## Compatibility

The 0.32 writer keeps the existing `KCOM` v4 commit, `KHED` v2 marker, `KPAK` v1 pack and authenticated Epoch v1 formats. The change affects when clients may publish or delete. Upgrade all writers sharing a destination. A legacy writer can still publish a pruning Epoch, and upgrading does not repair an existing fork. Preserve the remote objects and each device's checkpoint if two Epoch IDs claim one sequence. [Protocol and upgrade boundaries](docs/architecture/protocol-0.32.md#compatibility-and-change-control)

## Installation

Before upgrading, finish any pending Sync recovery with a compatible reader and back up your profile state and vault data.

Download the installer or portable archive for your platform (`kasumi-v0.32.0-windows-x86_64.msi`, `.zip`, `.deb`, `.rpm`, `.pkg.tar.zst`, or `.tar.gz`), verify it against `SHA256SUMS.txt` or `gh attestation verify`, check `kasumi --version` (or `kasumi version`), and run `kasumi web` to open the embedded Web UI.
