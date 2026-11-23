# Remote Storage and Maintenance

The remote is a passive store of keyed content IDs, encrypted Commit variants, physical HEAD markers, Epochs, and maintenance controls. [Remote Layout and Publication](remote-layout.md) owns object identities and publication order; [Transport](transport.md) owns required operations and optional provider capabilities.

The maintenance paths have different lifecycles and verification targets:

| Operation | Architectural flow |
|---|---|
| [`fsck`](fsck.md) | Recover a pending Sync transaction; authenticate history/namespace; audit **every referenced content payload** with AEAD, logical hash, and size; retain only private checkpoint metadata and publish a best-effort `KACT` v1 activity record. No GC mutation. |
| [`repack`](repack.md) | Refuse a dirty workspace or pending journal (recovering or inspecting read-only on `--dry-run`); consolidate loose small files and fragmented `KPAK\x01` Micro-Packs from verified local files with zero remote downloads or deletions; publish a tree-preserving `KCOM` Commit with an updated `StorageManifest` under cooperative writer registration. |
| [`gc`](garbage-collection.md) | `--dry-run`: read-only preview without barrier mutation or deletion. Real run: direct deletion of eligible orphan Content, redundant CommitVariants, expired unreachable Commits behind Epochs, and pruned `KACT` activities, plus `KACT` v1 activity publication. The contract covers pre-barrier read-only busy checks (`remote_busy`), unique multi-barrier publication with settle delay and legacy barrier interop, remote-clock fail-closed `--min-age` clamping, one authenticated observation including Epoch anchors, global plan validation, periodic mid-`Apply` exclusivity revalidation, transport-acknowledged removal accounting, and partial-failure diagnostics. Cooperative controls do not replace distributed CAS/fencing on passive storage; reserve `--min-age 0` for manual offline maintenance with Sync stopped. No full Fsck payload audit. |

[Remote Inspection](remote-inspection.md) exposes logical, physical, and maintenance diagnostics without entering either maintenance flow. In particular, [`remote health`](remote-maintenance-inspection.md) is a diagnostic composition and [`remote contents <profile> --audit`](remote-content-inspection.md) is a payload inspection report, not Fsck.
