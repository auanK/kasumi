# Remote Storage and Maintenance

The remote is a passive store of keyed content IDs, encrypted Commit variants, physical HEAD markers, Epochs, and maintenance controls. [Remote Layout and Publication](remote-layout.md) owns object identities and publication order; [Transport](transport.md) owns required operations and optional provider capabilities.

The two maintenance commands have different lifecycles and verification targets:

| Operation | Architectural flow |
|---|---|
| [`fsck`](fsck.md) | Recover a pending Sync transaction; authenticate history/namespace; audit **every referenced content payload** with AEAD, logical hash, and size; retain only private checkpoint metadata. No GC mutation. |
| [`gc`](garbage-collection.md) | Recover a pending Sync transaction; establish a writer-excluding barrier and provider visibility; validate stable reachability including Epoch anchors; restore, quarantine, or eventually purge physical objects. No full Fsck payload audit. |

[Remote Inspection](remote-inspection.md) exposes logical, physical, and maintenance diagnostics without entering either maintenance flow. In particular, [`remote health`](remote-maintenance-inspection.md) is a diagnostic composition and [`remote contents --audit`](remote-content-inspection.md) is a payload inspection report, not Fsck.
