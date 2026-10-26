# Remote Storage and Maintenance

The remote is a passive store of keyed content IDs, encrypted Commit variants, physical HEAD markers, Epochs, and maintenance controls. [Remote Layout and Publication](remote-layout.md) owns object identities and publication order; [Transport](transport.md) owns required operations and optional provider capabilities.

The maintenance paths have different lifecycles and verification targets:

| Operation | Architectural flow |
|---|---|
| [`fsck`](fsck.md) | Recover a pending Sync transaction; authenticate history/namespace; audit **every referenced content payload** with AEAD, logical hash, and size; retain only private checkpoint metadata. No GC mutation. |
| [`gc`](garbage-collection.md) | Direct deletion of authenticated orphan Content and redundant CommitVariants of reachable Commits. The contract covers a cooperative barrier, observed writers, probe visibility, one authenticated observation including Epoch anchors, global plan validation, transport-acknowledged removal accounting, and partial-failure diagnostics. Sync must be stopped and maintenance serialized across clients; barrier/probe checks do not prove distributed exclusion or provider-wide consistency. No full Fsck payload audit and no whole-unreachable-Commit collection. |

[Remote Inspection](remote-inspection.md) exposes logical, physical, and maintenance diagnostics without entering either maintenance flow. In particular, [`remote health`](remote-maintenance-inspection.md) is a diagnostic composition and [`remote contents <profile> --audit`](remote-content-inspection.md) is a payload inspection report, not Fsck.
