# Provider Certification

Provider evidence is specific to a source/build, configuration, workload, and
observed storage state. Synchronization results, optional physical-hash support,
payload integrity, and destructive-maintenance consistency are separate claims.

## Direct GC Validation — October 2026

### Optimized GC on Google Drive

Google Drive/rclone runs measured direct GC during optimization. Timings are
workload samples, not provider performance bounds:

| Authenticated candidates | GC duration (seconds) | GETs | Authenticated history reconstructions |
|---:|---:|---:|---:|
| 64 | 315.045 | 99 | 1 |
| 128 | 317.600 | 163 | 1 |
| 256 | 664.031 | 291 | 1 |
| 512 | 1,080.898 | 547 | 1 |
| 1,024 | 2,353.050 | 1,059 | 1 |

The final campaign ran on **2026-10-22** with
MSVC Release x64 from source
[`5ab238c`](https://github.com/auanK/kasumi/commit/5ab238c048604bd97c7b5b9cae906f6a607fa5ae),
whose project version was still 0.7.0. Its executable SHA-256 was
`7496e3c5ade7026022b8157d6a29e4f86e204567b04f19a8506d8a06797ade68`.
Earlier rows come from separate builds recorded in their campaign archives.

The final workload had 33 reachable Commits, 4,096-byte payloads, retention
depth 64 / age 6 hours, and 1,024 authenticated candidates. GC exited 0 with
`KASUMI_PERF outcome=success`, 1,024 attempts/acknowledgments, no uncertain
mutations, and one authenticated history reconstruction. Applying was
sequential; no candidate readback was used to count acknowledgments.

Post-run read-only physical reconciliation matched exactly:

| Reconciliation | Result |
|---|---:|
| Physical objects before / after | 1,092 / 68 |
| Candidate IDs remaining | 0 |
| Unexpected objects / missing expected protected objects | 0 / 0 |
| Maintenance barrier / writers | Absent / 0 |

The final set was the pre-GC inventory minus the exact candidate manifest.
Thirty-one older variants were deleted and 31 new variants retained as part
of the globally protected alternatives, not an unexpected deletion pattern.
No full post-campaign Fsck was run: acknowledgment and exact physical-set
reconciliation do not independently certify every payload cryptographically.

The external runner initially misclassified this successful GC because it
expected an absent progress message. Offline validation corrected the parser;
the original raw evidence and physical reconciliation were preserved.

### Local Regression Validation

The following results used
[`40aa01f`](https://github.com/auanK/kasumi/commit/40aa01f993b4b4db2a3a15bacb1adc7eb569c31d)
plus the test/release-infrastructure patch, before the 0.8.0 version bump:

| Configuration | Passed | Skipped | Disabled | Failed | Critical gate |
|---|---:|---:|---:|---:|---:|
| GCC 14.2 / MSYS2 UCRT64 Debug | 1,559 | 13 | 1 | 0 | 46/46 |
| MSVC 2022 Debug | 1,560 | 12 | 1 | 0 | 46/46 |
| MSVC 2022 Release | 1,560 | 12 | 1 | 0 | 46/46 |
| GCC 15.2 / WSL2 Debug | 1,533 | 12 | 1 | 0 | 46/46 |

The disabled test was preexisting. No release-critical test was skipped or
disabled. These are local results for the recorded source state.

## Google Drive Operational Validation — 0.7.0

The 2026-10-15–16 campaign used real Google Drive through rclone, Windows 11,
and Ubuntu under WSL2 with its local tree on ext4. Two independently configured
profiles exchanged changes in both directions within an isolated test vault.
The results apply to that two-client setup.

### Source and build identity

The campaign began at
[`913317f`](https://github.com/auanK/kasumi/commit/913317f8baf9523c8c5cc5a64e7b497231877636).
Simultaneous sibling-head publication exposed an ancestry-validation defect.
After the fix, locally rebuilt Release binaries resolved the existing heads and
passed a repeat of the simultaneous-publication scenario. That correction and
its regression test are committed in
[`e1a0ce3`](https://github.com/auanK/kasumi/commit/e1a0ce3c74762b0bc00931377aae4dc35ff117f0).
The initial SHA does **not** contain the fix; the campaign combines pre-fix
scenarios and post-fix reruns, rather than a complete rerun at the final SHA.

Hosted CI is a separate gate. As checked on 2026-10-16, the corrected commit's
[Ubuntu run](https://github.com/auanK/kasumi/actions/runs/38844759389) and
[Windows run](https://github.com/auanK/kasumi/actions/runs/38844759361) both
completed successfully. Their five toolchain jobs passed Debug and Release
builds/tests: Ubuntu GCC 14 and Clang 19; Windows MSVC 2022, GCC/UCRT64, and Clang64.
The earlier stabilization commit also passed its
[Ubuntu](https://github.com/auanK/kasumi/actions/runs/38831613296) and
[Windows](https://github.com/auanK/kasumi/actions/runs/38831613310) CI; those earlier
results alone do not establish the later fix's status.

### Observed coverage and limits

| Area | Evidence established by the campaign | Limit |
|---|---|---|
| Initialization and bidirectional Sync | Upload, download, update, rename, delete, Unicode paths, and subsequent no-op runs | Two clients on the recorded Windows/WSL2 setup |
| Large content | Initial transfer of 1, 10, and 100 MiB files, plus a real 100 MiB update; cross-client BLAKE3 and SHA-256 matched | The interrupted large-file scenario used **10 MiB**, not 100 MiB; timings are run-specific |
| Concurrency | File conflicts, independent edits, simultaneous sibling HEADs, post-fix resolution and repeat convergence | Multiple HEADs are normal; no global writer lock or universal conflict-free guarantee |
| Interruptions | Abrupt Windows process termination, Linux SIGKILL, transport termination, unreachable proxy endpoint, and later successful Sync | Process/transport failure tests do not simulate physical power loss; one download-failure attempt stopped during observation |
| Integrity | Both clients' Fsck audits passed; physical content audit authenticated all 36 then-present payloads, including retained historical versions | Fsck checked 27 current-tree payloads at that point, and 120 after later workload changes; these are not total protocol-object counts |
| Writer maintenance and GC (historical) | GC refused observed abandoned writers; six markers were removed after operational checks, then GC completed with **0 candidates, 0 quarantined, 0 restored, 0 purged**; subsequent Fsck passed | This campaign used the former quarantine collector with no candidates; it demonstrated no eligible-object purge, restoration, or corruption repair. |
| Volume | 100 small files in ten directories, update of 25 files, final cross-client manifest equality and no-op convergence | A workload sample, not a scalability bound |

The evidence is the campaign's `large-file-results.md`, `concurrency-results.md`,
`recovery-results.md`, `network-failure-results.md`, `integrity-results.md`,
`retention-results.md`, `performance-results.md`, and their original stage/final
logs and hash manifests. The final Fsck total changed after seven large test
files were logically deleted and the 100-file workload was added; historical
payloads remained in storage. Public performance guarantees cannot be inferred
from these runs. Detailed raw evidence remains in the external certification
archive, outside the source repository.

## Historical Multi-Provider Validation — 0.6.0

The recorded provider-neutral certification runs cover the following storage
backends. Every listed provider passed all 16 scenarios of that historical
campaign and completed ownership-safe cleanup; see the
[changelog's validation record](../CHANGELOG.md#060). These are historical
results, not certification of every later binary or provider configuration.
The current runner has 15 scenarios after removal of `gc-lifecycle`; it does
not certify GC behavior.

| Provider | Remote physical SHA-256 |
|---|---|
| Local Filesystem | Unsupported |
| Google Drive | Supported |
| OneDrive | Unsupported |
| SFTP | Not recorded |
| FTP | Unsupported |
| Explicit FTPS | Unsupported |
| WebDAV | Unsupported |
| Dropbox | Unsupported |
| Backblaze B2 | Unsupported |
| Azure Blob Storage | Unsupported |
| S3-compatible (MinIO) | Unsupported |

`physical_hash` is an optional transport optimization. In these historical runs,
providers without remote SHA-256 were validated through Kasumi's verified
fallback path; unsupported hash capability is not a payload-integrity failure.

## Maintenance and Integrity Boundaries

The provider matrix records optional physical-hash support, not the consistency
required for destructive maintenance. See [Transport](architecture/transport.md)
for backend requirements and [Garbage Collection](architecture/garbage-collection.md#operational-contract)
for the maintenance procedure.

Fsck, physical content audits, and provider SHA-256 cover different checks; a
provider-reported hash is not proof against a malicious provider. Keep
[independent backups](best-practices.md#backups).
