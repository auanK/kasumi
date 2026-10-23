# Provider Certification

Provider certification checks a particular Kasumi build, rclone configuration,
provider account, and observed storage state. A report applies only to that
setup and run; it is not a guarantee for every account, configuration, or later
storage behavior.

## Requirements and limits

The transport contract requires initialization, PUT, GET, PRESENCE, full LIST,
and idempotent REMOVE. Online destructive maintenance also depends on completed
control and namespace changes being visible to the LIST and PRESENCE checks
used by its protocol. A runtime visibility probe tests one temporary object; it
cannot establish provider-wide consistency or rule out stale listings of older
objects. See [Transport](architecture/transport.md) and the
[GC operational contract](architecture/garbage-collection.md#operational-contract).

The certification runner exercises transport operations, synchronization, and
Fsck. **It does not run GC and cannot certify a provider as safe for destructive
maintenance.** GC requires a separate assessment of the provider's consistency
behavior under the assumptions in the architecture documentation.

Optional capabilities such as copy, batching, prefix listing, control-read
batches, and physical SHA-256 can improve transport performance. A missing
optional capability is reported as `Unsupported`, not as a failure. A provider
reported physical hash is a transport check, not cryptographic evidence against
a malicious provider. Lack of physical SHA-256 support is not itself a payload
integrity failure; operation-specific checks use verified byte readback or
cryptographic payload validation where required. See
[Transport](architecture/transport.md) and [Security](security.md).

## What the runner checks

The opt-in runner performs a required transport round-trip and exercises these
application scenarios in an isolated namespace:

| Scenario | Behavior checked |
|---|---|
| `transport-round-trip` | Required object write, read, presence, listing, and removal |
| `bootstrap-publish`, `bootstrap-second-client` | Initial history publication and reading it from another client |
| `bidirectional-update`, `no-op`, `logical-delete` | Updates in both directions, unchanged synchronization, and logical deletion |
| `two-client-conflict` | Preservation and resolution of concurrent file changes |
| `partial-missing`, `publication-while-missing`, `restore-pending` | Pending content behavior while payloads are unavailable and when they return |
| `local-source-repair` | Repair of missing remote content from a matching local file |
| `fsck-healthy`, `fsck-missing`, `fsck-corrupt` | Detection of healthy, missing, and corrupted referenced content |
| `cleanup` | Removal of the namespace owned by the run |

This is operational integration coverage for the tested transport and build.
It does not prove behavior under every workload, every concurrent mutation, or
provider-internal failure mode.

## Build and run

Build the runner with tests enabled:

```powershell
cmake -S . -B build-provider-cert -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON -DKASUMI_BUILD_PROVIDER_CERTIFICATION=ON
cmake --build build-provider-cert --target kasumi_provider_certification
```

The local target uses a unique temporary directory:

```powershell
& .\build-provider-cert\kasumi_provider_certification.exe --target local --output "$env:TEMP\kasumi-cert-results\local.json"
```

For an rclone provider, install rclone and create a TOML target entry. Set
`remote` to the configured rclone remote name without a colon, and create or
verify the dedicated, non-root parent path before running:

```toml
[[targets]]
id = "drive"
provider_id = "google-drive"
remote = "drive"
authorized_parent = "drive:kasumi/provider-certification"
```

Set `RCLONE_CONFIG` to the configuration containing that remote, then run:

```powershell
$env:RCLONE_CONFIG = 'C:\private\rclone.conf'
& .\build-provider-cert\kasumi_provider_certification.exe --target rclone --config C:\private\provider-certification.toml --target-id drive --output C:\private\drive-certification.json
```

The runner creates a unique child beneath `authorized_parent`, writes and
removes test objects there, and cleans up only the namespace it owns. Do not
point it at a Kasumi vault or a location containing data you need. The report
must be written outside the test namespace; choose an output path outside the
repository when keeping it as run evidence. By default, a failed run still
attempts cleanup. `--preserve-evidence-on-failure` intentionally leaves the
owned test namespace for investigation.

## Reading results

The process exits `0` only when required transport operations, checks for
exposed capabilities, scenarios, and cleanup succeed. Unsupported optional
capabilities are acceptable; a failed capability check fails the report.
Exit `1` means the report failed; exit `2` means setup, arguments, or report
writing failed.

The JSON report records the provider ID, transport, platform, overall status,
cleanup status, optional capabilities, scenario statuses and diagnostics.
Scenario states are `Pass`, `Fail`, `Blocked`, or `NotRun`; a setup failure can
block scenarios that were not reached. Capability states are `Supported`,
`Unsupported`, or `Failed`. Investigate every failure or blocked scenario.
Unsupported optional capabilities are expected when the backend does not
implement them.

Keep the report with the exact Kasumi build identity, rclone version and
configuration, provider account/region, and relevant storage settings. A pass
does not establish a performance bound, payload integrity for all stored data,
protection against a malicious provider, or suitability for online GC.
