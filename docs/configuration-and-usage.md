# Configuration and Usage

For a first profile and two-machine setup, follow [Getting Started](getting-started.md).
This page is the command and configuration reference.

- [Profile Setup](#profile-setup) and [Configuration File](#configuration-file)
- [Core Commands](#core-commands) and [Updating Kasumi](#updating-kasumi)
- [Remote Inspection](#remote-inspection)
- [General Options](#general-options) and [Language Selection](#language-selection-i18n)
- [Environment Variables](#automation--environment-variables) and [Exit Codes](#exit-codes)
- [.kasumiignore](#kasumiignore) and [Synchronized Path Rules](#synchronized-path-rules)

## Profile Setup

Launch the interactive configuration wizard:

```powershell
kasumi config
```

A configuration read failure returns 1; cancellation or EOF at a wizard prompt
returns 130. EOF or interruption during a prompt stops before that profile
mutation.

The wizard lists profiles and allows creating, cloning, editing, renaming, and deleting them. It displays each profile's local state: `Initialized`, `Ready`, `Pending`, or `Problem`. During creation, it prompts for the profile name, local synchronized path, remote destination, Password, and Password Salt. Profile names contain only letters, digits, `_`, or `-`; the local path must be absolute. Cloning reuses configuration and the master key but creates fresh SQLite state without copying accepted history or remote data. Editing changes the configured local and remote paths, not the key. Renaming moves private profile state. Deleting removes local configuration, key, and state, while leaving the synchronized folder and remote objects intact. See [Profile Management](architecture/profile-management.md) for state meanings, the lifecycle, and rollback boundaries. For operational guidance, see [Best Practices](best-practices.md); for troubleshooting operational issues, see [Troubleshooting](troubleshooting.md).

* **Password**: Minimum 12 characters.
* **Password Salt**: Minimum 16 characters. A reproducible, user-provided passphrase used as the cryptographic salt for Argon2id key derivation (not an automatically generated or stored random salt). When configuring another machine for the same vault through the interactive wizard, use the same Password and Password Salt so that it derives the same vault master key.

For key derivation and storage details, see [Security Specification](security.md).

Accepted remote destinations include local filesystem paths, network shares, and rclone remote paths:

```text
D:/backup/kasumi
/mnt/backup/kasumi
drive:kasumi/my-profile
s3:my-bucket/kasumi-vault
```

`drive:` and `s3:` represent configured remote names in an external rclone configuration, not storage protocols natively implemented by Kasumi. The part after `:` must be a nonempty relative root without `..` components or a trailing slash. Local transport destinations must be absolute.

## Configuration File

Profiles are stored in `config.toml` within Kasumi's data directory.
* **Windows**: `%APPDATA%/kasumi`
* **Linux**: `$XDG_CONFIG_HOME/kasumi` or `$HOME/.config/kasumi`

If these environment paths are unavailable, the fallback is `.kasumi_data` in
the current directory. Private profile state lives under `profiles/<name>/`.
On Windows, prefer short synchronized and profile paths when long-path policy
is disabled. Internal staging paths can exceed the source path length even when
the source opens successfully; the embedded `longPathAware` manifest also needs
the host's `LongPathsEnabled` policy for long Win32 paths. See
[path diagnostics](troubleshooting.md#windows-path-exceeds-the-supported-limit).

```toml
[profiles.my-profile]
local_dir = "D:/Documents"
remote_dir = "drive:kasumi/my-profile"
min_history_depth = 5
min_history_age_hours = 6
```

New profiles default to a minimum retention depth of 5 commits and a minimum retention age of 6 hours. Manual editing of `config.toml` allows adjusting both values using positive integers; runtime operations limit depth to 4096. Unknown fields and missing required profile values are rejected rather than migrated. The local profile policy is used when planning or publishing retention state. Published authenticated Epochs carry the retention policy and anchors used by the remote history and maintenance protocol.

## Core Commands

Use `kasumi <command> --help` for the complete arguments, options and examples.

| Purpose | Command |
|---|---|
| Manage local profiles | `kasumi config` |
| Inspect the current plan | `kasumi status <profile>` or `kasumi sync <profile> --dry-run` |
| Synchronize | `kasumi sync <profile>` |
| Audit referenced payloads | `kasumi fsck <profile>` |
| Reclaim eligible remote storage | `kasumi gc <profile>` |
| Resolve permanently missing content as logical deletion | `kasumi resolve-missing <profile>` |
| Update the executable | `kasumi update` |

`--full` belongs only to Sync and Status, after the profile. It displays every
plan and pending-path item; otherwise lists longer than ten items show the first
and last five. Preview and Status do not execute the plan, recover transactions
or persist file-hash cache changes. See [Preview and Status](architecture/planning-and-status.md).

`sync --initial` requires no SQLite sidecars or unfinished transaction evidence.
It can bootstrap empty remote history or enroll into an authenticated vault.
`--trust-existing-content` requires `--initial` and empty remote history: it
reuses matching remote Content without payload verification, so audit it with
Fsck afterwards. See [Initial Sync](architecture/synchronization.md#initial-sync).

`sync --audit-inventory` runs Sync and then a structural inventory audit. It
cannot combine with `--dry-run` or `--initial`. The audit does not authenticate
payload bytes and its failure does not undo Sync's effects or publication.
See [Inventory Audit](architecture/synchronization.md#optional-remote-inventory-audit).

**GC permanently deletes eligible objects.** Stop Sync on every client and
serialize maintenance across the vault. Manual `gc remove-writer` requires an
exact marker whose process is verified inactive. `gc remove-barrier` requires
`--confirm-abandoned` after verifying no Sync or maintenance is active; barrier
age alone is insufficient. See the [GC operational contract](architecture/garbage-collection.md#operational-contract).

Fsck audits referenced payloads; transaction recovery before Fsck or GC can
have local and remote effects. Ordinary Sync only probes Content required by
its current work; a no-op is not a full integrity audit. See
[Synchronization](architecture/synchronization.md#required-content-availability).

### Updating Kasumi

Run the command with no command-specific arguments:

```sh
kasumi update
```

The command supports official Windows and Linux x86_64 binaries. Kasumi queries the official GitHub Releases API and selects the newest release on its supported channel: before a stable v1.0.0 release exists, this is the newest v0.x release, including prereleases; after a stable v1.0.0 or later exists, prereleases and v0.x releases are excluded.

Kasumi downloads the platform archive and its published SHA-256 checksum, verifies the archive, then replaces only the Kasumi executable. It keeps the previous executable beside it as a `.kasumi-previous-*` recovery copy. If verification of the replacement fails, Kasumi attempts to restore that copy; this is not a universal rollback guarantee. The updater does not access profile data, configuration files, keys, or configured remote storage, and it does not migrate local data.

On Windows, Kasumi uses the built-in `tar` command and starts a helper that waits for the original process to exit before replacing the executable. If installation permissions require administrator privileges and the current process lacks them, the updater cancels and instructs the user to run as administrator; it completes the update directly when permissions are sufficient.

Windows update duration ends at installer handoff, not at the separate installer's completion.
Cancellation is observed at safe stage boundaries and can wait for an ongoing native or network call.

On Linux, `curl`, `tar`, and `sha256sum` must be available. Kasumi installs without root when the executable's directory is writable. If permissions deny replacement, it attempts `pkexec`; it falls back to `sudo` only when authentication through `pkexec` is unavailable and the terminal is interactive.

Installations managed by a package manager must be updated through that manager.
Read [Upgrading Kasumi](best-practices.md#upgrading-kasumi) for compatibility
and backup requirements before replacing binaries.

### Partial Synchronization and Explicit Data-Loss Operations

When `kasumi sync <profile>` has unresolved missing payloads required by its current work, it records pending materializations and exits with status `2`. Treat this as **partial**, not full, synchronization. If a required Content object is absent, Sync can upload it when a compatible local source matches the expected hash and size; otherwise it preserves logical state and pending evidence. A no-op does not check for or repair unrelated missing objects, even if another local copy exists. Restore intact bytes from a client or independent backup so they are available when a later Sync operation needs them. Use `sync --audit-inventory` to identify broader structural absences and Fsck for payload integrity checks. Do not automatically convert status `2` into a deletion. Transport failures and LIST/PRESENCE disagreements fail the run rather than being classified as missing.

`kasumi resolve-missing <profile>` is an explicit, potentially destructive resolution path: it first recovers any pending synchronization transaction, then validates the accepted state and current observations and may publish logical deletions for eligible unresolved paths that have no local source. It is not a download/repair command. Use it only when losing those files is an informed decision.

### Interruption and Recovery

Synchronization records phase and progress in the private `transaction.bin.enc/`
journal directory: `snapshot.enc`, `transaction.log.enc`, `confirmed.enc`, and,
during retirement, `retired.enc`. `.transactions/<id>/` separately holds staging
and backups; these workspace files are not uniformly encrypted. Preserve both
directories when recovery fails. See the [journal format](architecture/transaction-journal.md).

If synchronization is interrupted:
* Sync, Fsck, `resolve-missing`, and GC inspect the existing local transaction journal before their own work. Preview, Status, remote inspection, and manual writer maintenance do not run this recovery path.
* Depending on the persisted phase and observed state, recovery may resume, rollback, or roll forward the transaction.
* Conflicting or indeterminate publication states are reported as recovery errors rather than assumed successful.
* Already present content objects may be reused when their identifiers and verification checks match the required content.
* A repair-only Sync uses the existing local-only transaction path: an interrupted repair may be resumed or rolled back without creating a new Commit or HEAD, and missing-source paths remain pending rather than being treated as deleted.

For the recovery state transitions, see [Transactions and Recovery](architecture/transactions-and-recovery.md).

### Concurrency & Multiple Profiles

* **Different Profiles Simultaneously**: Different profiles use separate local profile state, separate SQLite databases, and separate profile locks, and can be executed concurrently.
* **Same Profile Guard**: Running the same profile concurrently across multiple processes is prevented by an exclusive operating system file lock (`profile-<name>.lock` in Kasumi's data directory). A second process attempting to execute the same profile while the lock is held exits with an error indicating that the profile is in use. This local lock coordinates processes on a single machine and is distinct from remote multi-master writer coordination between different machines.

## Remote Inspection

These commands do not publish synchronization changes or run garbage collection. Complete-history inspection may maintain the local private `inspection-history-v1.cache`; `remote get` writes the requested destination after authenticating the payload. See [Remote Inspection](architecture/remote-inspection.md) for each family's data flow and failure behavior.

Use `kasumi remote --help` to choose a view, and
`kasumi remote <subcommand> --help` for its required arguments. For example:

```sh
kasumi remote summary Programming
kasumi remote tree Programming --head <commit>
kasumi remote contents Programming --audit
```

`contents` is a structural inventory; `contents <profile> --audit` downloads and
authenticates every physically present Content object, including orphans.
Fsck instead audits referenced content and has its own checkpoint/recovery flow.
See [Content Inspection](architecture/remote-content-inspection.md).

Commit and Content selectors require 64 lowercase hex characters. `tree --head`
selects a current logical head and is required for multiple heads. `stat` and
`get` use the resolved effective tree; `get` authenticates the requested file and
writes its explicit destination, whose parent must exist. Health diagnostics
are observations rather than a substitute for a payload audit.

## General Options

```text
kasumi [--lang <code>] <command> [subcommand] [arguments] [options]
```

`--lang <code>` is the optional global prefix, before the command. Command
options follow required arguments; `--full` is available only to Sync and Status.
`config` and `update` take no profile.

`kasumi --help` (`-h`) shows global Help. Add `--help` or `-h` after a command,
subcommand or otherwise valid invocation for contextual Help. Help returns 0
without credentials, transport, database access or locks. `--version` (`-v`)
prints the version. Calling without arguments shows Help and returns 1.

Unknown or duplicate options, missing values and incompatible combinations fail
before execution with a localized diagnostic and the relevant Help command on
stderr. Quote arguments containing spaces; pass `--` before an option-looking
path (such as `--notes.txt` or `-draft.txt`) to treat following arguments as
literal operands. Unicode spelling is preserved. On Windows, native command-line arguments are
converted to UTF-8 independently of the system ANSI code page; this does not
change the domain rules for profile names or synchronized paths.

## Operation Output

Each executed public operation prints one final elapsed-time line on stdout:
`Duration: 12.614 s` (English) or `Duração: 12.614 s` (Portuguese). A monotonic
clock measures real elapsed time in seconds with three decimal places, including
success, failure, pending results and cancellation. Sync has one duration line;
internal operational metrics are separate. Help, version and invalid invocations
have no operation duration.

Operation messages and errors use stdout; invocation diagnostics and optional
performance traces use stderr. Interpret the [exit code](#exit-codes) with the
output; partial results are not full success.

## Language Selection (i18n)

Kasumi defaults to **English**.

To switch to **Portuguese**:
* Command line: `kasumi --lang pt-BR <command> <profile>` (or `--lang pt`)
* Environment variable: set `KASUMI_LANG=pt-BR` (or `pt`)

To add a custom community language catalog, place `<lang>.json` in `%APPDATA%/kasumi/locales/` (Windows) or `$XDG_CONFIG_HOME/kasumi/locales/` (Linux; fallback `$HOME/.config/kasumi/locales/`) and select it with `kasumi --lang <lang> <command> ...`.

## Automation & Environment Variables

| Variable | Description |
|---|---|
| `KASUMI_LANG` | Sets CLI language (`en`, `pt-BR`, `pt`, etc.) |
| `KASUMI_MASTER_KEY` | Provides a 64-hex-digit master key to application/inspection operations. It does not replace the wizard's Password/Password Salt creation prompts. For an existing profile with `key.bin`, the supplied key must match the persisted key |
| `KASUMI_PASSWORD` | Provides the Password to the profile creation credential flow (minimum 12 characters) |
| `KASUMI_PASSWORD2` | Provides the Password Salt to the profile creation credential flow (minimum 16 characters) |
| `KASUMI_CONTENT_CONCURRENCY` | Sets content-transfer concurrency. Default: 8. Positive values above 16 are capped at 16; invalid or zero values use the default |
| `KASUMI_PERF_TRACE=1` | Writes operational trace metrics to `stderr` |
| `KASUMI_PERF_TRACE_LIVE=1` | With tracing enabled, emits live fsck audit-completion and checkpoint-write counters to `stderr` |

> [!NOTE]
> Once a profile is created, the derived 32-byte master key is persisted locally in `profiles/<profile>/key.bin` using a reversible XOR mask and operating system filesystem permissions. For existing profiles, routine operations use the persisted `key.bin` when no explicit `KASUMI_MASTER_KEY` credential is supplied. `KASUMI_PASSWORD` and `KASUMI_PASSWORD2` are used by the profile-creation credential flow and are not re-verified during routine synchronization operations. For details on the security boundaries and key storage, see [Security Specification](security.md).

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Successful operation |
| `1` | Invalid invocation or hard failure, including transport, permissions, authentication, or profile-lock errors |
| `2` | Partial synchronization: accepted metadata still has pending file materializations |
| `130` | User cancellation handled by Kasumi (SIGINT/SIGTERM) |

Treat code `2` as incomplete synchronization. Preserve pending paths, restore unavailable
content, and retry; do not turn it automatically into deletions. See
[Pending Materializations](troubleshooting.md#exit-code-2--pending-materializations).

## `.kasumiignore`

Create a `.kasumiignore` file in the root of the synchronized folder. The last matching rule takes precedence.

```text
*.tmp
!documents/important.tmp
cache/
**/draft?.txt
```

* `*` matches characters within a single path segment.
* `**` matches across directory boundaries.
* `?` matches a single character.
* Leading `/` anchors the pattern to the synchronization root.
* Trailing `/` restricts matching to directories.
* `!` negates the pattern (re-includes a path).
* Lines starting with `#` are comments.

Symlinks inside the synchronization root are not traversed.
Reserved private files at the synchronization root and generated transaction artifacts are excluded from synchronization. Generated artifacts use their exact current naming pattern. The `.kasumiignore` file itself can be synchronized; changes to its local or authenticated remote version can change the effective projection used for a run. See [Local Observation](architecture/local-observation.md).

## Synchronized Path Rules

Kasumi defines portable logical path rules for all entries admitted to the synchronized namespace. Entries excluded by `.kasumiignore` are not part of the synchronized namespace.

### Logical Paths and Components

* **Relative Hierarchy**: Logical paths are relative to the synchronization root and use `/` as their logical hierarchy separator.
* **Preserved Spelling**: Files and directories preserve their original UTF-8 spelling.
* **Valid UTF-8**: Each path component must contain structurally valid UTF-8.
* **Component Length**: Each path component is limited to a maximum of 255 UTF-8 bytes.
* **Disallowed Component Names**: A path component cannot be empty, `.`, or `..`.

### Prohibited Characters

A synchronized path component cannot contain:
* The ASCII characters `<`, `>`, `:`, `"`, `/`, `\`, `|`, `?`, or `*`;
* ASCII control characters `U+0000` through `U+001F`;
* The ASCII DEL character `U+007F`.

Additionally, a path component cannot end in an ASCII space (` `) or an ASCII period (`.`).

### Reserved Device Names

Device-name forms incompatible with the portable domain are rejected regardless of platform:
* `CON`, `PRN`, `AUX`, `NUL`
* `COM1` through `COM9`, as well as `COM¹`, `COM²`, and `COM³`
* `LPT1` through `LPT9`, as well as `LPT¹`, `LPT²`, and `LPT³`

This restriction applies both when the reserved device name constitutes the full component name and when it appears before an extension. For example, `CON`, `CON.txt`, `NUL.log`, `COM1.txt`, and `LPT².dat` are rejected.

### Portable Unicode Case Equivalence

Logical path spelling is preserved. However, two logical paths whose portable Unicode case keys are equal cannot coexist in the same synchronized snapshot.

The collision equivalence policy is:
* Platform-independent and locale-independent;
* Based on simple Unicode uppercase mapping;
* Backed by utf8proc 2.11.3;
* Defined using Unicode 17.0.0.

For example:
* `FILE.txt` and `file.txt` cannot coexist in the same snapshot;
* `Ä.txt` and `ä.txt` cannot coexist;
* `Ω.txt` and `ω.txt` cannot coexist.

Distinct names that do not collide under uppercase mapping, such as `日本.txt` and `日本2.txt`, are valid distinct paths.

Kasumi does not normalize Unicode filename spelling.
