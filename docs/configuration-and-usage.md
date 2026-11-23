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

With an empty profile list, the wizard offers New and Quit. Type `:back` at a
profile, path, or key storage prompt to return to the menu.

The wizard lists profiles and allows creating, cloning, editing paths, changing key storage (`[s] Storage`), re-entering keys (`[k] Key`), renaming, and deleting them. When `rclone >= v1.60.0` is installed and has configured remotes, the wizard also displays configured remote names from `rclone listremotes` before asking for the destination and warns if an rclone remote prefix is missing. For non-interactive automation and scripting, use `kasumi profile <create|edit|clone|storage|rename|delete>` with `KASUMI_PASSWORD` + `KASUMI_PASSWORD2` or `KASUMI_MASTER_KEY`. It displays each profile's local state (`Initialized`, `Ready`, `Pending`, `Running`, or `Problem`) alongside a compact summary of the last local sync timestamp and outcome. During an active operation on a profile, `config`, `show`, and `diagnostics` report `Running` (alongside the active operation such as `Running (gc)` when recorded) instead of `Problem`. During creation, it prompts for the profile name, local synchronized path, remote destination, and key storage mode before asking for Password and Password Salt. Press Enter at the key storage prompt to use `key_storage = "vault"` (Windows Credential Manager on Windows; GNOME Keyring / Freedesktop Secret Service or KDE KWallet on Linux). You can switch any profile between `vault`, `file` (stored locally in `profiles/<name>/key.bin`), and `memory` (prompted on every command without persisting the key) via `[s] Storage` in `kasumi config` or by editing `config.toml`; switching away from `vault` or `file` removes the previously saved key and requires `kasumi key <profile>` (or `[k] Key`) when entering `vault` or `file`. Profile names contain only letters, digits, `_`, or `-`; the local path must be absolute. Cloning reuses configuration and the master key but creates fresh SQLite state without copying accepted history or remote data. Editing changes the configured local and remote paths, not the key. Renaming moves private profile state and OS vault entries. Deleting removes local configuration, key, and state, while leaving the synchronized folder and remote objects intact. See [Profile Management](architecture/profile-management.md) for state meanings, the lifecycle, and rollback boundaries. For operational guidance, see [Best Practices](best-practices.md); for troubleshooting operational issues, see [Troubleshooting](troubleshooting.md).

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

The wizard validates names, paths, and minimum password sizes as they are entered.
Invalid input repeats only that field; accepted values are retained. Passwords and
password salts remain hidden and require confirmation.

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
key_storage = "vault"
```

New profiles default to `key_storage = "vault"`, a minimum retention depth of 5 commits, and a minimum retention age of 6 hours. Every profile in `config.toml` must specify `local_dir`, `remote_dir`, `min_history_depth`, `min_history_age_hours`, and `key_storage` (`vault`, `file`, or `memory`). Manual editing of `config.toml` allows adjusting `key_storage` (`vault`, `file`, or `memory`) and retention values using positive integers; runtime operations limit depth to 4096. Unknown fields and missing required profile values are rejected rather than migrated. The local profile policy is used when planning or publishing retention state. Published authenticated Epochs carry the retention policy and anchors used by the remote history and maintenance protocol.

## Core Commands

Use `kasumi <command> --help` for the complete arguments, options and examples.

| Purpose | Command |
|---|---|
| Manage local profiles interactively | `kasumi config` |
| Manage local profiles non-interactively | `kasumi profile <create\|edit\|clone\|storage\|rename\|delete> ...` |
| Re-enter or save profile key | `kasumi key <profile>` |
| List profile names | `kasumi list` |
| Show profile settings and local traceability | `kasumi show <profile> [--full]` |
| Inspect local environment, `rclone`, and profile health | `kasumi diagnostics [<profile>]` |
| Inspect the current plan | `kasumi status <profile>` or `kasumi sync <profile> --dry-run` |
| List preserved local conflict artifacts | `kasumi conflicts <profile>` |
| Synchronize (or fast-repair missing remote objects) | `kasumi sync <profile> [--repair]` |
| Audit referenced payloads | `kasumi fsck <profile>` |
| Consolidate fragmented Micro-Packs | `kasumi repack <profile> [--dry-run] [--reclaim-dirty] [--full]` |
| Reclaim eligible remote storage | `kasumi gc <profile> [--dry-run] [--min-age <hours>]` |
| Resolve permanently missing content as logical deletion | `kasumi resolve-missing <profile> [--dry-run \| --confirm]` |
| Output shell completion script | `kasumi completion <bash\|zsh\|fish\|powershell>` |

`--full` applies to `sync`, `status`, `repack`, `show`, and `remote summary`, after the profile. In `sync` and `status` it displays every plan and pending-path item (otherwise lists longer than ten items show the first and last five) and keeps detailed progress lines for each activity; in `repack` it displays the full pack inventory summary and published Commit/height details; in `show` it displays full Commit/machine IDs plus recorded local execution and cached remote maintenance histories (noting offline cache limits for other machines); in `remote summary` it expands full machine IDs and the complete operational activity timeline. Preview and Status do not execute the plan, recover transactions, or persist file-hash cache changes. See
[Preview and Status](architecture/planning-and-status.md).

`sync --initial` requires no SQLite sidecars or unfinished transaction evidence.
It can bootstrap empty remote history or enroll into an authenticated vault.
See [Initial Sync](architecture/synchronization.md#initial-sync).

`sync --audit-inventory` runs Sync and then a structural inventory audit. It
cannot combine with `--dry-run` or `--initial`. The audit does not authenticate
payload bytes and its failure does not undo Sync's effects or publication.
See [Inventory Audit](architecture/synchronization.md#optional-remote-inventory-audit).

`sync --repair` discovers missing remote physical objects across the entire
effective `StorageManifest` (loose objects, `KPAK\x01` Micro-Packs, and FastCDC
chunks) using a single remote physical listing, and re-uploads missing payloads
from verified local copies without downloading payloads (`fsck`) or publishing a
new logical Commit when no local changes require publication. It cannot combine
with `--dry-run` or `--initial`, and reports repaired count in `data.repaired`
under `--json`.

Before running remote transfers or downloads, `sync` performs local disk-space
and toolchain preflight checks: insufficient local free space for planned
downloads fails cleanly before staging (`error.code = "insufficient_disk_space"`
in `--json`), and `rclone` backends enforce a minimum supported `rclone` version
of `v1.60.0` via `core/version`. Run `kasumi diagnostics [<profile>]` to inspect
`rclone` availability/version, OS, free disk space, profile local state,
active locks, journals, and key availability read-only without remote access or
exposing secrets.

**GC permanently deletes eligible objects.** Scheduled unattended `kasumi gc <profile>`
checks active writers and barriers read-only before barrier acquisition (backing off
with `error.code = "remote_busy"` / `[BUSY]` when busy), publishes a unique
per-run barrier under `<barriers-ns>/<token>` with a post-publish settle window and
exclusivity check, periodically revalidates exclusivity during `Apply`, and enforces a
default 6-hour grace period (`min_history_age_hours`, override with `--min-age <hours>`
`0..8760`) clamped to `min(local_now, remote_now)` derived from the barrier's remote
`ModTime` (plus `Commit.created_at` for expired unreachable commits). Any object newer
than `--min-age` or with missing, invalid, or future timestamps is deferred safely, and
if remote barrier `ModTime` cannot be determined while `--min-age > 0`, GC fails closed
to protect recent uploads under local clock skew. Reserve `--min-age 0` for manual
maintenance with Sync stopped on every client. Use `kasumi gc <profile> --dry-run` to
preview candidate counts (content objects, redundant commit variants, expired commits,
and expired activity records), reclaimable bytes, and deferred recent objects read-only
without establishing a barrier, deleting objects, or publishing a `KACT` activity
record. `kasumi remote writers <profile>` displays active barriers, writers, and
diagnostic metadata (`started_at`, `pid`, `machine`). Manual `gc remove-writer`
requires an exact marker whose process is verified inactive.
`gc remove-barrier [<barrier-id>] --confirm-abandoned` requires `--confirm-abandoned`
after verifying no Sync or maintenance is active (and `<barrier-id>` when multiple
barriers are present); marker age alone is insufficient. See the
[GC operational contract](architecture/garbage-collection.md#operational-contract).

`kasumi repack <profile>` consolidates loose small files and fragmented
`KPAK\x01` Micro-Packs from live local files **without downloading payloads or
deleting remote objects**. Stop Sync on every client and ensure the workspace
has zero pending local, remote, or journal changes before running `repack`.
Use `--dry-run` to preview the plan without mutating remote state, `--reclaim-dirty`
to also rewrite large packs (`>= 2 MiB`) containing dead blobs, and `--full` to
display the pack inventory breakdown and published Commit/height details.
Replaced packs stay protected by history retention until removed later by
`kasumi gc <profile>`. See [Micro-Pack Repack](architecture/repack.md).

Fsck audits referenced payloads; transaction recovery before Fsck or GC can
have local and remote effects. Ordinary Sync only probes Content required by
its current work; a no-op is not a full integrity audit. See
[Synchronization](architecture/synchronization.md#required-content-availability).

### Updating Kasumi

Download the new installer or portable archive and its SHA-256 checksum from
[GitHub Releases](https://github.com/auanK/kasumi/releases), then
[verify the checksum and provenance attestation](getting-started.md#verify-downloads).
Read [Upgrading Kasumi](best-practices.md#upgrading-kasumi) for compatibility and
backup precautions before upgrading:

- **Native installers (in-place upgrade):** Stop running Kasumi operations and
  run the verified package (`kasumi-v<version>-windows-x86_64.msi` on Windows,
  `sudo pacman -U kasumi-v<version>-linux-x86_64.pkg.tar.zst` on Arch Linux,
  `sudo apt install ./kasumi-v<version>-linux-x86_64.deb` on Debian/Ubuntu, or
  `sudo dnf install --nogpgcheck ./kasumi-v<version>-linux-x86_64.rpm` on
  Fedora/RHEL). Installers detect existing installations, report the version
  transition, and preserve existing profiles, local databases, and configuration.
- **Portable archives (`.zip` / `.tar.gz`):** Stop Kasumi and replace the
  executable manually from the verified archive.

### Partial Synchronization and Explicit Data-Loss Operations

When `kasumi sync <profile>` has unresolved missing payloads required by its current work, it records pending materializations and exits with status `2`. Treat this as **partial**, not full, synchronization. If a required Content object is absent, Sync can upload it when a compatible local source matches the expected hash and size; otherwise it preserves logical state and pending evidence. A no-op does not check for or repair unrelated missing objects, even if another local copy exists; run `kasumi sync <profile> --repair` on a machine with intact local copies to discover and repair missing remote objects across the effective tree in a single listing without downloading payloads. Alternatively, restore intact bytes from a client or independent backup so they are available when a later Sync or `--repair` run needs them. Use `sync --audit-inventory` to identify broader structural absences and Fsck for payload integrity checks. Do not automatically convert status `2` into a deletion. Transport failures and LIST/PRESENCE disagreements fail the run rather than being classified as missing.

`kasumi resolve-missing <profile>` is an explicit, potentially destructive resolution path: by default it previews eligible unresolved paths with no local source and asks for interactive confirmation (`[y/N]` / `[s/N]`) before publishing logical deletions (returning exit `1` if declined or `130` on EOF/signal). Use `resolve-missing <profile> --dry-run` to inspect eligible paths read-only without mutating state, or `--confirm` for non-interactive automation after verifying pending paths. It is not a download/repair command; use it only when losing those files is an informed decision.

### Interruption and Recovery

Synchronization records phase and progress in the private `transaction.bin.enc/`
journal directory: `snapshot.enc`, `transaction.log.enc`, `confirmed.enc`, and,
during retirement, `retired.enc`. `.transactions/<id>/` separately holds staging
and backups; these workspace files are not uniformly encrypted. Preserve both
directories when recovery fails. See the [journal format](architecture/transaction-journal.md).

If synchronization is interrupted:
* Sync, Fsck, `resolve-missing` (non-`--dry-run`), `repack` (non-`--dry-run`), and GC (non-`--dry-run`) inspect the existing local transaction journal before their own work; both GC and `repack` refuse an interrupted upload (`ResumableTransaction`) so Sync finishes it first. Preview, Status, `--dry-run` modes (`repack --dry-run`, `gc --dry-run`, `resolve-missing --dry-run`), remote inspection, and manual writer/barrier maintenance do not execute journal recovery (and maintenance `--dry-run` modes inspect the journal read-only and refuse pending/invalid journals).
* Depending on the persisted phase and observed state, recovery may resume, rollback, or roll forward the transaction.
* Conflicting or indeterminate publication states are reported as recovery errors rather than assumed successful.
* Already present content objects may be reused when their identifiers and verification checks match the required content.
* A repair-only Sync uses the existing local-only transaction path: an interrupted repair may be resumed or rolled back without creating a new Commit or HEAD, and missing-source paths remain pending rather than being treated as deleted.

For the recovery state transitions, see [Transactions and Recovery](architecture/transactions-and-recovery.md).

### Concurrency & Multiple Profiles

* **Different Profiles Simultaneously**: Different profiles use separate local profile state, separate SQLite databases, and separate profile locks, and can be executed concurrently.
* **Same Profile Guard**: Running the same profile concurrently across multiple processes is prevented by an exclusive operating system file lock (`profile-<name>.lock` in Kasumi's data directory). A second process attempting to execute the same profile while the lock is held exits with an error indicating that the profile is in use. This local lock coordinates processes on a single machine and is distinct from remote multi-master writer coordination between different machines.

## Remote Inspection

These commands do not publish synchronization changes or run garbage collection. `remote get` writes the requested destination after authenticating the payload. See [Remote Inspection](architecture/remote-inspection.md) for each family's data flow and failure behavior.

Use `kasumi remote --help` to choose a view, and
`kasumi remote <subcommand> --help` for its required arguments. For example:

```sh
kasumi remote summary Programming [--full]
kasumi remote tree Programming --head <commit>
kasumi remote contents Programming --audit
```

`contents` is a structural inventory; `contents <profile> --audit` downloads and
authenticates every physically present Content object, including orphans.
Fsck instead audits referenced content and has its own checkpoint/recovery flow.
See [Content Inspection](architecture/remote-content-inspection.md).

Commit and Content selectors require 64 lowercase hex characters. `tree --head`
selects a current logical head and is required for multiple heads. `stat` and
`get` use the resolved effective tree by default, or an earlier retained snapshot
when `--commit <id>` is specified; `get` authenticates the requested file and
writes its explicit destination, whose parent must exist. Health diagnostics
are observations rather than a substitute for a payload audit.

## General Options

```text
kasumi [--lang <code>] <command> [subcommand] [arguments] [options]
```

`--lang <code>` is the optional global prefix, before the command. Command
options follow required arguments; `--full` is available to `sync`, `status`, `repack`, `show`, and `remote summary`. `config` and `list` take no profile.

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

Executed operations, except `config`, `list`, and `show`, print one final elapsed-time line on stdout:
`Duration: 12.614 s` (English) or `Duração: 12.614 s` (Portuguese). A monotonic
clock measures real elapsed time in seconds with three decimal places, including
success, failure, pending results and cancellation. Sync has one duration line;
internal operational metrics are separate. Help, version and invalid invocations
have no operation duration.

`list` prints only names, and `show` prints profile details; neither command nor
`config` prints elapsed-time lines. `list` and `show` errors go to stderr with a
nonzero exit code, leaving stdout empty.
Other operation messages and errors use stdout; invocation diagnostics use stderr. Interpret the [exit code](#exit-codes) with the
output; partial results are not full success.

## Language Selection (i18n)

Kasumi defaults to **English**.

To switch to **Portuguese**:
* Command line: `kasumi --lang pt-BR <command> <profile>` (or `--lang pt`)
* Environment variable: set `KASUMI_LANG=pt-BR` (or `pt`)

## Automation & Environment Variables

| Variable | Description |
|---|---|
| `KASUMI_LANG` | Sets CLI language (`en`, `pt-BR`, `pt`) |
| `KASUMI_MASTER_KEY` | Provides a 64-hex-digit master key to application/inspection operations. It does not replace the wizard's Password/Password Salt creation prompts. When the profile has a persisted key (`vault` or `file` mode), the supplied key must match the persisted key |
| `KASUMI_PASSWORD` | Provides the Password to the profile creation, `kasumi key`, or `memory`-mode credential flow (minimum 12 characters) |
| `KASUMI_PASSWORD2` | Provides the Password Salt to the profile creation, `kasumi key`, or `memory`-mode credential flow (minimum 16 characters) |
| `KASUMI_CONTENT_CONCURRENCY` | Sets content-transfer concurrency. Default: 8. Positive values above 16 are capped at 16; invalid or zero values use the default |

> [!NOTE]
> Master-key persistence depends on the profile's required `key_storage` setting in `config.toml` (`vault`, `file`, or `memory`; new profiles default to `vault`). In `vault` mode, the derived 32-byte master key is stored in the OS credential vault (`kasumi/<profile>`); in `file` mode, it is persisted in `profiles/<profile>/key.bin` using a reversible XOR mask and OS filesystem permissions; in `memory` mode, the key is never persisted and must be supplied via prompt, `KASUMI_PASSWORD` + `KASUMI_PASSWORD2`, or `KASUMI_MASTER_KEY` on every operation. For `vault` and `file` profiles, routine operations load the persisted key without re-verifying `KASUMI_PASSWORD` and `KASUMI_PASSWORD2`. For details on security boundaries and key storage, see [Security Specification](security.md).

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

### Quiet Mode (`--quiet`)

Pass `--quiet` after the profile (or after `kasumi list`, `kasumi diagnostics [<profile>]`, `kasumi profile <subcommand> <profile>`, or `kasumi remote <subcommand> <profile>`) to suppress banners, live progress, `Duration:` lines, and non-error operational stdout on `sync`, `status`, `conflicts`, `profile ...`, `fsck`, `gc`, `repack`, `resolve-missing`, and healthy `diagnostics` runs. Query commands (`list`, `show`, `remote ...`) retain their query output without progress or duration lines, and errors, partial-pending lists (exit `2`), unhealthy `diagnostics` summaries, and `stderr` warnings remain visible.

### Machine-Readable Output (`--json`)

Pass `--json` on supported commands (`list`, `show`, `diagnostics`, `profile ...`, `conflicts`, `status`, `sync`, `fsck`, `gc <profile>`, `gc remove-barrier`, `repack`, `resolve-missing`, `remote summary`, and `remote writers`) to emit a single language-independent JSON object (`"schema_version": 1`) to `stdout` with empty `stderr`, suppressing banners, progress output, and localized text differences regardless of `--lang`:

- Every response includes `schema_version`, `command`, `ok`, `exit_code`, and `timestamp` (UTC ISO-8601 ending in `Z`), plus `profile`, `duration_ms`, `data`, `warning`, or `error` as applicable.
- Command `data` objects retain all raw numeric/boolean/array fields alongside a concise language-independent `summary` string (such as `"Everything in sync"` or `"3 changes | ↑ 2 (2 KB) | ↓ 1 (512 bytes)"`). On `gc`, `data` also exposes `candidate_expired_commits`, `deferred_recent_objects`, `candidate_bytes`, `removed_bytes`, and `min_age_hours`.
- `resolve-missing <profile> --json` without `--confirm` or `--dry-run` runs read-only and fails safely with `error.code = "confirmation_required"` and `data.resolved_paths` whenever unresolved paths exist (never blocking on `stdin`).
- Stable `error.code` values: `invalid_arguments`, `profile_not_found`, `lock_busy`, `remote_busy`, `credentials_required`, `auth_failed`, `confirmation_required`, `insufficient_disk_space`, `io_error`, `cancelled`, `partial_pending`, `audit_findings`, `transport_error`, `plan_failed`, `sync_failed`, `recovery_failed`, `fsck_failed`, `gc_failed`, `repack_failed`, `writer_removal_failed`, `barrier_removal_failed`, `inventory_audit_failed`, `remote_observation_failed`, `config_error`, and `runtime_error`.

### Persistent Log File (`--log-file <path>`)

Pass `--log-file <path>` (or `--log-file=<path>`) on supported non-interactive commands (`list`, `show`, `diagnostics`, `profile ...`, `conflicts`, `sync`, `status`, `fsck`, `gc`, `repack`, `resolve-missing`, and `remote ...`) to append durable logs without interrupting terminal output:

- **With `--json`**: Appends the exact serialized JSON envelope (`timestamp`, `data.summary`, raw counts, and error codes) as one NDJSON line per invocation.
- **Without `--json`**: Appends UTF-8 plain-text entries in one atomic write per command using local timestamps with UTC offset, status tags (`[OK]`, `[WARN]`, `[PARTIAL]`, `[LOCKED]`, `[BUSY]`, `[CANCELLED]`, `[ERROR]`), command/profile target, ANSI-free compact summary (with human-readable sizes), duration (`(<seconds> s)`), and indented detail lines for pending paths, warnings, or unhealthy diagnostic items.
- The log path is validated before execution (creating missing parent directories; rejecting directories, symlinks, and unwritable targets with exit code `1` or `error.code = "io_error"` under `--json`). Passing `--help` / `-h` never creates or modifies the log file, and cryptographic keys or passwords are never logged.

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
* `(?d)` before a pattern marks matching regular files as disposable ignored
  content, for example `(?d)*.bak`. It does not make directories disposable;
  modifier combinations and negated disposable rules are rejected.
* Lines starting with `#` are comments.

Symlinks inside the synchronization root are not traversed.
Reserved private files at the synchronization root and generated transaction artifacts are excluded from synchronization. Generated artifacts use their exact current naming pattern. The `.kasumiignore` file itself can be synchronized; changes to its local or authenticated remote version can change the effective projection used for a run. See [Local Observation](architecture/local-observation.md).

Ignored entries remain local by default. A `(?d)` file is discarded only when
reconciliation authorizes removal of its previously managed containing
directory. New local-only directories, old ignored residue, protected entries,
links, and unexpected entries are preserved. A subtree containing protected and
disposable ignored files is preserved as a whole; Kasumi does not partially
discard it. Changing a rule to `(?d)` does not trigger cleanup by itself.

The root `.kasumiignore` remains synchronized even when a broad disposable rule
matches it. Status and Preview show planned disposable-file removals without
applying them. Sync backs up each file before removal and uses its transaction
recovery path if an operation is interrupted. These safeguards detect changes
observed before final validation; they do not isolate a mutation from arbitrary
same-user filesystem writers. See [Transactions and Recovery](architecture/transactions-and-recovery.md).

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

## Progress and transfer metrics

Sync, Status, and dry-run report the current planning activity, such as comparing snapshots, checking remote content, and preparing changes. Interactive output shows elapsed time when an ETA is unavailable. Known totals, such as objects checked and operations prepared, are shown as counts. While applying changes, Sync and Resolve Missing show confirmed operations out of the plan. A second line shows file or batch transfer progress and an ETA when the transfer total is known. A single checkpoint can advance the plan by several operations. FSCK, garbage collection, and remote content audits show progress against their known object totals. Redirected output uses plain stage lines and spaced progress milestones. With `--full`, Sync and Status retain more per-activity detail in the output.

Sync keeps its logical plan summary and reports the actual encoded payload bytes, physical object counts, and local reuse (verified FastCDC slices and deduplicated uploads) separately. Transfer progress and speeds appear under Applying changes. FSCK reports the logical audit totals alongside wire download bytes, physical objects downloaded, and files reassembled. Garbage collection reports live sub-stages (`CheckingControls`, `ListingRemote`, `AuthenticatingHistory` commit counts, `AnalyzingReachability`, `LoadingActivities`, `ProbingConsistency`, `RemovingObjects` with byte totals/rate/ETA, and `ReleasingBarrier`), listed remote objects, candidate breakdown (including expired commits and reclaimable bytes), deferred recent objects, and confirmed removals/reclaimed bytes. These payload measurements exclude HTTP headers and protocol control objects.
