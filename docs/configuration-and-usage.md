# Configuration and Usage

## Profile Setup

Launch the interactive configuration wizard:

```powershell
kasumi config
```

The wizard allows creating, editing, renaming, and deleting profiles. During creation, it prompts for the profile name, local synchronized path, remote destination, Password, and Password Salt.

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

`drive:` and `s3:` represent configured remote names in an external rclone configuration, not storage protocols natively implemented by Kasumi.

## Configuration File

Profiles are stored in `config.toml` within Kasumi's data directory.
* **Windows**: `%APPDATA%/kasumi`
* **Linux**: `$XDG_CONFIG_HOME/kasumi` or `$HOME/.config/kasumi`

```toml
[profiles.my-profile]
local_dir = "D:/Documents"
remote_dir = "drive:kasumi/my-profile"
min_history_depth = 5
min_history_age_hours = 6
```

New profiles default to a minimum retention depth of 5 commits and a minimum retention age of 6 hours. Manual editing of `config.toml` allows adjusting both values using positive integers. The local profile policy is used when planning or publishing retention state. Published authenticated Epochs carry the retention policy and anchors used by the remote history and maintenance protocol.

## Core Commands

| Command | Action |
|---|---|
| `kasumi config` | Launches interactive profile configuration wizard |
| `kasumi status <profile>` | Computes and displays the currently observed synchronization plan/status |
| `kasumi sync <profile> --dry-run` | Computes and displays the synchronization plan without executing its synchronization mutations |
| `kasumi sync <profile>` | Runs synchronization |
| `kasumi fsck <profile>` | Validates observed remote history and audits content objects referenced by the effective remote state |
| `kasumi gc <profile>` | Runs garbage-collection analysis and, when online collection conditions are met, quarantine and removal processing |

* `status` and `sync --dry-run` do not execute the computed synchronization plan or apply synchronization mutations to the synchronized tree or remote history. They read local profile configuration and private state, acquire the local profile lock, and perform observations.
* `sync` applies local tree modifications, transfers content payloads, and publishes commit and HEAD records.
* `gc` coordinates through a distributed barrier protocol, checks backend consistency visibility with probe objects, and stages candidate objects through a 10-day quarantine retention period prior to permanent removal. See [Remote Storage, Integrity, and Maintenance](architecture/remote-storage-and-maintenance.md) for details.
* `fsck` validates the observed remote history DAG, inspects physical namespace identifiers, audits referenced content payloads, checks AEAD authentication tags, sizes, and logical hashes, and reports missing or corrupted objects.

### Interruption and Recovery

Synchronization records transaction phase and operation progress in an encrypted and authenticated local transaction journal (`transaction.bin.enc` and `.transactions/<id>`).

If synchronization is interrupted:
* At the start of a subsequent synchronization or maintenance operation, Kasumi inspects the existing local transaction journal.
* Depending on the persisted phase and observed state, recovery may resume, rollback, or roll forward the transaction.
* Conflicting or indeterminate publication states are reported as recovery errors rather than assumed successful.
* Already present content objects may be reused when their identifiers and verification checks match the required content.

For the recovery state transitions, see [Synchronization and Reconciliation](architecture/synchronization.md).

### Concurrency & Multiple Profiles

* **Different Profiles Simultaneously**: Different profiles use separate local profile state, separate SQLite databases, and separate profile locks, and can be executed concurrently.
* **Same Profile Guard**: Running the same profile concurrently across multiple processes is prevented by an exclusive operating system file lock (`profile-<name>.lock` in Kasumi's data directory). A second process attempting to execute the same profile while the lock is held exits with an error indicating that the profile is in use. This local lock coordinates processes on a single machine and is distinct from remote multi-master writer coordination between different machines.

## Remote Inspection

These commands do not publish synchronization changes or run garbage collection. Some inspection operations maintain the local private `inspection-history-v1.cache` in the profile directory.

| Command | Description |
|---|---|
| `kasumi remote heads <profile>` | Lists the current logical heads |
| `kasumi remote tree <profile>` | Displays the tree when a single logical head is present |
| `kasumi remote tree <profile> --head <id>` | Displays the tree for a specified current logical head |
| `kasumi remote commits <profile>` | Lists reachable commits in the history DAG |
| `kasumi remote summary <profile>` | Summarizes vault history, conflicts, contents, and active writers |
| `kasumi remote stat <profile> <path>` | Displays properties and metadata of a specific logical path |
| `kasumi remote commit <profile> <id>` | Shows parents, metadata, and physical variants of a commit |
| `kasumi remote get <profile> <path> <dst>` | Authenticates and decrypts the selected remote content and writes it to the requested destination without running synchronization |
| `kasumi remote epochs <profile>` | Lists the authenticated Epoch chain |
| `kasumi remote epoch <profile> <id>` | Displays details for a specific Epoch |
| `kasumi remote contents <profile>` | Lists structural content inventory by metadata |
| `kasumi remote contents --audit <profile>` | Builds the content inventory and downloads physically present content objects for validation |
| `kasumi remote content <profile> <id>` | Displays details of a specific content ID |
| `kasumi remote markers <profile>` | Validates and classifies physical HEAD markers |
| `kasumi remote objects <profile>` | Lists and categorizes objects in the raw physical namespace |
| `kasumi remote orphans <profile>` | Lists orphaned objects outside the reachable/retained set without running garbage collection |
| `kasumi remote quarantine <profile>` | Displays quarantine contents without restoring or purging |
| `kasumi remote writers <profile>` | Shows active writer markers and barrier registration state |
| `kasumi remote health <profile>` | Runs remote health inspection checks |

## Language Selection (i18n)

Kasumi defaults to **English**.

To switch to **Portuguese**:
* Command line: `kasumi --lang pt-BR <command> <profile>` (or `--lang pt`)
* Environment variable: set `KASUMI_LANG=pt-BR` (or `pt`)

To add a custom community language catalog, place `<lang>.json` in `%APPDATA%/kasumi/locales/` (Windows) or `$XDG_CONFIG_HOME/kasumi/locales/` (Linux; fallback `$HOME/.config/kasumi/locales/`) and pass `kasumi --lang <lang>`.

## Automation & Environment Variables

| Variable | Description |
|---|---|
| `KASUMI_LANG` | Sets CLI language (`en`, `pt-BR`, `pt`, etc.) |
| `KASUMI_MASTER_KEY` | Provides a 64-hex-digit master key as explicit credentials. For an existing profile with `key.bin`, the supplied key must match the persisted profile key |
| `KASUMI_PASSWORD` | Provides the Password to the profile creation credential flow (minimum 12 characters) |
| `KASUMI_PASSWORD2` | Provides the Password Salt to the profile creation credential flow (minimum 16 characters) |
| `KASUMI_CONTENT_CONCURRENCY` | Sets content-transfer concurrency. Default: 8. Positive values above 16 are capped at 16; invalid or zero values use the default |
| `KASUMI_PERF_TRACE=1` | Writes operational trace metrics to `stderr` |

> [!NOTE]
> Once a profile is created, the derived 32-byte master key is persisted locally in `profiles/<profile>/key.bin` using a reversible XOR mask and operating system filesystem permissions. For existing profiles, routine operations use the persisted `key.bin` when no explicit `KASUMI_MASTER_KEY` credential is supplied. `KASUMI_PASSWORD` and `KASUMI_PASSWORD2` are used by the profile-creation credential flow and are not re-verified during routine synchronization operations. For details on the security boundaries and key storage, see [Security Specification](security.md).

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
