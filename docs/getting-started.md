# Getting Started

This tutorial connects two machines to one encrypted vault. Each machine keeps
its own local folder and profile; the shared destination stores encrypted objects,
not a browsable copy of your files. For exact command syntax and options, use
[Configuration and Usage](configuration-and-usage.md).

Use the same Kasumi release on every client. Kasumi provides no backward
compatibility between 0.x releases and no automatic migration; see the
[upgrade precautions](best-practices.md#upgrading-kasumi) before reusing existing data.

## 1. Obtain Kasumi

Official [GitHub Releases](https://github.com/auanK/kasumi/releases) provide:

- **Windows x86_64:** `kasumi-windows-x86_64.zip`. Extract it into a directory
  you can run programs from; use PowerShell or CMD to invoke `kasumi.exe`.
- **Linux x86_64:** `kasumi-linux-x86_64.tar.gz`. Extract it and run `kasumi`.

Add the executable's directory to `PATH`, or use its full path in the commands
below. Local storage requires no rclone installation. For a rclone remote,
install `rclone` in a directory on `PATH` outside the synchronized folder and
configure the provider's credentials with `rclone config` on each machine.
The binary updater has additional [platform prerequisites](configuration-and-usage.md#updating-kasumi).

### Verify Downloads

Download the archive and its matching `.sha256` file from the same official
release. Verify before extracting or executing the archive.

Linux:

```sh
sha256sum -c kasumi-linux-x86_64.tar.gz.sha256
tar -xzf kasumi-linux-x86_64.tar.gz
./kasumi --version
```

Windows PowerShell:

```powershell
$expected = ((Get-Content .\kasumi-windows-x86_64.zip.sha256 -Raw) -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash .\kasumi-windows-x86_64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 mismatch; do not extract or run this archive.' }
Expand-Archive .\kasumi-windows-x86_64.zip -DestinationPath .\kasumi
.\kasumi\kasumi.exe --version
```

The release also provides `SHA256SUMS.txt`; with both archives downloaded, Linux
users can verify it with `sha256sum -c SHA256SUMS.txt`. A mismatch means you
should download again and report a repeat failure. A matching checksum detects
changed bytes but does not independently authenticate the publisher. The
[release workflow](../.github/workflows/release.yml) generates GitHub build
provenance attestations for both archives and the consolidated checksum list.

### Build from Source

Install CMake 3.28+, Git, Ninja, Python 3, and a C++23 compiler. On Windows, use a Visual
Studio 2022 developer shell or an MSYS2 UCRT64 toolchain environment. On Linux,
repository CI uses GCC 14. From the repository root:

```sh
cmake --preset default
cmake --build --preset default
```

The executable is `build/kasumi.exe` on Windows or `build/kasumi` on Linux.
See [Build and Test](build-and-test.md) for toolchain setup and tests.

### Windows Path Lengths

Kasumi embeds a `longPathAware` manifest. Long Win32 paths also depend on the
host's `LongPathsEnabled` policy; short paths work without changing that policy.
Keep synchronized and private profile paths short when long paths are disabled:
internal staging adds directories and identifiers beyond the source path's length.
See [Windows path diagnostics](troubleshooting.md#windows-path-exceeds-the-supported-limit).

## 2. Choose Shared Storage

Use a dedicated destination accessible to both machines:

- **Local filesystem or mounted network share:** an absolute path such as
  `/mnt/share/kasumi/vault` or `D:/backup/vault`.
- **Configured rclone remote:** `drive:kasumi/vault` or `s3:my-bucket/vault`.
  `drive` and `s3` are names in your rclone configuration. The root after `:`
  must be nonempty and relative, without `..` components or a trailing slash.

Both clients must resolve their destination to the same underlying storage.
Mounted paths or rclone remote names can differ between machines. Ensure the
account has read, write, and delete access. Keep plaintext files and independent
backups outside this destination; do not edit Kasumi's remote objects manually.

## 3. Create the First Profile

On Machine A, create the local folder containing the files you want to sync,
then launch the wizard:

```sh
kasumi config
```

Select **New (`n`)** and supply:

1. **Profile name:** `work` (letters, digits, `_`, or `-`).
2. **Local directory:** an absolute path, such as `/home/user/documents` or `D:/Documents`.
3. **Remote directory:** the shared destination chosen above.
4. **Password:** a master passphrase of at least 12 characters.
5. **Password Salt:** a separate passphrase of at least 16 characters.

The Password and Password Salt are distinct inputs to Argon2id, which derives
the vault's 32-byte master key. The salt is user-provided and reproducible; Kasumi
does not generate it randomly or store it on the remote. **Record both inputs
securely and use exactly the same pair on the next machine.**

The derived key is kept in the private profile's `key.bin` using reversible XOR
masking and filesystem access controls, not password encryption at rest. Use
disk encryption for sensitive devices and back up your profile. If all copies
of the key and the credentials needed to derive it are lost, the encrypted vault
cannot be recovered. See [Security](security.md) and [Backups](best-practices.md#backups).

## 4. Preview and Synchronize Machine A

Inspect the proposed changes:

```sh
kasumi status work
```

Or preview with `kasumi sync work --dry-run`. Both commands reuse valid strong
fingerprints from the persistent local cache when available, falling back to
reading file content for new, modified, or uncached files. Neither command applies
sync changes, writes cache updates, or recovers pending transactions. Add `--full`
if you want every plan item. A preview is a point-in-time observation; the later
sync can replan if files or remote history change.

When the plan is acceptable:

```sh
kasumi sync work
```

For an empty destination, this publishes the initial encrypted files and history.
Check the result: exit code `0` means success; `2` means pending materializations
and **partial synchronization**, not a fully populated folder. Follow
[Exit Code 2](troubleshooting.md#exit-code-2--pending-materializations) if needed.

## 5. Connect Machine B

Create a local folder on Machine B; use an empty folder if you only want to
download Machine A's files initially. Run `kasumi config`, select **New (`n`)**,
and create a profile (it may also be named `work`). Supply Machine B's absolute
local path, the same underlying shared storage, and **exactly the same Password
and Password Salt** used on Machine A. No private SQLite state needs to be copied.

Preview and synchronize:

```sh
kasumi status work
kasumi sync work
```

Kasumi authenticates the shared history and decrypts available files into the
local folder. If that folder already contains files, its changes participate in
bidirectional synchronization; inspect the preview first.

## 6. Continue Synchronizing

Run `kasumi sync work` on each machine whenever you want to exchange changes.
Clients do not need to be online simultaneously. Concurrent changes can produce
preserved conflict files; review and resolve them using
[Best Practices](best-practices.md#multi-machine-usage).

Use [.kasumiignore](configuration-and-usage.md#kasumiignore) to exclude local
paths, and consult [maintenance guidance](best-practices.md) for integrity
audits, garbage collection, independent backups, and safe upgrades.
