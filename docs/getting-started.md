# Getting Started

This tutorial connects two machines to one encrypted vault. Each machine keeps
its own local folder and profile; the shared destination stores encrypted objects,
not a browsable copy of your files. For exact command syntax and options, use
[Configuration and Usage](configuration-and-usage.md).

Use the same Kasumi release on every client. Kasumi does not guarantee
compatibility across releases or automatically migrate existing data; see the
[upgrade precautions](best-practices.md#upgrading-kasumi) before reusing existing data.

## 1. Obtain Kasumi

Official [GitHub Releases](https://github.com/auanK/kasumi/releases) provide native installers and portable x86_64 archives:

- **Windows x86_64 installer (`.msi`):** `kasumi-windows-x86_64.msi` installs to `C:\Program Files\Kasumi`, adds that directory to the system `PATH`, and upgrades older `.msi` installations in-place.
- **Windows x86_64 portable (`.zip`):** `kasumi-windows-x86_64.zip` (built on `windows-2022` with the MSVC static C/C++ runtime `/MT`). Extract into a directory on `PATH` and invoke `kasumi.exe`.
- **Arch Linux (`.pkg.tar.zst` / `PKGBUILD`):** install or upgrade directly with `pacman`, or build locally using [PKGBUILD](../packaging/arch/PKGBUILD):

  ```sh
  sudo pacman -U kasumi-linux-x86_64.pkg.tar.zst
  ```

- **Debian / Ubuntu (`.deb`):**

  ```sh
  sudo apt install ./kasumi-linux-x86_64.deb
  ```

- **Fedora / RHEL (`.rpm`):** (after verifying the `.sha256` checksum / `gh attestation verify`, since packages are not GPG-signed; pass `--nogpgcheck` on Fedora 43+ / RPM 6.0):

  ```sh
  sudo dnf install --nogpgcheck ./kasumi-linux-x86_64.rpm
  ```

- **Portable Linux x86_64 (`.tar.gz`):** `kasumi-linux-x86_64.tar.gz` (built on GitHub `ubuntu-latest` with GCC 14 and dynamically linked against the host `glibc`; distributions with an older `glibc` should build from source). Extract and place `kasumi` on `PATH`.

Local storage requires no `rclone` installation. For a `rclone` remote,
install `rclone` in a directory on `PATH` outside the synchronized folder and
configure the provider's credentials with `rclone config` on each machine.
See [Updating Kasumi](configuration-and-usage.md#updating-kasumi) when upgrading
or replacing binaries on an existing installation.

### Verify Downloads

Download the package/archive and its matching `.sha256` sidecar from the same
official release. Verify before installing, extracting, or executing.

Linux (replace the filename with `.pkg.tar.zst`, `.deb`, `.rpm`, or `.tar.gz`):

```sh
sha256sum -c kasumi-linux-x86_64.pkg.tar.zst.sha256
# Or for the portable archive:
sha256sum -c kasumi-linux-x86_64.tar.gz.sha256
tar -xzf kasumi-linux-x86_64.tar.gz
./kasumi --version
```

Windows PowerShell (works for both `.msi` and `.zip`):

```powershell
$pkg = 'kasumi-windows-x86_64.msi' # or 'kasumi-windows-x86_64.zip'
$expected = ((Get-Content ".\$pkg.sha256" -Raw) -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash ".\$pkg" -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 mismatch; do not install or extract.' }
```

The release also provides `SHA256SUMS.txt` covering all installers and portable
archives (`sha256sum -c --ignore-missing SHA256SUMS.txt` on Linux). A mismatch
means you should download again and report a repeat failure. A matching checksum
detects changed bytes but does not independently authenticate the publisher. The
[release workflow](../.github/workflows/release.yml) generates GitHub build
provenance attestations for every package/archive and the consolidated checksum
list.

Verify build provenance with the [GitHub CLI](https://cli.github.com/) (`gh`)
before installing or extracting:

```sh
gh attestation verify kasumi-linux-x86_64.pkg.tar.zst --repo auanK/kasumi
gh attestation verify kasumi-windows-x86_64.msi --repo auanK/kasumi
```

`gh attestation verify` cryptographically verifies that the package or archive
was built by the official `auanK/kasumi` GitHub Actions release workflow. Release
artifacts are not currently OS-code-signed (Authenticode or GPG).

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
4. **Key storage mode:** Press Enter for `vault` (the OS credential vault), or type `file` (`profiles/<profile>/key.bin`) or `memory` (derive the key in RAM on every command).
5. **Password:** a master passphrase of at least 12 characters.
6. **Password Salt:** a separate passphrase of at least 16 characters.

The Password and Password Salt are distinct inputs to Argon2id, which derives
the vault's 32-byte master key. The salt is user-provided and reproducible; Kasumi
does not generate it randomly or store it on the remote. **Record both inputs
securely and use exactly the same pair on the next machine.**

In `vault` mode (the default for new profiles), the derived key is stored in the
OS credential vault (Windows Credential Manager on Windows; Freedesktop Secret
Service / GNOME Keyring or KDE KWallet on Linux). In `file` mode, it is kept in
the private profile's `key.bin` using reversible XOR masking and filesystem access
controls, not password encryption at rest. In `memory` mode, the key is never
saved and must be entered on each operation. Use disk encryption for sensitive
devices and back up your profile. If all copies of the key and the credentials
needed to derive it are lost, the encrypted vault cannot be recovered. See
[Security](security.md) and [Backups](best-practices.md#backups).

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
