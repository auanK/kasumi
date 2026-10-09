# Kasumi

Kasumi is multi-client bidirectional file synchronization with client-side encryption over local or rclone-compatible shared storage, without a dedicated server.

Kasumi is written in C++23 for Linux and Windows. It synchronizes directories through shared storage, including local filesystems, network shares, and rclone-compatible remotes. Clients synchronize independently and do not need to be online at the same time.

```text
Machine A ───┐
             │
Machine B ───┼──> Shared Storage
             │
Machine C ───┘
```

Kasumi records synchronization states as immutable commits in a shared history DAG. Clients can publish concurrently without an exclusive global synchronization lock. Concurrent publications form branches that are reconciled during subsequent synchronization.

## Features

- **Multi-Master Synchronization**: Multiple machines publish changes independently without a dedicated Kasumi coordination server.
- **Client-Side Encryption**: File contents and synchronization history are encrypted and authenticated before remote storage.
- **Immutable History**: State transitions are stored as immutable commits in a directed acyclic graph (DAG).
- **Shared Storage Backends**: Supports local filesystems, network shares, and rclone-compatible remotes.
- **Conflict Reconciliation**: Concurrent divergent branches are reconciled deterministically.
- **Transaction Recovery**: Interrupted operations are tracked in a transaction journal.
- **Integrity and Maintenance**: `fsck` audits authenticated remote content; `gc` collects unreachable objects through quarantine. Explicit high-risk quarantine purge/repair controls are available for manual recovery scenarios.
- **Remote Inspection**: Read logical history and physical storage diagnostics without running synchronization.
- **Linux and Windows**: Native builds for Linux and Windows.

## Quick Start

This guide demonstrates setting up a shared encrypted vault between two machines using shared storage (such as a local directory, network share, or rclone remote).

```text
Machine A ───┐
             ├──> Shared Storage (e.g., drive:kasumi/vault)
Machine B ───┘
```

### 1. Obtain or Build Kasumi

Download the Kasumi binary for your platform, or build it from source using CMake and a C++23 compiler:

```bash
cmake --preset default
cmake --build --preset default
```

The release preset places the binary at `build/kasumi.exe` on Windows or `build/kasumi` on Linux. The examples below assume `kasumi` is on `PATH`; otherwise run the binary from `build/`.

Official binaries from v0.6.0 onward include the manual `kasumi update` command. See [Updating Kasumi](docs/configuration-and-usage.md#updating-kasumi) for platform requirements and compatibility notes; it replaces the executable but does not migrate local state.

For platform prerequisites and build options, see [Build and Test](docs/build-and-test.md).

### 2. Configure Shared Storage

Kasumi synchronizes over passive shared storage. Ensure your backend is accessible:
* **Local path or network share**: e.g., `/mnt/share/kasumi/vault` or `D:/backup/vault`.
* **Rclone remote**: e.g., `drive:kasumi/vault` or `s3:my-bucket/vault`. (Ensure `rclone` is installed in `PATH` and configured.)

### 3. Set Up Machine A

Launch the interactive configuration wizard on the first machine:

```bash
kasumi config
```

Select **New (`n`)** and enter:
1. **Profile name**: A local profile name (letters, digits, `_`, or `-`, e.g., `work`).
2. **Local directory**: Absolute path to the folder you want to synchronize (e.g., `/home/user/documents` or `D:/Documents`).
3. **Remote directory**: Destination path on the shared storage (e.g., `drive:kasumi/vault` or `/mnt/share/kasumi/vault`).
4. **Password**: Master passphrase (minimum 12 characters).
5. **Password Salt**: Cryptographic salt passphrase (minimum 16 characters).

> [!IMPORTANT]
> **Password Salt is user-provided and reproducible**: Kasumi uses Argon2id to derive the 32-byte master key from your **Password** and **Password Salt**. The salt is **not** an automatically generated random value stored on the remote. To connect another machine to the same vault, you must provide the exact same Password and Password Salt. Keep a secure record of both.

### 4. Preview and Run Initial Sync on Machine A

Before applying mutations, preview the planned synchronization:

```bash
kasumi status work
```

Alternatively, run a dry-run:

```bash
kasumi sync work --dry-run
```

When you are ready to upload files and initialize the vault:

```bash
kasumi sync work
```

Kasumi creates the genesis commit in the remote history DAG, encrypts file payloads with client-side XChaCha20-Poly1305, and publishes them to shared storage.

### 5. Set Up Machine B

On the second machine, launch the configuration wizard:

```bash
kasumi config
```

Select **New (`n`)** and provide:
1. **Profile name**: Profile name on Machine B (e.g., `work`).
2. **Local directory**: Absolute path to the synchronized folder on Machine B.
3. **Remote directory**: The **exact same** remote destination used on Machine A (e.g., `drive:kasumi/vault`).
4. **Password**: The **exact same** Password entered on Machine A.
5. **Password Salt**: The **exact same** Password Salt entered on Machine A.

### 6. Synchronize Machine B

Run synchronization on Machine B:

```bash
kasumi sync work
```

Kasumi discovers the remote history, authenticates and decrypts the files, and materializes them in the local directory. Both machines can now synchronize independently at any time.

---

For detailed CLI options, portable path rules, and `.kasumiignore` syntax, see [Configuration and Usage](docs/configuration-and-usage.md). For operational habits, see [Best Practices](docs/best-practices.md). If you encounter errors, see [Troubleshooting](docs/troubleshooting.md).

> **Before replacing binaries:** Pre-1.0 releases may change persisted formats. Review each release's compatibility notes, complete active synchronizations and recovery, and back up your profile and synchronized files. Preserve `config.toml` and `key.bin`. A sync that exits with code `2` has pending materializations and is not fully complete.

## Local Key Protection

Remote payloads are encrypted and authenticated on your device before upload. The local master key in `key.bin` is stored with reversible XOR masking, not password-based encryption at rest. Its local protection depends on filesystem permissions and protection of the device; use full-disk encryption such as BitLocker or LUKS for sensitive deployments. If the only available master key is lost, the remote encrypted data cannot be recovered. See [Security](docs/security.md) for details.

## Verify Release Downloads

Check the archive against its published SHA-256 file before extracting it.

Linux:

```sh
sha256sum -c kasumi-linux-x86_64.tar.gz.sha256
```

Windows PowerShell:

```powershell
$expected = ((Get-Content .\kasumi-windows-x86_64.zip.sha256 -Raw) -split '\s+')[0].ToLowerInvariant()
$actual = (Get-FileHash .\kasumi-windows-x86_64.zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw 'SHA-256 mismatch; do not extract or run this archive.' }
```

If `SHA256SUMS.txt` is published and you downloaded both archives, verify the consolidated list on Linux with `sha256sum -c SHA256SUMS.txt`. If a checksum does not match, do not extract or run the archive; download it again from the release and report a repeat mismatch. A matching checksum detects file changes but does not, by itself, authenticate who published the file.

## Documentation

- [Configuration and Usage](docs/configuration-and-usage.md)
- [Best Practices](docs/best-practices.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Architecture](docs/architecture.md)
- [Remote Inspection](docs/architecture/remote-inspection.md)
- [Security](docs/security.md)
- [Build and Test](docs/build-and-test.md)
- [Provider Certification](docs/provider-certification.md)

## License

Kasumi is released under the [MIT License](LICENSE). Third-party components retain their respective licenses; see [Third-Party Notices](THIRD_PARTY_NOTICES.md).
