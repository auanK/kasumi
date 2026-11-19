# Kasumi v0.17.2

This release reduces temporary disk I/O during downloads, improves download recovery, and restores fast rclone session shutdown.

## Highlights

- **FastCDC downloads use less temporary storage.** Kasumi streams verified chunks directly into the temporary destination file and can reuse verified slices from files installed earlier in the same sync.
- **Micro-Pack downloads work in bounded windows.** Kasumi downloads and authenticates packs in bounded windows, installs their members directly with per-window checkpoints during sync and recovery, and avoids an intermediate extraction directory.
- **Recovery cleans up interrupted downloads.** Before replaying pending downloads during roll-forward recovery, Kasumi removes leftover temporary download files—including when the destination was already installed—and rejects non-regular files or links during cleanup.
- **rclone sessions shut down promptly again.** Kasumi terminates the rclone daemon as soon as it acknowledges `core/quit`, avoiding the extra wait at the end of each session.

## Compatibility and installation

- Existing Protocol v3 vaults open directly with v0.17.2. See the [upgrade precautions](https://github.com/auanK/kasumi/blob/v0.17.2/docs/best-practices.md#upgrading-kasumi).
- The built-in `kasumi update` command was removed in v0.17.0. For portable installations, download the archive for your platform, verify its SHA-256 checksum, and replace the executable. For managed installations, update through the package manager that installed Kasumi.
