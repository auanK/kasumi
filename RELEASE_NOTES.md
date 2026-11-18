# Kasumi v0.12.0

Configurable key storage release adding OS credential vault integration on Windows and Linux alongside file and in-memory key modes.

## Highlights

- **Per-profile `key_storage` modes (`vault`, `file`, `memory`):** New profiles default to `vault` (Windows Credential Manager on Windows; GNOME Keyring / Freedesktop Secret Service and KDE KWallet on Linux loaded dynamically on demand via `dlopen`). `file` keeps using `key.bin`, and `memory` prompts for password and salt on every operation without writing the key to disk or vault.
- **Interactive and CLI key management:** Added `kasumi key <profile>` and `[k] Key` / `[s] Storage` options in `kasumi config` to switch storage modes (cleaning up the previous persisted key) and re-enter profile keys.
- **Headless Linux portability:** Binaries remain portable without hard shared-library dependencies on desktop keyrings when running `file` or `memory` modes without D-Bus.

## Compatibility

- Existing profiles in `config.toml` without a `key_storage` field default to `file` and continue reading their existing `key.bin` automatically.
- Remote formats, encryption schemes, and the SQLite schema remain unchanged from v0.11.0. The journal writer remains format 10; readers accept formats 9 and 10.
- Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi). `kasumi update` replaces only the executable and does not migrate data or guarantee cross-release compatibility.
