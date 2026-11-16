# Kasumi v0.11.0

Profile usability release with simpler configuration and clearer local diagnostics.

## Highlights

- `kasumi list` prints only profile names. `kasumi show <profile>` displays settings, retention, local state, and the reason for inspection problems, without displaying credentials or contacting remote storage.
- The configuration wizard uses a compact list, grouped credential prompts, and per-field validation. Deleting profiles or changing paths requires explicit confirmation, defaulting to No.
- Status and dry-run plans use translated descriptions for local and remote actions, directories, and disposable ignored files.
- Ubuntu CI runs the existing test suite with AddressSanitizer and UndefinedBehaviorSanitizer.

## Compatibility

- Scripted wizard input must account for the new confirmations. `list` and `show` have no duration line and report errors on stderr.
- Remote formats, encryption schemes, and the SQLite schema remain unchanged from v0.10.0. The journal writer remains format 10; readers accept formats 9 and 10.
- Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi). `kasumi update` replaces only the executable and does not migrate data or guarantee cross-release compatibility.
