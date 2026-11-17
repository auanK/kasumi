# Kasumi v0.11.2

Minor CLI output fix omitting the elapsed-time line from the interactive configuration wizard.

## Highlights

- **`kasumi config` output:** Omitted the final `Duration` / `Duração` line from the interactive configuration wizard, keeping elapsed-time output on sync, maintenance, remote, and update operations (`config`, `list`, and `show` omit it).

## Compatibility

- Remote formats, encryption schemes, and the SQLite schema remain unchanged from v0.11.0. The journal writer remains format 10; readers accept formats 9 and 10.
- Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi). `kasumi update` replaces only the executable and does not migrate data or guarantee cross-release compatibility.
