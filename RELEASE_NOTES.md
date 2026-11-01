# Kasumi v0.9.2

Release focused on reusing local files and accepted remote Content to reduce transfers during moves, renames, and copies.

## Highlights

### Local Moves and Copies

Eligible remote moves and renames reuse verified local files instead of downloading them again. Copies use matching local bytes while preserving the source, and local moves reuse accepted remote Content to avoid redundant uploads. `CopyLocal` still checks required Content presence and repairs missing objects from verified local sources.

### Transaction Safety and Recovery

Verified staging, no-overwrite installation, and identity checks protect local files during execution, rollback, and recovery. Interrupted work preserves operation dependencies and confirmed progress; detected external changes stop conflicting mutations, and ambiguous recovery retains evidence.

## Compatibility

Remote object formats and the SQLite schema are unchanged. Local transaction journals can contain the new move and copy operations. Kasumi provides no backward compatibility between 0.x releases or automatic migration. Use the same release on all clients and follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi) before replacing binaries. `kasumi update` replaces only the executable.
