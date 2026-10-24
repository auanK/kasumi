# Kasumi v0.8.3

Maintenance release of Kasumi focused on transactional file crypto operations,
data integrity guarantees, handle ownership, and cryptographic buffer
management.

## Highlights

### Transactional file encryption and decryption

File encryption and decryption now use isolated temporary files with
private permissions and atomic publication. Before publication,
validation, authentication, or I/O failures leave existing destination
files unchanged.

If publication succeeds but a subsequent durability operation fails,
the operation may report an error even though the new output is already
present.

### Safe temporary cleanup and alias protection

Temporary output files are verified by unique physical file identity
(`FileIdentity`) before removal, preventing accidental unlinking of colliding
or replaced files. Encryption and decryption routines validate input and
destination paths up front, rejecting empty paths, identical inputs and outputs,
directory or symlink targets, and hardlinked aliases of the input file to prevent
destructive data overwrites.

### Handle lifecycle and leak prevention

Private file handling now uses RAII-based ownership (`PrivateHandle`)
for Windows handles and POSIX file descriptors. The changes fix a
double-close defect and improve resource ownership and cleanup across
the affected file operations.

### Buffer optimizations and secure memory wiping

- Encryption and decryption use payload-sized scratch buffers up to
  the configured chunk limit, reducing memory consumption and wipe
  work for small files.
- Sensitive working buffers, nonces, and authentication tags are wiped
  through RAII cleanup on normal and exceptional exits.
- BLAKE3 file hashing uses a 64 KiB read buffer with RAII memory
  wiping.

## Compatibility

Kasumi 0.8.3 introduces no remote protocol, SQLite, content, or history format
changes. The project does not guarantee backward compatibility between 0.x
releases; use the same release on all clients.
