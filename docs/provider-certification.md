# Provider Certification

The recorded provider-neutral certification runs cover the following storage backends. Every listed provider passed all 16 scenarios and completed ownership-safe cleanup; see the [changelog's validation record](../CHANGELOG.md#060). These results describe those runs, not certification of every later binary or provider configuration.

| Provider | Remote physical SHA-256 |
|---|---|
| Local Filesystem | Unsupported |
| Google Drive | Supported |
| OneDrive | Unsupported |
| SFTP | Not recorded |
| FTP | Unsupported |
| Explicit FTPS | Unsupported |
| WebDAV | Unsupported |
| Dropbox | Unsupported |
| Backblaze B2 | Unsupported |
| Azure Blob Storage | Unsupported |
| S3-compatible (MinIO) | Unsupported |

`physical_hash` is an optional transport optimization. Providers without remote SHA-256 support remain certified through Kasumi's verified fallback path.

This table records only physical-hash capability. It does not certify provider-wide `LIST`/`PRESENCE` consistency for online destructive maintenance. The maintenance probe checks its own temporary object and cannot establish visibility of every existing control object; confirm those provider guarantees separately as described in [Transport](architecture/transport.md).

See [Transport](architecture/transport.md) for the capability boundary and [Garbage Collection](architecture/garbage-collection.md) for runtime visibility checks.
