# Provider Certification

Kasumi's provider-neutral certification suite was successfully completed against the following storage backends. Every listed provider passed all 16 certification scenarios and completed ownership-safe cleanup.

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
