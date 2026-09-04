# Kasumi

Kasumi is a bidirectional file synchronizer written in C++23 for Linux and Windows. It synchronizes directories across multiple machines through shared storage, including local filesystems, network shares, and rclone-compatible remotes. Machines synchronize independently, encrypt data on the client side, and do not need to be online at the same time.

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
- **Linux and Windows**: Native builds for Linux and Windows.

## Documentation

- [Configuration and Usage](docs/configuration-and-usage.md)
- [Architecture](docs/architecture.md)
- [Security](docs/security.md)
- [Build and Test](docs/build-and-test.md)

## License

Kasumi is released under the [MIT License](LICENSE). Third-party components retain their respective licenses; see [Third-Party Notices](THIRD_PARTY_NOTICES.md).
