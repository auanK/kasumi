# Kasumi v0.9.1

Patch release fixing downloads directly in a synchronization root configured through a trailing-slash directory symlink.

## Highlights

### Symlink Root Downloads

Sync now handles downloads directly beneath a configured directory symlink root, consistent with upload and nested-directory behavior. Symlinks inside the synchronized tree remain rejected.

## Compatibility

No remote protocol or persistent format changes. Kasumi does not guarantee backward compatibility between 0.x releases; see [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).
