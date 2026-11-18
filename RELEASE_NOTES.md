# Kasumi v0.14.1

Patch release for the interactive profile wizard and compiler diagnostics.

## Highlights

- New profiles ask where to store the key before asking for the password and salt. Press Enter for the operating system credential vault, or choose `file` or `memory`.
- The empty profile menu offers New and Quit. Type `:back` at profile, path, or key storage prompts to return to the menu.
- GCC and Clang build fixes cover platform code and GCC's LTO handling of Zstandard's assembler flags.

## Compatibility

- Scripts that create profiles through `kasumi config` must pass a storage mode or an empty line after the remote destination.
- `v0.14.1` uses the same Protocol v3 vault format, transaction journal format, and profile configuration as `v0.14.0`. Follow [Upgrading Kasumi](docs/best-practices.md#upgrading-kasumi).
