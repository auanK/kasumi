# Windows self-update UAC smoke test

Automated tests cover ACL shape, file identity, rollback, and Unicode handoff. They do not emulate a real UAC credential prompt.

1. Create a disposable copy of a signed Kasumi release in a directory writable only by Administrators, and run it from a standard Windows account. Keep the original installation untouched.
2. Run `kasumi update`, then approve UAC with a **different** local administrator account. Confirm the update completes, the copy reports the new version, and a `.kasumi-previous-*` recovery file contains the previous executable.
3. Restore the old disposable copy and repeat, but cancel the UAC prompt. Confirm the command fails and the executable's SHA-256 is unchanged.
4. Repeat with a disposable path containing non-ASCII characters, such as `C:\Users\João\Aplicações\Kasumi`.

This smoke test is intentionally manual: it requires two Windows accounts and real UAC credentials. Do not point it at a production installation.
