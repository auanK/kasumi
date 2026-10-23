# Kasumi v0.8.2

Maintenance release of Kasumi.

## Highlights

### Faster no-op and small syncs

Normal Sync now checks remote Content needed by the current work instead of
checking every remote Content ID. An unchanged no-op avoids a global content
presence scan. In one observed run of the `Pictures` profile, a no-op went from
about 108–114 seconds to 4–5.1 seconds. Those measurements describe that
specific setup and are not a general performance guarantee.

### Optional remote inventory audit

Run `kasumi sync <profile> --audit-inventory` to request a structural audit
after normal Sync. It reports referenced, present, missing, and orphan Content
across reachable history, as well as unknown physical objects. This explicit
full-inventory operation can take time proportional to the remote inventory.
A complete Sync with no findings exits `0`; findings or a partial Sync exit
`2`; audit failure exits `1`. The flag cannot be combined with `--dry-run` or
`--initial`.

## Behavior change

Normal Sync no longer discovers or repairs remote Content missing outside the
current operation's requirements. Use the optional audit to find structural
absences; use Fsck or `remote contents --audit` for payload integrity checks.

## Compatibility

Kasumi 0.8.2 introduces no remote protocol, SQLite, content, or history format
changes. The project does not guarantee backward compatibility between 0.x
releases; use the same release on all clients.

## Known limitations

The audit is structural and does not download or authenticate Content payload
bytes. It compares two full physical listings and rejects detected writers,
barriers, or changes between them, but does not provide an atomic snapshot or
prove that no transient concurrent change occurred. The audit phase does not
repair or delete objects. Normal Sync runs first and may publish changes; a
later audit failure does not roll that publication back.
