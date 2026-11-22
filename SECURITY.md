# Security Policy

## Supported Versions

Kasumi is pre-1.0 software. Security fixes target only the latest released
`0.x` version on `main`; older `0.x` releases do not receive backports.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities privately through GitHub Security Advisories:
https://github.com/auanK/kasumi/security/advisories/new

Include as much of the following as possible:

- Kasumi version (`kasumi --version`), operating system, and architecture
- Affected command or component
- Steps to reproduce or a minimal proof of concept
- Expected versus observed behavior

Never include real passwords, password salts, master keys, `key.bin` files, or
private vault contents in a report.

## Scope & Threat Model

See [Security](docs/security.md) for Kasumi's cryptographic design, local key
storage trade-offs (`vault`, `file`, `memory`), and documented threat model
boundaries (including that Kasumi does not isolate against a compromised same-user
local host).
