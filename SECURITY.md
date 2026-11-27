# Security Policy

## Supported Versions

Neutron Drive is currently in pre-release (`3.0.x`). Security fixes are applied to the default branch and included in subsequent pre-release/release tags.

| Version | Supported |
| --- | --- |
| `3.0.x` (default branch / latest tag) | Yes |
| `< 3.0.0` | No |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security issue—especially involving SRP-6a authentication, OpenPGP key handling or streaming block encryption, `SessionVault` / Linux Secret Service credential storage, Unix domain socket IPC (`SO_PEERCRED`), or FUSE path/permission handling—please report it privately:

1. Open a private **GitHub Security Advisory** at:
   https://github.com/CheckForUpdates/neutron-drive/security/advisories/new
2. Include:
   - Affected component/file (e.g., `native/auth.rs`, `native/crypto.rs`, `ipc.rs`, `fuse_fs.rs`, `install.sh`).
   - Clear reproduction steps or proof-of-concept.
   - Potential impact and any suggested mitigation.

## Response Expectations

- We aim to acknowledge private reports within **72 hours** and provide an initial assessment or remediation plan within **7 days**.
- Please allow reasonable time for a fix and release before public disclosure.

## Scope & Security Model Notes

- Neutron Drive is an **unofficial, independent third-party client** and is not affiliated with Proton AG.
- Local secrets are stored via Linux Secret Service (`zbus`) or encrypted `SessionVault` files with `0700`/`0600` permissions; passwords are never persisted.
- IPC sockets enforce `0700`/`0600` permissions, Linux `SO_PEERCRED` caller UID verification, and bounded 64 KB framing.
