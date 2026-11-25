# Third-Party Artifacts, SDK Compliance & Dependency Provenance

This document outlines the provenance, Proton Drive SDK usage-guideline compliance, dependency architecture, and security audit status for **Neutron Drive** (`neutron-drive-daemon` and `neutron-drive-gui`), an unofficial third-party Linux client for Proton Drive.

---

## 1. Native Rust Protocol, SDK Compliance & CLI Retirement

Historically, early bring-up releases bundled an external Node/JS CLI executable (`bin/proton-drive`, SHA-256 `4f66f984b6361084d46567b8f4fd4851f4271eb9f77e5d181e1eff3c8a332501`, `cli-drive@0.9.0+75612299`).

With the completion of the pure-Rust native implementation (`crates/proton-drive-daemon/src/native/`):
- Authentication (SRP-6a, 2FA TOTP, and Browser SSO session forking), OpenPGP cryptography (`pgp 0.21`), encrypted key management (`zbus` Linux Secret Service / `SessionVault`), drive metadata/events, and 4 MiB streaming block transfers run directly inside `neutron-drive-daemon`.
- The bundled third-party CLI binary (`bin/proton-drive`), CLI download/extraction flags (`--cli-url`, `--cli-archive`, `--cli-sha256`), and `update-cli` provisioning subcommand have been retired.
- Upgrading existing installations via `./install.sh` / `./install.sh --update` automatically removes any legacy `$BIN_DIR/proton-drive` executable and migrates `"backend": "cli"` configurations to `"native"`.
- **Proton Drive SDK Usage Guidelines Compliance (`https://github.com/ProtonDriveApps/sdk`):**
  - `DEFAULT_APP_VERSION` in `crates/proton-drive-daemon/src/native/http.rs` is set to `external-drive-neutron_drive@3.0.3-alpha+linux` (`external-drive-{name}@{semver}-{channel}+{suffix}`) with an honest `DEFAULT_USER_AGENT` (`NeutronDrive/3.0.3 (Linux)`).
  - `RateLimitGate` (`crates/proton-drive-daemon/src/native/http.rs`) enforces per-family exponential backoff (base `2s`, capped at `300s`, resetting on `2xx`) when `Retry-After` is absent on `429` or transient `5xx` responses.
  - All CLI (`main.rs`) and GUI (`PreferencesDialog.cpp`) credential prompts display the required notice: `"This is a third-party application not officially supported by Proton."` Passwords are never stored.
  - `FORK_CHILD_CLIENT_ID` (`cli-drive`) in `crates/proton-drive-daemon/src/native/auth.rs` remains aligned with Proton's `account.proton.me` desktop session-fork endpoint pending live SSO verification with a disposable account.

### 1.1 Upstream Cryptographic Model Migration Tracking
- **Upstream Notice (`ProtonDriveApps/sdk`):** Proton has announced an upcoming cryptographic model migration for Proton Drive targeted for **late 2026 / early 2027** (subject to upstream schedule changes). Once deployed server-side, clients supporting only the v1 OpenPGP cryptographic model will not interoperate until updated.
- **Current Compatibility Status:** Neutron Drive currently implements the v1 OpenPGP + SRP-6a protocol (`native/crypto.rs`, `native/auth.rs`). Compatibility updates will track upstream releases in `ProtonDriveApps/sdk` prior to cutover.

---

## 2. Rust Dependencies & Security Review

The Rust backend (`proton-drive-daemon`) avoids legacy C wrappers wherever possible to minimize supply-chain risk and memory-safety vulnerabilities.

### 2.1 FUSE Implementation: `fuser 0.15.1`
- **Configuration**: Declared in `crates/proton-drive-daemon/Cargo.toml` as:
  ```toml
  fuser = { version = "0.15", default-features = false }
  ```
- **Security Rationale**:
  - `default-features = false` disables linking against the traditional system C `libfuse` shared library.
  - The implementation communicates directly with the Linux kernel via `/dev/fuse` using pure Rust serialization and deserialization of the kernel FUSE ABI.

### 2.2 Dependency Audit Summary

| Crate | Version | Rationale & Security Profile |
|---|---|---|
| `rusqlite` | `0.32` | Uses `features = ["bundled"]` to compile a pinned SQLite amalgamation directly into the binary. |
| `pgp` | `0.21` | Pure Rust OpenPGP (`rPGP`) implementation for key unlocking, signatures, PKESK/SEIPD encryption, and block decryption. |
| `reqwest` | `0.12` | Pure Rust TLS (`rustls-tls-webpki-roots`) HTTP client for Proton Drive REST API and block storage transfers. |
| `ring` / `sha2` | `0.17` / `0.11` | Audited cryptographic hash and HMAC primitives for SRP-6a, NameHasher, and block/file integrity verification. |
| `zbus` | `5` | Pure Rust D-Bus client for Linux Secret Service credential storage in `SessionVault`. |
| `zeroize` | `1.9` | Scrubs passphrases, session tokens, and private key material from memory on drop. |
| `tokio` | `1.40` | Asynchronous runtime for Unix domain socket IPC and background task coordination. |
| `serde` / `serde_json` | `1.0` | Typed JSON serialization and parsing for API payloads, IPC, and configuration. |
| `libc` | `0.2` | Minimal POSIX bindings used for socket peer credential validation (`SO_PEERCRED`), `isatty`/`termios`, and UID checks. |
| `dirs` | `5.0` | Standard XDG base directory lookup (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`). |
| `fastrand` | `2.0` | Lightweight PRNG used for non-cryptographic local cache identifiers and multipart boundaries. |
| `tempfile` | `3.10` | Secure creation of temporary files with restricted permissions (`0o600`) for staging and atomic cache operations. |
| `clap` | `4.5` | Command-line argument parsing for daemon and user CLI commands. |
| `log` / `env_logger` | `0.4` / `0.11` | Structured diagnostic logging. |

### 2.3 Dependency Provenance & Hygiene
- **Pinned Checksums**: All dependency sources and cryptographic package hashes are recorded in `crates/proton-drive-daemon/Cargo.lock`.
- **Zero Unvetted C Extensions**: Aside from SQLite (bundled and pinned) and `libc` (system interface), no unvetted C/C++ libraries are linked into the daemon.
- **Local Isolation**: Local IPC sockets, configuration directories, `SessionVault` metadata, and SQLite databases use mode `0o600` or `0o700`, preventing unprivileged local access across user boundaries.
