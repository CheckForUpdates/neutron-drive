# Contributing to Neutron Drive

Thank you for your interest in contributing to Neutron Drive (an unofficial third-party Linux client for Proton Drive). This document covers development prerequisites, local verification gates, and data-safety testing rules.

## Prerequisites

- **C++17 Compiler:** GCC 10+ or Clang 11+
- **CMake:** 3.22 or newer
- **Qt6:** `Core`, `Gui`, `Widgets`, `Network`, and `Test`
- **Rust & Cargo:** 1.70 or newer (with `rustfmt` and `clippy` components)
- **FUSE:** `fuse3` (`fusermount3`) or `fuse` (`fusermount`)

See [`README.md`](README.md) for distribution-specific package installation commands on Debian/Ubuntu, Fedora, and Arch Linux.

## Repository Layout

- `crates/proton-drive-daemon/` — Authoritative pure-Rust FUSE daemon, SQLite metadata store, sync engine, IPC server, and Proton Drive protocol/crypto stack (`src/native/`).
- `src/gui-cpp/` — C++17 Qt6 system tray client (`IpcClient`, `TrayCoordinator`, `PreferencesDialog`, `OnboardingDialog`, `QuotaWidget`).
- `tests/test_ipc_async.cpp`, `tests/test_onboarding.cpp` — Qt6 asynchronous IPC, UI event-loop, and guided onboarding test suites.
- `bin/neutron-drive`, `install.sh`, `desktop/`, `packaging/` — Unified launcher, installer, systemd user unit, and distribution packaging recipes.
- `docs/` — Technical reference documentation (`data-safety-fixes.md`, `third-party-artifacts.md`).

## Verification Gates

All contributions touching the Rust daemon or C++/Qt6 frontend must pass the release verification gates before submission:

1. **Rust formatting check:**
   ```bash
   cargo fmt --manifest-path crates/proton-drive-daemon/Cargo.toml --all -- --check
   ```
2. **Rust strict lint check:**
   ```bash
   cargo clippy --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets --all-features -- -D warnings
   ```
3. **Rust unit and integration test suites:**
   ```bash
   cargo test --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets
   ```
4. **CMake build and headless CTest suite (Rust + Qt6 IPC tests):**
   ```bash
   cmake -S . -B build -DBUILD_TESTS=ON
   cmake --build build -j"$(nproc)"
   QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure
   ```

## Mock vs. Live Test Boundaries

- **Automated Suites Run Against Isolated Mocks:** All default unit and integration tests execute against `FakeRemoteDrive` and isolated temporary directories (`TempDir`). They must never touch real user XDG directories (`~/.config`, `~/.local`, `~/.cache`) or live Proton accounts.
- **What Automated Tests Do Not Prove:** Passing local mocked tests does not prove live Proton server compatibility, live OpenPGP/SRP-6a authentication flows, token refresh behavior, or kernel FUSE mount durability under real workloads.
- **Live Validation Rules:**
  - The three `#[ignore]` live interoperability tests in `crates/proton-drive-daemon/tests/native_client.rs` require a dedicated, disposable Proton Drive test account with non-sensitive data.
  - Never test unverified changes, FUSE mount experiments, or manual sync runs against personal or critical Proton Drive data.

## Code & Data-Safety Expectations

- Preserve owner-only file and directory permissions (`0700` directories, `0600` files and Unix domain sockets) and `SO_PEERCRED` caller UID verification on IPC connections.
- Never allow background uploads or cache eviction to touch files with open writable handles (`ActivityRegistry`) or stale generations.
- Execute SQLite schema migrations and subtree namespace updates inside explicit transactions so failures roll back cleanly.
- Document known filesystem/sync trade-offs accurately in `docs/data-safety-fixes.md` and `CHANGELOG.md` if behavior changes.
