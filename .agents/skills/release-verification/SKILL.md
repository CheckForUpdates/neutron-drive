---
name: release-verification
description: >-
  Run the authoritative build, lint, unit/integration test, CTest, and packaging
  verification gates for Proton Drive Linux. Use when validating changes before task
  completion, checking release readiness, or diagnosing build/test regressions across
  the Rust daemon and Qt6 C++ GUI.
---

# Release and Verification Gates

Execute these verification steps in order when validating repository changes or running
release-gate checks. Report exact commands, pass/fail counts, and any sandbox or host
limitations.

## 1. Rust Daemon Formatting & Static Analysis

Run from the repository root:

```bash
cargo fmt --manifest-path crates/proton-drive-daemon/Cargo.toml --all -- --check
cargo clippy --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets --all-features -- -D warnings
```

- **Completion criterion**: Both commands exit `0` with zero warnings or formatting diffs.

## 2. Rust Unit & Integration Test Suites

```bash
cargo test --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets
```

- Covers `lib.rs` unit tests plus integration suites: `daemon_control`, `data_safety`,
  `migration`, `namespace`, `native_client`, `reconciliation`, and `security`.
- **Safety note**: All tests must use `tempfile` directories and `FakeRemoteDrive` / local
  HTTP mocks, never mutating real XDG directories or live mounts.

## 3. CMake Build & CTest Suite (Rust + Qt6 C++ Async IPC)

```bash
cmake -S . -B build -DBUILD_TESTS=ON
cmake --build build -j$(nproc)
QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure
```

- Executes all registered CTest targets:
  1. `rust_backend_tests` (`native;authoritative`)
  2. `qt_ipc_async_tests` (`native;authoritative` — verifies non-blocking Qt event loop,
     single-inflight status polling, timeout/disconnect handling, malformed JSON resilience,
     native/browser login, tray notifications, and error recovery controls)

## 4. Packaging & Staged Install Check

When changes touch build/install/packaging files (`CMakeLists.txt`, `install.sh`, `packaging/`):

```bash
DESTDIR=/tmp/proton-drive-stage ./install.sh --prefix /usr
cpack --config build/CPackConfig.cmake -G "DEB;RPM;TGZ" -B build/packages
```

## 5. Reporting Boundaries

Always distinguish executed local/mock checks from unverified live-system behavior:
passing Cargo, Qt, and CTest suites does not establish live Proton authentication,
remote cloud sync, or kernel FUSE mount behavior on real user data.
