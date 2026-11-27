## Summary
<!-- Briefly describe what this PR changes and why. -->

## Related Issues
<!-- Link any related issues (e.g., Fixes #123). -->

## Scope & Risk Area
- [ ] Rust daemon / CLI (`crates/proton-drive-daemon/`)
- [ ] High-risk core (`fuse_fs.rs`, `sync_engine.rs`, `metadata_db.rs`, `ipc.rs`, `native/`)
- [ ] Qt6 C++ GUI (`src/gui-cpp/`)
- [ ] Packaging / Installer / CI (`CMakeLists.txt`, `install.sh`, `packaging/`, `.github/`)
- [ ] Documentation only

## Verification Gates
Per [`CONTRIBUTING.md`](CONTRIBUTING.md), please confirm all applicable checks pass locally:

- [ ] `cargo fmt --manifest-path crates/proton-drive-daemon/Cargo.toml --all -- --check`
- [ ] `cargo clippy --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets --all-features -- -D warnings`
- [ ] `cargo test --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets`
- [ ] `cmake -S . -B build -DBUILD_TESTS=ON && cmake --build build -j"$(nproc)" && QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure`

## Data-Safety & Testing Notes
- [ ] Automated tests use isolated temp directories and `FakeRemoteDrive` mocks (no real XDG dirs or personal accounts).
- [ ] Preserves `0700`/`0600` permissions, `SO_PEERCRED` IPC UID checks, `ActivityRegistry` open-writer guards, and transactional SQLite updates.
- [ ] If tested against a live disposable Proton Drive account, describe the scope and outcome below.
