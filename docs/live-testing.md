# Live Interoperability & FUSE Durability Testing

> **Safety Rule:** Always run live tests against a **dedicated, disposable Proton Drive test account** with non-sensitive data. Never test unverified builds or FUSE mount experiments against personal or critical Proton Drive accounts.

Automated CI suites run against isolated `FakeRemoteDrive` mocks. Phase 2 validation verifies Neutron Drive against live Proton Drive servers and a real kernel `/dev/fuse` mount.

---

## 1. Automated Live Interoperability Tests (`native_client`)

Three `#[ignore]` tests in [`crates/proton-drive-daemon/tests/native_client.rs`](../crates/proton-drive-daemon/tests/native_client.rs) exercise real Proton API authentication, block transfers, FUSE handles, and event polling:

1. `test_live_disposable_account_authenticated_read` — SRP-6a or Browser SSO login, quota retrieval, and `/my-files` listing.
2. `test_live_disposable_account_transfer_interoperability` — Empty file and multi-block (`> 4 MiB`) upload, revision replacement, and SHA-256 verified download.
3. `test_live_disposable_account_namespace_and_events` — `ProtonDriveFUSE` write/release + `SyncEngine` upload, namespace operations, and event cursor polling.

### Option A: Browser SSO Login (Interactive)

If `PROTON_TEST_USERNAME` is unset (or `PROTON_TEST_BROWSER_LOGIN=1` is set), the tests launch `xdg-open` for Browser SSO and wait up to 300 seconds:

```bash
PROTON_TEST_BROWSER_LOGIN=1 cargo test \
  --manifest-path crates/proton-drive-daemon/Cargo.toml \
  --test native_client -- --ignored --nocapture --test-threads=1
```

### Option B: Username / Password (+ Optional TOTP)

```bash
PROTON_TEST_USERNAME="disposable@proton.me" \
PROTON_TEST_PASSWORD="your-test-password" \
PROTON_TEST_TOTP="123456" \
cargo test \
  --manifest-path crates/proton-drive-daemon/Cargo.toml \
  --test native_client -- --ignored --nocapture --test-threads=1
```

*(Omit `PROTON_TEST_TOTP` if 2FA is not enabled on the disposable account. Use `--test-threads=1` so tests do not race on rate limits or concurrent browser SSO prompts.)*

---

## 2. Live `/dev/fuse` & Desktop Smoke Checklist

After building and installing (or running from `build/`), validate the full daemon + FUSE + Qt6 tray stack:

- [ ] **Authentication & Vault:**
  - `neutron-drive login` (or `neutron-drive login --browser`) succeeds and persists session in Secret Service / `SessionVault` across daemon restarts.
  - `neutron-drive status --json` reports authenticated state and accurate storage quota.
- [ ] **Mount & Unmount Lifecycle:**
  - `neutron-drive start` and `neutron-drive mount` cleanly mount `~/NeutronDrive`.
  - `neutron-drive unmount` and `neutron-drive stop` cleanly unmount without leaving stale FUSE mounts (`mount | grep NeutronDrive` is empty).
- [ ] **File Manager Browsing:**
  - Open `~/NeutronDrive` in your desktop file manager (Dolphin, Nautilus, Thunar, etc.); directory listings hydrate without UI freezes or duplicate entries.
- [ ] **Transfers & Open-Writer Safety:**
  - Copy a small file (`< 4 MiB`) and a multi-block/large file (`> 100 MiB` or `> 1 GiB`) into `~/NeutronDrive`; verify SHA-256 matches after re-hydrating on a cleared cache (`neutron-drive clear-cache`).
  - Keep a file open for writing (`ActivityRegistry` active handle) and confirm background sync waits until the writer closes the handle.
- [ ] **Pause / Resume & Network Recovery:**
  - Trigger `neutron-drive pause` during active sync, verify `status` stays `paused`, then `neutron-drive resume`.
  - Temporarily disconnect network, verify `Offline` status badge and recovery upon reconnect.
- [ ] **Qt6 System Tray:**
  - `neutron-drive gui` shows tray icon, live `QuotaWidget`, desktop notifications on errors, and working Preferences/Onboarding dialogs on both X11 and Wayland.

---

## 3. Recording & Reporting Results

- File findings using the **Live Mount / Interoperability Feedback** GitHub issue template ([`.github/ISSUE_TEMPLATE/live_test_report.yml`](../.github/ISSUE_TEMPLATE/live_test_report.yml)).
- Never include session tokens, passwords, TOTP codes, or personal filenames in issue reports.
- Update [`docs/data-safety-fixes.md`](data-safety-fixes.md) and [`CHANGELOG.md`](../CHANGELOG.md) when live testing reveals or resolves protocol/FUSE edge cases.
