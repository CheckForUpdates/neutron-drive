# Project Workflow

Lead with outcomes, cite concrete evidence, keep updates concise, and state blockers
honestly. Make routine reversible decisions independently. Do not execute, suggest,
or provide Git commands unless explicitly asked.

## Custom Subagents (`.agents/agents/`) and Risk Routing

When delegating work to an isolated context window or separate workspace
(`invoke_subagent`), route by the task's highest-risk behavior:

| Subagent | Definition | Scope |
| --- | --- | --- |
| `implementer` | `.agents/agents/implementer.md` | Default: routine features, bounded fixes, CLI (`src/main.rs`) and Qt6 GUI (`src/gui-cpp/`) changes |
| `mechanical-implementer` | `.agents/agents/mechanical-implementer.md` | Narrow mechanical edits, boilerplate, lint/format cleanup, straightforward tests |
| `risk-implementer` | `.agents/agents/risk-implementer.md` | FUSE (`fuse_fs.rs`), sync engine (`sync_engine.rs`), SQLite migrations/WAL (`metadata_db.rs`), concurrent handles (`ActivityRegistry`), crash recovery, IPC auth (`ipc.rs`), native protocol/crypto (`native/`) |
| `research` | Built-in | Read-only codebase or documentation exploration requiring an isolated context window |

- **Model selection**: Leave `Model` set to `"inherit"` on `invoke_subagent` unless
  the user explicitly requests `"pro"`, `"flash"`, or `"flash_lite"`.
- **Single-writer discipline**: Keep at most one active writer per file scope; pass
  `Workspace: "share"` or `"branch"` only when parallel isolated checkouts are
  explicitly warranted. Subagents follow their assigned contract and do not spawn
  additional agents.
- **Delegation contract**: Supply the goal, allowed edit scope, relevant paths and
  symbols, `codebase-memory-mcp` coverage findings, invariants to preserve,
  acceptance criteria, and exact validation commands (see `docs/agent-workflow.md`
  for the brief template). Reuse the existing subagent `conversationId` via
  `send_message` for corrections within the same role.

## Workspace Skills (`.agents/skills/`)

- **`evidence-review`** (`.agents/skills/evidence-review/SKILL.md`): Project default
  for code-quality, concurrency, security, and storage/sync reviews of working
  changes, branches, PRs, or bounded audits. Load `code-review` only when explicitly
  requested. Keep reviews read-only and separate from fixes unless fixes are
  requested.
- **`release-verification`** (`.agents/skills/release-verification/SKILL.md`):
  Multi-step verification and release-gate runbook for the Rust daemon, Qt6 C++ GUI,
  and CPack/installer packaging.

## Project Context and Discovery

- **Authoritative Native Implementation**:
  - Rust daemon & FUSE backend: `crates/proton-drive-daemon/` (`src/lib.rs`,
    `src/daemon.rs`, `src/fuse_fs.rs`, `src/sync_engine.rs`, `src/metadata_db.rs`,
    `src/ipc.rs`, `src/client.rs`, `src/config.rs`, `src/native/`, and `tests/`).
  - C++17 Qt6 GUI frontend: `src/gui-cpp/` (`IpcClient`, `TrayCoordinator`,
    `PreferencesDialog`, `OnboardingDialog`, `QuotaWidget`),
    `tests/test_ipc_async.cpp`, and `tests/test_onboarding.cpp`.
  - Launcher & packaging: `bin/neutron-drive`, `install.sh`, `CMakeLists.txt`
    (CPack `.deb`/`.rpm`/`.tar.gz`), and `packaging/arch/PKGBUILD`.
- **Excluded from Default Search**: `build/`, `crates/proton-drive-daemon/target/`,
  and any local ignored reference artifacts (`mac-drive-source/`, `extracted/`,
  `*.dmg`) if present. Verify README capability claims in code.
- **Structural Discovery**: Query `codebase-memory-mcp` first (`list_projects` /
  `index_status`, `search_graph`, `trace_path`, `get_code_snippet`, and batched
  `check_index_coverage`). Read/grep source directly for coverage gaps or excluded
  paths. Pass graph findings and coverage limits in plans and subagent briefs so
  workers do not repeat discovery.
- **Documentation**:
  - `docs/` holds repo-committed technical reference documentation
    (`data-safety-fixes.md`, `third-party-artifacts.md`, `agent-workflow.md`).

## Validation and Data Safety

Run targeted checks during implementation, then execute the relevant verification
commands before completion:

- **Rust backend**:
  - `cargo fmt --manifest-path crates/proton-drive-daemon/Cargo.toml --all -- --check`
  - `cargo clippy --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets --all-features -- -D warnings`
  - `cargo test --manifest-path crates/proton-drive-daemon/Cargo.toml --all-targets`
- **CMake & CTest (Rust + Qt6 IPC suites)**:
  - `cmake -S . -B build -DBUILD_TESTS=ON && cmake --build build -j$(nproc) && QT_QPA_PLATFORM=offscreen ctest --test-dir build --output-on-failure`

Report exact commands, outcomes, and any sandbox or environmental constraints.
Use isolated temporary directories and `FakeRemoteDrive` mocks for filesystem and
sync checks. Passing unit or integration tests does not prove live Proton cloud
sync, FUSE mount durability, or encryption correctness.
