# Working with Google Antigravity and Orchestrator (Argon)

This project uses **Google Antigravity** with **Orchestrator (Argon)** as the primary
model configuration. Workspace rules live in [`AGENTS.md`](../AGENTS.md), custom
subagents in `.agents/agents/`, and on-demand procedural skills in `.agents/skills/`.

## 1. How Orchestrator (Argon) Works

Orchestrator (Argon) dynamically routes turns within a single conversation between two
phases:

1. **Planning Turn (Gemini 4 Argon)**:
   - Opens in read-only **plan mode** on every user message and every `[plan review]`
     hand-back from the execution model.
   - For questions, architecture explanations, or read-only reviews (`evidence-review`),
     Argon answers directly and ends the turn without calling `exit_plan_mode`.
   - For implementation or workspace changes, Argon performs read-only investigation
     (`codebase-memory-mcp`, `read_file`, non-mutating test/build commands), settles
     all design and data-safety decisions, and calls `exit_plan_mode` with a complete
     execution plan.
2. **Execution Turn (Fast Execution Model)**:
   - Runs in the same conversation immediately after `exit_plan_mode`.
   - Applies the planned edits, runs the specified verification gates, and hands back
     to Argon (`[plan review]`) if any `"Re-plan if:"` condition triggers or when
     execution completes.

## 2. Plan Hand-Off Template (`exit_plan_mode`)

Every plan passed to `exit_plan_mode` should include:

```text
Goal: [observable behavior or defect to resolve]
Graph & source evidence: [checked paths, symbols, and coverage gaps]
Ordered steps:
  1. [File + symbol + exact change]
  2. [Tests to add or update]
Invariants to preserve: [relevant items from docs/data-safety-fixes.md]
Verification commands & expected output:
  - [exact cargo / cmake / ctest / unittest commands]
Pitfalls: [known edge cases, lock ordering, or environment notes]
Re-plan if:
  - [specific signs that the plan is wrong and the executor must hand back]
```

## 3. Delegating to Custom Subagents (`invoke_subagent`)

When a task benefits from an isolated context window, risk-scoped execution, or
parallel workstreams, invoke one of the workspace subagents in `.agents/agents/`:

- **`implementer`** (`.agents/agents/implementer.md`): Routine features, bounded bug
  fixes, CLI (`crates/proton-drive-daemon/src/main.rs`), and Qt6 GUI (`src/gui-cpp/`) changes.
- **`mechanical-implementer`** (`.agents/agents/mechanical-implementer.md`): Narrow
  mechanical edits, lint/formatting cleanup, and straightforward tests.
- **`risk-implementer`** (`.agents/agents/risk-implementer.md`): High-risk storage,
  FUSE (`fuse_fs.rs`), sync (`sync_engine.rs`), SQLite migrations/WAL (`metadata_db.rs`),
  concurrent handles (`ActivityRegistry`), IPC `SO_PEERCRED` auth (`ipc.rs`), and CLI
  executable safety (`client.rs`).

### Subagent Brief Template

Subagents start with a fresh context window and do not see prior conversation turns.
Include all required context in `Prompt`:

```text
Goal:
Allowed files / scope:
Relevant symbols and current behavior:
Graph coverage / source checks / known gaps:
Decisions and data-safety invariants to preserve:
Acceptance criteria:
Validation commands:
Return: changed files, acceptance results, exact test outputs, unresolved issues.
Escalate architectural or scope changes. Do not spawn more agents.
```

Leave `Model` as `"inherit"` unless the user explicitly requests `"pro"`, `"flash"`,
or `"flash_lite"`. Reuse the returned `conversationId` via `send_message` when sending
follow-up corrections to the same subagent.

## 4. Verification and Review Standards

- Use the **`evidence-review`** skill (`.agents/skills/evidence-review/SKILL.md`) for
  code reviews and audits.
- Use the **`release-verification`** skill (`.agents/skills/release-verification/SKILL.md`)
  for full Rust, Qt6 C++, Python, and binary provenance checks.
- Always run filesystem and sync tests against isolated temporary directories and
  `FakeRemoteDrive` mocks, and distinguish mock test results from live Proton / FUSE
  runtime verification.
