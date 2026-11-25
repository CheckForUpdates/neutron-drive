---
name: evidence-review
description: >-
  Default code quality, concurrency, security, and data-safety review for this project:
  uncommitted changes, branches, PRs, or bounded code audits. Use for review requests
  unless the user explicitly selects another review skill. Produces evidence-backed
  findings without modifying the workspace.
---

# Evidence Review

Deliver actionable, evidence-backed findings with an explicit scope and verification record.
In **Orchestrator (Argon)**, a review request without an explicit fix request is a
read-only turn: complete the review directly on Gemini 4 Argon and **stop without calling
`exit_plan_mode`**. Only transition to an execution plan if the user explicitly asks to
apply fixes.

## 1. Establish the Review Target

- Honor the requested scope: working changes, a branch/PR diff, or a bounded path audit.
  Record the target and baseline before interpreting changes. Ask only when ambiguity
  materially changes what is reviewed; otherwise state the chosen scope.
- Check whether version control is active before running diff commands. In directories
  without a Git checkout, compare against preserved `.old/` or backup baselines if
  present, or audit the named paths directly without inventing a baseline or labeling
  existing issues as regressions. Never initialize Git to perform a review.
- When reviewing working changes in a Git checkout, inspect status, staged/unstaged
  diffs, and untracked files. If a requested diff is empty, report that and stop rather
  than silently expanding to a codebase audit.
- Read applicable specs and `docs/data-safety-fixes.md`. When no external requirement
  exists, evaluate code behavior and invariant adherence and note that spec conformance
  is unverified.

## 2. Gather Evidence Read-Only

- Preserve source, tests, build artifacts, configuration, and user data. Run verification
  commands only after confirming they are read-only and use isolated temporary paths.
  Never authenticate, mount a live FUSE filesystem over user data, start live sync, or
  mutate workspace files to substantiate a finding.
- Use `codebase-memory-mcp` (`list_projects` / `index_status`, `search_graph`,
  `trace_path`, `get_code_snippet`, and batched `check_index_coverage`) scoped to Linux
  implementation paths (`crates/proton-drive-daemon/`, `src/gui-cpp/`, `src/`, `tests/`).
  Use `read_file` / grep fallback for any coverage gaps or excluded paths
  (`src/third_party/`).
- Inspect implementation and tests together across correctness, concurrency, security,
  error propagation, and maintainability. For any change touching FUSE, sync, SQLite
  metadata, caching, IPC, or CLI execution, apply [storage and sync checks](references/storage.md).

## 3. Qualify Every Candidate Finding

Before reporting a defect, establish all four elements:

1. **Location & mechanism**: Exact file, line range, symbol, and caller/callee chain.
2. **Trigger & impact**: Concrete input, timing, or failure condition and the resulting
   data loss, security exposure, crash, or user-visible failure.
3. **Evidence**: A failing test/reproduction output, or a complete source-level trace.
   Label source-traced findings as `Source-verified`—never claim they were reproduced
   at runtime unless executed.
4. **Guard check**: Confirm no caller guard, lock, SQLite constraint, or existing test
   already prevents the issue.

Place unproven suspicions in **Verification Gaps**, never in the confirmed findings list.
Deduplicate by root cause. Zero actionable findings is a valid outcome.

## 4. Report Format

Lead with findings ordered by severity:
- **P0**: Silent data loss, corruption, credential/UID bypass, or arbitrary code execution.
- **P1**: Crash, deadlock, stuck sync state, broken durability propagation, or UI freeze.
- **P2**: Incorrect behavior on recoverable paths, missing error reporting, or test gaps on critical invariants.
- **P3**: Minor actionable defect or edge-case hygiene issue.

For each finding, include: `[P0-P3] Title`, file and line link, trigger, consequence,
evidence status (`Reproduced` or `Source-verified`), and a concise remedy. Separate
optional design improvements from defects.

Conclude with:
- **Scope & baseline reviewed**
- **Checks executed & exact results**
- **Coverage & environment limits** (distinguish unit/mock verification from live FUSE/Proton sync)
- **Recommended fix order**
