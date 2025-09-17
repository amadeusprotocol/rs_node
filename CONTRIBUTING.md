# Contributing to **Amadeus Node**

> **tl;dr** — Every change (commit or PR) must include code + tests + docs and
> pass `fmt`, `clippy`, and CI.

This repository implements an Amadeus blockchain node. Contributions are welcome
and reviewed with a focus on the **correctness, safety, determinism, 
maintainability, and performance**.

## 1) Governance & Scope

- **Mainline-first (trunk-based)**: short‑lived topic branches merge to `main`
  quickly; keep diffs small.
- **Single responsibility**: each change solves one thing end‑to‑end.
- **Public review**: all code lands via review (even maintainer changes).
- **Respectful conduct**: see `CODE_OF_CONDUCT.md`.

## 2) Legal

- **License**: Apache‑2.0. Add SPDX headers to new files.
- **DCO required**: sign off every commit with `git commit -sS` (adds
  `Signed-off-by: Name <email>` and GPG signs).
- **CLA**: _Not required yet_. We may introduce a CLA later.

## 3) Branching & History

- Default branch: `main` (protected).
- Create a fork and work in your local fork, feel free to use any branch name.
- **Rebase locally** to keep a linear history. Only force‑push your topic branch
  to **amend the last commit**.

## 4) Commit Messages

- Short, imperative subject, e.g. `add ping protocol message`,
  `fix tokio memory leak`.
- Recommended (for tooling & changelogs): **Conventional Commits** minimal set:
    - `feat: …`, `fix: …`, `perf: …`, `refactor: …`, `docs: …`, `test: …`,
      `chore: …`, `build: …`.
    - Use `BREAKING CHANGE:` in body (or `!` after type) when applicable.
- Keep subject ≤ 72 chars; wrap body at 80; reference issues `(#123)` when
  relevant.

## 5) Pull Requests

Even if you commit directly (during early rewrite), treat each **commit** like a
PR: include code, tests, docs, and pass checks.

When opening PRs:

- One problem per PR; aim for small, focused diffs.
- Show how you tested (commands, data); link to design notes if behavior
  changes.
- Request at least **1 reviewer**; **2** for consensus‑critical logic.
- Address review comments with new commits (not amend) until final squash;
  resolve threads explicitly.
- PRs may be closed if inactive for 30 days; re‑open with context.

**PR Template** (`.github/PULL_REQUEST_TEMPLATE.md`):

```markdown
### Summary

### Rationale / design notes

### Risks & mitigations

### Testing done

- [ ] unit tests
- [ ] manual testing
- [ ] docs updated

### Checklist

- [ ] \`cargo test-all`
- [ ] \`cargo fmt --all --check\`
- [ ] \`cargo clippy --all-targets --all-features\`
- [ ] \`cargo deny check\`
```

## 6) Code Style & Lints

- **Formatting**: `rustfmt` enforced; run `cargo fmt --all --check` in CI.
  Configure via `rustfmt.toml`.
- **Clippy**: treat warnings as errors in CI:
  `cargo clippy --all-targets --all-features`.
- Avoid `unsafe` unless essential; justify and isolate it; test thoroughly.
- Avoid `unwrap`/`expect` in long‑running paths; prefer `?` or explicit error
  handling, add comments for justification.
- Use `tracing` for logs; no `println!` in library/runtime code.
- For unimplemented functions leave `todo!()`, `unimplemented!()`, or 
  `unreachable!()`.
- For additional improvements, leave `// TODO: ... ` or `// FIXME: ...` 
  comments

## 7) Testing Requirements

- Every change ships tests:
    - **Unit** tests for new/changed code.
    - **Manual** tests for overall correct node behavior.
- Determinism: consensus‑critical code must be deterministic across platforms;
  avoid time/locale/FS nondeterminism; fix RNG seeds.
- Concurrency: add tests for race conditions; use `loom` where feasible.
- Performance: add benchmarks for hot paths; include baseline comparisons 
  when refactoring.
- Set `RUSTFLAGS='-D warnings'` for tests.

## 8) Documentation

- Public APIs have Rustdoc comments with examples.
- Record design decisions in `/docs/CONSENSUS.md` (Architecture Decision
  Records).
- Update protocol specs / message formats in `/docs/PROTOCOL.md` with 
  versioning.
- Keep README quickstart up‑to‑date when CLI or config changes.

## 9) Security & Safety

- Reporting: see `SECURITY.md`.
- **Dependencies**: check in `Cargo.lock`; run `cargo deny check`.
- Cryptography: use well‑reviewed crates; no home‑rolled crypto; constant‑time
  where applicable.
- Secrets: never commit keys or credentials; use env vars or secret managers.
- Fuzzing: maintain `cargo fuzz` targets for parsers/decoders; run periodically.
- Threat model docs for P2P, consensus, and RPC surfaces.

## 10) Versioning & Releases

- Use **SemVer** in the core library; document MSRV bumps as breaking.
- Tag releases `vX.Y.Z`; publish release notes derived from commits/PRs.
- For protocol changes that break compatibility, bump the major version version 
  number.

## 11) Local Dev Quickstart

```bash
rustup toolchain install stable
rustup component add rustfmt clippy
cargo build --workspace
cargo test --workspace --all-features
cargo fmt --all --check
cargo clippy --all-targets --all-features
```

## 12) Contact

- Security issues: see `SECURITY.md`.
- Questions: open a discussion or issue.

### Review ownership
We use a `CODEOWNERS` fallback team:

- Code owner team: `@amadeus-robot/core-maintainers`.

