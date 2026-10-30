# R1 — Source consolidation notes (17 October 2026)

## Starting point
- Branch: `recovery/r1-source-consolidation-20261017`
- Original head: [PR #41 at `6634b0f20869a4ffc4ce38dba6ea48bbfe2baabd`](https://github.com/knehari/trust-platform/pull/41)
- Independent audit: [PR #42](https://github.com/knehari/trust-platform/pull/42) from `main`; this recovery branch **does not** automatically contain the four audit documents.
- Status: recovery working branch only; no merges to `main`, no release or production authorization.

## Changes in this increment
1. Restore the empty-capacity snapshot success assertion from PR #23 in `capacity_policy.rs`.
2. Restore the audit manifest determinism assertion from PR #24 in `audit_manifest.rs`.
3. Copy `ROADMAP.md` from `main` (otherwise absent from the PR #41 tree), explicitly flagging the historical/stale planning table.
4. Update the root README to reflect the audited lab-only state; add `AGENTS.md` for future Codex contributions.

## What this does NOT accomplish
- It is **not** a demonstrated union of all 41 historical heads. The audit reported divergences and missing assertions; remaining code/API/migration equivalence still requires independent verification.
- It does not fix S-01 (dual-approval same-key alternate SEC1 encodings) or investigate the C-01 transactional activation race.
- It does not establish an authenticated service, HSM provider, UI, CLM, revocation service, secure DB role model or production assurance.
- It does not clear G0 legal/employment/IP or approve a bulk merge.

## Review and acceptance checklist
- [ ] Compare tree/API/test/migration union across all 41 audit-pinned SHA values.
- [ ] Verify restored tests run in CI on this exact branch head (Rust + schema jobs).
- [ ] Verify recovery-budget tests retain `Exhausted` and `UnknownOperation` cases.
- [ ] Review docs and roadmap against PR #42 audit.
- [ ] Human approval of recovery sequence and security/legal gates before further integration.

## Next independent pull requests
- R2: CI reproducibility, force DB tests to fail if their expected environment is absent, schema migrations on populated databases and least-privilege roles.
- R3: reject cryptographically identical P-256 keys even with distinct SEC1 encodings / aliases.
- R4: unify provider/algorithm/profile capability truth without silently enabling production signing.
