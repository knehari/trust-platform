# Open PR integration checkpoint — 2026-11-07

This is an integration workspace, not a release or an instruction to deploy. The remote `main` head inspected for this checkpoint is `f7acd0f`. GitHub reported 174 open PRs. Most are stacked: merging their terminal heads captures their ancestors without replaying every diff. This branch locally combines the terminal Claude profile stack (#182, through #1–#181 where ancestral), the distinct-key security fix (#44), the recovery audit (#42), and repository instructions (#167). The recovery reports in #42 are already present in expanded form in the Claude stack, so the expanded versions were kept.

## Remaining incompatible heads

| Head | Unique work | Why it is not yet on the combined tree |
| --- | --- | --- |
| `claude/friendly-hopper-3l9y56` (#94) | Revocation, CRL, signed administration and lab security hardening; migrations `0014`–`0065` | #94 is marked “Draft, do not merge” for a CI experiment. It branches from the older management stack and assigns migration numbers `0014`–`0024` to different SQL files than the profile stack. Its management API, Compose stack, init scripts and CI overlap. A text merge reports 16 conflicts, but auto-adding both sets of numbered migrations would also create an invalid upgrade order. Its unique behavior must be ported and tested against the chosen profile schema. |
| Local `codex/reader-isolation-readiness` | Client-bound IAM checks, filter validation and a database trigger enforcing dense immutable draft revisions | The Claude profile stack uses migration `0022` for draft submission, `0023` for decisions and `0024` for activation. The local branch uses `0022` for a different revision trigger. A text merge reports 18 conflicts. The guard and useful client checks need adaptation and a new migration number after the canonical lifecycle migrations, followed by upgrade and restore tests. |

## Required integration work before `main`

1. Choose one canonical migration history. This branch keeps the Claude profile lineage through `0024`. Port the local revision invariant as a later migration, and test both fresh and populated upgrades.
2. Port #94's revocation/CRL and administration capabilities onto that history. Preserve its negative tests and recovery evidence; rename and revalidate every dependent migration, role, view, function and API contract. Do not simply concatenate SQL files with the same number.
3. Run the full Rust, PostgreSQL, frontend, Compose, migration/restore and security regression gates on the exact integrated head. Test the management API and CRL routes together, including authorization and rollback behavior.
4. Obtain the G0 legal/IP decision and independent security/cryptographic review recorded as open in `AGENTS.md` and the PR descriptions. Do not treat draft CI or this branch as those decisions.

The existing 5173 laboratory instance remains on the prior local integration commit and has not been pointed at this branch. No production system or signing key is involved in this checkpoint.

## Checks on this branch

On the published integration tree, `cargo fmt --all -- --check` and `cargo test --workspace --all-targets --locked` pass. The workspace run does not establish database coverage for tests that skip without a URL. All 48 frontend tests and the frontend build pass. On a separate disposable PostgreSQL 16 database, migrations `0001`–`0024` apply in order and the lifecycle, signed-decision and activation SQL suites pass. This verifies the compatible profile stack only; it does not validate the unported #94 or local-branch changes, nor replace independent review or exact-head CI.
