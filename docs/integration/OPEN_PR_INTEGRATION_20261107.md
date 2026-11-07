# Open PR integration checkpoint — 2026-11-07

This is an integration workspace, not a release or an instruction to deploy. The remote `main` head inspected for this checkpoint is `f7acd0f`. GitHub reported 174 open PRs. Most are stacked: merging their terminal heads captures their ancestors without replaying every diff. This branch locally combines the terminal Claude profile stack (#182, through #1–#181 where ancestral), the distinct-key security fix (#44), the recovery audit (#42), repository instructions (#167), and the local reader-isolation/IAM work. The recovery reports in #42 are already present in expanded form in the Claude stack, so the expanded versions were kept.

## Remaining incompatible heads

| Head | Unique work | Why it is not yet on the combined tree |
| --- | --- | --- |
| `claude/friendly-hopper-3l9y56` (#94) | Revocation, CRL, signed administration and lab security hardening; migrations `0014`–`0065` | #94 is marked “Draft, do not merge” for a CI experiment. It branches from the older management stack and assigns migration numbers `0014`–`0024` to different SQL files than the profile stack. Its management API, Compose stack, init scripts and CI overlap. A text merge reports 16 conflicts, but auto-adding both sets of numbered migrations would also create an invalid upgrade order. Its unique behavior must be ported and tested against the chosen profile schema. |
| Local `codex/reader-isolation-readiness` | Client-bound IAM checks, filter validation and a database trigger enforcing dense immutable draft revisions | Integrated on this branch. The local trigger was moved from its conflicting `0022` to `0025`; the Claude API's lifecycle authentication and routes remain authoritative. The reader-isolation gate and console filters were adapted. Full upgrade and restore validation remains open. |

## Required integration work before `main`

1. Keep the Claude profile lineage through `0025` as the canonical migration history and complete populated upgrade and restore validation for the ported revision guard.
2. Port #94's revocation/CRL and administration capabilities onto that history. Preserve its negative tests and recovery evidence; rename and revalidate every dependent migration, role, view, function and API contract. Do not simply concatenate SQL files with the same number.
3. Run the full Rust, PostgreSQL, frontend, Compose, migration/restore and security regression gates on the exact integrated head. Test the management API and CRL routes together, including authorization and rollback behavior.
4. The user confirmed on 2026-11-07 that G0 legal/IP clearance and independent security review are complete. Link their artifacts to the integration record before `main`; this branch does not itself establish those decisions.

The existing 5173 laboratory instance remains on the prior local integration commit and has not been pointed at this branch. No production system or signing key is involved in this checkpoint.

## Checks on this branch

On the earlier published integration tree, `cargo fmt --all -- --check` and `cargo test --workspace --all-targets --locked` pass. The workspace run does not establish database coverage for tests that skip without a URL. After the local merge, all 57 frontend tests and the build pass; the management API test suite passes 34 tests without database variables. On a separate disposable PostgreSQL 16 database, migrations `0001`–`0025` apply in order and the revision, lifecycle, signed-decision and activation SQL suites pass. The populated 0011→0025 upgrade, existing-gap rollback and concurrent revision insertion also pass. This does not validate the unported #94, logical restore, Compose or exact-head remote CI.
