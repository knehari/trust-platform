# Open PR integration checkpoint — 2026-11-07

This is a laboratory integration record, not a release or an instruction to deploy. The remote `main` head inspected for this checkpoint was `f7acd0f`. GitHub reported 174 open PRs. Most are stacked: merging their terminal heads captures their ancestors without replaying every diff. The first integration phase combines the terminal Claude profile stack (#182, through #1–#181 where ancestral), the distinct-key security fix (#44), the recovery audit (#42), repository instructions (#167), and the local reader-isolation/IAM work. The recovery reports in #42 are already present in expanded form in the Claude stack, so the expanded versions were kept.

## Remaining incompatible heads

| Head | Unique work | Why it is not yet on the combined tree |
| --- | --- | --- |
| `claude/friendly-hopper-3l9y56` (#94) | Revocation, CRL, signed administration and lab security hardening; original migrations `0014`–`0065` | #94 branches from the older management stack and assigns migration numbers `0014`–`0024` to different SQL files than the profile stack. A first isolated port is published at [`codex/revocation-port-onto-profile`](https://github.com/knehari/trust-platform/tree/codex/revocation-port-onto-profile): its migrations were renumbered to `0026`–`0077` and a fresh database accepted the combined sequence. The upgrade runner, Compose/API integration and full tests remain incomplete; the port must not be merged or deployed yet. |
| Local `codex/reader-isolation-readiness` | Client-bound IAM checks, filter validation and a database trigger enforcing dense immutable draft revisions | Integrated on this branch. The local trigger was moved from its conflicting `0022` to `0025`; the Claude API's lifecycle authentication and routes remain authoritative. The reader-isolation gate and console filters were adapted. Full upgrade and restore validation remains open. |

## Work required before #94 reaches `main`

1. Keep the Claude profile lineage through `0025` as the canonical history. The populated `0011`→`0025` upgrade and revision guard passed in a disposable database; logical restore remains open.
2. Complete the isolated #94 port. Its fresh `0001`→`0077` migration run and seven SQL suites passed, and the combined Rust workspace compiles. Preserve negative tests and recovery evidence; rework the runner for an existing `0025` database and reconcile Compose, API and documentation before merge.
3. Run the full Rust, PostgreSQL, frontend, Compose, migration/restore and security regression gates on the final combined head. Test management and CRL routes together, including authorization and rollback behavior. The profile phase passed full Rust tests with and without all features, 57 frontend tests and the profile SQL suites; this does not validate the #94 port.
4. The user confirmed on 2026-11-07 that G0 legal/IP clearance and independent security review are complete. Link their artifacts to the integration record before `main`; this branch does not itself establish those decisions.

The existing 5173 laboratory instance remains on the prior local integration commit and has not been pointed at this branch. No production system or signing key is involved in this checkpoint.

## Checks on this branch

On the first integration phase, `cargo fmt --all -- --check` and `cargo test --workspace --all-targets --locked` and the all-features variant pass. The workspace runs do not establish database coverage for tests that skip without a URL. All 57 frontend tests and the build pass; the management API test suite passes 34 tests without database variables. On a separate disposable PostgreSQL 16 database, migrations `0001`–`0025` apply in order and the revision, lifecycle, signed-decision and activation SQL suites pass. The populated 0011→0025 upgrade, existing-gap rollback and concurrent revision insertion also pass. This does not validate the #94 port, logical restore, Compose or exact-head remote CI. Docker Desktop became unavailable after the later port test filled local build storage; the first-phase checks above completed before that failure.
