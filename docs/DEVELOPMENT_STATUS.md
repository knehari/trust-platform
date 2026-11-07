# Development status

**Checked 2026-11-07.** Local branch `codex/reader-isolation-readiness` is based on `fad16fe` (`claude/p-history-ca-isolation`). The current branch's roadmap remains at **4/12 MVP criteria**. The Keycloak IAM laboratory is on separate local branch `codex/keycloak-iam-lab` at `ffcbdb5`; its 5/12 assessment does not apply to this branch until the histories are reviewed and integrated.

## This increment

Migration 0021 filters each of seven management views by the principal declared on the PostgreSQL session. The API already denied reads without token scope and grants, but its startup/readiness gate checked only `management_ca` and `management_reader_scope`. A later unfiltered certificate, audit, SAN, history-bound or profile view could therefore pass the gate. The gate now checks all seven views for zero rows on a session without a principal. It still checks the migration marker. API request authorization is unchanged.

A restricted PostgreSQL login on a disposable database with migrations 0001–0021 ran `reader_isolation_gate_checks_every_management_view`. The test temporarily shadowed each view with a one-row unfiltered view. It **failed before the fix** on `management_certificate` and **passed after the fix** for all seven views. The full API suite also passed **22/22** without database variables (its database-dependent cases skipped); the targeted isolation test above exercised the disposable database. `cargo fmt --all -- --check`, `cargo clippy -p trust-management-api --all-targets --locked -- -D warnings` and `git diff --check` passed. The frontend suite and a large-data readiness cost measurement remain to be run on this branch before proposing a PR. No application database or GitHub branch was changed by the test.

## Integration and next work

An attempted local merge of `codex/keycloak-iam-lab` into the recent `claude/` history was **rejected by automatic approval review**, which cited the lack of explicit authorization for a conflict-producing merge. The branches remain separate. The IAM work needs a reviewed integration with migrations 0017–0021 before criterion 6 can expose authenticated profile or CA writes. Profile lifecycle, protected signing keys, issuance, revocation, durable audit and release gates remain open on this branch.
