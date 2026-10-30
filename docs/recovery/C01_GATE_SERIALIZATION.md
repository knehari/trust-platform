# TRUST-89 — CP/CPS activation and signing-intent serialization

C-01 was reproduced on PostgreSQL 16.15 at `cfd408744d396b411d3fcfa6df4247562134cb6d`: [historical reproduction](https://github.com/knehari/trust-platform/actions/runs/39030863605). Both activation functions can commit while an intent that already skipped their uncommitted gates waits on a later audit foreign-key lock. After activation commits, that intent completes without repeating its gate decision. This is a laboratory trusted-caller concurrency defect; no exposed service or production incident is claimed.

## Correction

Migration 0011 adds a per-CA write fence before INSERT on `signing_intent`, `ca_policy_enforcement`, and `ca_dual_signature_enforcement`. Gate insertion checks for existing intents under the same fence, including direct INSERT. The trigger sorts before the existing policy and receipt checks. A real non-key UPDATE makes stale REPEATABLE READ and SERIALIZABLE snapshots fail with 40001; merely locking an unchanged row would not suffice. READ COMMITTED sees the committed gate or intent and rejects the competing operation with 23514.

Historical migrations, public function signatures, policy checks, replay behavior and the Rust signing boundary are preserved. Serial allocation and recovery do not invoke a signer. The existing orchestrator must still commit intent before external signing and quarantine ambiguous outcomes; a serialization error is not permission to re-sign.

## Evidence and acceptance

[Post-fix run on 7cd4193](https://github.com/knehari/trust-platform/actions/runs/39030964921) reproduces both old failures on 0001–0010, upgrades the populated database, then passes 24 cases: two gate levels × three isolation levels × two ordering directions × function/direct INSERT. Existing SQL positive approval and receipt tests pass. Additional regression coverage asserts final intent/gate counts, unrelated issuers, rollback, replay and uncertainty quarantine; final-head CI must also pass.

The tests synchronize through `pg_blocking_pids`, with bounded deadlines and statement timeouts. A fixed sleep is never treated as proof of ordering. No PostgreSQL/Rust tests ran locally: Cargo is absent and Docker remains unresponsive; Python syntax and `git diff --check` passed locally. Rustfmt, Clippy, OpenSSL, SQL and crash/recovery coverage run in GitHub Actions on the exact PR commit/tree.

## Review and remaining constraints

A separate agent investigated the boundary before implementation. The subsequent agent review could not run because of an account usage limit; it is not counted as a successful independent review. Parent review checked the three insertion paths, trigger order, transaction visibility, ordinary approval path and replay bypass of new insertion. Human security review remains pending.

The write fence serializes new intents per CA until transaction completion and creates row versions; benchmark contention and vacuum overhead before deployment. Use short, single-issuer transactions. Future least-privilege roles must have the required narrowly scoped fence update permissions (current tests use a disposable owner role). Cross-issuer multi-operation transactions need a consistent issuer ordering; no general deadlock-freedom claim is made.

Migration 0011 does not delete or reclassify historical intents, repair prior unauthorized issuance, authenticate SQL callers, or clear G0. Before upgrading a non-disposable database, inspect existing intents and policy evidence independently; the migration cannot establish whether historical signing was authorized. Table owners capable of disabling triggers remain outside this boundary.

References: [PostgreSQL isolation](https://www.postgresql.org/docs/16/transaction-iso.html), [trigger execution order](https://www.postgresql.org/docs/16/trigger-definition.html). Draft PR #46 depends on #45; #44 remains a separate prerequisite for the consolidated application baseline.
