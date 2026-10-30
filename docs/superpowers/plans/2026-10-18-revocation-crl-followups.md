# Revocation/CRL lab slice — follow-ups

Collected from the per-task and whole-branch reviews of
`2026-10-18-revocation-crl.md` (branch head cdfef84); statuses refreshed on
30 October 2026 for migrations up to 0065. None blocks the lab slice;
items marked **before non-lab use** must be done before any non-ephemeral issuer
or exposed service. The plan's Task 2 text still shows the original 4-argument
`record_crl_intent`; spec §4 step 3 (8 arguments, content-bound) supersedes it.
Its `CrlPlan` still carries `tbs_der`; `crl_once` now builds the TBS from the
reservation and `CrlPlan::issuer` (spec §4 step 2).

## Before non-lab use
- Least-privilege write model and dual-controlled CA administration:
  implemented in the lab by 0023-0024 (ADR-0006). Open: its acceptance
  conditions (independent review of the SECURITY DEFINER functions, runtime
  without superuser, schema-change control, external audit anchoring,
  authenticated time), real service logins and their credentials, and the
  owner role holding UPDATE on `ca`/`certificate` (row locks).
- Maker-checker is textual by default; `AGENTS.md` requires cryptographically
  distinct signer keys. Since 0028-0029 (status changes) and 0037-0042 (CA
  administration) a CA can opt in, one way, to WebAuthn-signed claims with
  distinct keys and persons (ADR-0007, still Proposed); CAs that do not opt
  in keep the known deviation.
- Authentication of revocation officers stays with the identity adapter.
- Dependency advisory RUSTSEC-2026-0387 (timing variability in
  crypto-bigint, 2026-10-23) is ignored in `deny.toml` with a reason:
  only crypto-bigint 0.7.6+ is patched, elliptic-curve 0.13 (p256/p384 0.13,
  also inside jsonwebtoken 10.3) pins 0.5.5, and P-256 private-key use is
  confined to `lab-software` and tests (production paths verify with public
  keys). Move to p256/p384 0.14 once jsonwebtoken supports it, and before any
  ECDSA private key leaves the lab. tokio (RUSTSEC-2026-0386) and ctutils
  (RUSTSEC-2026-0385) were upgraded to patched releases.
- CA issuer binding (0022) has one immutable issuer certificate per CA; key
  rollover (several issuer certificates over time, CRLs signed by the new key
  for the old certificates) is not modelled.

## Test gaps
- Closed: the PostgreSQL pipeline test checks that the stored CRL's
  thisUpdate and nextUpdate are the reserved ones, that nextUpdate −
  thisUpdate is the CA's `crl_validity`, and that thisUpdate is the
  database's present (besides OpenSSL on the stored CRLs, `ExpiredCertsOnCRL`
  per conformance target, and the `crl.rs` golden vector).
- Migration-retry and ledger scripts stop at 0013 (the populated 0014/0015
  upgrade and its fail-closed aborts are covered by
  `tests/revocation_populated_upgrade.sh`). From 0026 on,
  `scripts/lab/migrate.sh` applies only the missing migrations to an
  existing database and refuses gaps, newer databases and pre-0026 ones
  (`tests/revocation_migration_runner.sh`). Since 0064 it keeps the SHA-256
  of each applied file and refuses a changed or missing one; digests of
  files applied before are adopted only with `--adopt` (trust on first use).
  A second runner on the same database is refused (session advisory lock).
- Rerunning on a reused database: `revocation_lifecycle.sql` and
  `lab_policy_gate` (a fresh CA per run since 22 October 2026) pass again,
  as do `audit_chain_postgres` and `signed_status_change_postgres`. The
  historical issuance suites `postgres_store`, `lab_verified_issuance`,
  `lab_rsa_pss_postgres` and `policy_decisions` still fail on a second run:
  they use the CI-seeded CA and fixed idempotency keys or ids by design and
  are left unchanged; run them on a fresh database (as CI does).

## Robustness and hygiene
- Request budgets: per client address before the token (600 per minute,
  per process, all HTTP services including the CRL distribution point;
  X-Forwarded-For read only from proxies listed in
  `TRUST_HTTP_TRUSTED_PROXIES`), and per identity for the write APIs,
  shared by replicas in the database (0062, idle rows purged since 0063).
  A full address table falls back to /48 (IPv4 /24) prefixes. Connections
  are capped (1,024 per process, 64 per client address), with 10 s for a request header and 30 s
  per request, body included. Every 429 carries `Retry-After: 60`; the
  first per-address refusal of each window is logged. Open: an address
  budget shared across replicas.
- `crl_housekeeping` (management-api binary, verified TLS,
  `docs/operations/lab-crl-housekeeping.md`) runs the sweeps and alerts
  through its exit status; deploying it, `signed_evidence_audit` and the
  audit chain anchoring on a schedule with their dedicated logins remains
  open.
- `crl_due` / `overdue_status_changes` still call `crl_change_covered` per
  approved change (the supersession probe is indexed since 0025); read-only
  queries do not check isolation.
- Closed in 0025: `propose_` locked the grant before the certificate while
  `approve_`/`reject_`/`withdraw_` locked the certificate first, so a bulk grant
  deletion could deadlock (`tests/revocation_lock_order.sh`).
- Migrations copy whole function bodies to change one line (0016-0020).
  The entries digest has had one definition since 0061: the ordered
  aggregate `crl_entries_sha256`, used by `reserve_crl`,
  `reserve_delta_crl` and `crl_listed_digest`. `tests/crl_entries_digest.sql`
  fails if another function body encodes entries, and checks the aggregate
  against the 0015 expression.
- The lifecycle audit decision format has one definition since 0065,
  `status_change_audit_decision`, called by the four lifecycle bodies. The
  migration rewrites those bodies from `pg_get_functiondef` with an exact,
  checked replacement instead of copying them;
  `tests/status_change_audit_decision.sql` fails on a fifth copy.
- Reject path and approve's generic message still fold maker=checker wording;
  (0021 reports the certain "reserve again" refusals as SQLSTATE 55000 /
  `CrlError::ReserveAgain`.)
- `reconcile_crl` (0021) stores a quarantined CRL only when the caller still
  holds its DER (`CrlError::VerifiedButNotStored`); the `crl_reconcile` lab
  tool does it from a DER file under a signer login
  (`tests/crl_reconcile.sh`). A CRL lost with its process stays
  `RECONCILIATION_REQUIRED` (no signer read-back exists).
- Expired-entry pruning (`keep_expired_on_crl = false`): implemented in 0031
  from `certificate.not_after` recorded at issuance; certificates stored
  before 0031 are backfilled by housekeeping from their stored DER (0055);
  an unreadable DER is reported and never pruned. Entry
  order is raw serial bytes, not OpenSSL's (length, bytes).
