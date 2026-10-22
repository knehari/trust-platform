# Laboratory break-glass for lost CA-admin keys

Lab only (migration 0045, ADR-0007 section 6, Proposed). It is not a
production emergency procedure, and no CPS text covers it yet.

Once a CA requires signed administration (`signed_admin_required`, 0037),
admin keys change only by signed dual control between two other admins
(0040), and the DBA bootstrap is closed. If the admins lose their
authenticators, nobody can sign again. Break-glass is the narrowest way back.

## What it can do

The CA's emergency key can enrol **one CA-admin key per use**, and only that:
- only on a CA with `signed_admin_required`;
- only while fewer than two admin keys are active on the CA (checked under
  the CA lock, again when the use is submitted);
- only for an identity that already holds `ca_admin_grant` on the CA, under
  the one-person rule of 0037.

It cannot revoke, issue, grant officers, remove keys or approve anything. Its
`BREAK_GLASS` claim never verifies as another step.

## Procedure

1. **DBA, in advance:** enrol the emergency key and name its custodian.
   Use a superuser login; no service role may call this.
   ```sql
   SELECT enroll_breakglass_credential('<ca>', '\x<credential id>', 'custodian-name',
                                       '<custodian person id>', '\x<P-256 SEC1 key>');
   ```
   In Rust: `PgRevocationStore::enroll_breakglass_credential`, which also
   checks and canonicalises the key. The database refuses a key already used
   as an officer or admin key, and (0046) a custodian person who holds an
   active officer or admin credential on the CA. Once the custodian is
   enrolled, that person can no longer receive such a credential there.
   Keep the authenticator sealed and in custody.
   `remove_breakglass_credential` retires it.
2. **DBA, on loss:** retire the lost admin keys
   (`SELECT remove_ca_admin_credential('\x<credential id>')`). This only takes
   signing power away, and is what makes the CA eligible for break-glass.
3. **Custodian, through the Rust core** (`trust_ca_admin` login; not exposed
   over HTTP):
   1. Review the new admin key's content: CA, credential id, identity,
      person and key.
   2. `issue_breakglass_challenge` (single use, at most 10 minutes).
   3. Sign with the emergency authenticator, then call `submit_breakglass`.
      The assertion is verified against the claim and the emergency key
      before anything is written. Repeat for the second admin.
4. **Review:** two admins other than the enrolled one, with distinct keys and
   persons, each call `issue_breakglass_review_challenge` and
   `submit_breakglass_review`, or use the CA-admin API
   (`GET /v1/cas/{ca}/breakglass-uses`,
   `POST /v1/breakglass-uses/{use}/review-challenges`, then the assertion
   route). Their `REVIEW` claim names the use and its
   claim digest. The use is closed at the second review.

## Alerts and audit

- Each use writes a `ca_admin.breakglass.used` audit event and each review a
  `ca_admin.breakglass.reviewed` event. Enrolment and removal of the
  emergency key write `ca_admin.breakglass.enrolled` and `.removed`.
- `crl_housekeeping` reports `open_breakglass_uses` and
  `overdue_breakglass_uses` (past `ca_revocation_policy.breakglass_review_hours`,
  1-168, default 24). Any open use sets the attention exit status until it
  is reviewed.
- `breakglass_uses(ca)` lists the uses (`trust_ca_admin`,
  `trust_crl_operator`, `trust_audit_verifier`).
- `signed_evidence_audit` re-verifies each use and its reviews offline, as
  family `break_glass`.

## Limits

- Custody of the emergency key is procedural.
- The custodian's person identifier is caller-supplied, like every person
  identifier until the IAM decision: one human under two identifiers is
  not detected.
- Keys enrolled under 0045 without a custodian person were retired by
  0046 (audit event `MIGRATION_0046:no_custodian_person`); re-enrol them.
- The database cannot verify ECDSA. A holder of `trust_ca_admin` could store
  a forged break-glass assertion while the CA has fewer than two admin keys.
  Since 0051 a reviewer cannot get a review challenge for a use whose
  evidence does not re-verify in the Rust core, so such a use stays open and
  housekeeping keeps alerting. The offline audit also exposes it. A forged
  use's admin key stays enrolled until two admins remove it, but the Rust
  core (and so the CA-admin API) refuses every signature made with it while
  the use's evidence does not re-verify. A direct database call by a holder
  of `trust_ca_admin` is not stopped by this.
- There is no on-call rota and no CPS text yet.

Tested by `break_glass_restores_admin_keys_under_review`,
`breakglass_custodian_is_never_a_signer` and
`concurrent_breakglass_uses_cannot_exceed_two_admin_keys` (two custodians:
a second use waits for the CA lock held by an open first use, then is
refused; removing the lock lets it enrol a third key) in
`crates/pki-core/tests/signed_status_change_postgres.rs` and by the grant
invariants in `tests/revocation_privileges.sql`.
