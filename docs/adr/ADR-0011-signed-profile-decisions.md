# ADR-0011 — Signed approval and rejection of profile revisions

**Status:** Proposed · 2026-11-07. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0023;
- two API routes;
- an audit tool;
- the console and the laboratory stack.

**Roadmap:** second slice of MVP criterion 6. The criterion stays unchecked.

**Not here:**
- **No activation, retirement or issuance.** `APPROVED` changes nothing for
  issuance. Activation and retirement came later, in
  [ADR-0012](ADR-0012-profile-revision-activation.md).
- **No CA lifecycle.**

## Context

The [lifecycle contract](../architecture/ca-profile-lifecycle-boundary.md)
asks two things of an approval:
- the policy approver reviews **the exact revision and digest**;
- approval needs **a separately authenticated actor and a cryptographically
  distinct approval key, not merely a different string key ID**.

ADR-0009 provides authenticated, separately signed-in approvers. ADR-0010
provides submitted revisions with a digest the database computes itself.

The owner chose to build on the v1.5 P-256 decision receipts (decision of
2026-11-02):
- each approver holds their own laboratory P-256 key;
- the owner registers its public half;
- the approver signs outside the console;
- the API verifies the signature with the reviewed `p256` verifier of
  `trust-pki-crypto`.

## Decision

1. **Owner-registered keys** (`profile_approver_key`).
   - Each approver has one active key at a time, stored as an uncompressed
     P-256 point (65 bytes).
   - A point cannot be registered twice. Since only one encoding is
     accepted, equal points are equal bytes. The audit tool also compares
     canonical points.
   - Keys are append-only: they are never deleted or changed, only revoked
     once.
   - Private keys never reach the database or the browser.
2. **The database builds the claim.** `prepare_profile_decision_lab` returns
   one line with ten fields in a fixed order:
   `trust-platform/profile-decision/v1;decision=…;ca_id=…;profile_id=…;revision=…;snapshot_sha256=…;submission_event_id=…;approver_issuer=…;approver_subject=…;key_id=…;issued_at=…`.
   - Identities containing `;` or control characters are refused, so the
     line has a single parse.
   - The claim binds the exact submission (digest and event), the approver,
     their key and the issue time.
   - It is valid for ten minutes.
3. **Signing happens outside the console.**
   - The approver signs the exact claim bytes with ECDSA P-256 and SHA-256
     (DER), for example
     `printf '%s' '<claim>' | openssl dgst -sha256 -sign <key>.pem | openssl base64 -A`.
   - The console shows the claim and that command, and accepts the pasted
     signature.
   - The console never holds a key.
4. **Recording is checked twice, in one transaction.**
   `record_profile_decision_lab` re-runs every rule and rebuilds the claim.
   It then writes three rows:
   - the decision row, with the claim, signature and public key;
   - a `profile_lifecycle_event`;
   - an `audit_event`.

   It returns the claim and key to the API, which verifies the signature
   before committing. A signature that does not verify rolls everything
   back (422).
5. **Rules the database enforces.** It refuses:
   - a caller without a `policy-approver` grant for the CA, or without an
     active key;
   - the revision's author or submitter (separation of duties);
   - a revision that is not submitted, or that is already approved or
     rejected;
   - a second decision by the same approver, or the reuse of a key on the
     same revision;
   - a claim more than ten minutes old, or issued in the future.

   **Outcome:** two approvals make the revision `APPROVED`; one rejection
   makes it `REJECTED`, which is final for that revision. Idempotency keys
   work as in ADR-0010.
6. **Readers** see the status, `approval_count` and `decided_at`. The
   approvers' identities, claims and signatures stay owner-only, as actor
   identities do elsewhere.
7. **Independent audit tool: `lab_verify_profile_decisions`.** Run as the
   database owner, it rereads every decision and checks that:
   - the claim equals the claim the database rebuilds;
   - the submission digest equals the recomputed revision digest;
   - the key is the approver's registered key;
   - the signature verifies;
   - each revision's approvals come from distinct approvers and distinct
     canonical points.

   It exits non-zero on any failure. The Rust CI job runs it after the API
   tests.

## Laboratory keys

- **Generation:** `scripts/lab/init-env.sh` generates one key per approver
  with OpenSSL into the git-ignored `.lab-keys/`, with modes 700 and 600.
- **Public halves:** only the uncompressed points go into `.env.lab`.
  `init-db.sh` registers them for `lab-approver-1` and `lab-approver-2`.
- **CI test keys:** the CI API test uses three deterministic test scalars.
  Their public halves are pinned in
  `tests/management_profile_decision_api_seed.sql`, and a unit test checks
  that they match.

These software keys are for the disposable laboratory only. They do not meet
any custody requirement.

## Evidence

- **`tests/management_profile_decision.sql`.** It fails before 0023 and
  passes on it. It covers:
  - **Key registration:** a duplicate point, a compressed point and a second
    active key are refused; registration is append-only.
  - **Writer role:** it cannot read the key or decision tables.
  - **Claim format.**
  - **Refusals:** a reader without the grant, the author, the submitter, an
    approver without a key, an unsubmitted or unknown revision, a malformed
    issuer or decision, an expired or future claim.
  - **Decisions:** first approval, replay and key reuse, a repeated decision,
    the second approval, a rejection that ends the revision, and a revoked
    key.
  - **Reader view:** the state after one approval and after the decisions.
  - **Records:** the events and the claims rebuilt for each decision, and the
    immutability of decisions.
  - **Interrupted transaction:** a failing audit write leaves no decision.
  - **Mutations detected:** each of these makes the test fail:
    - dropping the separation-of-duties check;
    - dropping the repeated-decision check;
    - dropping the freshness check;
    - dropping the already-decided check;
    - letting one approval suffice, in the view or in the function.
- **`profile_decisions_need_two_distinct_signed_approvals`** (Rust,
  PostgreSQL in CI). It covers:
  - **Refusals:** an editor, the author holding an approver grant, an unknown
    decision.
  - **Bad signatures:** a signature by another approver's key, a signature
    over altered text, a stale issue time and malformed base64 are refused,
    and none of them leaves anything.
  - **Outcomes:** a repeated decision is refused; the second distinct
    approval approves; one rejection ends a revision.
  - **Mutation detected:** disabling the API's signature check makes the test
    fail (201 instead of 422).
  - **The audit tool flagged the forged decision** that mutation had
    recorded: "signature does not verify over the claim".
- **`frontend/dev/profile-lifecycle-e2e.mjs`** (Compose job) signs with
  OpenSSL and the `.lab-keys` of `lab-approver-1` and `lab-approver-2`:
  - the author is refused;
  - another approver's key gives 422;
  - two approvals give APPROVED;
  - a rejection gives REJECTED;
  - the audit events are present.
- **`browser-e2e.mjs`** runs the same approval through the console.

## What this does not establish

- **The database does not verify ECDSA.**
  - A compromised API, or a holder of the writer login, could record a
    decision without a valid signature.
  - The stored claim, key and signature make that detectable by the audit
    tool. That tool must run regularly, and is not yet scheduled outside CI.
- **Key custody is software only.** The keys are lab files without hardware
  protection, attestation or ceremony, and nothing proves that only the
  approver holds their key.
- **Key registration is an owner action in SQL.** There is no enrolment
  workflow, and nothing proves possession of the private key at
  registration.
- **No MFA at sign-in** (ADR-0009).
- **Rules are fixed.** Two approvals, ten minutes, and no policy per CA or
  per profile.
- **Not checked again at approval:** syntax warnings and suite/provider
  compatibility. Activation must check them.

## Alternatives considered

- **WebAuthn passkeys.** Closer to production, and they would double as MFA,
  but they need an enrolment flow and attestation decisions. Deferred by
  the owner.
- **Signing in the browser with WebCrypto.** It would put private keys in
  the browser. Rejected.
- **ECDSA verification in PostgreSQL.** It would need an extension or SQL
  code implementing elliptic-curve arithmetic, and AGENTS.md rules out
  home-grown primitives. Rejected in favour of verification in Rust plus
  the independent audit tool.
