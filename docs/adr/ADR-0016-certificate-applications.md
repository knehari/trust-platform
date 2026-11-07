# ADR-0016 — Certificate applications and their registration decision

**Status:** Proposed · 2026-11-07. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0028;
- three API routes;
- an optional identifier on CA proposals;
- the console and the laboratory stack.

**Roadmap:** first slice of MVP criterion 7, application issuance. The
criterion stays unchecked.

**Not here: nothing is signed.** An `APPROVED` application is the input of
the next slice:
- a separate laboratory signer, the only process that reads the CA key;
- a journaled signing intent through the core issuance state machine (PRs
  #4–#9);
- independent verification and persistence.

No certificate exists because of this slice.

## Context

Criteria 5 and 6 provide:
- authenticated, separately granted people;
- ACTIVE CAs with an attested key (ADR-0013 to ADR-0015);
- ACTIVE profile revisions that bind zones, name count, validity and suites
  (ADR-0010 to ADR-0012).

Criterion 7 asks for authenticated CSR submission and approval, profile
enforcement and Core orchestration.

The owner chose (decision of 2026-11-07):
- **a separate laboratory signer** for the signing slice;
- **a requester plus a registration-officer (RA) approval**, by different
  people;
- **requests first**, signing next.

## Decision

1. **Roles.** `management_role_grant` gains two per-CA roles:
   - `certificate-requester`, with the token role
     `trust-certificate-requester`;
   - `registration-officer`, with `trust-registration-officer`.

   The token's CA scope must include the CA, as for every CA route.
2. **Submission** (`POST /v1/cas/{ca_id}/certificate-applications`). The
   request carries the profile, a PKCS#10 CSR (PEM), the requested common
   name, the DNS names and the validity in days.
   - **The API verifies the CSR** with the strict verifier of
     `trust-pki-core`: canonical DER, PKCS#10 v1, ECDSA-SHA256, an
     uncompressed P-256 key, a subject of exactly `CN=<requested name>`,
     and proof of possession. It refuses otherwise (422, with a reason).
   - **The CSR's extensions and names are never used.** The certificate's
     names are those requested and allowed by the profile.
   - The API also checks the syntax of the names: lowercase LDH, at least
     two labels, no wildcard. The CN must be one of the names.
   - **The database** (`submit_certificate_application_lab`) requires:
     - the requester grant;
     - a lifecycle-managed **ACTIVE CA**: CAs created by the owner, and
       suspended or retired CAs, are refused (422);
     - an **ACTIVE revision** of the profile for that CA (otherwise 404).

     It binds the application to that exact revision and checks the names
     against it:
     - no more than its maximum number of names, with no repeat;
     - each name equal to, or under, one of its zones, at a label boundary;
     - a validity no longer than its maximum.

     A subject key equal to the CA's key is refused.
   - It stores the CSR DER, its digest, the SPKI digest, the names and the
     validity, with an application event and an audit event, in one
     transaction. Applications are immutable.
3. **Registration decision**
   (`POST /v1/cas/{ca_id}/certificate-applications/{id}/decision`).
   - It needs the officer grant, and the officer cannot be the requester.
   - The decision is `approve` or `reject`, with a reason, once.
   - **Approval** also requires the CA to be ACTIVE and the application's
     revision to be still the profile's active revision. Otherwise it is
     refused (409), and a new application is needed.
   - **Rejection** is always possible while undecided.
   - The decision is recorded with an event and an audit event (`allow` or
     `deny`).
4. **Readers of the CA** list its applications (`GET`): status, names,
   profile and revision, digests, reason and times. Requester and officer
   identities stay owner-only.
5. **Idempotency keys** work as in ADR-0010.
6. **CA proposals accept an optional `ca_id`** (ADR-0013). The database
   still refuses an identifier already used, and draws one when none is
   given. This lets identity-provider CA scopes name a CA before it exists.
7. **Laboratory issuing CA.**
   - **Identifier:** `dddddddd-dddd-4ddd-8ddd-dddddddddddd`, named in the
     Keycloak scopes of `lab-author`, `lab-approver-1`, `lab-approver-2`,
     `lab-operator`, and the new users `lab-requester` and `lab-ra-officer`
     (IDs `…015` and `…016`).
   - **Creation:** the CA itself is created only through the lifecycle
     routes.
   - **Grants:** the database owner then runs
     `scripts/lab/provision-issuing-ca.sql`. It refuses a CA that is not
     ACTIVE and lifecycle-managed.
8. **Console.** In **Certificates**:
   - a requester sees a form to submit an application, with the OpenSSL
     command that makes a key and CSR outside the browser;
   - an officer sees **Approve application** and **Reject application**
     with a reason.

## Evidence

- **`tests/management_certificate_application.sql`.** It fails before 0028
  and passes on it. It covers:
  - **Roles and writer:** the role constraint; the writer role cannot read
    the new tables.
  - **Submission refusals:**
    - no grant;
    - an owner CA;
    - an unknown profile;
    - a name outside the zones;
    - a suffix that is not a label boundary (`notlab.invalid`);
    - an upper-case name and a wildcard;
    - too many names and a repeated name;
    - a CN outside the names;
    - a validity above the profile;
    - the CA's own key.
  - **Submission:** submission, replay, and key reuse for another body.
  - **Decision refusals:** no grant, the requester, an unknown application,
    and an application decided under another CA.
  - **Decisions:** approval, replay, a second decision.
  - **Suspended CA:** no submission and no approval, but rejection still
    works.
  - **Stale revision:** no approval once the revision is superseded.
  - **Views and records:** the reader view without identities, and nothing
    for an ungranted reader; events, audit decisions and immutability.
  - **Interrupted transaction:** a failed submission leaves nothing.
  - **Mutations detected:** each of these makes the test fail, 18 in all:
    - both grant checks;
    - CA usability, and ACTIVE only;
    - name count, repeats and syntax;
    - the label boundary;
    - the zones;
    - CN among the names;
    - validity;
    - the CA key;
    - requester separation;
    - decided once;
    - approval needing an ACTIVE CA and the active revision;
    - matching the application's CA;
    - the view filter.
- **`certificate_applications_need_a_verified_csr_an_active_profile_and_an_officer`**
  (Rust, PostgreSQL in CI).
  - **Setup:**
    - the CA is created through the API;
    - an owner login (`TRUST_API_OWNER_TEST_DATABASE_URL`) provisions grants
      and the active revision, as only the owner can;
    - the test declares a skip without it.
  - **Submission refusals:**
    - no grant, and an officer only;
    - a wildcard name, and a CN outside the names (400);
    - a CSR for another CN (`SubjectMismatch`);
    - a CSR signed by another key (`InvalidSignature`);
    - a certificate instead of a CSR (`Encoding`);
    - a name outside the zones, and a validity too long (422);
    - an unknown profile (404).
  - **Submission:** submission and replay.
  - **Decisions:** the requester is refused; an unknown decision is
    refused; approval; a second decision is refused (409).
  - **Listing:** without identities.
  - **Suspended CA:** submission is refused.
  - **Proposals:** the existing proposal test covers a chosen `ca_id`
    (created, invalid, or naming an existing CA).
  - **Mutations detected:** disabling the API's name syntax check, or its
    CN-among-names check, makes the tests fail.
- **`frontend/dev/certificate-application-e2e.mjs`** (Compose job):
  1. creates the lab issuing CA through the lifecycle (OpenSSL root, two
     CA approvers);
  2. the owner provisions it;
  3. a profile is drafted, submitted, approved by the two OpenSSL-signing
     approvers, and activated;
  4. the requester submits OpenSSL CSRs; an officer, a name outside the
     zones, a validity too long and a CSR for another CN are refused;
  5. the officer approves; the requester cannot; the decision happens once.

  The audit tools then pass on the lab database.

## What this does not establish

- **Nothing is signed or issued.** No serial, signing intent or
  certificate exists.
- **Domain control is not validated.** The names are only checked against
  the profile's zones; there is no ACME-like challenge.
- **Only P-256 CSRs** with a subject of exactly one CN; no other key type.
- **One officer suffices.** The registration decision is not signed; the
  officer is a separately authenticated person with a grant.
- **The database trusts the API's CSR parsing.** The CSR DER is stored, but
  no audit tool re-verifies it yet. The signing slice must verify it again
  before signing.
- **The console form is not covered by the browser test.** It is covered
  through the API end-to-end test only.
- **The lab issuing CA's key** is a software file, generated by OpenSSL
  outside the platform (ADR-0013).

## Alternatives considered

- **Automatic approval when the policy passes.** Closer to ACME, but no
  second control. Rejected by the owner for now.
- **Copying names from the CSR.** It would let CSR content decide the
  certificate. Rejected: names come from the request and the profile.
- **Writing applications into the core `certificate_request` table now.**
  That table is the signing state machine's. The signing slice will hand
  approved applications to it.
- **Granting the lab issuing CA in `init-db.sh`.** Impossible before the CA
  exists, and it would bypass the lifecycle. Rejected in favour of an
  explicit owner script run after activation.
