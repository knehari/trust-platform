# ADR-0014 — Signed two-person approval and activation of CA proposals

**Status:** Proposed · 2026-11-07. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0026;
- three API routes;
- an independent audit tool;
- the console and the laboratory stack.

**Roadmap:** second slice of the *CA* half of MVP criterion 6. The criterion
stays unchecked.

**Not here:**
- **No suspension or retirement of CAs.** They followed in
  [ADR-0015](ADR-0015-ca-suspension-and-retirement.md).
- **No issuance.** No issuance path uses an activated CA; it has no signing
  provider or key access.
- **No key custody.** The issuer key is still a laboratory software file
  ([ADR-0013](ADR-0013-ca-proposal-and-issuer-certificate.md)).

## Context

[ADR-0013](ADR-0013-ca-proposal-and-issuer-certificate.md) records
`KEY_ATTESTED` proposals: a verified self-signed root, bound to the proposal.
A single administrator did everything, and a proposal is not a CA.

The [lifecycle contract](../architecture/ca-profile-lifecycle-boundary.md)
asks for CA approval by separately authenticated actors with
cryptographically distinct keys, then activation.

The owner chose (decision of 2026-11-07):
- **a new platform role**, `ca-approver`, with its own owner-registered
  P-256 keys, rather than reusing profile approvers or keeping approval in
  SQL;
- **approval and activation in one slice**; suspension and retirement next.

## Decision

1. **CA approvers and their keys.**
   - `management_platform_grant` accepts the role `ca-approver`, besides
     `ca-administrator`. The token must carry `trust-ca-approver`.
   - `ca_approver_key` holds one active uncompressed P-256 point per
     approver. Keys are append-only, as in ADR-0011.
   - **One power per key.** A trigger on both key tables refuses a point
     already registered for the other power. Profile approval and CA
     approval never share a key.
2. **The database builds the claim.** `prepare_ca_decision_lab` returns one
   line:
   `trust-platform/ca-decision/v1;decision=…;ca_id=…;certificate_sha256=…;spki_sha256=…;registration_event_id=…;approver_issuer=…;approver_subject=…;key_id=…;issued_at=…`.
   - It binds the exact certificate and key, not the display name.
   - It is valid for ten minutes.
3. **Recording** (`record_ca_decision_lab`) re-runs every rule, writes the
   decision, a `ca_lifecycle_event` and an `audit_event`, and returns the
   claim and key. The API verifies the signature with the reviewed
   `trust-pki-crypto` verifier before commit; a signature that does not
   verify rolls everything back (422).
4. **Rules the database enforces on decisions.** It refuses:
   - a caller without the `ca-approver` grant or without an active key;
   - the proposer and the registrant of the certificate (separation of
     duties);
   - a proposal that is not `KEY_ATTESTED`, or that is already decided;
   - a second decision by the same approver, or the same key twice;
   - a claim older than ten minutes or issued in the future;
   - an expired issuer certificate (422).

   **Outcome:** two approvals make the proposal `APPROVED`; one rejection
   makes it `REJECTED`, which is final.
5. **Activation** (`activate_ca_lab`). It needs the `ca-administrator` grant
   and names the approved certificate's SHA-256. It refuses:
   - an approver of the proposal (separation of duties);
   - a proposal that is not `APPROVED`, or that was activated;
   - another certificate digest;
   - an expired certificate (422);
   - an identifier already used by a CA.

   **Outcome:** in one transaction, the database writes:
   - the `ca` row (same identifier, name and policy version);
   - `ca_activation`;
   - the proposal's suite as the CA's signing capability;
   - a lifecycle event and an `audit_event` that now carries the CA.

   **Before commit**, the API verifies the stored certificate again with
   the ADR-0013 verifier, and checks the suite against the catalogue.
   Otherwise it rolls back (422). This covers a certificate recorded by a
   compromised writer path, since the database does not parse X.509.
6. **Profile activation now checks the attested key.** A trigger on
   `ca_signing_capability` refuses any suite other than the attested one
   for an activated CA. Profile activation (ADR-0012) is unchanged, but for
   such a CA it can only match the suite the approvers approved. CAs
   created by the owner keep declared capabilities.
7. **Readers.** `GET /v1/ca-proposals` now also serves `trust-ca-approver`
   tokens. The view shows rows to holders of either platform grant, with
   `approval_count`, `decided_at` and `activated_at`. Approver identities,
   claims and signatures stay owner-only. The new CA appears to readers
   only through the usual owner-granted reader grants (ADR-0008).
8. **Independent audit tool: `lab_verify_ca_lifecycle`.** Run as the owner,
   it checks:
   - every stored certificate, with the same verifier at its registration
     time, including that the stored SPKI digest, CN and validity are the
     certificate's own;
   - every CA decision: the claim the database rebuilds, the registered
     key, the signature;
   - that the approvals of a proposal come from distinct approvers and
     keys;
   - that every activation had two approvals, no rejection and an activator
     who did not decide, and that its `ca` row matches the proposal.

   The Rust CI job runs it after the API tests.
9. **Console.** In **CA proposals**:
   - a CA approver sees **Prepare CA approval** and **Prepare CA rejection**
     on a `KEY_ATTESTED` proposal. They are shown the claim and an OpenSSL
     command, and paste the signature.
   - an administrator sees **Activate this CA** on an `APPROVED` one.
10. **Lab stack.**
    - Keycloak has the role `trust-ca-approver` and the users
      `lab-ca-approver-1` and `lab-ca-approver-2` (IDs `…013` and `…014`).
    - `init-env.sh` generates their keys into `.lab-keys/` with OpenSSL;
      `init-db.sh` registers the public halves and the grants.

## Evidence

- **`tests/management_ca_activation.sql`.** It fails before 0026 and passes
  on it. It covers:
  - **Keys:** one power per point, in both directions; append-only CA keys.
  - **Writer role:** it cannot read the new tables.
  - **Decision refusals:**
    - a key without the grant;
    - the grant without a key;
    - the proposer holding the approver grant;
    - an unknown proposal;
    - a `PROPOSED` proposal;
    - an expired certificate;
    - an invalid decision or identity.
  - **Claim:** the exact claim format.
  - **Decisions:**
    - the first approval and its replay;
    - a repeated decision;
    - stale and future claims;
    - the second approval;
    - a decision on an approved proposal;
    - a rejection that ends a proposal;
    - a single approval that stays `KEY_ATTESTED`.
  - **Activation refusals:**
    - no grant;
    - an approver;
    - proposed, rejected and single-approval proposals;
    - another digest;
    - an unknown proposal;
    - an expired approved certificate.
  - **Activation:** the activation, its replay, and a second activation.
  - **Capabilities:** the `ca` row and the attested capability; another
    suite refused for the activated CA but still allowed for an owner CA.
  - **Views and records:** both views, the events and audit rows,
    immutability.
  - **Interrupted transaction:** an interrupted activation leaves no CA.
  - **Mutations detected:** each of these makes the test fail, 16 in all:
    - dropping either grant check;
    - dropping proposer/registrant separation;
    - dropping activator separation;
    - dropping the repeated-decision check;
    - one approval sufficing, in the function or in the view;
    - dropping freshness;
    - dropping the state check;
    - dropping the digest check;
    - dropping either expiry check;
    - dropping the attested-capability guard;
    - dropping the single-power guard;
    - opening the view;
    - allowing activation of a non-approved proposal.
- **`ca_proposals_are_approved_by_two_signers_then_activated`** (Rust,
  PostgreSQL in CI). It uses test scalars `0x44` and `0x55`, whose public
  points are pinned by a unit test. It covers:
  - **Order:** no decision before the certificate.
  - **Claim refusals:** the administrator, and a profile approver holding
    only the role.
  - **Decisions:** the claim binds the certificate digest; approval,
    replay and a repeated decision.
  - **Bad signatures:** another key's signature, and a signature over
    altered text, give 422.
  - **Activation:** refused before approval; the second approval; then
    refused for an approver with the administrator role, a role without a
    grant, another digest and unknown fields; then the activation, its
    replay and a second activation.
  - **Listing:** an approver lists the record.
  - **Mutations detected:** disabling the API's signature check, the
    activation evidence check, or the approver's right to list makes the
    tests fail.
- **`activation_reverifies_a_certificate_recorded_without_the_api`**.
  - The writer login records an RSA root as if it were P-256, as a
    compromised API could. Two approvers approve it; activation gives 422.
  - Removing the API's re-verification makes it fail (201).
  - On that database, `lab_verify_ca_lifecycle` reports the forged
    certificate (`SignatureAlgorithm`).
  - **It runs only with `TRUST_API_FORGERY_TEST_DATABASE_URL` set**, on a
    separate disposable database, and declares a skip otherwise. **CI does
    not set it**, because the forged record would fail CI's audit step by
    design. It was run locally.
- **`lab_verify_ca_lifecycle` unit test:** a faithful record passes; another
  name, another SPKI digest, a tampered certificate and a registration
  after expiry are each reported.
- **`frontend/dev/ca-proposal-e2e.mjs`** (Compose job):
  - the administrator and a profile approver cannot decide;
  - the profile approver's key and the other CA approver's key give 422;
  - the two CA approvers sign with OpenSSL, and the proposal is APPROVED;
  - activation is refused for an approver and for another digest;
  - then the activation, its replay and a second activation;
  - the list shows ACTIVE to administrators and approvers.
- **`browser-e2e.mjs`:** both CA approvers sign from the console, and the
  administrator activates the CA.

## What this does not establish

- **Possessing a software key at one moment is not custody** (ADR-0013).
  Approvers approve a certificate and a key, not the conditions it is held
  in.
- **The database verifies no signature and parses no certificate.** A
  compromised API or writer login could still record decisions or
  certificates. Activation's re-verification and the audit tool detect
  this; the tool must run regularly and is not scheduled outside CI.
- **Approver keys are owner-registered software files**, with no enrolment
  workflow, proof of possession or MFA (ADR-0011).
- **Fixed rules:** two approvals, ten minutes, and no policy per CA.
- **No suspension, retirement, renewal or revocation** of a CA.
- **An activated CA cannot issue.** No provider is bound to it.

## Alternatives considered

- **Reusing profile approvers and their keys.** Less code, but one key
  would hold two powers. Rejected by the owner; the single-power trigger
  makes the separation explicit.
- **Approval as an owner action in SQL.** No separation of duties and no
  signature. Rejected.
- **Creating the `ca` row at proposal and gating it with a status.** Every
  CA read path would need to filter by status. Rejected: the row exists
  only once activated.
- **Trusting the stored certificate at activation.** Simpler, but the
  database cannot detect a certificate recorded without the API. Rejected
  in favour of re-verification before commit.
