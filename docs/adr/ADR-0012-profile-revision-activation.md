# ADR-0012 — Activate and retire approved profile revisions

**Status:** Proposed · 2026-11-07. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0024;
- two API routes;
- the console and the laboratory stack.

**Roadmap:** third and last slice of the *profile* half of MVP criterion 6.
The criterion stays unchecked: the CA lifecycle (create, approve, activate,
retire CAs) is still open.

**Not here: no issuance effect.** No issuance path reads the active revision,
so `ACTIVE` authorizes no certificate. Wiring it into issuance belongs to
criterion 7, application issuance.

## Context

The [lifecycle contract](../architecture/ca-profile-lifecycle-boundary.md)
says that:
- a CA operator may request activation only after approval and after
  provider, issuer-certificate and CP/CPS compatibility checks;
- at most one revision of a profile is active;
- retirement stops new issuance without changing the evidence of past
  certificates.

The platform has no record that binds a CA to its signing provider, its keys
or its issuer certificate. The owner therefore chose (decision of
2026-11-07) to have the database owner **declare** the signing suites each CA
supports, and to check revisions against that declaration and the CA's
policy version. The issuer certificate is not checked; this is stated, not
assumed.

## Decision

1. **Declared capabilities.** `ca_signing_capability` holds `(ca_id,
   suite_id)` rows written by the owner.
   - Identifiers use the typed catalogue form, for example
     `ecdsa-p256-sha256`.
   - Rows are append-only; a row can only be revoked once.
2. **Activation** (`activate_profile_revision_lab`, through the writer login
   of ADR-0010). It refuses:
   - a caller without a `ca-operator` grant for the CA;
   - the revision's author, submitter or either approver (separation of
     duties);
   - a revision that is not `APPROVED`, or that was activated before (no
     re-activation of a superseded or retired revision);
   - a digest other than the approved one;
   - a revision whose policy version is not the CA's (CP/CPS compatibility
     as far as the platform records it);
   - any proposed suite that the CA has not declared, or whose declaration
     is revoked.

   **Additional API check:** every suite must be an identifier of
   `trust_pki_crypto::typed_algorithm_catalog` with a registered
   implementation route. Otherwise the transaction is rolled back (422).

   **Outcome:** the revision becomes `ACTIVE`, and any active revision of
   the same profile becomes `SUPERSEDED`. One transaction writes three
   things:
   - the pointer row;
   - history rows (`activate`, and `supersede` when another revision was
     active);
   - a lifecycle event and an audit event.
3. **One active revision per profile.** `certificate_profile_active` is the
   only mutable lifecycle state. Its primary key `(ca_id, profile_id)` is
   the invariant, and the per-profile advisory lock of ADR-0010 serializes
   the changes.
4. **Retirement** (`retire_profile_revision_lab`). It needs a `ca-operator`
   grant, applies only to the active revision, and happens once. The
   revision becomes `RETIRED` and nothing replaces it.
5. **Idempotency keys** work as in ADR-0010.
6. **Readers** see:
   - the statuses `ACTIVE`, `SUPERSEDED` and `RETIRED`;
   - `activated_at`;
   - `ended_at`, the time a revision was superseded or retired.
7. **Console.** A user with `trust-ca-operator` sees **Activate this
   revision** on an `APPROVED` revision and **Retire this revision** on the
   `ACTIVE` one.
   - The server decides; the console offers no override.
   - New drafts default to the catalogue identifier `ecdsa-p256-sha256`.
8. **Lab stack.**
   - `lab-operator` holds the `ca-operator` grant on the allowed CA.
   - The owner declares `ecdsa-p256-sha256` for that CA.

## Evidence

- **`tests/management_profile_activation.sql`.** It fails before 0024 and
  passes on it. It covers:
  - **Capabilities:** the identifier format is enforced, and capabilities
    are append-only.
  - **Writer role:** it cannot read or write the new tables.
  - **Activation refusals:**
    - a caller without the grant;
    - an approver who also holds the operator grant;
    - an unapproved revision;
    - an altered digest;
    - a policy-version mismatch;
    - an undeclared suite;
    - an unknown revision.
  - **Activation:** activation, replay and key reuse; a second activation
    of the same revision; supersession; no re-activation of a superseded or
    retired revision.
  - **Retirement:** only the active revision can be retired, once.
  - **Capabilities again:** a revoked capability blocks activation.
  - **Reader view:** every state and its times.
  - **History:** the history rows and their lifecycle and audit events, and
    their immutability.
  - **Interrupted transaction:** a failing audit write leaves no pointer
    and no history.
  - **Policy change:** activation works once the CA's policy version
    matches.
  - **Mutations detected:** each of these makes the test fail:
    - dropping separation of duties;
    - dropping the policy check;
    - ignoring revoked capabilities;
    - dropping the digest check;
    - allowing re-activation of a superseded revision.
- **`approved_revisions_activate_one_at_a_time_and_retire`** (Rust,
  PostgreSQL in CI).
  - **Refusals:** an editor, and an approver holding the operator role, get
    403; an altered digest gets 409.
  - **Catalogue:** a suite declared for the CA but outside the catalogue
    gets 422, and the revision stays `APPROVED`.
  - **Activation:** activation, replay, supersession, refused re-activation.
  - **Retirement:** only the active revision, once; unknown body fields are
    refused.
  - **Mutation detected:** disabling the API's catalogue check makes the
    test fail (201 instead of 422).
- **`frontend/dev/profile-lifecycle-e2e.mjs`** (Compose job):
  - an approved revision with a suite the CA does not declare gets 422;
  - a compatible revision is approved by the two signing approvers;
  - the author, an approver and a wrong digest are refused;
  - the operator activates the revision, then retires it;
  - the audit events are present.
- **`browser-e2e.mjs`:** `lab-operator` activates and retires a revision
  from the console.

## What this does not establish

- **No issuance effect.** Nothing reads `ACTIVE`; a profile still authorizes
  no certificate.
- **Declared capabilities are not provider evidence.**
  - They are the owner's statement, not a test that a provider and a key
    can sign under the profile.
  - The issuer certificate is not checked, because no CA key, provider or
    certificate binding exists yet.
  - Both come with the CA lifecycle and key custody (criteria 6 and 9).
    [ADR-0013](ADR-0013-ca-proposal-and-issuer-certificate.md) starts the
    former with verified issuer certificates of proposed CAs; activation
    does not use them yet.
- **Policy compatibility is an equality of version strings.** CP/CPS content
  is not compared.
- **A single operator activates.** No second operator confirms, and there is
  no MFA (ADR-0009).
- **The database trusts the declared principal** (ADR-0008, ADR-0010).
- **No re-activation.** Restoring a superseded behaviour means a new
  revision through the whole lifecycle.

## Alternatives considered

- **Building the CA lifecycle first** (key, provider and issuer certificate
  binding), then checking against it. More complete, and much longer. The
  owner chose declared capabilities for now.
- **No compatibility check.** This would contradict the contract and the
  fail-closed rule of AGENTS.md. Rejected.
- **A mutable status column on the revision.** Rejected in favour of
  append-only history plus a single pointer whose key enforces "one active
  revision".
