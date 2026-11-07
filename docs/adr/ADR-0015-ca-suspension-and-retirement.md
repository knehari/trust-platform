# ADR-0015 — Suspend, reactivate and retire activated CAs

**Status:** Proposed · 2026-11-07. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0027;
- five API routes;
- the audit tool;
- the console and the laboratory stack.

**Roadmap:** last slice of the *CA* half of MVP criterion 6. The criterion
stays unchecked: no issuance path uses a CA or a profile yet (criterion 7),
and key custody is open (criterion 9).

**Not here:**
- **No revocation of the CA certificate, CRL or publication.** Retiring a
  CA is a platform state, not a revocation.
- **No renewal or rekey.** A new key means a new proposal (ADR-0013).

## Context

[ADR-0014](ADR-0014-ca-approval-and-activation.md) creates ACTIVE CAs after
two signed approvals. The
[lifecycle contract](../architecture/ca-profile-lifecycle-boundary.md) also
asks for suspension and retirement.

The owner chose (decision of 2026-11-07):
- **Asymmetric controls.** One administrator suspends at once, because
  stopping must be fast, for example after a suspected key exposure.
  Reactivation and retirement need the two-person signed control of
  ADR-0014.
- **Profiles follow the CA.** While a CA is suspended, no profile revision
  can be activated for it. Retiring a CA retires its active profile
  revisions; nothing is deleted.

## Decision

1. **Operational state.** `ca_operational_state` holds `ACTIVE`,
   `SUSPENDED` or `RETIRED` for each activated CA.
   - Activation (0026) starts a CA as `ACTIVE`, through a trigger. CAs
     activated before 0027 are backfilled.
   - Only the functions below change the state. Every change is a
     `ca_state_change` history row with a reason, plus a lifecycle event and
     an audit event that carries the CA.
   - CAs the owner created directly have no state and are unchanged.
2. **Suspension** (`suspend_ca_lab`). It needs the `ca-administrator`
   platform grant and a reason, and applies only to an `ACTIVE` CA. It takes
   effect immediately.
3. **Change requests** (`request_ca_change_lab`). An administrator requests
   a change, with a reason:
   - `reactivate`, only for a `SUSPENDED` CA;
   - `retire`, for an `ACTIVE` or `SUSPENDED` CA.

   A CA has at most one open request. A request records the state it was
   made in. **If the CA changes state** (for example, it is suspended after
   a retirement was approved), the request becomes stale: it can no longer
   be decided or applied, and it does not block a new request.
4. **Signed decisions on a request.**
   - `prepare_ca_change_decision_lab` builds the claim:
     `trust-platform/ca-change-decision/v1;decision=…;action=…;request_id=…;ca_id=…;from_state=…;reason_sha256=…;certificate_sha256=…;approver_issuer=…;approver_subject=…;key_id=…;issued_at=…`.
   - `record_ca_change_decision_lab` re-checks everything, as in ADR-0014:
     the `ca-approver` grant and an active CA approver key, ten-minute
     freshness, one decision per approver, distinct keys.
   - **The requester cannot decide.**
   - The API verifies the signature before commit (422 otherwise).
   - **Outcome:** two approvals make the request `APPROVED`; one rejection
     makes it `REJECTED`.
5. **Application** (`apply_ca_change_lab`).
   - It needs the `ca-administrator` grant, from someone who did not decide
     on the request.
   - The request must be `APPROVED` and not applied, and the CA must still
     be in the request's state.
   - Reactivation refuses an expired issuer certificate (422).
   - **Retirement** is final. In the same transaction it retires every
     active profile revision of the CA, as 0024's retirement does: history
     row, pointer removal, profile lifecycle event, audit event.
6. **Profiles follow the CA.** A trigger on `certificate_profile_active`
   refuses (409) any profile activation for a CA that is not `ACTIVE`.
   Readers see the CA's `operational_state` on `GET /v1/cas` and
   `/v1/cas/{ca_id}`. The console warns on the profile view of a suspended
   or retired CA.
7. **Administrators and approvers** see the operational state, when it last
   changed, and the open or approved request (action, status, approvals,
   reason) in `GET /v1/ca-proposals`.
8. **Audit tool.** `lab_verify_ca_lifecycle` also checks:
   - every change decision: rebuilt claim, registered key, signature;
   - that approvals of a request come from distinct approvers and keys;
   - that each applied request had two approvals and no rejection, and that
     neither the requester nor the applier decided;
   - that the state change matches the request;
   - that a retired CA has no active profile revision left.
9. **Console.** In **CA proposals**:
   - an administrator sees **Suspend this CA**, **Request reactivation** and
     **Request retirement**, with a reason, then **Apply the …** once
     approved;
   - a CA approver sees **Prepare approval/rejection of the …**, then signs
     outside the browser as in ADR-0014.
10. **Lab stack.** No new user: `lab-ca-admin`, `lab-ca-approver-1` and
    `lab-ca-approver-2` (ADR-0013, ADR-0014) operate CAs.

## Evidence

- **`tests/management_ca_operation.sql`.** It fails before 0027 and passes
  on it. It covers:
  - **Start:** activated CAs start `ACTIVE`.
  - **Writer role:** it cannot read the new tables.
  - **Suspension:** grant, an unknown or owner CA, replay, only from
    `ACTIVE`.
  - **Requests:** grant, action against state, one open request, replay.
  - **Decisions:**
    - the requester, a key without the grant, and a request under another
      CA are refused;
    - the exact claim;
    - first approval, repeated decision and stale claim;
    - second approval;
    - a decision on an approved request is refused.
  - **Application:**
    - no grant, or an approver of the request, is refused;
    - reactivation and its replay;
    - a second application is refused.
  - **Rejection:** a rejection ends a request; a new request is then
    possible.
  - **Stale requests:** an approved retirement made stale by a suspension
    cannot be applied, and a new request is accepted.
  - **Profiles:** no profile activation on a suspended CA; owner CAs are
    unaffected.
  - **Interrupted transaction:** a failed retirement leaves CA and profiles
    unchanged.
  - **Retirement:** retirement with its profile revision and events; nothing
    is possible after it.
  - **Expiry:** reactivation with an expired certificate is refused.
  - **Views, history and immutability.**
  - **Mutations detected:** each of these makes the test fail, 23 in all:
    - each of the four grant checks;
    - suspension only from `ACTIVE`;
    - the request state rules;
    - the retired-CA check;
    - one open request, and stale requests not blocking;
    - matching the CA of a request;
    - requester separation;
    - repeated decisions;
    - one approval sufficing;
    - freshness;
    - applier separation;
    - applying only `APPROVED`;
    - stale application;
    - reactivation expiry;
    - retiring profiles;
    - the profile trigger;
    - the start state;
    - the CA view column;
    - the proposal view filter.
- **`activated_cas_are_suspended_then_reactivated_or_retired_with_two_signers`**
  (Rust, PostgreSQL in CI). It covers:
  - **Suspension:** an approver and a padded reason are refused; suspension
    and its replay; a second suspension is refused.
  - **Requests:** an invalid action; reactivation requested; a concurrent
    request is refused.
  - **Decisions:** the requester's claim and another key's signature are
    refused; then the first approval.
  - **Application:** refused before approval; the second approval; refused
    for an approver with the administrator role; then reactivation.
  - **Retirement:** retirement; then suspension and requests are refused.
  - **Listing:** the record.
  - **Mutations detected:** disabling the API's signature check (the audit
    tool then reports the forged decision), the reason validation, or the
    action validation makes the tests fail.
- **`frontend/dev/ca-proposal-e2e.mjs`** (Compose job). After activation:
  - an approver cannot suspend;
  - suspension, then a second suspension is refused;
  - for reactivation:
    - the requester cannot decide;
    - another key's signature gives 422;
    - applying before approval gives 409;
    - two OpenSSL-signed approvals, then application;
  - retirement with two approvals, then no further request.
- **`browser-e2e.mjs`:** after activating it, `lab-ca-admin` suspends the
  CA from the console.

## What this does not establish

- **No revocation.** Retiring or suspending a CA does not revoke or publish
  anything, and the issuer certificate stays valid outside the platform.
- **Suspension by one person** can be abused to deny service. That is the
  chosen trade-off, and it is recorded and audited.
- **No issuance path reads the state**, because none exists yet. Criterion
  7 must check it.
- **Software keys and owner-registered approvers**, without custody, MFA or
  enrolment (ADR-0011, ADR-0014).
- **The database checks no signature.** The API and the audit tool do; the
  tool runs only in CI.

## Alternatives considered

- **Two-person suspension.** Safer against abuse, but slows a protective
  action. Rejected by the owner.
- **A single administrator for every change.** No separation of duties for
  irreversible retirement or for resuming. Rejected.
- **Only blocking profiles on retirement.** Active revisions would outlive
  their CA. Rejected in favour of retiring them in the same transaction.
- **Mutable status columns on `ca`.** Rejected in favour of one state
  pointer with an append-only history, as in ADR-0012.
