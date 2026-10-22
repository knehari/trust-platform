# ADR-0007 — Signed, key-distinct double control for certificate status changes and CA administration

**Status:** Proposed · 2026-10-20 · requires human security review and IAM decisions. Steps 1 and 2 (credential registry and canonical claim, migration 0028; signed status-change approvals, migration 0029) are implemented in the lab at the repository owner's request; that is not an acceptance of this ADR.  
**Scope:** Approval of status changes (suspend, release, revoke) and of CA-administration changes (issuer registration, officer grants) on top of ADR-0006. Laboratory only.  
**Related:** ADR-0006 (least-privilege write model; this ADR was split out of it), ADR-0003 (authenticated identity), `crates/pki-core/src/policy_decisions.rs` (`verify_dual_approval`), `docs/security/v1-6-approval-challenge-replay-design.md`, `AGENTS.md` (double control).

## Context

After ADR-0006, only the maker-checker functions can change status or administration, and service logins have EXECUTE only. The two actors are still `(issuer, subject)` strings asserted by the calling service. Anyone holding a service login, or controlling that service, can assert two identities.

`AGENTS.md` requires double control to rest on **cryptographically distinct signer keys as well as separately authenticated actors**. The lab slice does not meet this, which is a recorded deviation.

PostgreSQL cannot verify ECDSA; migration 0009 already relies on the Rust path for signed receipts. The repository already has `policy_decisions::verify_dual_approval`. It verifies two P-256 signatures over one claim and rejects the same key presented under another id or another SEC1 encoding.

## Decision (proposed)

### 1. Officer keys in hardware, through WebAuthn

Officers and CA admins sign with **FIDO2/WebAuthn authenticators with user verification**: security keys or platform authenticators, ES256 (P-256). Software keys are not accepted. Smart cards or PKCS#11 tokens are an acceptable alternative where WebAuthn is unavailable.

WebAuthn does not sign the claim directly. It signs `authenticatorData || SHA-256(clientDataJSON)`. The adapter therefore:
- sets the WebAuthn challenge to the SHA-256 of the canonical claim (section 2);
- verifies `rpIdHash`, the origin, the UP and UV flags and the signature counter (it must not regress);
- checks that `clientDataJSON.challenge` equals the claim digest;
- verifies the ES256 signature with the pinned credential public key.

Only after that does the Rust core treat the claim as signed by that officer. The P-256 verification itself reuses the existing primitive; no home-grown cryptography is added.

### 2. Canonical claim

Deterministic encoding: DER, or JSON canonicalised with RFC 8785. Free-form JSON is not accepted. A claim contains at least:
- a domain-separation tag, `trust-platform/status-change/v1` or `trust-platform/ca-admin/v1`;
- the CA id and the SHA-256 of the CA's registered issuer certificate (0022);
- for status changes: serial, action, reason code, invalidity date and change id;
- for administration: change kind, content digest (as in 0024) and change id;
- the policy edition, a single-use challenge (section 4) and a short expiry.

The maker signs the claim at proposal and the checker signs the same claim at approval. The database stores the claim digest, both signatures, both credential ids and both public-key fingerprints. It enforces, by CHECK and by joins on current grants, that the fingerprints differ, that each one belongs to the acting officer's current grant, and that the claim digest matches the stored change fields.

### 3. Distinct people, not only distinct keys

Distinct keys do not prove distinct people: one person can enrol two authenticators. Each credential is bound to a **unique person identifier** from the IAM (not the OIDC subject alone, which can differ per client). The rule enforced is "maker person ≠ checker person", in addition to distinct keys.

### 4. Challenges

Challenges follow the v1.6 design:
- 256-bit CSPRNG nonce;
- its digest is persisted with the change and the acting identities;
- an expiry is set;
- it is consumed once, by conditional update, in the approving transaction.
A signed approval therefore cannot be replayed onto another change.

### 5. Credential lifecycle under dual control

Enrolling, rotating or removing an officer or admin credential is itself a CA-administration change: two admins, content digest of the credential public key and person id (0024 mechanism). Otherwise enrolment is the obvious bypass. Credential revocation takes effect immediately for pending changes: an approval signed by a removed credential is refused.

### 6. Urgency and break-glass

Dual control must not make the CA miss revocation deadlines. Examples are the CA/Browser Forum Baseline Requirements (24 hours for key compromise, where applicable) and the CA's own CPS commitments under ETSI EN 319 411-1.
- An **on-call checker rota** is required, with escalation driven by `overdue_status_changes`.
- **Suspension (`certificateHold`) as a precaution** may be allowed with a single signed officer action, if the CPS permits suspension. It is reversible and is followed by a dual-controlled definitive revocation or release.
- A **break-glass procedure** is documented, rare and dual-reviewed after the fact. It uses a sealed emergency credential, raises an alert on every use, and is reported in the audit.

### 7. Where the decision is taken

Only the Rust core holds `trust_revocation_officer_api` and `trust_ca_admin`. It verifies the WebAuthn assertions and the claim before calling the database. The stored evidence lets an auditor re-verify every approval offline, without trusting the service.

## Lab implementation status

- **Step 1 (migration 0028, `officer_credential` module):**
  - Credential registry: WebAuthn credential id, P-256 key stored as canonical compressed SEC1 after a curve check in Rust, unique key digest, person id, signature counter.
  - Enrolment and removal under CA-admin dual control (section 5), with one person per officer identity and per CA (section 3).
  - `StatusChangeClaim`, the canonical, domain-separated, length-prefixed claim of section 2, whose SHA-256 is the WebAuthn challenge.
- **Step 2 (migration 0029, `webauthn` module, `PgRevocationStore::submit_signed`):**
  - Single-use challenges bound to the change and the acting officer (section 4). Since 0049 one actor may hold at most 16 open (unexpired, unconsumed) challenges per CA, for status changes and for CA administration each. Since 0053 housekeeping purges challenges that expired unused more than 30 days ago; consumed challenges, which the evidence references, are never deleted.
  - Verification of the ES256 WebAuthn assertion in Rust: RP id hash, UP and UV flags, origin, `webauthn.get` type, challenge equal to the claim digest, non-regressing counter. Attested data, extensions and cross-origin ceremonies are refused.
  - Database re-checks of everything except the ECDSA signature, and storage of the evidence.
  - Distinct keys and persons for maker and checker.
  - Removal of the maker's credential voids a pending proposal.
  - A per-CA, one-way `signed_approvals_required` setting.
  - Offline re-verification (`reverify_signed_change`). Since 22 October 2026 the Rust core also re-verifies the maker's stored signature before writing a checker's approval, so a proposal stored with a forged maker signature cannot be completed through it.
  - Tests cover every case in the evidence list below except "same person with two credentials", which the registry refuses at enrolment (0028). `removed_credentials_never_sign_again` covers "a credential removed mid-flow" and the counter of a removed credential, for officer, admin and break-glass keys. A challenge issued before the removal cannot be answered afterwards, either in the Rust core or, for officers, straight at the database (42501). A removed key's counter refuses even a superuser's UPDATE. Mutation: with the officer credential guard disabled, the counter advances and the test fails.
- **Precautionary hold (migration 0036, section 6):**
  - Opt-in per CA (`precautionary_hold_hours`, 1-72), only where suspension is allowed under a CPS reference.
  - One officer signs a `PRECAUTIONARY_SUSPEND` claim through a single-use `PRECAUTION` challenge. The action is part of the claim, so the signature can never stand in for an ordinary maker signature.
  - The hold is applied at once, with a fixed `confirm_by` deadline and one stored signature, which `reverify_signed_change` accepts only for a precaution.
  - Confirmation is the ordinary signed double control: hold to revoked, or release. The deadline never lifts the hold. Past it, `precautionary_holds` reports it as overdue and `crl_housekeeping` alerts.
  - Each use writes an audit event and a `precautionary_hold_applied` log line.
  - Migration 0038 caps the open holds of one officer on a CA (`precautionary_hold_limit`, 1-100, default 3). Migration 0047 adds a cap for all officers of the CA together (`precautionary_hold_ca_limit`, 1-1000, default 10). Both are checked under one per-CA lock; a concurrency test shows a second officer's hold waiting and refused, and passing under 0038's per-officer lock.
- **Signed CA administration (migration 0037, `trust-platform/ca-admin/v1`):**
  - Admin WebAuthn keys in `ca_admin_credential`, bound to an identity holding `ca_admin_grant` and to a person. They are bootstrapped by the DBA, like `ca_admin_grant` (`enroll_ca_admin_credential`, granted to no service). A key or person is never both officer and admin on a CA.
  - A per-CA, one-way `signed_admin_required` setting. Once set, the unsigned propose and approve of issuer registration, officer grants and credential changes are refused. The original bodies are kept as `*_unchecked`, granted to no service.
  - `CaAdminClaim`: step, CA, issuer certificate digest (absent before the first registration), family, kind, change id (approval only), content digest (0024 / 0028), policy edition, single-use challenge and expiry.
  - Deviation from section 2: a proposal claim has no change id, because the 0024/0028 functions allocate it. The database checks the signed kind and content digest against the change it creates in the same transaction, and the signature row links the two.
  - Distinct keys and persons for maker and checker; removing the maker's admin credential voids the approval. Offline re-verification: `reverify_admin_change`.
- **Admin keys under dual control (migration 0040, section 5):** enrolling or removing a CA admin's WebAuthn key is a signed maker-checker change between two other admins (family `ADMIN_CREDENTIAL`), with no unsigned path. Nobody changes their own key, and the enrolled identity must hold `ca_admin_grant`. Once `signed_admin_required` is set, the DBA bootstrap is closed. DBA removal stays open, because it only takes signing power away (emergency removal of a stolen key).
- **Signed rejection and withdrawal (migration 0039):** on a CA with `signed_approvals_required`, a proposal is closed only by a checker's signed rejection (distinct key and person from the maker) or the maker's signed withdrawal. Each signs a closing claim with its own tag (`trust-platform/status-change-close/v1`) and step, so it never verifies as a maker or checker claim. The unsigned paths are refused; their bodies are kept as `*_unchecked`. The closer's signature is re-verified offline with the maker's.
- **Signed CA-admin rejection (migration 0042):** on a CA with `signed_admin_required`, a pending CA-admin change of any family is rejected only by another admin signing the `ca-admin/v1` claim with step `REJECT` (distinct key and person from the maker). The unsigned rejections are refused, and their bodies are kept as `*_reject_unchecked`.
- **Proposal age (migration 0052):** a CA-admin proposal older than `admin_proposal_max_age_hours` (default 168, at most 90 days) is no longer approved, in all three families and on the signed and unsigned paths alike. It can still be rejected and proposed again. Since 0054 `stale_admin_proposals(ca)` lists such proposals, and `crl_housekeeping` alerts until they are rejected.
- **CA-admin HTTP API (`ca_admin_api`, section 7):** the signed CA-administration flow over HTTP, in its own process with a login holding only `trust_ca_admin` (contract `openapi/ca-admin-v1.yaml`).
- **Offline audit (migration 0041, section 7):** `trust_audit_verifier` may read every change carrying signatures (`signed_evidence_index`) and the signatures and claims, and nothing that acts. `PgRevocationStore::audit_signed_evidence` and the `signed_evidence_audit` job (management-api binary, verified TLS; exit 3 on any failure) re-verify every change of a CA, an open proposal on its maker signature alone, and report each failure without hiding the others.
- **Break-glass (migration 0045, section 6; minimal lab version chosen by the owner):**
  - A separate emergency WebAuthn key per CA (`ca_breakglass_credential`), enrolled and removed by the DBA only and held by a named custodian (`holder_label`). Its key is never an officer or admin key.
  - Its only power is to enrol one CA-admin key: it signs the `ca-admin/v1` claim with step `BREAK_GLASS` over the 0040 content digest (`ENROLL_ADMIN_CREDENTIAL`). It cannot revoke, issue, grant officers or remove anything, and its claims never verify as another step.
  - It works only on a CA with `signed_admin_required` and only while fewer than two admin keys are active (checked under the CA lock); a concurrency test with two custodians shows a second use waiting for the lock and refused). The enrolled identity must hold `ca_admin_grant`, and the one-person rule applies.
  - Each use is recorded with its signature (`breakglass_use`), writes a `ca_admin.breakglass.used` audit event and gets a review deadline (`breakglass_review_hours`, 1-168, default 24).
  - Two admins other than the enrolled identity, with distinct keys and persons, must each sign a `REVIEW` claim over the use's claim digest. Until then `crl_housekeeping` alerts (`open_breakglass_uses`, `overdue_breakglass_uses`).
  - `audit_signed_evidence` re-verifies the break-glass and review signatures offline (`breakglass_evidence`, `trust_audit_verifier`). Since 0051 reviewers see the enrolled content, and no review challenge is issued for a use whose evidence does not re-verify in the Rust core (`breakglass_use_evidence`).
  - Deviations from section 6:
    - the "sealed" credential is a WebAuthn key whose custody is procedural, not enforced;
    - the custodian was a free label in 0045; since 0046 it is a person (`holder_person_id`) who may hold no active officer or admin credential on the CA, in either order of enrolment, so the emergency key cannot enrol an admin key for its custodian. The person identifier is still caller-supplied until the IAM decision;
    - "lost" means the DBA removed the keys (`remove_ca_admin_credential`), since the database cannot tell a lost key from an idle one.
- **Concurrent challenge consumption (evidence item below):** `concurrent_answers_consume_a_status_challenge_once` and `concurrent_answers_consume_an_admin_challenge_once` answer one approval challenge twice at once, from two sessions with two valid assertions. The second answer passes the Rust checks, because the first is not committed yet. It waits on the database locks and is refused, and one CHECKER signature is stored. Mutation analysis shows three independent layers: the functions' row locks ("already used"); with them removed, the challenge guard trigger ("consumed once"); with that also disabled, the change-status check ("closed change"). `concurrent_breakglass_uses_cannot_exceed_two_admin_keys` covers the break-glass CA lock. `concurrent_custodian_and_admin_enrolment_stay_disjoint` covers the registry lock of migration 0048: before it, a custodian and an admin key for the same person could both be enrolled by concurrent transactions.
- **Not yet:**
  - the on-call rota (section 6);
  - attestation policy.

  The person identifier is whatever the caller supplies until the IAM decision.

## Alternatives considered

- **Raw ECDSA over the claim with software or PKCS#11 keys:** simpler to verify (`verify_dual_approval` as is). Software keys do not prove possession by a person; PKCS#11 tokens are acceptable but heavier to deploy than WebAuthn.
- **Per-officer database roles:** see ADR-0006.
- **Signature verification inside PostgreSQL:** adds native code to the database trust base and duplicates the Rust path. Rejected.

## Required evidence before acceptance

- An IAM decision on the person identifier and the authenticator policy (attestation, allowed models).
- A threat-model update: credential theft, authenticator cloning (counter), phishing (origin and rpId), insider with two credentials, and replay.
- RED/GREEN tests:
  - the same key under two ids;
  - compressed versus uncompressed SEC1;
  - same person with two credentials;
  - swapped maker and checker;
  - a claim for another change, CA or issuer;
  - an expired or replayed challenge;
  - a counter regression;
  - a credential removed mid-flow;
  - a forged assertion submitted directly to the database function (refused by grants; evidence re-verification fails).
- Concurrency tests for challenge consumption.
- A CPS text for the suspension and break-glass rules, and an operational on-call procedure.
