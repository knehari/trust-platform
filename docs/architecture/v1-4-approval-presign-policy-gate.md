# v1.4 — CP/CPS policy approval and pre-signature gating (LAB ONLY)

## Delivered

The previous v1.3 implementation stored a **DRAFT_UNAPPROVED** CP/CPS and a retrospective **DRAFT_REFERENCE_ONLY** correlation to an already signed certificate. Version 1.4 introduces a small, explicitly **untrusted laboratory** approval registry and a pre-signature issuance control.

### Policy approval registry
`migrations/0008_policy_approval_presign_gate.sql` adds `approved_policy_edition`: issuer, frozen draft and CP/CPS content digests, policy OID and revision, distinct proposer and approver strings and `[effective_from,effective_until)` effective window. The **original draft remains DRAFT_UNAPPROVED**. The new approved-policy row is a lab governance decision, not a cryptographically authenticated policy authority attestation, legal approval, or evidence of actual deployed CPS practices.

Separate actor strings are deliberately not described as authentication. A trusted identity and authorization boundary must derive the preparer and approver from real IdP/security roles, audit their action and guard against delegated-account misuse.

### Effective issuer-scoped pre-signature gate
A CA without an activated gate follows the original lab paths. `activate_ca_policy_gate_lab` can enroll a CA **before any signing attempts have been recorded** and its enrollment is irreversible at the application SQL level. For opted-in CAs, the `BEFORE INSERT` trigger on `signing_intent` prevents both the new and legacy signing paths from recording signing intent unless an issuer/request-scoped `issuance_policy_grant` exists, matching the exact previously verified TBS SHA-256, immutable request policy revision, policy OID and currently effective approved policy.

`crates/pki-core/src/policy_gate.rs` independently parses the exact X.509 TbsCertificate DER and checks canonical DER, serial, ECDSA P-256 algorithm, and the exact `certificatePolicies` DER extension against `ApprovedPolicyBinding`. It creates a private typed `VerifiedPresignPolicyIntent` consumed by the database adapter's `grant_presign_policy_lab` method. This prevents a caller from merely claiming an OID in a string without checking actual pre-signature certificate data. It does not prove the approved document's authority or actual CA operations.

The SQL grant and signing intent are separate transactions in this lab. The signing-intent trigger re-checks time/issuer/policy/TBS at insertion under the request lock; the database owner, table owner and privileged function callers can bypass or modify this lab mechanism. Production requires restricted privileges, atomic authorization semantics, validation of actual active CA configuration and an authenticated policy authority.

### Test coverage
- `tests/policy_approval_presign_gate.sql`: no self-approval, invalid CP SHA, missing grant before signing, mismatched OID, TBS mutation, attempted approval edit, duplicate activation after signing.
- `crates/pki-core/tests/lab_policy_gate.rs`: real ephemeral ECDSA X.509 root/leaf generated in a disposable CI database. No signed issuance before a valid issuer-specific grant; reject incorrect OID and policy revision; verify the immutable TBS DER before granting; persist a properly signed leaf exactly once after the gate.
- Full CI retains v1.3 observed CA/certificate-draft traces, v1.1 signed collector evidence and anti-replay, and process SIGKILL recovery tests.

## Security limitations and roadmap

1. **Not a production approval**. Proposer/approver are untrusted caller-provided strings; there is no IdP, signed decision, SOD entitlement validation, authenticated request service or governed approval revocation.
2. **Only opt-in issuers are gated**; no change was made to earlier laboratory issuers/tests. Production must not permit a permissive fallback.
3. **No proof of OID ownership or publication**. The lab OID `1.3.6.1.4.1.55555.1.1` is an unowned fixture.
4. **Not a real HSM test or live CA configuration collector**, so neither the policy nor CPS is shown to be deployed.
5. **SQL guards are not a full security boundary**. A privileged DB principal can bypass triggers, inject issuer policy records or forge identity strings. No external WORM/independent trusted clock or policy-signature attestation.
6. **RFC 3647 compliance is not automatically produced**, and no eIDAS/ETSI/ANSSI/ISO certificate/service qualification claim is justified by this prototype.

**Next v1.5**: IdP-verified policy roles, identity-bound approvals and revocations, actual CA/HSM runtime configuration attestation, end-to-end mandatory pre-signature gate, controlled policy publication/CLM, external audit log anchor, G0 employer/IP legal clearance and independent security review.

## Links
- [PR #14](https://github.com/knehari/trust-platform/pull/14)
- [PRD v0.2](https://app.notion.com/p/3f6e759bb68e81cc8892f0154b928d6c)
- [TRUST-57](https://knehari.atlassian.net/browse/TRUST-57)
- [TRUST-58](https://knehari.atlassian.net/browse/TRUST-58)
