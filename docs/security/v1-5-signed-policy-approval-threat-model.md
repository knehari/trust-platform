# v1.5 — Dual signed CP/CPS decisions (laboratory prototype)

**Status:** stacked draft PR #15 on #14. Not merged and **not** an authenticated IdP approval or proof of ETSI/eIDAS/ANSSI readiness.

## Why the additional signature layer matters

v1.4 accepts two distinct *caller-supplied identity strings* as a lab approval. Those strings do not prove that independent authorized human reviewers approved a document. v1.5 adds **cryptographic integrity and holder-of-key proof** using separately pinned ECDSA P-256 keys, but still does NOT prove human identities, role entitlement, actual organizational separation, qualified signatures or deployed CPS controls.

## Delivered

- `policy_decisions.rs`: exact deterministic, domain-separated `STP-CP-CPS-DUAL-APPROVAL-V1` binary claim, containing issuer ID, original draft ID, certificatePolicies OID, policy revision, CP SHA-256, CPS SHA-256, time interval as UNIX seconds and a random-looking 32-byte decision nonce (generated externally). No dynamic signing happens inside verification.
- `verify_dual_approval`: independently pinned P-256 public keys for preparer and approver, different key IDs AND distinct public key material, two validated ECDSA signatures over **the exact same claim**. Cross-policy, hash, date, nonce, role-substitution and forged signatures are rejected. Returns a privately constructed `VerifiedDualApproval` with original claim bytes, signatures and evidence hash.
- `migrations/0009_signed_policy_receipts.sql`: issuer/approval/draft-bound immutable application receipt, exact canonical bytes, both signatures, key IDs, evidence SHA-256, unique approval/claim reference and audit record. Function checks CP/CPS hashes, policy OID, revision **and effective dates** against the frozen v1.4 approval.
- `postgres_store.rs`: narrow typed evidence persistence interface, accepting `VerifiedDualApproval`, preventing ordinary application callers from creating evidence from unchecked strings through this Rust method.
- **Opt-in second guard:** `ca_dual_signature_enforcement` can be enabled only after the issuer's existing v1.4 policy gate and before any signing attempts. An additional database `BEFORE INSERT` trigger on signing intents rejects missing signed decision receipt for the issuer's granted policy. This is an extra lab gate, not production RBAC or HSM access control.
- `tests/policy_decisions.rs`: real ephemeral P-256 signature verification, tampering, shared-key attack, swapped roles, changed validity interval, policy OID, CP hash, nonce and invalid claims. PostgreSQL integration signs **actual approval claims**, stores the verified receipt, rejects replay and confirms exact readback through another connection.
- `tests/signed_policy_receipts.sql`: SQL invariants, missing signed receipt blocks signing, forged CP hash, altered effective window, duplicate receipt, immutable receipt, and the permitted lab path after receipt. **Synthetic test signatures in SQL are NOT cryptographically authenticated by PostgreSQL**.

## Security model and hard gaps

1. **Key ownership is not human authorization.** An ECDSA signature verifies possession of a key; keys must be mapped to individual authenticated policy roles with protected key custody and non-export/anti-sharing rules, governance of lifecycle, revocation and trusted approval session.
2. **No IdP integration** or verified separation of named approvers. Database proposer and approver IDs are still caller strings. An attacker with direct SQL rights or the ability to substitute trust pins can bypass this intended adapter flow.
3. **PostgreSQL cannot verify ECDSA** in the supplied stored procedure. Only the typed Rust application verifies both signatures. DB owners/admins can bypass triggers and inject records. Production needs least-privilege roles and strongly authenticated API-layer authorization.
4. **Nonce is signed but not minted by a trusted authority**. DB uniqueness helps detect repeated receipts; genuine end-to-end challenge issuance, trusted timestamp, replay windows, and authenticated policy-authority trust stores are future work.
5. **Approval != deployed practices or OID ownership.** No source-attested CA control plane, actual HSM operation, legally owned OID, signed CP/CPS effective publication, revocation authorization and qualified-service evaluation is demonstrated.
6. **Gate remains opt-in** for lab issuers; legacy routes are unmodified unless CA was enrolled. Real product must deploy mandatory default deny, privileged role separation, trusted time and cryptographically bound approval BEFORE intent creation.
7. **No regulatory qualification claim**: qualified certificates/qualified trust services and their assessments cannot be derived from a software demonstration.

## Next v1.6
Authenticated reviewer identity via an actual external IdP, user-bound cryptographic key attestation and separate authority roles; attest original CA/HSM runtime state; enforce verified signed policy decisions for every signing-capable issuer, implement verified time/challenge issuance, policy withdrawal and controlled CP/CPS publication.

## Traceability
- [PR #15](https://github.com/knehari/trust-platform/pull/15)
- [PRD v0.2](https://app.notion.com/p/3f6e759bb68e81cc8892f0154b928d6c)
- [TRUST-57 (approval)](https://knehari.atlassian.net/browse/TRUST-57)
- [TRUST-58 (pre-sign gate)](https://knehari.atlassian.net/browse/TRUST-58)

**G0 legal / employer-IP separation and independent security review remain outstanding before any code merge or commercial use.**
