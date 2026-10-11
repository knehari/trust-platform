# v1.3 — Observed public CA certificate and CP/CPS draft-to-certificate trace

**Status: laboratory demonstration, stacked draft PR #13. Not an approved CP/CPS lifecycle or operational audit attestation.**

## Precisely what is observed

The observer inspects the **actual DER bytes of a CA public certificate** as supplied to the process, checks its SHA-256 against an **independently configured pin**, and verifies the X.509 v3 certificate's signature, subject/issuer self-issued relation, and narrow lab CA BasicConstraints/KeyUsage profile. The exact DER, certificate SHA-256 and SPKI SHA-256 are retained with an immutable issuer-scoped database reference.

This does **not** read the active HSM/CA service configuration, show HSM private-key possession, identify which templates are actually enabled, confirm policy enforcement, verify root validity against trusted time, validate revocation/chain paths or prove effective CP/CPS governance. In the disposable test, the pin is derived from the test fixture; real independent pin distribution is a future critical requirement.

## Data lineage (draft/reference only)

    Observed CA public DER (verified, externally pinned in intended design)
         |
         v
    ca_public_observation [issuer, certificate hash, SPKI hash, DER]
         |
         v
    cp_cps_draft_snapshot [RFC 3647 markdown CP + CPS, exact SHA-256,
                           configuration source SHA-256, OID, edition,
                           policy revision, DRAFT_UNAPPROVED]
         |
         +------------------+
                            |
    existing signed X.509 certificate + signing_intent
    (independently verified certificate DER, TBS, signer, serial, SAN, OID)
                            |
                            v
    issued_certificate_draft_trace [DRAFT_REFERENCE_ONLY, audit-event]

The Rust trace verification **does not ask the signer to sign**. It parses the root observation's DER, makes it the issuer authority for the existing independent lab X.509 verifier and validates the exact original TBS/serial, real certificate signature, SAN/profile, and certificatePolicies OID. The generated CP/CPS digests are recomputed from the declared input, not accepted from arbitrary caller-provided digest strings. The PostgreSQL function then checks actual persisted certificate SHA-256, signing-intent policy revision, observed CA fingerprint and exact documentary/OID fingerprints before inserting one immutable trace.

## Implemented files

- Rust CA observer: crates/pki-core/src/ca_observation.rs
- Rust signed-certificate draft verifier: crates/pki-core/src/policy_trace.rs
- PostgreSQL metadata adapter: crates/pki-core/src/postgres_store.rs
- Migration 0007: migrations/0007_ca_observation_policy_draft_trace.sql
- SQL invariants: tests/ca_observation_policy_draft_trace.sql
- Real ECDSA/X.509 integration: crates/pki-core/tests/lab_verified_issuance.rs
- GitHub Actions applies migration/negative SQL tests and exercises Rust/PostgreSQL and prior process SIGKILL tests.

## Security and design constraints

1. **No direct approved policy**: stored document state is always DRAFT_UNAPPROVED. The retrospective certificate link is always DRAFT_REFERENCE_ONLY and never asserts the issuance complied with the CP/CPS.
2. **Not an issuance gate**: before production signing, a future policy-authority approved document, OID registration/ownership, legal entity roles and effective-date/cert profile validation must be checked transactionally. A post-signature audit link cannot establish compliance retroactively.
3. **No trusted runtime observer yet**: the presented DER may not be the root actually serving a live CA. A real read-only CA API and authenticated attestation of its active configuration, subject/key binding, HSM identities and behavior are still required.
4. **PostgreSQL cannot validate X.509 signatures or trust pins**: the Rust typed verification is the lab guardrail; a future least-privilege authenticated service must prohibit direct table/function writes by untrusted actors. Privileged DB owners can bypass triggers.
5. **No external WORM/independent timestamps**: event and document immutability are enforced via database triggers at the application level only.
6. **Unowned test OID**: 1.3.6.1.4.1.55555.1.1 is a fixture; it is NOT an approved or registered product policy OID.
7. **No live HSM and no production crypto-policy proof**: ECDSA P-256 ephemeral software lab root only, no approved key ceremony, offline root, algorithm transitions, revocation or QTSP proof.
8. **No qualifications by implication**: ISO/IEC 27099, ETSI EN 319 401 / 411, ANSSI and eIDAS controls require independently scoped evidence, conformity assessment, organization/operator controls, legal and technical approval.

## Acceptance test cases

- Actual independently self-consistent pinned P-256 CA public certificate is accepted; wrong externally provided fingerprint, altered signature and leaf-as-root are rejected.
- Declared CP/CPS policy revision cannot differ from database CA policy version; altered CP Markdown fails digest check; root fingerprint mismatch fails certificate trace.
- A real X.509 leaf is issued and persisted once; after independent re-verification against the observed root, a single retrospective draft trace is committed and read back on a **new PostgreSQL connection**.
- Wrong requested policy OID, wrong observed root, malformed dossier hashes, nonexistent certificate or duplicate trace must be rejected.
- CP/CPS draft state remains DRAFT_UNAPPROVED; no signed certificate state is changed; no automatic re-signing or publication occurs.
- Regression: v1.1 signed-collector evidence/anti-replay, v0.8 real SIGKILL recovery, Postgres serial races and OpenSSL interoperability.

## Product requirement mapping

- FR-014: **partial**. Source now contains an observed CA **public certificate**, but not independent technical practices, HSM operation or implemented identity/revocation controls.
- FR-017: **partial** immutable relationship for **unapproved draft references only**; not approved, effective CP/CPS-to-certificate issuance mapping.
- FR-015: existing section-level declarative drift detection remains; no real-time control-plane observer or change alerts.

## Next milestone

Build an authenticated read-only configuration collector for a known CA deployment and an issuer-scoped immutable policy approval registry with distinct authenticated preparer/approver, policy OID proof, effective dates and a fail-closed **pre-signature issuance gate**. Controlled publication/CLM distribution comes after that, not before.

**Governance:** G0 founder/employer intellectual-property separation, external code/security review and explicit IP/licensing decisions remain mandatory before merging any PRs or using in a production environment.
