# Lab X.509 key identifiers and certificate-policy metadata

**Scope:** native Rust laboratory issuer only. This is not a production-grade PKI or qualified certificate profile.

## Implemented

- **Subject Key Identifier** `2.5.29.14`: 160 leftmost bits of SHA-256 over the DER SubjectPublicKey BIT STRING value, excluding tag, length and unused-bit count, following [RFC 7093 §2(1)](https://www.rfc-editor.org/rfc/rfc7093.html#section-2). Present in root and leaf, noncritical.
- **Authority Key Identifier** `2.5.29.35`: keyIdentifier `[0]` for the issuing root's key, noncritical. Root AKI is optional under [RFC 5280 §4.2.1.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.1); this laboratory root includes it.
- **certificatePolicies** `2.5.29.32`: a single explicitly supplied policy OID without qualifiers. Encoded as SEQUENCE OF PolicyInformation, per [RFC 5280 §4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4). The issued policy OID comes from CA-side configuration, never from the CSR.
- A Rust `ApprovedPolicyBinding` **laboratory input contract** carries the OID, document revision label and a 32-byte document reference digest. It rejects `anyPolicy`, blank version and all-zero digest.

## Crucial assurance limitations

The lab binding **does not validate actual external approval**. The constructor currently receives caller-supplied metadata, and the test document hash is an illustrative placeholder. It does **not** prove that any approved CP/CPS exists. Code review should rename/refine the type once approval workflow and immutable document repository exist. No audit readiness, policy provenance, compliance, qualification or successful publication can be inferred from the presence of an OID.

The test OID `1.3.6.1.4.1.55555.1.1` is **NOT claimed as assigned to this company** and MUST NOT be used in real-world issuing profiles. Production issuance must use a legitimately delegated OID namespace and a formally approved, effective certificate policy.

## CI evidence

- `cargo test --workspace --all-targets --all-features --locked` including a root-SKI-to-leaf-AKI comparison and negative policy-reference tests.
- `openssl verify -purpose sslserver`, OpenSSL root SKI and leaf AKI inspection, explicit certificatePolicies OID inspection.
- This demonstration uses process-local signer and serial reservation; no durable history exists.

## Follow-on work

1. Approved CP/CPS lifecycle, immutable storage, computed content hashes, approver provenance, effective dates, four-eyes authorization.
2. Policy OID delegation validation and policy-to-issuer/profile/version binding enforced by the CA service.
3. Audit events atomically correlated with durable issuance intent and the relevant CP/CPS revision; independent tamper-evident anchor.
4. More X.509 profile requirements and strict chain/path validation; HSM + backup + CRL and revocation lifecycle.

See [PRD v0.2 traceability](../../product/prd-v0.2-traceability.md), ADR-0004 and Jira TRUST-79.
