# ADR-0003 — Post-quantum migration: hybrid-first signature strategy

Status: Proposed · 2026-10-13
Related: ADR-0004 (crypto provider contract), `docs/specifications/x509/requirements.md`

## Context
The platform targets sovereign (EU / French) private PKI customers. The relevant
national guidance (ANSSI, BSI) currently recommends **hybridation** of
post-quantum signatures with a well-established classical algorithm during the
transition period; standalone ML-DSA is not yet the expected default for
production deployments. Stateless hash-based signatures (SLH-DSA, FIPS 205) are
generally considered acceptable without hybridation because their security rests
only on hash-function assumptions.

Standards status (to be re-checked at each release):
- ML-DSA (FIPS 204) in X.509: RFC 9881 — pure ML-DSA, empty context string.
- Composite ML-DSA signatures: IETF LAMPS `draft-ietf-lamps-pq-composite-sigs`
  (OIDs and encoding may still change until RFC publication).
- SLH-DSA in X.509: IETF LAMPS specification (FIPS 205 parameter sets).
- ML-KEM (FIPS 203) is a KEM: it is **never** a signature algorithm and never signs
  a CSR, certificate or CRL.

The algorithm choice structures the data model (key references, CA profiles,
chain-building rules), the provider contract and interoperability testing, so it
must be decided before implementation starts.

## Options considered
| Option | Summary | Assessment |
|---|---|---|
| A. Standalone ML-DSA | RFC 9881 certificates only | Simplest; not aligned with current hybridation guidance for production. Lab only. |
| B. Composite signatures | One certificate, one composite key (ML-DSA + ECDSA/RSA), both signatures must verify | Aligned with hybridation guidance; single chain; depends on a draft until RFC. |
| C. Parallel hierarchies | Separate classical and PQ chains; relying parties choose | Good compatibility; doubles issuance, revocation and lifecycle work. |
| D. Alternative-signature extensions (X.509 `altSignatureValue`, "catalyst") | Classical cert carrying a PQ signature in extensions | Rejected: weak tooling support, silently ignorable by relying parties, stripping attacks. |

## Decision
1. **Crypto-agility by CA profile.** Each CA key has exactly one *algorithm suite*
   fixed at key creation; it never changes. Migration is done by issuing new CA
   keys and hierarchies, never by re-keying in place with another algorithm.
2. **Supported suites** (target, in order of delivery):
   - Classical: ECDSA P-256/SHA-256, ECDSA P-384/SHA-384, RSA-PSS ≥ 3072 bits;
     RSA PKCS#1 v1.5 only in an explicit legacy-compatibility profile.
   - **Composite (default PQ suite for production profiles):** ML-DSA-65 + ECDSA
     P-256 and ML-DSA-87 + ECDSA P-384, per the LAMPS composite specification.
     Verification semantics: **both** component signatures must be valid (AND).
   - Standalone ML-DSA-44/65/87 (RFC 9881): **lab profile only** until guidance
     permits standalone use in production.
   - SLH-DSA: evaluated for **offline root CAs** (long-lived, low signing volume,
     large signatures acceptable). Separate ADR before implementation.
3. **Parallel hierarchies (option C) remain possible** because a CA profile is
   single-suite; the platform does not forbid running a classical and a composite
   hierarchy side by side for compatibility.
4. **Draft OIDs are lab-only.** While composite is a draft, the implemented draft
   version and OIDs are pinned, displayed in the CA profile, and certificates
   using them must not be issued under a production profile. A change of draft
   version is a new suite, never an in-place change.
5. **Key separation.** Composite component keys are generated independently and
   are never reused standalone, in another composite, or for another purpose.
6. **No silent downgrade.** A policy referencing a suite that the configured
   provider does not support is rejected at policy load time (SEC-06).

## Consequences
- The data model stores an explicit suite identifier per CA key and per issued
  certificate; chain-building rules restrict mixing suites within a chain unless
  the policy explicitly allows it (e.g. classical root cross-certifying a
  composite intermediate during migration).
- Interoperability testing must cover composite verification in at least one
  independent implementation before any non-lab use (gate G1/G4).
- Composite signature and key sizes affect CRL size, storage and transport
  limits; size limits must be set per suite.
- This ADR must be revisited when the composite RFC is published and when
  national guidance changes.
