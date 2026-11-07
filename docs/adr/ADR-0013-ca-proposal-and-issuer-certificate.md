# ADR-0013 — Propose a CA and register its self-signed issuer certificate

**Status:** Proposed · 2026-11-07. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0025;
- three API routes and a certificate verifier;
- an OpenSSL laboratory script;
- the console and the laboratory stack.

**Roadmap:** first slice of the *CA* half of MVP criterion 6. The criterion
stays unchecked.

**Not here:**
- **No CA is created.** A proposal is not a row of `ca`. It appears in no
  CA list, holds no grant, and nothing can issue under it.
- **No approval, activation, suspension or retirement of CAs.** Approval
  and activation followed in
  [ADR-0014](ADR-0014-ca-approval-and-activation.md).
- **No key generation by the platform, and no key custody.** The private
  key is generated outside the API and the database (OpenSSL in the lab).
- **No subordinate CAs.** Only self-signed roots.

## Context

The [lifecycle contract](../architecture/ca-profile-lifecycle-boundary.md)
asks for CA creation, approval, activation and retirement with key, provider
and issuer-certificate binding. ADR-0012 activates profiles against suites
the owner *declares* for a CA, and states that the issuer certificate is not
checked, because no CA key binding exists.

The owner chose (decision of 2026-11-07) to split the CA lifecycle in two:
1. a proposal plus a verified issuer certificate (`PROPOSED` →
   `KEY_ATTESTED`), with the key generated outside the platform;
2. two-person signed approval, then activation, suspension and retirement.

This ADR is the first part.

## Decision

1. **Platform administrators.** `management_platform_grant` holds `(issuer,
   subject, platform_role)` rows written by the owner. The only role is
   `ca-administrator`. It is not scoped to a CA, because a proposal has no
   CA yet. The token must also carry the `trust-ca-administrator` role.
2. **Proposal** (`propose_ca_lab`, through the writer login of ADR-0010).
   - Fields: display name, policy version, signing suite.
   - The database draws the CA identifier, and refuses an identifier
     already used by a CA or a proposal. Since ADR-0016, the administrator
     may choose it.
   - The API accepts only the suite `ecdsa-p256-sha256`: the only suite
     whose key type the certificate check and the database map (P-256).
   - The proposal is `PROPOSED`. It is immutable.
3. **Issuer certificate** (`register_ca_issuer_certificate_lab`). The
   administrator generates a key and a self-signed root outside the
   platform, for example with `scripts/lab/create-lab-root.sh`, and sends
   only the certificate (PEM).
   - **The API verifies it** (`ca_certificate.rs`) and refuses, with 422 and
     a reason, anything but:
     - one PEM `CERTIFICATE` block in canonical DER;
     - X.509 v3, `ecdsa-with-SHA256` without parameters in both algorithm
       fields;
     - a P-256 key on the named curve, as an uncompressed point;
     - a subject of exactly one common name, and an issuer equal to it;
     - only the basicConstraints, keyUsage, subjectKeyIdentifier and
       authorityKeyIdentifier extensions, each once; basicConstraints
       critical with `cA`; keyUsage critical with keyCertSign and cRLSign;
     - a validity that has started (five minutes of skew) and not ended;
     - a signature that verifies under its own key, with the reviewed
       verifier of `trust-pki-crypto`.

     Structural rules run before the signature, so each refusal names the
     first rule that failed.
   - **The database checks the facts the API extracted** against the
     proposal. It refuses:
     - a caller without the platform grant;
     - an unknown proposal;
     - a second certificate for the same proposal;
     - a public key (SPKI digest) already registered for another proposal;
     - a common name other than the proposed display name;
     - a key type that does not match the proposed suite;
     - a validity window that is not current.

     It stores the DER, its SHA-256 (computed by the database), the SPKI
     digest, the validity and the custody `lab-software-file`.
   - **Outcome:** the proposal becomes `KEY_ATTESTED`. This proves that
     whoever produced the certificate held the private key when signing it.
4. **One transaction** writes the proposal or certificate row, a
   `ca_lifecycle_event` and an `audit_event`. The audit event has no CA
   (`ca_id` is NULL), because `audit_event.ca_id` references `ca`.
5. **Idempotency keys** work as in ADR-0010. The per-proposal advisory lock
   serializes registrations.
6. **Readers.** `GET /v1/ca-proposals` reads the `management_ca_proposal`
   view through the reader login and the declared principal (ADR-0008).
   - The view returns rows only when that principal holds the platform
     grant.
   - The route needs the `trust-ca-administrator` token role.
   - Readers of CAs see nothing new: `management_ca` is unchanged.
7. **Console.** A user with `trust-ca-administrator` sees **CA proposals** on
   the overview. They can propose a CA and paste a certificate for a
   `PROPOSED` one. The console never holds a key and shows the command that
   generates one.
8. **Lab stack.**
   - Keycloak has the realm role `trust-ca-administrator` and the user
     `lab-ca-admin` (fixed ID `…012`, password `TRUST_LAB_PW_CA_ADMIN`).
   - `init-db.sh` gives that user the platform grant.
   - `scripts/lab/create-lab-root.sh "<name>"` writes the key to the ignored
     `.lab-keys/` (modes 700 and 600), never overwrites one, and prints the
     certificate.

## Evidence

- **`tests/management_ca_proposal.sql`.** It fails before 0025 and passes
  on it. It covers:
  - **Grants:** the platform role is constrained; the writer role cannot
    read or write the new tables.
  - **Proposal refusals:** a non-administrator, the identifier of an
    existing CA, a control character in the name, a non-catalogue suite
    format.
  - **Proposals:** creation, replay, reuse of a key by another
    administrator, a duplicate identifier, an identifier drawn by the
    database.
  - **Certificate refusals:** a non-administrator, an unknown proposal, a
    CN mismatch, a P-384 key, a suite without a key mapping, an expired
    certificate.
  - **Registration:** registration and replay, then a second certificate
    for the proposal and the same key for another proposal (both 409).
  - **View:** an administrator sees every proposal and its state; anyone
    else sees none; a proposal is not listed as a CA.
  - **Records:** events and audit rows match; rows are immutable.
  - **Interrupted transaction:** a failing audit write leaves no
    certificate.
  - **Mutations detected:** each of these makes the test fail:
    - dropping the grant check, in either function;
    - dropping the existing-CA check;
    - dropping the SPKI-reuse check;
    - dropping the CN check;
    - dropping the suite/key check;
    - dropping the expiry check;
    - dropping the second-certificate check;
    - opening the view to every principal.

    One mutation survives, and it is equivalent: removing the explicit
    `v_expected_key IS NULL` guard. A NULL expected key already refuses
    every key parameter.
- **`ca_certificate` unit tests** (7). They cover:
  - an OpenSSL P-256 root, and a root built by the Rust lab CA;
  - committed OpenSSL vectors (certificates only, keys discarded): P-384,
    RSA, not a CA, no cRLSign, an extra subject attribute, a CA issued by
    another key;
  - validity at its edges;
  - a tampered serial number, and another root's signature;
  - each structural rule on its own;
  - PEM framing and non-canonical DER.
- **`ca_proposals_record_one_verified_root_per_key`** (Rust, PostgreSQL in
  CI). It covers:
  - **Refusals:** no role or no grant gives 403; a P-384 suite gives 422;
    unknown fields and a missing key give 400.
  - **Proposals:** creation, replay, key reuse (409).
  - **Certificate refusals:** P-384 (`KeyAlgorithm`), not a CA
    (`BasicConstraints`), a CN mismatch, a forged signature
    (`Signature`), a non-administrator, an unknown proposal.
  - **Registration:** registration and replay; a second certificate and a
    reused key give 409.
  - **Listing:** a granted administrator sees both states; the role without
    the grant sees an empty list; other roles get 403.
  - **Mutations detected** (each makes the unit or HTTP tests fail):
    - skipping the signature check;
    - skipping the issuer-equals-subject check;
    - skipping the expiry check;
    - accepting any suite at proposal;
    - dropping the role check on the list route.
- **`frontend/dev/ca-proposal-e2e.mjs`** (Compose job). It signs in through
  Keycloak and generates roots with `create-lab-root.sh`:
  - an operator and a P-384 suite are refused;
  - a proposal and its replay;
  - a root for another name gives 422; a private-key field gives 400;
  - the proposal's own root is recorded, and its digest matches OpenSSL's;
  - a second root gives 409;
  - the list shows `KEY_ATTESTED`; readers get 403 and see no new CA.
- **`browser-e2e.mjs`:** `lab-ca-admin` proposes a CA and registers its
  OpenSSL root from the console.

## What this does not establish

- **Possession at one moment is not custody.** The key is a software file.
  Nothing proves how it was generated, who else holds it, or that it is
  protected. There is no ceremony, HSM or attestation (criterion 9).
- **A single administrator proposes and attests.** No second person
  confirms. Approval by two signers is the next slice.
- **The database trusts the API's X.509 parsing.** A compromised API, or a
  holder of the writer login, could record a certificate the verifier would
  refuse. The DER is stored, so an audit tool could re-verify it; ADR-0014
  added that tool and a re-verification at activation.
- **The database trusts the declared principal** (ADR-0008, ADR-0010).
- **No revocation, renewal or replacement.** A certificate cannot be
  withdrawn from a proposal; a new proposal is needed.
- **Only self-signed P-256 roots.** No subordinate CA, no other suite, no
  name constraints or policy extensions.
- **Profile activation is unchanged.** It still checks declared
  capabilities, not the attested key; it will once a CA is activated.

## Alternatives considered

- **Generating the key in the API or the browser.** It would put CA private
  keys where AGENTS.md forbids them. Rejected.
- **Creating the `ca` row at proposal.** CA readers, grants and profile
  routes would see an unapproved CA. Rejected in favour of a separate
  proposal table; activation will create the row.
- **Parsing X.509 in PostgreSQL.** It would mean home-grown ASN.1 parsing in
  SQL. Rejected: the API verifies with reviewed crates, and the database
  checks the extracted facts.
- **A CSR instead of a self-signed certificate.** It proves possession too,
  but leaves the certificate to be built later by the platform, which has no
  signing path for CA keys. Deferred to the activation slice.
