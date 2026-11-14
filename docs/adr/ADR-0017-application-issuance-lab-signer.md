# ADR-0017 — Issuing approved applications through a separate laboratory signer

**Status:** Proposed · 2026-11-08. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0030;
- one API route;
- the `application_leaf` module of `trust-pki-core`;
- the new `trust-lab-signer` crate;
- an audit tool, the console and the laboratory stack.

**Roadmap:** second slice of MVP criterion 7, application issuance. The
criterion stays unchecked: revocation, reconciliation tooling, domain
control and production custody remain.

**Laboratory only.** The CA key is a software P-256 key in a file on the
laboratory host. It has no custody, ceremony, HSM or backup. Nothing here
is a production signing path or evidence for one.

## Context

ADR-0016 records verified CSR applications, bound to the active profile
revision of an ACTIVE CA, and approved by a registration officer who is not
the requester. Nothing was signed.

The core issuance state machine (PRs #4–#9, migrations 0002, 0003 and
0015) already provides:
- issuer-scoped serial reservation;
- a durable signing intent with the TBS digest, before signing;
- `RECONCILIATION_REQUIRED` for an ambiguous outcome;
- the `issue_once` orchestrator in `trust-pki-core`, which verifies the
  certificate independently before it is stored.

The owner chose (decision of 2026-11-08):
- **the signer is an independent policy gate**: it re-checks everything
  itself and does not trust the API;
- **the transport is a Unix socket**, with nothing on the network;
- **the API orchestrates on demand**: an authorised person asks for
  issuance, and there is no background worker.

## Decision

1. **Issuance route**
   (`POST /v1/cas/{ca_id}/certificate-applications/{id}/issuance`, body
   `{}`).
   - The caller is a registration officer of the CA, or the application's
     own requester while they still hold the requester grant. The token
     needs the matching role and the CA in its scope.
   - The database decides the identity (`certificate_issuance_permitted`).
2. **Database wrappers** (migration 0030). The writer login drives the core
   functions only through four SECURITY DEFINER wrappers. Each one checks:
   - the caller;
   - that the application is APPROVED;
   - that its CA is ACTIVE;
   - that its revision is still the profile's active one.

   The wrappers are:
   - `begin_application_issuance_lab` creates the core request (idempotency
     key `application:<id>`), moves it to AUTHORIZED and reserves a serial.
     A second call returns the same request.
   - `record_application_signing_intent_lab` journals the signing intent
     with the TBS digest, **before** the signer is called. A replay returns
     `replayed = true`, and the API then never signs.
   - `store_application_certificate_lab` stores the certificate the API
     verified. It refuses (TP422) names or a CN that are not the
     application's.
   - `mark_application_signing_uncertain_lab` moves the request to
     `RECONCILIATION_REQUIRED`.

   The application status adds `ISSUING`, `ISSUED` and
   `RECONCILIATION_REQUIRED`. Readers see the serial and the certificate
   digest.
3. **The certificate.** `trust_pki_core::application_leaf` builds the TBS of
   an X.509 v3 server leaf. Every element comes from stored facts:
   - the subject key is the stored CSR's key, re-verified by the API (the
     CSR is never trusted, and its extensions are never used);
   - the subject is `CN=<common name>`, and the SAN holds exactly the
     application's DNS names;
   - the serial is the reserved one;
   - the validity starts now and lasts the approved number of days;
   - the issuer and the AKI come from the CA's registered certificate;
   - ECDSA with SHA-256;
   - fixed extensions: BasicConstraints (critical, CA false), KeyUsage
     (critical, digitalSignature), EKU serverAuth, SKI, AKI.
4. **The laboratory signer** (`trust-lab-signer`) is a separate process. It
   is the only one that reads the CA key.
   - **Interface.** It serves one CA and listens only on a Unix socket
     (mode 0600, handed to the API's user). Its protocol is one JSON line
     per connection: an intent identifier and the TBS.
   - **Database access.** Its login holds only `trust_lab_signer`. It can
     read only the `lab_signer_intent` view and call
     `claim_lab_signing_intent`. At start it refuses a login with more
     rights.
   - **Checks before signing,** in this order:
     1. The intent exists, is for its CA, and is not yet claimed.
     2. The database still says the intent is signable: the application is
        APPROVED, the CA ACTIVE, the revision active, and the request in
        SIGNING.
     3. The TBS digest is the journaled one.
     4. Its key is the CA's attested key: the SPKI equals the registered
        certificate's.
     5. The CSR re-verifies and carries the key the TBS certifies.
     6. The TBS is exactly the server leaf the application allows.

     Only then does it claim the intent and sign.
   - **Sign once.** The database refuses a second claim, so even a
     compromised API cannot get an intent signed twice.
   - **Key handling.** The key is read for each request and never logged.
5. **Independent verification and outcomes.** The API uses `issue_once`
   from `trust-pki-core`. It verifies the returned certificate with
   `verify_server_leaf`:
   - the signature under the CA's key;
   - the exact TBS that was journaled;
   - the facts and the extensions.

   Only then is the certificate stored. The outcomes are:
   - **201** with the PEM, the serial and the digest when issued;
   - **200** when it was issued before (the PEM is not returned again);
   - **409** when the application is not approved, or an intent already
     exists;
   - **502 `RECONCILIATION_REQUIRED`** when the signer refused, failed or
     timed out after the intent, or the certificate did not verify. The
     request is never signed again.
6. **Audit tool** `lab_verify_issued_certificates`. For every issued
   application it re-verifies, without the API or the signer:
   - the certificate against the issuer certificate, the CSR key, the
     names, the serial and the extensions;
   - the stored fingerprint;
   - the journaled TBS digest;
   - exactly one signer claim;
   - the approval.

   CI runs it after the API tests.
7. **Laboratory stack.**
   - The `signer` Compose service is built from `Dockerfile.signer`. It
     serves the lab issuing CA `dddd…` with its own login
     (`trust_signer_lab`, password from `init-env.sh`).
   - It mounts read-only only `.lab-keys/ca/`, where
     `create-lab-root.sh` now writes CA root keys.
   - It shares the socket volume with the API (`TRUST_SIGNER_SOCKET`).
     Without that variable the route answers 503.
8. **Console.** An APPROVED application shows **Issue certificate**. The
   issued PEM is shown once, with an `openssl verify` hint.

## Evidence

- **`tests/management_application_issuance.sql`.** It fails before 0030 and
  passes on it. 16 mutations of the migration are all detected. It covers:
  - roles and grants;
  - unapproved, suspended and superseded refusals;
  - idempotent begin;
  - an intent before signing and its replay;
  - a single claim, a wrong TBS and claims after suspension;
  - names refused at storage;
  - reconciliation;
  - the signer view filters, and a reader without a grant.
- **`application_leaf` unit tests.** 11 mutations are all detected.
- **`trust-lab-signer` unit tests.** The check order, each refusal before
  the claim, and the claim before the signature. 9 mutations are all
  detected.
- **HTTP test `approved_applications_are_issued_once_through_the_lab_signer`**
  (PostgreSQL, real signer in-process on a temporary socket, with its own
  restricted login, `TRUST_API_SIGNER_TEST_DATABASE_URL`). It covers:
  - **Setup:** a CA created and activated through the API with a key the
    test holds.
  - **Issuance:** an unapproved application gets 409; the requester's
    issuance gets 201. The certificate's issuer, subject, serial and
    subject key are the expected ones, and the signature verifies under
    the CA key alone.
  - **Replay:** 200, without the PEM; the list shows ISSUED with the
    digest.
  - **Wrong key:** a signer holding another key gets 502
    `RECONCILIATION_REQUIRED`. Then 409, even with the right signer.
  - **Lying signer:** a signer that signs with another key gets 502, and
    nothing is stored.

  8 API mutations were run and 6 are detected. The 2 survivors are
  redundant guards, which the database refuses anyway:
  - ignoring the `replayed` flag;
  - accepting a `RECONCILIATION_REQUIRED` request at begin.
- **Audit tool.** It passes on the CI database and on the laboratory
  database. On forged copies it detects:
  - an altered signature;
  - a wrong fingerprint;
  - a wrong journaled digest;
  - a missing claim;
  - an application that was not approved.
- **Laboratory end-to-end** (`certificate-application-e2e.mjs`). It runs
  with Keycloak identities and the real signer, and checks:
  - the requester's issuance;
  - `openssl verify -purpose sslserver` against the root made by
    `create-lab-root.sh`;
  - the SAN, `CA:FALSE`, the EKU, the applicant's own key and the serial;
  - a replay;
  - refusals for a rejected application and an undecided one.

## Consequences and open risks

- **No reconciliation tool for applications yet.** A
  `RECONCILIATION_REQUIRED` request stays blocked. The core review
  functions (migration 0005) are not wired to applications. *Superseded in
  part by ADR-0020 (Proposed): two officers can now void such an issuance;
  its serial goes on later CRLs.*
- **No revocation, CRL or OCSP** for these certificates.
- **No domain-control validation.** The registration officer's approval is
  the only check of the names. The decision is not signed. *Per ADR-0024
  (Proposed), identity and domain validation belong to the RA or the CLM;
  the CA enforces the profile's zones.*
- **Key custody.**
  - The CA key is a host file, read by a container running as root (to
    read the host-owned 0600 file).
  - The signer has no rate limit and serves one request at a time.
  - Between `bind` and `chmod` the socket briefly has the default mode;
    only the signer and API containers share its volume.
- **One CA per signer process.** The lab runs one signer, for the issuing
  CA.
- **Untested here:**
  - the console button has no browser test;
  - Compose itself was not run locally (no Docker); CI's laboratory job
    runs it.
