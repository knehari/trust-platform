# ADR-0018 — Revoking issued certificates and publishing signed CRLs

**Status:** Proposed · 2026-11-08. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0030;
- four API routes;
- the `application_crl` module of `trust-pki-core`;
- the CRL path of `trust-lab-signer`;
- the audit tool, the console and the laboratory end-to-end suite.

**Roadmap:** first slice of MVP criterion 8, revocation and publication.
The criterion stays unchecked: there is no CRL distribution point in
certificates, no unauthenticated publication, no scheduled CRL renewal and
no OCSP.

**Laboratory only.** CRLs are signed by the same software key as the
certificates (ADR-0017). Nothing here is a production publication service.

## Context

ADR-0017 issues certificates for approved applications through a separate
laboratory signer. Until now an issued certificate could not be revoked.
The core already had a `revocation` table and a `crl_publication` record
(migration 0001), but no authorized path wrote to them.

The owner chose (decision of 2026-11-08):
- **request plus registration-officer approval**: the certificate's
  requester, or an officer, asks; an officer who did not ask approves; an
  RFC 5280 reason is mandatory;
- **CRLs signed by the laboratory signer, on demand**: a journaled intent
  and a strictly increasing CRL number; publication through the API (GET),
  verifiable with `openssl crl -verify`.

## Decision

1. **Revocation request**
   (`POST /v1/cas/{ca_id}/certificate-applications/{id}/revocation-requests`).
   - **Who may ask:**
     - the application's own requester, while they still hold the
       requester grant;
     - or a registration officer.

     The database decides who may ask (`certificate_issuance_permitted`).
   - **The certificate** must have been issued for that application and
     must not be revoked yet.
   - **One open request at a time.** A rejected request does not prevent a
     new one.
   - **The reason code** must come from a closed list: unspecified (0),
     keyCompromise (1), affiliationChanged (3), superseded (4),
     cessationOfOperation (5) and privilegeWithdrawn (9). These are
     refused:
     - caCompromise and aACompromise, which are not end-entity reasons;
     - certificateHold, because revocation is final here;
     - removeFromCRL, which belongs to delta CRLs.
   - **A written reason** is mandatory.
   - **CA state:** the CA must be ACTIVE or SUSPENDED. Suspension stops
     issuance, not revocation. A RETIRED CA is refused.
2. **Revocation decision**
   (`POST …/revocation-requests/{revocation_id}/decision`).
   - A registration officer who did not ask approves or rejects, once.
   - **Approval** writes the core `revocation` row with the request's
     reason code. It is written under the CA's CRL lock with
     `clock_timestamp()`, so a CRL intent fixed earlier never includes it,
     and one fixed later always does.
   - Core revocations become immutable (trigger `immutable_revocation`).
   - Every step writes an application event and an audit event:
     `certificate.revocation.requested`, then `certificate.revoked` or
     `certificate.revocation.rejected`.
3. **CRL intent** (`POST /v1/cas/{ca_id}/crls`, body `{}`, registration
   officer). `begin_crl_publication_lab`:
   - takes the CA's CRL lock;
   - allocates the next number (`max + 1` over all of the CA's intents, so
     a number is never reused, even after an ambiguous outcome);
   - fixes the instant whose revocations the CRL lists (`entries_until`);
   - sets thisUpdate to that instant truncated to the second, and
     nextUpdate to seven days later.

   The intent then moves forward only:
   - PREPARED → UNCONFIRMED, when the TBS digest is journaled, **before**
     the signer is called;
   - UNCONFIRMED → PUBLISHED or RECONCILIATION_REQUIRED.

   A trigger refuses any other change. **Only the CA's latest intent** can
   be journaled, claimed or signed. A signed CRL therefore never carries a
   lower number than one signed earlier.
4. **The CRL** (`trust_pki_core::application_crl`) is a v2 CRL with
   ecdsa-with-SHA256, issued by exactly the CA's registered certificate:
   - exactly thisUpdate and nextUpdate;
   - one entry per revocation, ordered by serial, with its revocation date
     and, unless unspecified, a non-critical reasonCode;
   - exactly two CRL extensions: authorityKeyIdentifier and cRLNumber.

   An empty CRL has no `revokedCertificates` field. Instants must be whole
   seconds.
5. **The laboratory signer** gets a `crl` request kind. Before it claims
   the intent and signs, it checks:
   1. the intent: its CA, not yet claimed, signable (UNCONFIRMED, the CA's
      latest, and a CA that publishes);
   2. the journaled TBS digest;
   3. that its key is the CA's attested key;
   4. that the TBS is exactly the CRL rebuilt from the database's own
      entries (`lab_signer_crl_entry`), number and instants.

   Then it claims the intent once (`claim_lab_crl_intent`) and signs. Its
   login can only read the two views and call that function.
6. **Independent verification.** The API checks the returned CRL before it
   is stored (`verify_crl`):
   - canonical DER;
   - exactly the journaled TBS;
   - the facts;
   - a signature under the issuer certificate's key.

   The database stores the CRL (`crl_document`, plus the core
   `crl_publication` row) only for a claimed intent. Outcomes:
   - **201** with the PEM;
   - **200** for a replay of the same key (no PEM);
   - **409** for an intent already journaled;
   - **502** `RECONCILIATION_REQUIRED` when the signer refused, failed or
     timed out after the journal, or the CRL did not verify;
   - **503** without a signer.
7. **Readers of the CA** (`trust-ca-reader`, CA in scope, reader grant)
   see on applications the revocation state (REVOCATION_REQUESTED or
   REVOKED), the reason code and the revocation instant. They can also:
   - list published CRLs (`GET /v1/cas/{ca_id}/crls`);
   - fetch one as DER (`GET /v1/cas/{ca_id}/crls/{crl_number}`,
     `application/pkix-crl`).

   This goes through the security-barrier view `management_certificate_crl`,
   filtered on the declared reader principal.
8. **Audit tool** `lab_verify_issued_certificates` also checks:
   - **every revocation:** an approved request with the same reason, and
     an approver who is not the requester and holds the officer grant;
   - **every published CRL:** rebuilt from the database's entries and
     verified against the issuer key, with the stored digests, the
     journaled digest, exactly one claim, and the PUBLISHED outcome.
9. **Console.**
   - **Request revocation:** a reason from the list and an explanation, on
     ISSUED applications.
   - **Approve revocation** and **Reject revocation**, for officers.
   - **Publish CRL:** shows the PEM once, with the OpenSSL commands.
   - The published CRLs are listed.

## Evidence

- **`tests/management_revocation_crl.sql`.** It fails before 0030 and
  passes on it. 25 of 25 mutations of the migration are detected. It
  covers:
  - **Requests:** who may request; the reason list; idempotency; one open
    request.
  - **Decisions:** separation of duties; a single decision; reject then
    request again; core rows and audit events.
  - **CRL intents:**
    - numbers;
    - a fixed instant: a later revocation is not in an earlier CRL;
    - journal before claim;
    - one claim and a wrong digest;
    - storage only after a claim;
    - supersession, including of a journaled intent;
    - reconciliation;
    - suspended and retired CAs.
  - **Immutability** and the forward-only transitions.
  - **Reader isolation.**
- **Test helper fix (separate commit).** `expect_state` used to pass on
  success when P0001 was expected. All the earlier suites now really check
  their immutability triggers. With a trigger dropped, the old helper
  passes and the new one fails.
- **`application_crl` unit tests.** 13 of 13 mutations are detected.
- **Signer CRL tests.** 7 of 8 mutations are detected. The survivor is the
  re-encoding guard, which a strict DER parser already makes unreachable.
- **HTTP test** (PostgreSQL, the real signer in-process). The cases:
  - a requester cannot publish;
  - an empty CRL 1 verifies under the CA key;
  - a forbidden reason code is refused;
  - the requester's request is approved by an officer, and the requester
    cannot decide;
  - CRL 2 lists the serial and is fetched as the same DER;
  - a key replay returns 200 without the PEM; an unknown field gets 400;
  - a wrong-key signer gives 502, recorded as RECONCILIATION_REQUIRED and
    refused again under the same key;
  - a faulty signer that claims and then signs with another key gives 502,
    and nothing is stored;
  - the next CRL takes a new number.

  8 API mutations, 5 detected. The 3 survivors are guards the database
  enforces anyway:
  - ignoring `replayed`;
  - resending a journaled intent;
  - the API's own reason-code filter.
- **Audit tool.** On forged copies it detects:
  - a changed reason;
  - an approval by the requester or without a grant;
  - an altered CRL;
  - a missing claim;
  - a revocation without an approved request.

  It also flagged a badly signed CRL that a deliberate mutation of the API
  had really stored.
- **Laboratory end-to-end** (Keycloak identities, real signer). It checks:
  - `openssl crl -verify` on the empty CRL and the next one;
  - `openssl verify -crl_check`: OK before revocation, "certificate
    revoked" after;
  - the CRL text: serial, Key Compromise, CRL number;
  - the DER fetched by a reader equals the PEM the officer received.

## Consequences and open risks

- **No distribution point.** Certificates carry no CRL distribution point,
  and CRLs are behind authentication. A relying party gets them through an
  authorized reader.
- **No automatic renewal.** CRLs are renewed only when an officer
  publishes. Nothing alerts before nextUpdate (seven days).
- **No reconciliation tool.** A RECONCILIATION_REQUIRED CRL intent is
  simply superseded by the next number. There is no tool to reconcile it
  with what the signer may have signed.
- **Full CRLs only.** No delta CRL, no OCSP, no indirect CRL. Each CRL
  lists every revocation of the CA.
- **Same key custody limits as ADR-0017** (software key file, root
  container).
- **Revocation decisions are not signed.** They are authenticated sessions
  only, unlike the CA and profile decisions.
- **Untested here:** the console's revocation and CRL controls have no
  browser test.
