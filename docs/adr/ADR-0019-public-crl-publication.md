# ADR-0019 — Public CRL publication and distribution points

**Status:** Proposed · 2026-11-08. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0031;
- two API routes;
- the leaf builder (`application_leaf`), the laboratory signer, the audit
  tool, the console and the laboratory end-to-end suite.

**Roadmap:** second slice of MVP criterion 8. The criterion stays
unchecked:
- renewal is manual;
- there is no OCSP;
- the laboratory publishes on loopback HTTP only.

## Context

ADR-0018 signs CRLs, but serves them only to authenticated readers of the
CA, and the certificates do not say where to find them. A relying party
(OpenSSL, a TLS client) cannot fetch them on its own.

The owner chose (decision of 2026-11-08):
- **publish on an unauthenticated route**;
- **put a CRL distribution point in the certificates**, at a per-CA URL
  that the owner records in the database and that is validated (http(s),
  no credentials);
- **report when nextUpdate approaches.**

## Decision

1. **The distribution point is the owner's decision.**
   - The owner records one base URL per CA in
     `ca_crl_distribution_point`, once. No API route writes it.
   - The URL must be `http` or `https`, with a lowercase host and an
     optional port. It must have no credentials, path, query or fragment,
     and at most 200 characters (CHECK constraint).
   - The distribution point is
     `<base>/v1/public/crls/<ca_id>/latest.crl`.
   - The table is immutable. A CA without a row publishes nothing publicly.
2. **Certificates name it.**
   - The API reads the URL (`application_crl_distribution_point_lab`, same
     callers as issuance) and adds a non-critical cRLDistributionPoints
     extension, with exactly that one URI, after the other extensions.
   - The journal (migration 0029's `record_application_signing_intent_lab`,
     replaced with the same signature) snapshots the URL in effect with the
     intent (`signing_intent_crl_distribution_point`, immutable).
   - The signer reads the snapshot from its view and refuses a TBS without
     it, or with another one.
   - The audit tool checks certificates against the same snapshot.
   - If the owner records a URL between the API's read and the journal,
     the signer refuses and the request becomes `RECONCILIATION_REQUIRED`.
     It fails closed.
3. **Public route** `GET /v1/public/crls/{ca_id}/latest.crl`. No token.
   - It returns `application/pkix-crl` with the latest published CRL of a
     CA that has a distribution point.
   - It returns 404 otherwise: unknown CA, unpublished CA, no CRL yet, or
     an identifier that is not a UUID.
   - It reads `public_crl_latest` with the reader login and no principal.
     This view is deliberately not filtered by reader grant, because CRLs
     are public. It exposes only the CA identifier, the CRL number and the
     CRL itself, and only for published CAs.
   - The route sits behind the same HTTP and database concurrency limits
     as the other data routes.
4. **Renewal status** `GET /v1/cas/{ca_id}/crl-status` (readers of the CA,
   through the security-barrier view `management_crl_status`):
   - the distribution point;
   - the latest CRL number and nextUpdate;
   - `renewal_due`: no CRL yet, or nextUpdate within two days;
   - `expired`: nextUpdate has passed.

   The console shows an alert while renewal is due, an error once the CRL
   has expired, and the public URL.
5. **Laboratory.** `provision-issuing-ca.sql` records `http://127.0.0.1:8081`
   (the API's loopback port) for the lab issuing CA.

## Evidence

- **`tests/management_crl_publication.sql`.** It fails before 0031 and
  passes on it. 15 of 16 mutations of the migration are detected. It
  covers:
  - the writer and the reader cannot read or write the new tables;
  - eleven rejected URLs (scheme, credentials, path, query, fragment,
    case, trailing colon or slash, leading hyphen, length, no scheme);
  - a single, immutable URL;
  - the issuance callers only;
  - no snapshot before publication, one after, none on a replay, and an
    immutable snapshot;
  - what the signer sees;
  - the public view: nothing before publication, then only the latest
    published CRL, not a later unpublished intent;
  - the status: no CRL yet, normal, due within a day, expired;
  - reader isolation.

  The survivor inserts a snapshot on a replayed journal. That path is
  unreachable (0029 returns earlier), and the primary key would refuse it.
- **Leaf tests.**
  - The extension is exactly the URL, non-critical and last.
  - A TBS without it, or with another URL, is refused.
  - An invalid URL is never built.
- **Signer tests.** An intent journaled under a URL that the TBS lacks is
  refused before any claim.
- **HTTP test** (PostgreSQL, real signer):
  - the issued certificate carries the URL;
  - the public route returns 404 before any CRL;
  - the status reports renewal due with no CRL;
  - after CRL 2, the route returns the same DER without a token,
    `application/pkix-crl`;
  - an unknown or malformed CA gives 404;
  - the status reports CRL 2, not due, not expired.

  4 of 4 API mutations detected: the URL not read, the content type, a 400
  instead of 404, the due flag.
- **Audit tool.** It passes on the CI database. With the snapshots
  deleted, it reports the certificates as not verifying.
- **Laboratory end-to-end.**
  - The certificate shows the URI (`openssl x509 -ext crlDistributionPoints`).
  - `openssl verify -crl_check -crl_download` downloads the CRL by itself:
    OK before revocation, `certificate revoked` after.
  - An unauthenticated `fetch` gets the CRL.
  - The status reports the latest CRL as current.

## Consequences and open risks

- **Unauthenticated route.** It is exposed to anyone who can reach the
  API. It is bounded by the existing concurrency limits but has no rate
  limit or cache. `Cache-Control: no-store` stays, as on every route.
- **Plain HTTP on loopback** in the laboratory. CRLs are signed, so their
  integrity does not depend on the transport; availability does.
- **Manual renewal.** Nothing re-signs before nextUpdate. The status and
  the console alerts are the only safeguard.
- **Owner-only configuration.** No route changes the URL, by design. A
  wrong URL is permanent for that CA in this laboratory schema.
- **Certificates issued before** a URL was recorded carry no distribution
  point.
- **Untested here:** the console's status display has no browser test.
