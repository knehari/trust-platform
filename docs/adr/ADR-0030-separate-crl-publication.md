# ADR-0030 — Publish CRLs through a separate publisher and static server

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It
follows the owner's choice of 2026-11-11 among the P0 items of the
architecture review.

**Scope:**
- migration 0043;
- the new `trust-crl-publisher` crate;
- the removal of the API's anonymous route;
- the laboratory compose services `publisher` and `crl-web`;
- provisioning, the end-to-end suite and the OpenAPI contract.

**Supersedes in part:** ADR-0019. The distribution point path is
unchanged; it is now served by a static server, not by the management API.

## Context

Since ADR-0019 the management API served `GET
/v1/public/crls/{ca_id}/latest.crl` without authentication, through its
reader login. That endpoint is anonymous, reachable by every relying party,
and called on every certificate check. It shared with every sensitive
management operation:
- the API's process and memory;
- its database connection slots;
- its attack surface.

A flood of CRL requests, or a parser or routing defect on that path, could
therefore weaken the management plane.

## Decision

1. **The API serves nothing anonymous.** The route and its handler are
   removed. The API reader loses `SELECT` on `public_crl_latest`, and the
   API's readiness no longer probes it.
2. **A separate publisher.** `trust-crl-publisher` runs as its own process,
   with its own login. That login is granted only the NOLOGIN role
   `trust_crl_publisher`, which can read one view, `crl_publisher_feed`: the
   latest published CRL of each publishing CA and its issuer certificate.
   The publisher refuses to start with any login that can read or write
   more. It holds no key.
3. **Verify before publishing.** For each CA, the publisher requires:
   - canonical DER;
   - ECDSA P-256 / SHA-256, verified under the registered issuer
     certificate's key;
   - an issuer name equal to that certificate's subject;
   - a single CRL number equal to the recorded one;
   - a `nextUpdate`;
   - a CA identifier that is a UUID, so it cannot be used as a path.

   Otherwise it refuses and logs an alert.
4. **Never roll back.** The publisher writes only a CRL whose number is
   greater than the number already served. A database restored to an
   older state never replaces a newer public CRL; the publisher logs
   `rollback` as an alert.
5. **Atomic files.** `<dir>/v1/public/crls/<ca_id>/latest.crl` and
   `<crl_number>.crl` are written to a temporary name, synced, then
   renamed.
6. **A static server.** In the laboratory, `crl-web` (nginx) serves that
   tree read-only, on `127.0.0.1:8082`:
   - only GET, and only the exact file paths;
   - no listing;
   - `application/pkix-crl`;
   - no database access.

   The owner sets that host as the CA's distribution point base URL. New
   certificates therefore carry
   `http://127.0.0.1:8082/v1/public/crls/<ca_id>/latest.crl`, with the path
   unchanged.

## Alternatives considered

- **Keep the route, behind a rate limiter.** Rejected: the route would
  still share the API's process and login.
- **Have the API push files.** Rejected: the API would need write access
  to the public tree, and a compromised API could then publish anything.
  The publisher verifies under the issuer key instead.
- **Serve directly from the publisher.** Rejected: the database reader and
  the internet-facing server would be the same process again.

## Consequences and open risks

- **Publication delay.** A CRL appears on the static server within the
  publisher's interval (2 seconds in the laboratory) after it is stored.
  "Publish on revocation" (ADR-0027) inherits that delay.
- **Older certificates.** Certificates issued before the base URL changed
  name the API's former route. In the laboratory, stacks are disposable;
  elsewhere, the old path would have to keep serving until those
  certificates expire.
- **Not production hosting.** The laboratory server is plain HTTP on
  loopback. CRLs are signed, so integrity holds, but availability, caching
  and a CDN are not addressed.
- **The publisher runs as root** in its container, to write the named
  volume. The static server only reads it.
- **Bypass by a compromised owner.** A compromised owner login can grant
  the publisher role more rights. The publisher refuses to start when its
  login has more, but that check runs only at each pass.

## Tests

- `crates/crl-publisher` (3 tests):
  - newer CRLs are published, the same one is unchanged, an older one is
    refused as a rollback;
  - no temporary file is left;
  - refusals: another signing key, another issuer, a renumbered CRL,
    altered or invalid bytes, and a path-like CA identifier, each without
    writing any file.
- `tests/management_crl_separate_publication.sql`:
  - the feed equals the public view, with the issuer certificate;
  - the API reader and the writer cannot read it;
  - the publisher role reads only its view: no table, no other view, no
    writing function.

  The earlier publication suite now reads the public view as the owner.
- The API HTTP test (63 tests):
  - the former route answers 404;
  - an in-process publisher pass writes the exact stored CRL;
  - a second pass leaves it unchanged.
- The certificate-application e2e suite, against the static server:
  - certificates name the static server;
  - it serves the exact CRL the officer received;
  - no listing and no POST;
  - `openssl verify -crl_download` fetches CRLs from it;
  - the RA revocation's CRL appears there by itself.
