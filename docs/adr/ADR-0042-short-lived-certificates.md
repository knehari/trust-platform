# ADR-0042 — Short-lived certificates without revocation (noRevAvail)

**Status:** Proposed · 2026-11-12. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It is the
review's P1 item "short-lived certificates".

**Scope:**
- migration 0048: the owner's short-lived policy per profile and CA, the
  per-application snapshot, the validity bound, the refusal of revocation,
  the distribution point and the signer's view;
- the leaf builder and checker (`trust_pki_core::application_leaf`);
- the API, the laboratory signer and `lab_verify_issued_certificates`;
- tests.

**Out of scope:**
- validities shorter than a day (the platform counts validity in days);
- automatic renewal by the CLM;
- OCSP, which is not in scope;
- the console's display of the policy.

## Context

Every certificate the platform issues could be revoked:
- the CA lists it on its CRLs;
- since ADR-0019, the certificate names the CA's distribution point.

For workloads that renew often, revocation is a cost with little benefit:
- each revocation grows every later CRL;
- relying parties must fetch CRLs;
- a revocation reaches them only after the next CRL and their cache.

A short validity bounds the exposure instead. RFC 9608 (June 2024) defines
`id-ce-noRevAvail` (2.5.29.56). It tells relying parties that no revocation
information is available for the certificate.

**Verification of the reference.** The RFC text could not be fetched from
this session's network. Three points come from the editor's recollection of
RFC 9608 and must be checked against the published text before acceptance:
- the extension value is NULL;
- the extension is non-critical;
- certificates that carry it must not also carry a CRL distribution point
  or an OCSP access method.

The OID and its name were checked against OpenSSL 3.0.13, which names
2.5.29.56 "X509v3 No Revocation Available".

## Decision

1. **Policy, per profile and CA, owned by the database owner.**
   `profile_short_lived_policy(ca_id, profile_id, max_validity_days)`, with a
   maximum of 1 to 7 days. The API's roles can neither read nor change it.
2. **Snapshot per application.** When an application is submitted under a
   short-lived profile:
   - a validity beyond the bound is refused (TP422 → 422);
   - otherwise `certificate_application_short_lived` records the application
     and its bound. The record is append-only and immutable.

   A later change of the policy affects new applications only. The certificate
   follows what was in force when the RA or requester submitted.
3. **The certificate.** For a short-lived application, the leaf carries
   `noRevAvail` (non-critical, DER NULL `05 00`) as its last extension, and
   no CRL distribution point, even when the CA publishes CRLs:
   - `application_crl_distribution_point_lab` returns no URL;
   - the signing intent snapshots none.

   The core refuses to build or accept any of these, whoever asks:
   - noRevAvail together with a distribution point;
   - noRevAvail with more than 7 days of validity.

   The API builds the TBS, the signer re-checks it against the flag it reads
   in `lab_signer_intent.no_rev_avail`, and the audit tool re-verifies stored
   certificates the same way. A TBS with or without the extension, when the
   flag says otherwise, is refused.
4. **No revocation.** Any revocation request for a short-lived application
   is refused (TP409 → 409). The trigger on `certificate_revocation_request`
   covers both the officers' route and the RA route. The audit tool reports
   any revocation of a short-lived certificate. A void of an ambiguous
   issuance still lists the serial (ADR-0020): it covers a certificate that
   may never have been delivered, and the listing is harmless.

## Alternatives considered

- **A field of the profile revision.** The signed profile snapshot
  (ADR-0010, ADR-0011) would change, along with its digest and the approval
  workflow. That is the right place in the long run, once the owner accepts
  the design; the owner table follows the precedent of the optional
  extensions (ADR-0028) and of the CRL point (ADR-0019).
- **Allowing revocation of short-lived certificates.** It would contradict
  what the certificate says: relying parties would never look.
- **Keeping the distribution point.** It would contradict RFC 9608 as
  recalled above, and invite needless fetches.

## Consequences and open risks

- **A compromised short-lived key stays usable until its certificate
  expires** (at most 7 days). This is the accepted trade-off. Only disabling
  the RA, suspending the CA or rotating the CA stops issuance.
- **Daily granularity.** Certificates for hours or minutes need validity in
  seconds or hours (a schema and API change).
- **The policy is outside the signed profile.** A compromised owner login
  could mark a profile short-lived, which takes revocation away from its
  future certificates. This is unchanged from the owner's other powers.
- **The RFC text has not been verified in this session** (see Context).

## Tests

- `tests/management_short_lived.sql` (new):
  - privileges, and the 1–7 day bounds;
  - a longer validity is refused;
  - the snapshot is taken, survives lifting the policy, and is immutable;
  - `application_short_lived_lab` gives the right answers and its access
    rule holds;
  - no distribution point for the short-lived application;
  - a revocation request is refused (TP409), while the ordinary application
    passes the trigger;
  - the signer view's column is present.

  Mutations checked by hand: dropping each of the three triggers fails the
  suite.
- `application_leaf` unit test:
  - the extension is non-critical with exactly `05 00`, and comes with no
    distribution point;
  - a TBS with or without it is refused against the other flag;
  - noRevAvail with a point, or with 8 days, is refused.
- Signer unit test: a short-lived intent with a 30-day TBS is refused
  before any claim.
- API HTTP test (67 tests), with the in-process signer:
  - the owner marks `server` short-lived (3 days), and an RA request for
    30 days gets 422;
  - an RA request for 3 days is issued: noRevAvail is present, there is no
    CRL distribution point, and the validity is exactly 3 days;
  - the RA's revocation of that certificate gets 409.
- The certificate decoded by OpenSSL 3.0.13 shows "X509v3 No Revocation
  Available" and no CRL distribution point. `lab_verify_issued_certificates`
  re-verifies it without a finding.
