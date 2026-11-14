# ADR-0043 — OCSP architecture: pre-signed responses from a delegated responder

**Status:** Proposed · 2026-11-13. Design only: no code, no migration. It is
not accepted; acceptance needs the owner's decision and an independent
security review (AGENTS.md).

It first asks the owner whether OCSP enters the MVP's scope. AGENTS.md
applies RFC 6960 only "si ces composants entrent dans le périmètre". ROADMAP
v2.9 lists an "OCSP architecture", and ROADMAP's revocation criterion says
OCSP "require[s] a separate design decision". This ADR is that design. It
is meant to be decided before any implementation.

**References to verify before acceptance.** This session could not reach
rfc-editor.org. The RFC points below come from the editor's knowledge of the
texts and must be checked against the published RFCs and their errata:
- RFC 6960 (OCSP), and RFC 5019 (the lightweight profile for high-volume,
  pre-produced responses);
- RFC 9654 (the updated OCSP nonce rules);
- RFC 5280 (AIA);
- RFC 9608 (noRevAvail).

## Context

The platform publishes revocation only through CRLs:
- signed by the laboratory signer after a journaled intent (ADR-0018);
- with each entry's proof re-verified (ADR-0029);
- published by a separate publisher and a static server (ADR-0030);
- renewed automatically and on revocation (ADR-0021, ADR-0027).

Certificates name the CA's CRL (ADR-0019). Short-lived certificates name no
revocation source at all (ADR-0042).

CRLs have known limits for relying parties:
- a relying party downloads the whole list;
- it sees a revocation only after the next CRL and its own cache.

OCSP answers about one certificate at a time. It also brings new risks:
- an online signing service;
- a key that signs statements about every certificate;
- a public endpoint;
- a second source of revocation truth that must never contradict the first.

## Options

| Option | Who signs | When | Main cost |
| --- | --- | --- | --- |
| A. Online responses signed by the CA key | the CA key, per request | at each request | the CA key signs on demand for unauthenticated requests; a denial of service reaches the signer |
| B. Online responses signed by a delegated responder key | a responder certificate the CA issues (EKU id-kp-OCSPSigning) | at each request | an online key and service with database access; nonces possible |
| C. Pre-signed responses by a delegated responder key, served statically | the responder key, in the signer, in batches | after each CRL and each revocation | no nonce; responses at most as fresh as the last batch; storage per certificate |

## Decision (proposed)

0. **Scope (owner decision).** OCSP enters the MVP for leaf certificates of
   issuing CAs that publish CRLs. Without that decision, nothing below is
   implemented.
1. **Option C, following RFC 5019's pre-produced model.** It keeps the
   platform's existing pattern:
   - the signer signs only from journaled intents;
   - a separate publisher writes static files;
   - a server without database access serves them;
   - no unauthenticated request ever reaches a key or the database.

   Nonces are not supported. Clients that require one are out of scope;
   RFC 9654's guidance on unsupported nonces must be checked.
2. **A delegated responder key, never the CA key.**
   - The responder key lives in its own PKCS#11 token
     (`trust-lab-ocsp`), the way the audit key does (ADR-0035).
   - It is certified by the CA with EKU id-kp-OCSPSigning, the
     id-pkix-ocsp-nocheck extension and a short validity (proposed: 30
     days). It is renewed before expiry by the same journaled issuance path.
   - nocheck means relying parties do not check the responder certificate's
     revocation. Its short life is the control, as in ADR-0042.
3. **One truth with the CRL.**
   - Each batch is a journaled "OCSP intent" bound to a CRL intent: same CA,
     same `entries_until`.
   - It covers every certificate the CA issued that is unexpired at
     `this_update`.
   - The signer rebuilds every status from the same views it uses for CRL
     entries:
     - a certificate listed on that CRL (revocation or void) is **revoked**,
       with its time and reason, and needs the same entry proof as the CRL
       (ADR-0029);
     - every other issued certificate is **good**.
   - Responses carry the CRL's `thisUpdate` and `nextUpdate`, so an OCSP
     answer is never fresher or staler than the CRL it mirrors.
   - Batches follow every CRL publication, including publication on
     revocation (ADR-0027).
4. **Unknown and non-issued serials.**
   - A serial the CA never reserved gets no pre-signed response. The server
     answers `unauthorized` (RFC 5019) or a pre-signed `unknown`, to be
     decided.
   - A reserved serial whose issuance was voided is listed on the CRL and
     answered **revoked**.
   - RFC 6960's "revoked for non-issued certificates" convention (reason
     certificateHold, time 1970) is not used without the owner's decision.
5. **Short-lived certificates (ADR-0042)** get no responses. They name no
   OCSP URL, as RFC 9608 is understood (to verify).
6. **AIA in leaves.**
   - An owner-set responder URL per CA, snapshotted with each signing intent
     exactly like the CRL point (ADR-0019, migration 0032).
   - The leaf carries an authorityInfoAccess id-ad-ocsp entry.
   - The core, the signer and the audit tool check it as they check the CRL
     point.
   - Certificates issued before the URL existed carry none.
7. **Serving.**
   - The publisher writes one DER response per certificate, keyed by the
     CertID: issuer name hash, issuer key hash and serial.
   - It writes both SHA-1 and SHA-256 CertIDs: OpenSSL and many clients
     still send SHA-1 CertIDs; this is a lookup key, not a signature.
   - A small server answers GET (RFC 5019) and POST, with bounded request
     sizes, without a database. It never replaces a response with an older
     one (the anti-rollback of ADR-0030).
   - Caching headers follow `nextUpdate`.
8. **Evidence.**
   - Each batch journals the digest of its responses before signing.
   - The signer claims it once.
   - The audit tool re-verifies every stored response: signature by a
     responder certificate the CA issued, status equal to the CRL's, and
     equal times.
   - Metrics (ADR-0038) add the age of the latest batch and the count of
     certificates without a current response.

## Alternatives considered

- **Option A (CA key online):** rejected. It exposes the CA key's signing
  operation to unauthenticated traffic. ADR-0034 keeps the CA key in a token
  for signatures driven by journaled, authorized intents only.
- **Option B (online delegated responder):** kept as a possible later step
  if nonces or immediate freshness become requirements. It needs an online
  key, a database read path from the public edge and rate limiting.
- **No OCSP; CRLs plus short-lived certificates:** a valid outcome of
  decision 0. In that case this ADR is recorded as Rejected, and ROADMAP's
  criterion is reworded.

## Consequences and open risks

- **Freshness equals the CRL's.** OCSP adds per-certificate answers and
  smaller downloads, not faster revocation. Publication on revocation
  (ADR-0027) is the freshness lever for both.
- **Batch cost** grows with the number of unexpired certificates; one
  signature per certificate per batch. A large inventory needs incremental
  batches: re-sign only changed statuses, plus a full batch before
  `nextUpdate`. This must be measured before a pilot.
- **No nonce:** replay of a response within its validity is possible by
  design.
- **The responder key is a new key to custody:** it can be revoked only by
  letting it expire (nocheck), and backup covers its token (ADR-0041).
- **Time:** responses inherit the trusted-time assumptions of CRLs.

## Planned slices, once decision 0 is taken

1. The responder token and certificate:
   - ceremony;
   - issuance with EKU and nocheck;
   - renewal;
   - checks in the core and the signer.
2. The OCSP intent and the signer's batch signing from the CRL views, with
   entry proofs and journaling.
3. The publisher's response tree and the static OCSP server, with
   anti-rollback.
4. AIA in leaves (owner-set URL, intent snapshot, checks).
5. End-to-end tests, with OpenSSL as the independent client
   (`openssl ocsp -issuer … -cert … -url … -CAfile …`):
   - good, revoked and voided statuses;
   - unknown serials;
   - expired and stale responses;
   - a forged responder;
   - a status contradicting the CRL;
   - responder key rotation;
   - backup and restore.

## Decisions requested from the owner

1. Is OCSP in the MVP's scope (decision 0)?
2. Pre-signed (C) now, with online (B) only if needed later?
3. Is the no-nonce limitation acceptable?
4. For unknown serials: `unauthorized` or a signed `unknown`?
5. The responder certificate's validity (proposed: 30 days).
