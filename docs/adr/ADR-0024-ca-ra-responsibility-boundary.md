# ADR-0024 — The CA signs; the RA and the CLM verify subscribers

**Status:** Proposed · 2026-11-09. It records the owner's direction of
2026-11-09. Formal acceptance remains the owner's decision (AGENTS.md); this
ADR does not accept itself.

**Scope:** documentation of the responsibility boundary. No code, schema or
route changes in this ADR.

**Roadmap:**
- domain-control validation is removed from the CA's open items for MVP
  criterion 7 ("Application issuance");
- it is assigned to a lightweight RA or to the CLM (ACME, later);
- the CA's next interface work is an authenticated RA/CLM issuance channel
  (see "Consequences").

## Context

ADR-0016 and ADR-0017 listed "domain control is not validated" as a gap of
the laboratory CA. A DNS-01 challenge was considered for the CA. It would
have required:
- a resolver dependency;
- a laboratory DNS service;
- outbound network access.

The owner's direction (2026-11-09), in substance:

> Identity checks, and so domain checks for server certificates, are done
> by the RA, and by the CLM once ACME is implemented, not by the CA and
> the PKI. The PKI is there above all to sign certificate requests and
> CRLs. Everything that faces end users will be handled by a light RA or
> by the CLM.

## Decision

1. **The CA and the PKI core** do the following:
   - verify and **sign certificate requests** that an authorized RA or CLM
     submits;
   - **sign CRLs** (later, possibly OCSP responses);
   - keep the durable state, the audit evidence, and the CA and profile
     lifecycle.

   They do not face subscribers. They perform no identity proofing, no
   domain-control validation and no subscriber communication.
2. **A lightweight RA, or the CLM, owns every end-user interaction.** That
   covers:
   - identity proofing and authorization of the subscriber;
   - domain-control validation for server certificates (ACME HTTP-01 or
     DNS-01 at the CLM, or an RA procedure);
   - request intake;
   - notifications;
   - renewal and revocation requests from subscribers.

   The CA trusts the RA's registration decision as an authorization. It
   does not repeat the RA's checks.
3. **The CA still enforces its own technical policy on every request, even
   from a trusted RA.** An RA can only obtain what the CA's active profile
   allows:
   - the DNS names stay within the profile's zones, which act as the CA's
     own name constraint;
   - key type and algorithm, maximum validity and number of names;
   - fixed extensions (no CA certificate, no `basicConstraints` elevation,
     no extension copied from the CSR);
   - a verified CSR signature (proof of possession);
   - an ACTIVE CA and an active profile revision;
   - issuer-scoped unique serials, and one signature per journaled intent;
   - independent verification before storage.
4. **Every registration decision is attributable to an authenticated RA
   actor**, a person or a system. The CA records which RA authorized each
   issuance and revocation, so that the RA's checks can be audited on the
   RA side.

## Consequences

**For the laboratory as it is:**
- **The certificate applications of ADR-0016** (requester, registration
  officer, console) are reclassified as the laboratory's stand-in for a
  light RA. They stay as they are, and they do not make the CA an RA.
- **The "no domain-control validation" limits** in ADR-0016 and ADR-0017
  are no longer CA gaps. They are RA or CLM responsibilities.
- **The threat model** places identity and domain assurance on the RA/CLM
  side of the trust boundary. A compromised or careless RA can obtain
  certificates for any name within the profile's zones. The zones, the
  per-CA RA grants and the audit trail bound that risk; they do not remove
  it.

**The CA's next interface work** is an authenticated RA/CLM channel: a
registered RA system submits a CSR, with the names it validated and a
profile, and receives the signed certificate or a refusal. The same channel
carries revocation requests. That work needs its own ADR, including:
- **machine authentication for an RA system.** Today the API refuses
  workload tokens (ADR-0009). The candidates are mTLS or
  `private_key_jwt`, not a shared secret;
- **authorization per RA, per CA and per profile;**
- **idempotency and replay protection;**
- **whether RA decisions are signed claims** (as for profile and CA
  decisions, ADR-0011 and ADR-0014) or authenticated calls.

## Alternatives considered

- **Domain-control validation in the CA** (DNS-01 with a resolver and a
  laboratory DNS service). Rejected by the owner's direction. It would
  also add outbound network access, and an SSRF surface, to the CA side.
- **No CA-side name policy, trusting the RA entirely.** Rejected: the
  profile zones are the CA's last line against a compromised RA.

## What this does not establish

- No RA, CLM or ACME component exists; the laboratory requester and officer
  flow is a stand-in.
- No machine authentication for RA systems exists yet.
- Nothing here is a CP/CPS statement; the RA's obligations still need to be
  written in the policy documents once they exist.
