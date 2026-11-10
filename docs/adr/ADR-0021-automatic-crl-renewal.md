# ADR-0021 — Automatic CRL renewal in the laboratory

**Status:** Proposed · 2026-11-09. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0035;
- the API's renewal task;
- the CRL status route and the console;
- the laboratory Compose stack.

**Roadmap:** ADR-0027 extends the due rule, per CA, to pending revocations.
Closes the "scheduled renewal" gap of MVP criterion 8
(ADR-0018, ADR-0019). The criterion stays unchecked: there is no OCSP, and
there is no production custody or publication service.

## Context

A CRL is valid for seven days (ADR-0018). Until now only a registration
officer renewed it, by publishing. When nobody published in time, the CRL
expired and relying parties could reject every certificate of the CA. The
console warned two days ahead (ADR-0019), but nothing acted.

## Decision

1. **A per-CA `crl-publisher` role.** The database owner grants it to a
   system principal: issuer `urn:trust-platform:system`, subject
   `crl-renewer`. The role may run the five CRL publication functions of
   migration 0031, and nothing else: no revocation, no decision, no
   issuance, no read route.
2. **Only a due CRL.** For that role, `begin_crl_publication_lab` refuses
   (TP409) unless the CRL is due: none was published yet, or the latest
   published one reaches nextUpdate within two days. This is the same rule
   as `management_crl_status`. Registration officers keep publishing at any
   time.
3. **The renewal task.** It runs inside the API, with the writer login and
   the signer socket, when `TRUST_CRL_RENEWAL_INTERVAL_SECONDS` is set
   (30 to 86400). The task:
   - makes its first pass five seconds after startup, then one per
     interval;
   - asks `crl_renewal_candidates_lab` for the CAs granted to the renewer
     that still publish (ACTIVE or SUSPENDED) and are due;
   - publishes each through the unchanged path: journaled intent,
     separate signer, independent verification, never a resend.

   An ambiguous outcome is logged. The next pass takes a new CRL number.
   Each pass writes `crl_auto_renewal` log lines (CA and outcome, never a
   secret). The audit trail attributes the CRL to `crl-renewer`.
4. **Visibility.** `GET /v1/cas/{ca_id}/crl-status` adds `auto_renewal`.
   The console shows whether renewal is automatic, and the dashboard does
   not ask officers to renew a CRL the renewer will handle. It still raises
   an expired CRL.
5. **Laboratory.**
   - Compose sets an hourly pass, and the issuing CA's provisioning grants
     the renewer.
   - Two days of margin and hourly passes leave about 47 attempts before
     expiry.

## Alternatives considered

- **A separate renewer process with a client-credentials token.** The API
  refuses tokens not issued to the console client (ADR-0009). Workload
  identity by shared secret is a known laboratory weakness. A system
  principal inside the API reuses the writer login and the signer socket
  the API already holds, and its database grant stays narrower than an
  officer's.
- **Renew from the signer.** The signer only signs what the database
  journaled. Giving it a scheduling role would widen the one process that
  reads the CA key.
- **A cron job calling the officer route.** That would need an officer's
  credentials stored on a host.

## Consequences and open risks

- The renewer acts without a human. Its only power is to publish a due
  CRL, which lists exactly the recorded revocations and voids.
- Several API replicas would each run passes. They serialize on the CA's
  CRL lock: the second finds the CRL no longer due and is refused. No
  coordination exists beyond that.
- A long signer outage still lets a CRL expire. The status route and the
  console report it. There is no alert channel other than logs.
- The two-day window and the seven-day validity are fixed in SQL.

## Tests

- `tests/management_crl_renewal.sql`:
  - a candidate only when granted and due;
  - an ungranted principal is refused;
  - the renewer cannot issue;
  - it publishes a due CRL, then is refused once the CRL is fresh, while an
    officer still may;
  - readers see `auto_renewal`;
  - the audit trail attributes the CRL to the renewer.
- Database-backed HTTP test: with the real signer, a pass without the grant
  does nothing. With the grant it publishes CRL 1, which verifies under the
  CA key. A second pass does nothing.
