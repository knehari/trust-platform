# ADR-0027 — Publish a CRL as soon as a revocation is recorded

**Status:** Proposed · 2026-11-10. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It
follows the owner's request of 2026-11-10 for this to be configurable.

**Scope:**
- migration 0040;
- the API's revocation, RA revocation and void routes;
- the CRL status route and the console;
- the laboratory end-to-end suite.

**Roadmap:** shortens the revocation delay for MVP criterion 8 (ADR-0018,
ADR-0021, ADR-0026). OCSP remains a separate decision.

## Context

A revocation is written to the core table at once (migration 0031), but
relying parties see it only on the next CRL. That CRL was published when:
- an officer published by hand;
- or the renewer found the CRL due by time, meaning none yet or nextUpdate
  within two days (ADR-0021).

A revocation could therefore wait up to the CRL's lifetime, seven days. RA
revocations (ADR-0026) have the same delay.

## Decision

1. **A per-CA setting**, set by the database owner: the table
   `ca_crl_policy (ca_id, publish_on_revocation)`. It is off by default,
   and a CA without a row behaves as before. Neither the API nor its writer
   login can change it.
2. **A wider "due" rule.** `crl_renewal_due` is still true when the CRL is
   due by time. It is now also true when the CA's setting is on and
   `crl_unpublished_entries` is positive. That function counts the
   revocations and confirmed voids (migration 0034) whose instant is after
   the latest published CRL intent's `entries_until`: exactly what that CRL
   could not list. The renewer's candidates, and its right to begin a
   publication (migration 0035), follow the same rule, so the renewer
   still publishes nothing else.
3. **Immediate request.** Right after it records:
   - a revocation (officer approval, or an RA-signed revocation);
   - or a void confirmation;

   the API starts a renewal pass in the background. The response does not
   wait for it. The pass publishes through the unchanged path (journaled
   intent, separate signer, independent verification), and only for CAs
   granted to the renewer. It does nothing without a writer login and a
   signer. A missed or failed pass is caught by the periodic pass of
   ADR-0021.
4. **Visibility.** `crl-status` and the reader view report
   `publish_on_revocation` and `unpublished_entries`. The console's
   Revocation & CRLs view shows:
   - whether revocations publish at once;
   - how many entries wait for the next CRL;
   - that the setting needs automatic renewal to take effect.

## Alternatives considered

- **Publish inside the revocation transaction.** Rejected: the signer is a
  separate process, and the revocation and CRL locks would be held across
  a network call. A failed signature would also roll back the revocation.
- **A global switch in the API configuration.** Rejected: the owner wanted
  this per CA. Some CAs may keep a fixed publication schedule.
- **Delta CRLs.** Not in scope: no delta CRL support yet (ADR-0018).

## Consequences and open risks

- **More CRLs.** Each revocation, or burst of revocations, produces a new
  CRL number. Concurrent passes serialize on the CA's CRL lock. A later
  pass finds nothing pending and is refused (`TP409`), which the renewer
  logs.
- **Best effort, not a guarantee.** If the signer is down, the revocation
  stays recorded and pending (`unpublished_entries` > 0, shown in the
  console). It is retried at the next pass. A failed signature leaves the
  intent `RECONCILIATION_REQUIRED`, as before.
- **Requires the renewer's grant** (ADR-0021). The console says so when the
  setting is on without it.

## Tests

- `tests/management_crl_on_revocation.sql`:
  - due by time without a CRL;
  - with the setting off, a revocation is pending but not due;
  - with it on, it is due, also for the renewer;
  - the renewer publishes, and the new CRL lists the entry;
  - once nothing is pending the renewer is refused again;
  - a second revocation makes the CRL due again, and turning the setting
    off stops that;
  - the reader view's columns and isolation;
  - the writer cannot change the setting.
- The existing CRL, renewal, revocation, void and isolation suites, on the
  0040 schema.
- The HTTP test with the real signer:
  - the status reports the setting off with nothing pending;
  - after the owner turns it on, an RA revocation publishes a new CRL with
    nobody asking;
  - that CRL verifies under the CA key and lists the serial.
- Certificate-application e2e: on the laboratory stack, the RA's
  revocation is published by itself. The suite fetches the CRL from the
  public distribution point, and `openssl verify -crl_check` reports the
  certificate revoked.
