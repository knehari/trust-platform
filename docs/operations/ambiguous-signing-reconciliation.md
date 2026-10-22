# Operator runbook — ambiguous CA signing outcome

**Status:** proposed operational control, not a validated or deployed production procedure. For laboratory review only.

## Trigger
A signing attempt has a durable `signing_intent` but no verified, committed certificate result. Possible causes: worker SIGKILL, HSM/network timeout, database outage, crash after receiving the signed response, or failover.

## Safety invariant
**Do not re-sign, rebuild the TBS, reuse the reserved serial for a different TBS, or publish a certificate until the result has been independently reconciled.** A database `UNCONFIRMED` outcome means *unknown*, not *not signed*.

## Controlled steps

1. **Quarantine:** run the issuer-scoped recovery scanner after an approved grace interval using a separately authenticated recovery identity (not implemented in the lab). Confirm `RECONCILIATION_REQUIRED` and check the unique transition audit event.
2. **Preserve provenance:** record `ca_id`, `request_id`, `intent_id`, `operation_ref`, signing key reference, certificate serial reservation, TBS SHA-256, policy revision, timestamps and impacted service.
3. **Investigate signing provider:** if supported, request a read-only query by `operation_ref` from HSM/audited signer journal, including provider evidence of whether it accepted/completed the operation. Provider-specific APIs and independent evidence are not implemented.
4. **Locate verified result:** if an actual signed certificate is available, validate DER signature against issuer SPKI, exact original TBS fingerprint, reserved serial, authorized SANs, certificatePolicy OID, validity and required profile, with a separately reviewed verifier. If not available, outcome remains unknown.
5. **Segregation of duties:** an authorized PKI operator collects evidence, a second reviewer approves the proposed disposition, and the Security Officer / policy authority is engaged as required by the incident's scope. Neither role should be able to mutate signed logs or key material.
6. **Evidence:** store the provider report, verified certificate or absence-of-evidence finding in a controlled repository; record only a reference/hash in the lab DB. Independently anchor audit logs when implemented.
7. **Disposition:** only a future separately approved reconciliation state machine may commit a verified, previously signed certificate (without calling the signer again). Otherwise leave the request quarantined pending an incident decision. Never interpret missing evidence as proof that signing did not happen.
8. **Post-incident:** correlate a single incident ticket to the issuer/request, quantify affected certificates and relying parties, assess publication/revocation implications, and document root cause and corrective actions.

## Evidence rubric

| Outcome | Evidence | Allowed automated action |
|---|---|---|
| Signature definitely completed | Verified provider record + exact signed certificate matching recorded TBS | **None in v0.8**; future dual-approved reconciliation workflow |
| Signature may have completed | Timeout, ambiguous provider result, lost worker output | Keep quarantined; collect evidence |
| No provider evidence found | Absence of a log entry or timed-out query | Keep quarantined; never re-sign automatically |
| Confirmed never executed | Independent authoritative provider proof, signed and reviewed | Future separately designed corrective process; **no automatic retry in v0.8** |

## Limitations
v0.8 captures scanner output and append-only database observation references. It does not implement a real HSM operation journal, external WORM audit, qualified QTSP operator controls, access enforcement, time synchronization, two-person approval or automated certificate recovery. The example CA key is ephemeral and disappears after SIGKILL.

## Links
- [PR #8 — implementation and tests](https://github.com/knehari/trust-platform/pull/8)
- [Crash recovery architecture](../architecture/v0-8-crash-recovery.md)
- [Jira TRUST-83](https://knehari.atlassian.net/browse/TRUST-83)
