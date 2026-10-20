# Threat model — v0.1

## Assets
CA private keys, issuance policy, authenticated identities, certificate/serial database, CRL, audit chain, signing authorization.

## Trust boundaries
User/API -> authenticated control plane -> policy engine -> CA signing service -> signing provider/HSM; persistence and publication are separate boundaries.

## Threats and controls
- Unauthorized issuance: requester binding, least privilege, policy approval, negative tests.
- CSR parser abuse: size limits, fuzzing, strict DER and X.509 validation.
- Key theft: HSM/PKCS#11 isolation, no key export by default, no secret logging.
- Serial duplication: unique issuer+serial constraint, durable reservation.
- Signature ambiguity: reconciliation and no blind retry.
- CRL manipulation/staleness: signed CRLs, controlled publication, freshness monitoring.
- Supply chain: pinned dependencies, SBOM, SCA, provenance, signed releases.
- Insider abuse: role separation, privileged action audit, two-person control where justified.

## Revocation and CRL write path (lab, migrations 0014-0024, ADR-0006, ADR-0007)

| Threat | Control in the lab slice | Residual risk / open |
| --- | --- | --- |
| A service login revokes, releases or suspends without maker-checker by writing tables directly | 0023: tables owned by NOLOGIN `trust_revocation_owner`; SECURITY DEFINER functions; capability roles have EXECUTE only (tests/revocation_privileges.sql) | Superusers, the owner role and anyone able to `SET ROLE` to it bypass; deployment must keep service logins out of those |
| One actor plays maker and checker by asserting two identities | Database refuses equal `(issuer, subject)`; officer grants are server-owned | Identities are asserted by the calling service: textual, not key-distinct (ADR-0007 not implemented; known deviation from AGENTS.md) |
| Fake coverage: rows added to a CRL snapshot or a `STORED` row inserted without signing | No INSERT for services (0023); snapshot and publication guards; store checks digests | Owner/superuser can still insert |
| CRL signed by another CA's key or stored under the wrong CA | 0022 registered issuer certificate per CA; `crl_once` checks the verifier issuer and the signer's SPKI before the intent | Key rollover not modelled; registration needs two CA admins (0024) but their identities are textual; DBA bootstrap outside dual control |
| Shadowing through `search_path` or temporary objects | Service functions pin `search_path = pg_catalog, public, pg_temp` (planted temp table test) | Independent review of every SECURITY DEFINER body (dynamic SQL, error leakage) still required |
| A service runs with a superuser or owner-member login and bypasses everything | `connect_lab_service` refuses privileged `session_user` (0024 commit) | Only enforced by the services that use it; deployment evidence required (ADR-0006 acceptance condition 2) |
| One CA admin registers an issuer or grants officers alone, or grants themselves officer rights | 0024 `ca_admin_change`: two distinct admins, approval of the exact content digest, no self-grant | Textual admin identities (ADR-0007) |
| Stale or superseded CRL signed late | Only the highest reserved number may record an intent; staleness and nextUpdate checks (0017, 0020, 0021) | Relies on the database clock |
| Lost or ambiguous signature | Durable intent before signing, quarantine, reconciliation of a held DER (0021), housekeeping alerts | A CRL lost with its process cannot be recovered (no signer read-back) |

## Open
STRIDE workshop, risk scoring and independent security review before non-critical pilot.