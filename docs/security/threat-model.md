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

## Revocation and CRL write path (lab, migrations 0014-0031, ADR-0006, ADR-0007)

| Threat | Control in the lab slice | Residual risk / open |
| --- | --- | --- |
| A service login revokes, releases or suspends without maker-checker by writing tables directly | 0023: tables owned by NOLOGIN `trust_revocation_owner`; SECURITY DEFINER functions; capability roles have EXECUTE only (tests/revocation_privileges.sql) | Superusers, the owner role and anyone able to `SET ROLE` to it bypass; deployment must keep service logins out of those |
| One actor plays maker and checker by asserting two identities | Database refuses equal `(issuer, subject)`; officer grants are server-owned | Identities are asserted by the calling service: textual, not key-distinct (known deviation from AGENTS.md). ADR-0007 steps 1-2 (0028-0029): enrolled P-256 keys and persons under CA-admin dual control; per CA, `signed_approvals_required` makes maker and checker sign the canonical claim with WebAuthn (UP+UV, origin, counter, single-use challenge), with distinct keys and persons. Open: the database cannot verify ECDSA, so a holder of the officer API role could store a forged assertion (exposed by `reverify_signed_change`); CA-admin actions are still textual; IAM person ids are asserted |
| Fake coverage: rows added to a CRL snapshot or a `STORED` row inserted without signing | No INSERT for services (0023); snapshot and publication guards; store checks digests | Owner/superuser can still insert |
| CRL signed by another CA's key or stored under the wrong CA | 0022 registered issuer certificate per CA; `crl_once` checks the verifier issuer and the signer's SPKI before the intent | Key rollover not modelled; registration needs two CA admins (0024) but their identities are textual; DBA bootstrap outside dual control |
| Shadowing through `search_path` or temporary objects | Service functions pin `search_path = pg_catalog, public, pg_temp` (planted temp table test) | Independent review of every SECURITY DEFINER body (dynamic SQL, error leakage) still required |
| A service runs with a superuser or owner-member login and bypasses everything | `connect_lab_service` refuses privileged `session_user` (0024 commit) | Only enforced by the services that use it; deployment evidence required (ADR-0006 acceptance condition 2) |
| One CA admin registers an issuer or grants officers alone, or grants themselves officer rights | 0024 `ca_admin_change`: two distinct admins, approval of the exact content digest, no self-grant | Textual admin identities (ADR-0007) |
| Stale or superseded CRL signed late | Only the highest reserved number may record an intent; staleness and nextUpdate checks (0017, 0020, 0021) | Relies on the database clock |
| A function, grant or guard is changed outside a reviewed migration (e.g. `SECURITY DEFINER` reset, trigger disabled) | Catalog invariant in tests/revocation_privileges.sql (0025); 0026 event triggers record every DDL and object grant (append-only, `ENABLE ALWAYS`, no SQL text) and `crl_housekeeping` alerts on changes no reviewed migration acknowledged | Roles, role membership, `ALTER SYSTEM` and event triggers themselves are not recorded (server logging/pgaudit needed); a superuser can drop the triggers or the rows (external anchoring, ADR-0006 condition 5) |
| A superuser rewrites, deletes or truncates the audit trail, or recomputes it consistently | 0027 sealed hash chain over `audit_event` and `schema_change_audit`; Rust re-encodes every record and checks heads against checkpoints exported outside the database (`audit_chain_anchor`, exit 3) | Unsealed records and entries after the last checkpoint; checkpoints not signed or timestamped; forged records inserted before sealing are sealed too |
| A CRL altered or substituted in the database is published to relying parties; the public endpoint becomes a write path | 0030: `trust_crl_publisher` can only read the latest stored CRL; the distribution point refuses privileged logins and re-verifies signature, issuer, number and times before serving (503 otherwise) | No TLS or availability engineering; a stale CRL is still served (uncached); denial of service by withholding new CRLs is not detected here (housekeeping `crl_due`) |
| A revoked certificate silently disappears from CRLs through pruning | 0031: pruning is opt-in, refused for ETSI EN 319 411-2, only after a stored CRL issued past `not_after` listed the entry; `not_after` comes from the verified certificate at issuance and is immutable; NULL is never pruned | Whoever can call the 8-argument `store_signed_certificate` (the issuance path, not yet least-privilege) could record an early `not_after`; no independent re-check of `not_after` against the stored DER when a CRL is planned |
| Lost or ambiguous signature | Durable intent before signing, quarantine, reconciliation of a held DER (0021), housekeeping alerts | A CRL lost with its process cannot be recovered (no signer read-back) |

## Open
STRIDE workshop, risk scoring and independent security review before non-critical pilot.