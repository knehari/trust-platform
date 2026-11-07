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
- Cross-authority reads through the management API: the token's CA scope intersected with server-owned grants in every API query, and since migration 0021 the same restriction inside every management view for the principal the API declares; a session that declares none reads nothing. The database cannot authenticate the declared principal, so a compromised API process or a holder of the reader login can still read any granted principal's authorities ([ADR-0008](../adr/ADR-0008-database-reader-isolation.md), Proposed).
- Impersonation and token confusion at the management API (laboratory, [ADR-0009](../adr/ADR-0009-laboratory-identity-provider.md), Proposed): people sign in through a Keycloak realm with per-user passwords and lockout after repeated failures; the API accepts only RS256 `at+jwt` access tokens of the pinned issuer and audience that were issued to the console client (`azp`), so workload, ID and foreign-realm tokens are refused; roles grant only their own permission. Open: no multi-factor authentication, development-mode Keycloak, workload identity by shared secret, and anyone administering the realm can mint users, roles and CA scopes (database grants remain a second, owner-held layer).
- Unauthorized or forged profile changes (laboratory, [ADR-0010](../adr/ADR-0010-profile-draft-writes.md), Proposed): writes need the editor token role, the CA in scope and an owner-held role grant; they go through a login limited to two `SECURITY DEFINER` functions that recompute the revision digest, serialize per profile, refuse stale or already submitted revisions and record lifecycle and audit events atomically; idempotency keys make retries safe and refuse key reuse. Open: the database trusts the principal the API declares (a compromised API or writer login can act as any granted editor), denied attempts are not persisted as audit events, and no approval or activation exists yet.
- Forged or self-approved profile decisions (laboratory, [ADR-0011](../adr/ADR-0011-signed-profile-decisions.md), Proposed): two approvers with owner-held grants and distinct owner-registered P-256 keys must each sign the claim the database builds for the exact submission; the API verifies each signature before commit, the author and submitter cannot decide, and `lab_verify_profile_decisions` re-verifies every stored decision. Open: PostgreSQL does not verify ECDSA (a compromised API or writer login can record an unsigned decision until the audit tool runs), keys are software files without custody, registration proves no possession, and there is no MFA.

## Open
STRIDE workshop, risk scoring and independent security review before non-critical pilot.