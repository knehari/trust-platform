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

## Open
STRIDE workshop, risk scoring and independent security review before non-critical pilot.