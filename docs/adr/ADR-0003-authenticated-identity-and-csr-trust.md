# ADR-0003 — Separate authenticated identity from untrusted CSR data

**Status:** Proposed · 2026-10-11
**Related:** TRUST-11, TRUST-17, TRUST-27

## Decision

The control plane authenticates clients independently from the CSR. CA Core receives an explicitly authenticated subject and the untrusted request as separate inputs. The X.509 subject and SAN are never trusted as evidence of requester's identity. The policy engine authorizes actor, profile, names, algorithm and lifetime, returning immutable authorization data tied to a policy version.

## Threats mitigated

- Subject/SAN impersonation by rewriting a CSR.
- Authorization bypass when user-supplied identity is accepted.
- Domain-suffix confusion (e.g. attacker-lab.invalid vs lab.invalid).
- Unreviewed ML-DSA enablement or algorithm downgrade.

## Remaining work

AuthenticatedPrincipal in Sprint 0 is an API contract, not proof that a trusted auth layer exists. The management API selected in [ADR-0005](ADR-0005-rust-management-control-plane.md) must instantiate principals **only after** authenticating the request; the CA service must enforce that trust boundary. CSR signature and proof-of-possession support is path-specific and must be demonstrated for each enabled suite/profile, not inferred from this contract.

## Verification

Negative tests for missing actor, disallowed DNS, SAN/CN mismatch, wildcard names, unapproved algorithms and invalid validity.
