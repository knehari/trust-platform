# Trust Platform — Repository instructions for Codex

## Purpose and state
- Treat this repository as a **lab-only private PKI prototype**, not a shipped CA. Draft PRs and CI success do not imply production readiness.
- Read `docs/recovery/TECHNICAL_AUDIT.md` in [audit PR #42](https://github.com/knehari/trust-platform/pull/42), `ROADMAP.md`, the security requirements, and relevant ADRs before changing behavior.
- Respect the existing Rust CA core, PostgreSQL migrations, historical tests and feature flags; do **not** replace the Rust core with Go as an unreviewed architectural change.

## Branch and PR discipline
- Never push directly to `main`, force-push historical branches, merge stacked PRs, or close historical PRs without explicit human authorization.
- Create small, reviewable feature branches and Draft PRs, with a PR base reflecting the correct parent in the stack.
- Do not self-approve G0 legal/IP clearance, security review, production readiness, CA qualification, HSM evidence or release gates.
- Explain each deviation from historical behavior, missing test or migration; compare against the frozen PR heads in the Codex audit.

## PKI/crypto security
- No home-grown cryptographic primitives. No private CA keys, credentials or production data in source, database or logs.
- Lab software signing must remain isolated from production build and deployment.
- Fail closed on authentication, authorization, profile/algorithm/provider mismatch, invalid CSR/DER or uncertain signer state.
- No silent signature algorithm downgrade or inference of capabilities from an enum, OID or documentation.
- Separate issuer signing key and certificate subject key. Keep CSRs untrusted; validate actual proof-of-possession.
- Preserve issuer-scoped serial uniqueness, idempotency, signing intent before signing, independent X.509 verification before persistence and quarantined ambiguous outcomes.
- Double-control must enforce **cryptographically distinct signer keys** as well as separately authenticated actors, not different textual key IDs alone.

## Evidence and test requirements
- Record tested commit SHA, toolchain, `cargo fmt`, `cargo clippy`, workspace tests, enabled features, OpenSSL interoperability and PostgreSQL integration results.
- Detect/declare skips when `TRUST_CI_DATABASE_URL` is missing; unit tests alone cannot prove DB integration.
- For security fixes, include a failing regression test on the old behavior and evidence of passing on the fix.
- Never report an operation as completed solely because the change was written. Report actual tool results and unresolved risks.
- Do not assert a version is `Released` from a draft PR. Document supported lab algorithms per provider and X.509 profile.

## Planned application boundaries
- Rust CA core remains the policy-enforcing authority for issuance and revocation.
- A future control plane (Go or Rust, pending ADR) and React console may not bypass CA policy.
- API contracts, authentication, PostgreSQL roles/TLS, key custody and audit architecture must be threat-modelled before exposure.
