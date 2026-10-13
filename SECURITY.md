# Security policy

## Reporting a vulnerability
Please **do not open a public issue** for security problems.

Use GitHub private vulnerability reporting: *Security* tab → *Report a
vulnerability* on this repository. Include affected component/commit, impact,
and reproduction steps. Do not include real private keys or customer data.

We aim to acknowledge reports within 5 business days and to agree on a
disclosure timeline with the reporter (default: 90 days).

## Scope
In scope: CA core, crypto provider adapters, persistence, CI/release pipeline,
documentation that defines security behaviour.

## Status
The platform is **pre-implementation / lab only** (see
`docs/testing/acceptance-gates.md`). No production-readiness, certification or
audit claim is made before gate G4.

## Handling secrets
- No private keys, passwords, tokens, HSM PINs or customer data in the
  repository, issues, PRs or logs.
- Secret scanning (gitleaks) runs in pre-commit and CI. If a secret is committed,
  treat it as compromised: revoke/rotate first, then clean history.
