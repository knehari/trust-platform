# Contributing

- No employer-confidential information, proprietary code or internal infrastructure data.
- Use feature branches and pull requests. Changes to areas listed in `.github/CODEOWNERS` require code-owner review.
- Link the Jira TRUST issue, affected ADR/requirement and tests in every PR; update `docs/security/traceability.md` when a requirement, threat or test changes.
- Prefer small changes, reproducible tests, dependency locking (`Cargo.lock` is committed) and documented threat impact.
- New dependencies must pass `cargo deny check`; cryptographic implementations are chosen by ADR only.
- Every parser of untrusted input gets a fuzz target under `fuzz/`.
- `unsafe` is forbidden in core crates.
- No private keys, passwords, tokens, HSM PINs or production customer data in commits (gitleaks runs in pre-commit and CI). Test vectors in `testdata/` are public material only.
- No claim of audit/certification without independent evidence.

Recommended repository settings (to be applied by an owner): branch protection on `main` (required PR review, required status checks `secrets`, `rust`, `deny`, `fuzz`, code-owner review, no force push), private vulnerability reporting enabled, Dependabot alerts enabled, signed commits.
