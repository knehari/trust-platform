# Unintegrated domain contracts in `trust-pki-core`

Status: inventory, 18 October 2026. Branches `feature/v2-5-*` to `feature/v4-0-*`
(Draft PRs #25–#40) added the modules below. Each is a pure predicate of 27–56
lines with unit tests. **No other module, binary, migration or test calls any of
them.** (`revocation_policy` was integrated by the lab revocation/CRL slice, migrations
0014–0015, and is no longer listed; its historical `authorize_revocation` stays, deprecated and unused, for the recovery inventory. 15 contracts remain.) Their names describe a future capability, not one that exists.

| Module | What it actually checks | What its name might suggest but does not exist |
| --- | --- | --- |
| `audit_integrity` | non-zero digest plus `externally_anchored` / `signature_verified` booleans | verified audit chain or external anchoring |
| `audit_retention` | a retention decision on caller inputs | a retention worker or WORM storage |
| `certificate_profile` | validity 1–398 days, at least one DNS SAN, not a CA (caller-supplied numbers) | enforced issuance profiles |
| `crypto_migration` | presence of an approved target | algorithm migration tooling |
| `identity_boundary` | caller-supplied claims | an identity provider adapter |
| `key_attestation` | caller-supplied attestation flags | HSM key attestation verification |
| `key_ceremony` | quorum 2–16 and distinct, non-empty witness names (strings, not identities) | ceremony workflow, dual control or evidence |
| `platform_readiness` | booleans (not evidence) | a platform readiness assessment |
| `pqc_rollout` | caller-supplied rollout flags | any post-quantum signer (none is implemented) |
| `production_gates` | booleans for identity/HSM/etc. | production enablement |
| `recovery_budget` | an attempt counter | recovery orchestration |
| `release_gate` | composed booleans | a release or legal/security approval |
| `request_rate` | `used < limit` for given numbers | rate limiting (no counter, no storage) |
| `resilience_policy` | a decision table | resilience or HA mechanisms |
| `tenant_isolation` | equality of caller-supplied tenant IDs | tenant isolation in storage or APIs |

## Rules until each is integrated

1. Do not cite these modules, or the `v2.5`–`v4.0` branch names, as evidence of
   a capability in roadmaps, PR descriptions, sales or assessment material.
2. Integrate a contract only together with the runtime component that supplies
   **authenticated** inputs (for example a real rate counter for
   `request_rate`), with an end-to-end test through that component.
3. A contract still unused when its runtime component is designed should be
   rewritten from that design or deleted, not carried forward by default.
