# Audit readiness architecture — initial control/evidence model

Status: design only. No certification or qualified status is claimed.

## Evidence event schema (proposed)

- `event_id` UUID, CA/request/certificate correlation IDs, actor identity and authentication context.
- `occurred_at`, trusted clock provenance, monotonic local event sequence and source node.
- `event_type`, input/reference digests, decision result, policy/profile revision and signing key reference.
- `prev_event_hash`, `event_hash`, retained evidence object URI + SHA-256, export classification.
- `control_ids` qualified by **standard edition and applicability**.
- Integrity checkpoints published to independently governed WORM/external store, access logged.

Do not log key contents, secret material, CSR private information beyond authorized needs or unredacted personal data.

## Evidence class

- TECHNICAL: automatically observed config, signature providers, operations, tests, logs.
- PROCEDURAL: approved ceremonies, training, physical-security attestations (humans responsible).
- COMPLIANCE: scope, standard edition, qualified external assessment, authority decision, authorized owner attestation.
- GAP: missing, expired, contradictory or unverified evidence.

Never promote unverified facts to verified; evidence age and approved retention must be reflected in reports.

## Minimum acceptance gates

- Control-to-evidence provenance and edition pinning.
- Unauthorized claim/approval/publication denied.
- Gap preserved on changes until reviewed.
- Redacted audit export verifies content hashes offline.
- Role separation demonstrated with negative tests.
- Historized policy OID, certificate issuance and CP/CPS effective revisions.

## Non-goals at early alpha

Automatic QTSP qualification, copying licensed standard text, real-time ANSSI endorsement, SAAS-only audit service, evidence that cannot be verified independently.
