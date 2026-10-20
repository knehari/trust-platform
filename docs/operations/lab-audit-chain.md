# Laboratory audit chain and external anchoring

Lab only (migration 0027, ADR-0006 section F, proposed). It addresses open
item D-04 in part: a database administrator can still alter the database,
but no longer unnoticed once the chain is anchored outside it.

## What is sealed

`seal_audit_chain(limit)` appends every `audit_event` and
`schema_change_audit` row not yet sealed to `audit_chain_entry`:

- `event_sha256` is the SHA-256 of the row's canonical encoding: the tag
  `trust-platform:audit-record:v1\0`, the source name, then each column as
  `0x00` (NULL) or `0x01` + 4-byte big-endian length + bytes. UUIDs are
  16 bytes, text is UTF-8, and timestamps and integers are 8-byte big-endian,
  timestamps in microseconds since the Unix epoch.
- `entry_hash = SHA-256("trust-platform:audit-chain:v1\0" || previous || seq || event_sha256)`
  (`audit_chain::next_audit_hash`); the first `previous` is 32 zero bytes.

Sealing is a scheduled job, not a trigger, so issuance and revocation
transactions never wait on the chain head. Records are only protected once
sealed and anchored.

## Jobs

```
# every few minutes, login granted trust_audit_sealer only
TRUST_DATABASE_URL=postgresql://... \
  cargo run -p trust-pki-core --features postgres-store --example audit_chain_anchor -- seal

# after sealing, on another host, login granted trust_audit_verifier only
TRUST_DATABASE_URL=postgresql://... \
  cargo run -p trust-pki-core --features postgres-store --example audit_chain_anchor -- \
  verify /var/lib/trust-audit/checkpoints [--unsealed-older-than 3600]
```

`verify` loads the whole chain, re-encodes every record in Rust, checks the
links and every checkpoint already in the file, then appends the new head
(`audit-chain-checkpoint v1 <seq> <hex>`) and syncs the file. It never
appends after a failure.

Exit status:
- 0: verified;
- 2: records older than the threshold are not sealed yet;
- 3: the chain does not verify. The output names the first bad entry:
  `RecordAltered`, `SourceMissing`, `EntryHash`, `Chain`,
  `CheckpointMismatch` (rewritten history) or `Truncated`. Treat it as an
  incident and do not "repair" the anchor;
- 1: error, including an unreadable or damaged checkpoint file (fail closed).

## Keeping the anchor out of reach

The checkpoint file is the anchor. It must be out of reach of the database
administrators:
- keep it on another system, with append-only or WORM storage;
- copy the last line out of band, for example into a ticket, a signed email
  or an RFC 3161 timestamp request.

The lab does not sign or timestamp checkpoints; that, and an authenticated
time source, remain open (D-04, ADR-0006 conditions 5 and 6).

## Limits

- Entries sealed after the last checkpoint, and records not yet sealed, can
  be rewritten unnoticed.
- A forged record inserted before sealing is sealed like any other; the
  chain proves integrity after sealing, not the origin of a record.
- Verification reads the whole chain each time (lab scale).

Covered by `tests/audit_chain.sql`, `crates/pki-core/tests/audit_chain_postgres.rs`
(superuser rewrite, deletion, recomputed chain, truncation) and
`tests/audit_chain_anchor.sh` (the jobs end to end, committed tampering).
