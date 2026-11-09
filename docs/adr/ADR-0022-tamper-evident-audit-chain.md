# ADR-0022 — Tamper-evident audit chain in the laboratory

**Status:** Proposed · 2026-11-09. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0036;
- the API's sealing task;
- the independent tool `lab_verify_audit_chain`;
- the audit routes and the console's audit detail;
- the laboratory Compose stack.

**Roadmap:** first slice of MVP criterion 10, "Durable audit evidence". The
criterion stays unchecked:
- the chain head is not signed;
- the actor is recorded as text, not as an authenticated claim;
- the manifest is not stored outside the platform automatically;
- there is no governed retention.

## Context

`audit_event` (migration 0001) is protected only by a trigger that forbids
UPDATE and DELETE. The database owner, a superuser or whoever restores a
backup can:
- disable that trigger;
- truncate the table, which the trigger never covered;
- or edit a dump.

Nothing would show it. `trust_pki_core::audit_chain` already defined a
SHA-256 chain construction, but nothing persisted or checked it.

## Decision

1. **Canonical event encoding (version 1).** Every column of `audit_event`,
   in table order, is encoded:
   - texts are length-prefixed (32-bit big-endian) UTF-8;
   - optional values carry a presence byte;
   - the instant is microseconds since the Unix epoch, as a big-endian
     64-bit integer;
   - the whole encoding is prefixed with `trust-platform:audit-event:v1\0`.

   The SQL function `audit_event_canonical` and the Rust function
   `audit_event_canonical` produce the same bytes. Shared test vectors, one
   with absent values and an instant before 1970, are asserted on both
   sides.
2. **The chain.** Each link is computed as
   `chain_hash = SHA-256("trust-platform:audit-chain:v1\0" ‖ previous chain_hash ‖ seq (int8 BE) ‖ SHA-256(canonical event))`.
   - The first link (sequence 1) uses an all-zero previous hash.
   - Sequences have no gap.
   - This is `next_audit_hash` of `pki-core`.
   - Links live in the append-only table `audit_chain_link`, one per event.
     Triggers refuse UPDATE, DELETE and TRUNCATE on it, and now refuse
     TRUNCATE on `audit_event` too.
3. **Sealing after commit, not in the writing transaction.**
   `seal_audit_events_lab(max)` seals committed events not yet sealed,
   oldest first (`recorded_at`, then `event_id`):
   - it is SECURITY DEFINER and executable by the writer login only;
   - a table lock serializes concurrent sealers, not readers.

   The API runs it every `TRUST_AUDIT_SEAL_INTERVAL_SECONDS` (5–86400; the
   laboratory Compose file sets 60), in bounded batches. Each pass is
   logged with the new head.

   The transactions that write events hold CA, CRL and application locks.
   A global head lock taken inside them could deadlock with them and
   serialize every write path. Sealing in a separate pass changes none of
   those paths.
4. **Independent verification.** `lab_verify_audit_chain` reads the raw
   columns in one read-only snapshot. It recomputes every event digest and
   link in Rust, without calling the database's functions, and reports:
   - a gap in the sequence;
   - a link that does not name its predecessor;
   - a sealed event that changed or disappeared;
   - a hash that does not recompute.

   It prints a JSON manifest: head sequence and hash, unsealed count, and
   the encoding and chain versions.
5. **The head kept outside the database is what makes the chain evidence.**
   Whoever can rewrite `audit_event` can rebuild the chain. The tool
   therefore takes back an exported head with
   `TRUST_AUDIT_EXPECTED_HEAD=<seq>:<hash>`. It fails unless the link at
   that sequence still carries that hash. That proves nothing sealed up to
   that point was altered, removed or reordered since.
   `TRUST_AUDIT_REQUIRE_SEALED=1` also fails while any event is unsealed;
   CI uses it.
6. **Readers see only a flag.** A separate reader view,
   `management_audit_seal`, lists the sealed event UUIDs of the granted
   authorities. It uses the same per-principal filter as migration 0021,
   and the isolation gate checks it.
   - The audit routes return `chain_sealed` per event. They look up only
     the events of the page they return, by UUID, through the link index.
   - Readers never see the global sequence or hashes, which would reveal
     the activity of other authorities.
   - The console's audit detail shows "Sealed" or "Not yet sealed", and
     says that only the tool against an exported head proves integrity.

   A column on `management_audit` was measured first and rejected. On the
   history load fixture (81,000 sealed events), PostgreSQL hashed every
   link for each page: the first audit page went from about 70 ms to
   105 ms, and the cost grows with the whole chain. The separate lookup
   costs about 0.4 ms for 101 events, and the history plans are
   unchanged.

## Alternatives considered

- **A trigger that chains each event on insert.** Rejected: it adds a global
  lock to every writing transaction, after CA, CRL and application locks
  already taken. That risks deadlocks and serializes all writes.
- **Hash only, without a chain.** A deleted event would leave no trace.
- **Sign the head now.** Deferred: it needs a key with its own custody. The
  laboratory has no HSM (ADR-0017). An unsigned head exported to separate
  storage already detects rewriting by the database owner.
- **An external append-only store (WORM, transparency log).** Deferred to a
  later slice; the manifest is the format to send there.

## Consequences and open risks

- **Unsealed window.** An event is protected only once sealed: up to one
  interval, plus the time for its transaction to commit. Readers see which
  events are not yet sealed.
- **Late commits.** An event committed after later events were sealed is
  sealed at the next pass, with a higher sequence. The chain order is the
  sealing order, not exactly the `recorded_at` order.
- **Upgrades.** Events written before 0036 are sealed at the first pass.
  The chain proves nothing about changes made before that.
- **Head custody.** Detection depends on someone exporting the head and
  keeping it where the database owner cannot change it. ADR-0023 automates
  that with checkpoints signed by the laboratory signer.
- **Content.** The chain covers the `audit_event` row only. Lifecycle,
  decision and CRL tables keep their own verifiers (ADR-0011, ADR-0014,
  ADR-0017).
- **Cost.** Each pass scans `audit_event` for unsealed rows, bounded by
  batches and the statement timeout. Sealing 81,000 events of the history
  load fixture took about 3 s. A pass with nothing to seal still scans the
  table; that was not measured at the 800,000-row scale of the history
  studies.

## Tests

- `tests/management_audit_chain.sql`:
  - the canonical digests equal the Rust vectors;
  - bounds and privileges (reader refused, writer may seal, nobody but the
    owner reads links);
  - sealing in batches, oldest first;
  - contiguity and every digest recomputed;
  - continuation from the head;
  - the reader seal view, without leakage across authorities or without a
    declared principal;
  - UPDATE, DELETE and TRUNCATE refused;
  - foreign key and uniqueness of links.
- `tests/management_audit_chain_tamper.sh`, as the owner with triggers
  disabled:
  - an altered event, a removed link, and a removed and renumbered link are
    each reported;
  - a chain rebuilt consistently passes on its own, but fails against the
    exported head;
  - an unknown head fails.
- Rust:
  - the canonical vectors, and that every field changes the digest;
  - parsing of the expected head;
  - the HTTP test seals the CRL renewal's event and reads `chain_sealed`
    before and after.
- CI:
  - after every API test, it seals and runs the tool with
    `TRUST_AUDIT_REQUIRE_SEALED=1`;
  - the Compose e2e waits for the voiding event to be sealed by the API's
    own pass.
