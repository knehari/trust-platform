# ADR-0023 — Signed checkpoints of the audit chain in the laboratory

**Status:** Proposed · 2026-11-09. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md).

**Scope:**
- migration 0037;
- the laboratory signer's `audit_checkpoint` request;
- the API's checkpoint task;
- `lab_verify_audit_chain`;
- the laboratory Compose stack.

**Roadmap:** second slice of MVP criterion 10, "Durable audit evidence",
after ADR-0022. The criterion stays unchecked:
- the audit key is a software key file;
- actors are still text, not authenticated claims;
- nothing exports checkpoints to an external store;
- there is no governed retention.

## Context

The chain of ADR-0022 is evidence only against a head kept outside the
database, and exporting that head was a manual step. Whoever controls the
database (owner, superuser, a restore) can rebuild a consistent chain over
altered history. Nothing would object unless someone had exported a head
earlier and checked it.

## Decision

1. **A separate audit key.** The laboratory signer receives a P-256 audit
   key (`TRUST_SIGNER_AUDIT_KEY_FILE`). It signs only audit checkpoints.
   - The signer refuses a request when that key is the CA key.
   - In the laboratory, `init-env.sh` generates the key with OpenSSL into
     `.lab-keys/audit/`, the only directory the signer mounts for it.
   - Its public half (`audit-checkpoint.pub.pem`) is what verifiers use.
     It is supplied out of band, never read from the database.
2. **What is signed.** `trust_pki_core::audit_chain::audit_checkpoint_message`
   is the concatenation of:
   - `trust-platform:audit-checkpoint:v1\0`;
   - the sequence (int8, big-endian);
   - the chain hash;
   - the signing instant in Unix seconds (int8, big-endian);
   - the key identifier, the SHA-256 of the key's SubjectPublicKeyInfo DER.

   The signature is ECDSA P-256 with SHA-256 over these bytes, in DER.
   A signature cannot be moved to another head, instant or key.
3. **The signer signs only an extension of what it signed.** On request
   (`{"kind":"audit_checkpoint"}`), it:
   1. reads its state file (`TRUST_SIGNER_AUDIT_STATE_FILE`, outside the
      database): the last checkpoint it signed (sequence, hash, key id). A
      damaged file is a refusal, never "no state";
   2. requires the database's latest checkpoint to be that one, or a later
      one signed by its key. Otherwise it refuses with `AuditRollback`: the
      database was rolled back, rewritten or replaced;
   3. reads the links after its state, with the raw event columns, through
      `lab_signer_audit_links`. In Rust, it recomputes every event digest
      and link from its state, or from the genesis without one. On any
      mismatch it refuses with `AuditChain`;
   4. verifies the stored checkpoint it passes, under its own key. On a
      mismatch it refuses with `AuditCheckpointSignature`;
   5. signs the new head and records it through
      `lab_signer_record_audit_checkpoint`;
   6. only then updates its state file (temporary file, sync, rename).

   A lost state file is recovered safely. The signer recomputes from the
   genesis and confirms the stored checkpoints with its key. A rewritten
   history then fails at the first checkpoint it signed.
4. **Storage.** `audit_chain_checkpoint` is append-only:
   - triggers refuse UPDATE, DELETE and TRUNCATE;
   - each checkpoint references its link, so checkpointed links cannot be
     deleted;
   - the recording function requires the link's exact hash and a strictly
     later sequence.

   Recording writes no audit event: that event would itself be sealed and
   call for another checkpoint, forever. The table is the record.
5. **Schedule.** The API asks for a checkpoint every
   `TRUST_AUDIT_CHECKPOINT_INTERVAL_SECONDS` (30–86400; the Compose file
   sets 60), on its own thread, over the signer's socket. It logs
   `audit_checkpoint` as `SIGNED` or `UNCHANGED`. A refusal is logged as
   `REFUSED` with `"alert": true` and the code.
6. **Verification.** `lab_verify_audit_chain` checks that every checkpoint
   names a link of the recomputed chain with that link's hash. With
   `TRUST_AUDIT_CHECKPOINT_PUBLIC_KEY`, it also checks the key identifier
   and the signature. `TRUST_AUDIT_REQUIRE_CHECKPOINT=1` fails without the
   key, or when sealed links have no checkpoint.

## What this changes for an attacker who controls the database

- **Altering, removing or reordering sealed history** fails verification at
  every earlier checkpoint. The attacker cannot re-sign without the audit
  key.
- **Deleting the checkpoints and rebuilding the chain:**
  - the signer refuses to sign again (`AuditRollback`), and the API raises
    an alert;
  - the tool reports that sealed links have no signed checkpoint.
- **Putting old checkpoint rows back over a rebuilt chain** fails: the hash
  differs, or the signature no longer verifies.
- **Restoring an older backup together with the signer's state file** is
  not detected. The state file must be protected and backed up apart from
  the database. In production, this would be an HSM counter or an external
  transparency log.

## Alternatives considered

- **Signing with a CA key.** Rejected: key separation. A CA key signs
  certificates and CRLs only.
- **A signing key held by the API.** Rejected: the API build carries no
  software signing (ADR-0017), and a compromised API could sign anything.
- **Trusting the database's latest checkpoint without state.** Rejected: a
  database rebuilt from scratch has no checkpoint to contradict it.
- **An external transparency log.** Deferred; the checkpoints are the unit
  such a log would receive.

## Consequences and open risks

- **Rollback is detected only while the state file is intact.** Resetting
  the database without the state (for example `down -v`, which removes
  both volumes) starts afresh. Resetting only the database makes the signer
  refuse until an operator deliberately removes its state. That is
  intended, but needs a procedure.
- **Cost.** A checkpoint recomputes only the links since the last one. A
  recovery without state recomputes the whole chain.
- **Coverage.** Events are covered once sealed and checkpointed: up to one
  sealing interval plus one checkpoint interval.
- **Key handling.** The software key file is laboratory-only. Rotation is
  not designed: a new key makes the signer refuse (`AuditKeyChanged`)
  until its state is reset by procedure.

## Tests

- `tests/management_audit_checkpoint.sql`:
  - privileges (reader and writer refused; the signer only through the
    functions);
  - link paging with raw columns;
  - recording only an existing link with its exact hash, and only forward;
  - the 72-byte bound on signatures;
  - no audit event written;
  - append-only, and a checkpointed link cannot be deleted.
- Signer unit tests:
  - a signed head verifies;
  - nothing new means no signature;
  - an altered event, a missing event, a broken link or a gap is refused
    before signing;
  - a database behind the state (checkpoints removed, history rebuilt,
    checkpoint copied) is refused;
  - a lost state recovers from verified checkpoints;
  - another or a changed key is refused;
  - a failed record leaves no state;
  - the state file is parsed strictly.
- HTTP test with the real signer: a checkpoint is signed, then `UNCHANGED`.
  The stored key identifier and signature verify under the audit key, and
  the state file names the checkpoint.
- `tests/management_audit_chain_tamper.sh`, with a key and signature made
  by OpenSSL:
  - a checkpoint verifies;
  - without the key, or with another key, verification fails;
  - after a rebuild, the old row no longer matches the chain;
  - a moved signature does not verify.
- Certificate-application e2e: the API's own pass obtains a checkpoint
  that names its link.
- On the laboratory:
  - the tool verifies the real signer's checkpoints with the OpenSSL
    public key;
  - after an owner rebuild, the signer refuses with `AuditRollback` and
    the tool fails.
