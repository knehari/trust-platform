# ADR-0041 — Cold backup, restore and a recovery drill for the laboratory stack

**Status:** Proposed · 2026-11-12. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It is the
review's P1 item "HA/DR". AGENTS.md asks: "Tester sauvegarde, restauration,
reprise et cohérence de l'audit." ROADMAP lists "Operational recovery" as
open.

**Scope:**
- `scripts/lab/backup.sh`, `scripts/lab/restore.sh` and
  `scripts/lab/backup-facts.sql`;
- `tests/lab_backup_restore_drill.sh`, run in the laboratory Compose CI job;
- a Compose variable for the audit intervals;
- the operations guide.

**Out of scope:**
- high availability: database replication, a standby signer, failover;
- online or point-in-time backups (WAL archiving);
- backup encryption, off-site retention, rotation;
- HSM vendor backup and key ceremony quorum;
- production RTO and RPO targets.

## Context

`tests/management_dump_restore.sh` (Drafts #61–#68) restores a fixture of
the management tables. Nothing covered the platform as a whole. A recovery
must bring back three parts that have to agree:

| Part | Content | Where |
| --- | --- | --- |
| Database | issuance, revocation and CRL records, the audit chain and its checkpoints | `trust_lab_pg` |
| PKCS#11 tokens | the CA key and the audit key (ADR-0034, ADR-0035) | `trust_signer_hsm` |
| Signer state | the last audit checkpoint the signer signed (ADR-0023) | `trust_signer_state` |

The signer refuses to checkpoint a database that no longer extends what it
signed (`AuditRollback`). A database restored without the matching state is
therefore either accepted or detected. Which one happens had never been
exercised.

## Decision

1. **Cold, consistent backup.** `backup.sh`:
   - stops the services that write: api, worker, publisher, signer;
   - dumps the database as its owner (`pg_dump -Fc`);
   - archives both signer volumes (tokens and state);
   - records `manifest.json`: the time, the code revision, each file's
     SHA-256, and facts from `backup-facts.sql`:
     - counts and digests of certificates, serial reservations, revocations
       and CRLs;
     - the audit event count, the chain head and the latest checkpoint;
     - a digest of the schema's `management_*_version()` markers;
   - restarts the services.

   The output directory is owner-only, under the git-ignored
   `.lab-backups/`. Because the signer is stopped, its state never runs
   ahead of the dumped database.
2. **Secrets stay apart.** The backup holds the token files, which the
   tokens' PINs protect. It does not hold `.env.lab` (PINs, passwords) or
   `.lab-keys/` (TLS, approver and officer keys). A restore needs those
   unchanged; keeping them apart means one stolen archive does not yield
   usable keys. Keycloak's state and the public CRL tree are not saved
   either: the realm is imported at start, and the CRLs are republished from
   the database.
3. **Restore.** `restore.sh` takes one of two modes:
   - `--replace-stack`: destroys the stack and all its volumes, starts a
     fresh database, restores the dump and the signer volumes, and starts
     everything;
   - `--database-only`: replaces only the database and keeps the tokens and
     the signer state.

   Before replacing anything, both modes check:
   - each file against the manifest;
   - the code's schema markers against the backup's (otherwise it names the
     backup's revision).

   After restoring, both modes require every fact to match the manifest, and
   they report the duration.
4. **The drill.** `tests/lab_backup_restore_drill.sh` runs at the end of the
   laboratory Compose CI job, with the audit intervals shortened to
   30 seconds, the shortest checkpoint interval
   (`TRUST_LAB_AUDIT_INTERVAL_SECONDS`):
   1. Back up A, then restore it on a destroyed stack:
      - the worker reads the database;
      - the public CRL is republished; it verifies under the issuing CA and
        carries the database's latest number;
      - after a new audit event, the signer signs a checkpoint beyond the
        backup's, so it accepts the restored chain as the continuation of
        what it signed.
   2. Back up B, then restore only A's database under B's signer state:
      - the signer refuses every checkpoint (`AuditRollback`, logged by the
        worker), and none is recorded;
      - the database rollback is detected.
   3. Restore B entirely: checkpoints resume.

## Alternatives considered

- **Online backup (`pg_dump` while running, or WAL archiving).** A dump is
  consistent within the database. But the signer's state and the tokens can
  move during it: a checkpoint recorded after the dump's snapshot would leave
  the state ahead of the dump, and the drill shows that is refused. Online
  backup needs the signer quiesced or its state taken first; that is left to
  a pilot design with RPO targets.
- **Backing up `.env.lab` with the archive.** It is simpler, but the PINs
  would then sit next to the token files they protect.
- **Volume snapshots of the whole Docker state.** They are not portable, not
  checked against the records, and would include the secrets.

## Consequences and open risks

- **Downtime during backup.** Issuance, revocation and CRL renewal stop for
  the backup's duration (seconds in the lab). The database and Keycloak stay
  up.
- **RPO is the time since the last backup.** Nothing between backups is
  recoverable. The RTO measured by the drill is a laboratory figure, not a
  target.
- **The archive is as sensitive as the keys' PINs allow.** It is not
  encrypted: a SoftHSM2 token protects keys only by its PIN. Store archives
  as key material, apart from `.env.lab`.
- **Same code revision.** A backup cannot be restored by code whose
  migrations differ. Upgrading after a restore is a separate step (the
  migration runner).
- **The public CRL tree** is not restored. After a database-only restore of
  an older backup, the publisher keeps the newer public CRL (anti-rollback,
  ADR-0030) until the database catches up.
- **A database rollback blocks checkpoints until resolved.** That is the
  intended alert. To resume, restore the matching signer state; only
  re-initialising the signer's state would accept the rollback, and that
  must be a deliberate, recorded decision.

## Tests

- `tests/lab_backup_restore_drill.sh`, in the `laboratory-compose` CI job,
  covers the three phases above.
- Locally, against the full Docker stack after
  `scripts/lab/up.sh --reset --demo` (sandbox image override), the drill
  passed. Measured on that laboratory host:
  - backup: about 30 s, with the services stopped;
  - full restore: about 75 s;
  - database-only restore: 32 s;
  - after the full restore, 110 s to a new checkpoint (30-second
    intervals).

  A backup whose dump was altered by one byte was refused before anything
  was replaced, and the backup directory and its files were owner-only
  (0700, 0600).
