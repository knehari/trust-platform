# ADR-0037 — A dedicated background worker with its own database role

**Status:** Proposed · 2026-11-11. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It is the
review's P1 item "dedicated worker".

**Scope:**
- migration 0044 (role `trust_worker`, grants, the renewer's identity
  bound to the worker login);
- `trust-management-api --worker`;
- the removal of the background tasks from the API process;
- the laboratory login, certificate and compose service;
- the affected SQL, HTTP and end-to-end tests;
- CI.

**Supersedes in part:**
- ADR-0021 (renewal in the API, through its writer login);
- ADR-0022 (sealing in the API);
- ADR-0023 (checkpoint requests from the API);
- ADR-0027: a revocation no longer triggers a renewal pass inside the API;
  the worker's next pass publishes.

## Context

The API process ran three periodic tasks on its own threads:
- sealing committed audit events into the chain;
- renewing due CRLs;
- asking the signer for audit checkpoints.

They ran through the API's writer login (`trust_profile_writer`). Two
consequences followed:
1. **The system principal was only a parameter.** The renewer's identity,
   `urn:trust-platform:system` / `crl-renewer`, was a pair of strings that
   any caller holding the writer role could pass to the CRL publication
   functions. A compromised API could therefore publish CRLs as the
   renewer. It could also seal at will.
2. **Shared fate.** The tasks shared the API's process, memory, database
   connection slots and restarts. A request flood or an API crash stopped
   sealing and renewal. In the other direction, a long sealing pass
   competed with requests.

## Decision

1. **A separate process.** `trust-management-api --worker` runs the tasks
   with the same code, and nothing else:
   - no listener;
   - no OIDC configuration;
   - two database connections at most.

   Each task runs only when its interval is set:
   - `TRUST_CRL_RENEWAL_INTERVAL_SECONDS`, 5 to 86400;
   - `TRUST_AUDIT_SEAL_INTERVAL_SECONDS`, 5 to 86400;
   - `TRUST_AUDIT_CHECKPOINT_INTERVAL_SECONDS`, 30 to 86400.

   A worker without any task is a startup error.
2. **The API refuses those variables.** A configuration that still sets
   them on the API fails at startup and names the worker. It never silently
   stops sealing or renewal.
3. **Its own role (migration 0044).**
   - `trust_worker` is NOLOGIN. It can read no table or view. It holds
     EXECUTE only on:
     - `seal_audit_events_lab`;
     - `crl_renewal_candidates_lab`;
     - the five CRL publication functions of migration 0031;
     - its version marker.
   - The writer role loses sealing and the renewal candidates.
   - The worker's login must be a direct member of `trust_worker` and of no
     other platform role, with no attribute and no table. Otherwise the
     worker refuses to start.
4. **The renewer's identity is bound to the login.** `session_is_worker()`
   checks direct membership of the session's login (`session_user`) in
   `trust_worker`. A superuser or `SET ROLE` does not count. The CRL
   publication grant check (`crl_publication_granted`) then decides:
   - **worker session:** only the system principal, and only with its
     `crl-publisher` grant. The worker can never publish as an officer;
   - **any other session:** never the system principal. Officers are
     unchanged.

   `crl_renewal_candidates_lab` returns nothing outside a worker session.
5. **Publish on revocation becomes a short poll.** The API no longer starts
   a renewal pass after a revocation. The revocation makes the CRL due
   (migration 0040), and the worker's next pass publishes it. The
   laboratory worker polls every 5 seconds. The candidates query reads only
   the due CAs granted to the renewer.
6. **Laboratory.**
   - `init-env.sh` generates `TRUST_LAB_WORKER_PASSWORD` and a client
     certificate for `trust_worker_lab` (ADR-0036).
   - `init-db.sh` creates the login.
   - The compose `worker` service runs the API image as `nobody` with
     `--worker`. It shares the signer socket volume and mounts only its own
     certificate.

## Alternatives considered

- **Keep the tasks in the API, under a second login.** The tasks would
  still share the API's process, and a compromised API would hold both
  logins. A separate process holds only its own.
- **A separate crate and binary.** It would duplicate the database access
  and the CRL publication code. The same binary, in another mode with
  another login, keeps one tested path. The process boundary and the login
  are what separate the privileges.
- **A notification from the API (LISTEN/NOTIFY) instead of polling.** It
  would be lower latency, but it adds a channel the API could abuse to
  wake the worker. Polling a cheap, due-only query is enough for the
  laboratory's 5-second target.

## Consequences and open risks

- **Publication delay on revocation.** CRLs are published within one
  worker interval (5 seconds in the lab) after a revocation, instead of
  immediately. Then the publisher's interval (ADR-0030) applies.
- **One worker.** There is no leader election or high availability. Two
  workers would be safe, because the database serializes CRL numbers and
  sealing, and a renewal never retries an ambiguous outcome. They would
  only duplicate effort. High availability is a separate P1 item.
- **The worker can still sign through the signer.** It reaches the signer
  socket for CRLs and checkpoints. The signer's own checks (ADR-0017,
  ADR-0029) still decide what it signs.
- **Existing databases** need migration 0044 and a worker login. The API
  then refuses to start until its interval variables move to the worker.

## Tests

- `tests/management_dedicated_worker.sql` (new):
  - the role is NOLOGIN with no attribute, reaches no table or view, and
    holds exactly its eight functions;
  - the writer lost sealing and the candidates; `session_is_worker()` is
    not public;
  - the owner with `SET ROLE trust_worker` is not a worker, and neither is
    a writer login;
  - a worker login is refused for another system subject, a human issuer,
    tables, views and the revocation functions, and it can seal.
- The earlier suites now run their renewer and sealing steps from a
  worker login (`SET SESSION AUTHORIZATION`) and show the writer's
  refusals: `management_crl_renewal.sql`, `management_crl_on_revocation.sql`
  and `management_audit_chain.sql`.
- The API HTTP test (64 tests):
  - the worker login passes the restriction check; the writer login fails
    it;
  - with the writer's login, renewal and sealing fail, even after the
    renewer's grant;
  - with the worker's login, the renewer publishes the due CRL, sealing
    works, and checkpoints are signed;
  - after an RA revocation with publish on revocation, the API itself
    publishes nothing: one entry stays pending until the worker's pass
    publishes it.
- Locally, against the lab stack with a separate worker process:
  - all end-to-end suites passed, including publish on revocation and
    sealing within their bounds;
  - the API refused an interval variable;
  - the worker refused the writer's login.
- Plumbing: the migration runner (0012–0044), ledger, restore, populated
  upgrade, retry, dump/restore role checks and CI lists.
