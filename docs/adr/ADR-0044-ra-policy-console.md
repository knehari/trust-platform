# ADR-0044 — Readers see the RA channel's policies in the console

**Status:** Proposed · 2026-11-13. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It was
chosen by the owner as the next step: "Console des nouveautés".

**Scope:**
- migration 0049: two reader views;
- two read-only API routes;
- the console's "RA channel" section;
- tests.

**Out of scope:**
- changing any policy from the API or the console: owner-only, by design
  so far. A write path needs its own design (who, dual control, audit
  events), since a quota, a zone, a key or a short-lived profile changes
  what the CA will sign;
- backup status (outside the database) and the worker's metrics (ADR-0038:
  Prometheus on the worker, not the API);
- a dashboard alert for exhausted quotas.

## Context

Since ADR-0039, ADR-0040 and ADR-0042, the database owner sets in SQL:
- each RA's quotas and zones;
- its keys and their rotation;
- the short-lived profiles.

Officers and auditors could not see any of it, though it explains what they
observe:
- why an RA's requests get 429;
- why a name is refused (403);
- why a certificate cannot be revoked (409);
- which key an RA uses.

## Decision

1. **Two reader views, filtered like every management view** (the
   principal set by the API from the verified token, and a
   `management_reader_grant` on the CA):
   - `management_ra_system`, one row per RA granted a profile of the CA:
     - whether it is enabled, and its profiles;
     - its effective quotas (the owner's row, or the defaults 100 and 20,
       inlined since a view's functions run with the reader's privileges);
     - their use over the last hour;
     - its zones;
     - its keys as JSON: `key_id`, the SHA-256 of the SEC1 point,
       `activated_at`, `retired_at`. Public keys are not secrets, but a
       fingerprint is all a reader needs.
   - `management_short_lived_profile`: the CA's short-lived profiles and
     their bound.

   The API's reader role selects from them; the writer and the signer do
   not. The raw tables stay closed to every API role. Without a principal,
   or with another one, the views return nothing; the API's start-up
   isolation check now includes them.
2. **Two routes**, with the reader role and the CA in the token's scope:
   - `GET /v1/cas/{ca_id}/ra-systems`;
   - `GET /v1/cas/{ca_id}/short-lived-profiles`.

   At most 500 rows each.
3. **Console**: a new "RA channel" section for readers.
   - RA systems:
     - an enabled or disabled badge, and the granted profiles;
     - issuance and revocation meters for the last hour (warning from 80 %,
       red at the quota, "Stopped" at a zero quota);
     - the zones;
     - the keys: shortened fingerprints with dates, retired keys dimmed,
       "Rotation in progress" with two unretired keys, "No usable key" with
       none.
   - Short-lived profiles: each profile and its longest validity.

   A note says the view is read-only and where the owner changes it.

## Alternatives considered

- **Exposing write routes now.** They would give the API's writer login the
  power to raise quotas or register keys. That power belongs to the owner
  today, and moving it needs dual control and audit design first.
- **Showing it only in the Revocation or Profiles section.** The RA channel
  spans issuance, revocation and keys, so it gets its own section.

## Consequences and open risks

- **Readers learn each RA's quotas and current use.** This is operational
  information inside the CA's scope, comparable to the CRL status.
- **The use counts are live queries** over an index range per RA (migration
  0046's indexes); fine at laboratory volumes.
- **No history** of policy changes is shown; the tables keep only their
  current state (open since ADR-0039).

## Tests

- `tests/management_ra_policy_views.sql` (new):
  - the raw tables stay closed to the reader;
  - only the RAs granted a profile of the CA are listed;
  - defaults versus the owner's values, use in the last hour, zones;
  - keys: fingerprint, order, the retired one dated, never the point;
  - short-lived profiles;
  - another principal, or none, sees nothing;
  - the writer and the signer have no access.
- The API HTTP test (67 tests):
  - the reader lists the test RA with its defaults, its profile, its use
    and both keys (key 1 retired, key 2 active), with fingerprints
    recomputed from the keys;
  - the short-lived profile is listed during its window.
- Frontend unit tests (`dev/ra-policy.test.mjs`): quota tones and bounds,
  active keys and rotation, fingerprint shortening, and the navigation
  route for the new section.
- The console checked in a browser against the full laboratory stack (see
  `docs/DEVELOPMENT_STATUS.md`).
