# ADR-0039 — Quotas, zones and a tighter clock for RA systems

**Status:** Proposed · 2026-11-12. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It is the
architecture review's P1 item "RA hardening".

**Scope:**
- migration 0046: `ra_system_policy`, the policy triggers on the recorded RA
  requests, `management_ra_hardening_version()`;
- the API's mapping of the new refusals and its tighter clock check;
- the OpenAPI contract of the two RA routes;
- tests.

**Out of scope:**
- RA key rotation and multiple keys per RA;
- an API or console to manage the policy (the owner edits the table);
- rate limiting of user (OIDC) routes and of the public CRL route;
- domain-control validation.

## Context

ADR-0025 and ADR-0026 gave RA systems a token-less channel with signed
requests. An enabled RA with a granted profile could then:

- submit as many issuance and revocation requests as the API answered. A
  stolen RA key could mass-issue within the profile, or mass-revoke every
  certificate the RA had obtained, before anyone noticed;
- ask for any name in the profile's zones, even when the RA serves only part
  of them. Two RAs sharing a profile could each obtain the other's names;
- date a request up to five minutes ahead. With the five minutes allowed
  behind, a captured request stayed usable for up to ten minutes. Replays of
  the exact bytes were already idempotent (same `request_id`), but a request
  never submitted by the RA could still be played later by whoever captured
  it.

## Decision

1. **A per-RA policy, owned by the database owner.** `ra_system_policy`
   holds, per RA:
   - `max_issuance_per_hour` and `max_revocation_per_hour`, 0 to 100 000;
   - `allowed_dns_zones`: NULL for the profile's zones, otherwise 1 to 100
     DNS zones, validated as lowercase DNS names (no wildcard).

   Without a row the defaults apply: 100 issuances and 20 revocations per
   rolling hour, the profile's zones. The API's roles cannot read or change
   the table.
2. **Enforced by the database, on what is recorded.** BEFORE INSERT
   triggers on `ra_issuance_request` and `ra_revocation_request` run inside
   the submission's transaction, so a refusal rolls back the whole
   submission:
   - a request dated more than 30 seconds after the database clock is
     refused (`TP422`);
   - the RA's submissions are serialized by a per-RA advisory lock, then
     counted over the last hour by `recorded_at`; at the quota the request
     is refused (`TP429`);
   - with zones set, every DNS name of the application must fall within one
     of them, on a label boundary (`certificate_name_in_zone`); otherwise
     `42501`. The profile's own zone and name rules still apply.

   A replay of an accepted request inserts nothing, so it never consumes
   quota and is still answered once the quota is exhausted.
3. **API.** `TP429` becomes 429 Too Many Requests and `42501` the existing
   403. The API's own freshness check now also refuses a `signed_at` more
   than 30 seconds ahead (401), before any database work; the five minutes
   allowed behind are unchanged.

## Alternatives considered

- **Rate limiting in the API.** An in-process counter is neither shared
  between API instances nor atomic with the recording, and a compromised API
  would bypass it. The trigger counts exactly what is recorded, under a
  lock.
- **Rewriting the submission functions.** The checks would be duplicated in
  `submit_ra_issuance_lab` and the revocation function, and a later version
  of either could drop them. Triggers on the request tables hold for every
  path that records a request.
- **A token bucket table.** More precise bursts, but more state to keep
  consistent; a count over an index range is enough at these volumes.

## Consequences and open risks

- **Defaults apply to existing RAs.** After 0046 an RA above 100 issuances
  or 20 revocations an hour is refused until the owner raises its quota.
  This is deliberate (safe default), and visible as 429.
- **Clock skew.** An RA whose clock runs more than 30 seconds ahead of the
  database is refused (401). Operators must keep RA hosts on NTP.
- **Rolling window by `recorded_at`.** A burst at the end of one hour and
  another at the start of the next can reach twice the quota within a few
  minutes.
- **Policy changes are owner-only and not audited as events.** A compromised
  owner login can raise any quota; the table records only `updated_at`.
- **No alert on 429 yet.** Repeated refusals only show in the API's logs.
- **RA key rotation is still deferred:** an RA has one key; replacing it is
  an owner update without overlap.

## Tests

- `tests/management_ra_hardening.sql` (new, fixture of
  `management_ra_channel.sql`):
  - the writer and reader roles cannot read or change the policy;
  - invalid zones, wildcard zones, negative quotas and unknown RAs are
    refused;
  - the defaults (100, 20, NULL);
  - names outside the RA's zones, mixed with names inside, and across a
    label boundary (`xteam.lab.invalid` is not under `team.lab.invalid`) are
    refused, and nothing is recorded;
  - a request dated 120 seconds ahead is refused;
  - the quota: two accepted, the third refused, replays free before and
    after exhaustion; requests older than an hour no longer count; a zero
    quota stops the RA at once.
- The API HTTP test (67 tests): a request dated 120 seconds ahead gets 401;
  with zones `ra.lab.invalid`, a request for `other.lab.invalid` gets 403;
  an issuance quota of 0 gets 429; a revocation quota of 0 gets 429 before
  the RA's revocation.
- The existing suites `management_ra_channel.sql`,
  `management_ra_revocation.sql` and `management_authorization_proofs.sql`
  pass unchanged with the defaults.
