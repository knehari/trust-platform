# ADR-0040 — RA key rotation without losing past evidence

**Status:** Proposed · 2026-11-12. It is not accepted; acceptance needs the
owner's decision and an independent security review (AGENTS.md). It follows
ADR-0039, which deferred RA key rotation.

**Scope:**
- migration 0047: `ra_system_key`, its rules, the key lookups and the
  signer's views;
- the API's, the signer's and the audit tool's verification of RA requests;
- tests.

**Out of scope:**
- an API or console to manage RA keys (the owner edits the table);
- RA key custody, expiry dates, automatic rotation;
- officer and approver key rotation, which already work by revoking a key
  and registering another (ADR-0028, ADR-0029).

## Context

ADR-0025 registered one P-256 key per RA in `ra_system.public_key_sec1`.
Every verifier read that column at verification time:
- the API, for new requests;
- the signer, for the RA request behind an issuance intent (ADR-0028), and
  for every RA-signed revocation listed on a CRL (ADR-0029);
- `lab_verify_issued_certificates`, for every stored request.

The only way to change an RA's key was to update that column. The past
requests would then no longer verify:
- the signer never drops a listed revocation, so it would have refused
  every later CRL of the CA (integrity over availability, ADR-0029);
- the audit tool would have reported every past request as forged.

A routine or emergency rotation was therefore not possible without breaking
CRL publication.

## Decision

1. **Keys in their own append-only table.** `ra_system_key(ra_id, key_id,
   public_key_sec1, activated_at, retired_at)`, owner-only:
   - every existing RA's key becomes its key 1, active since the RA was
     registered; registering a new RA registers its key 1 the same way;
   - `ra_system.public_key_sec1` can no longer be changed (55000);
   - the database numbers each new key after the RA's last one and dates it
     (`activated_at`), whatever the insert says; a key cannot be born
     retired;
   - at most two unretired keys per RA, so the old and the new key overlap
     while the RA switches (55000 for a third);
   - a key is retired once, dated by the database; it is never changed or
     deleted (55000);
   - a key is never another RA's, an approver's or an officer's (23505), and
     an officer key can no longer be any RA key.
2. **Which keys verify what.**

   | Verifier | Keys accepted |
   | --- | --- |
   | API, new request | the enabled RA's unretired keys (`ra_system_keys_lab`) |
   | Signer, issuance | the RA's keys active when the request was recorded and still unretired |
   | Signer, listed revocation | the RA's keys active when the request was recorded, retired since or not |
   | Audit tool, any stored request | the same as for a listed revocation |

   Issuance looks forward: retiring a key stops the issuance still pending
   under it. Revocations and the audit look back: a request accepted under a
   key active at the time stays valid evidence after a rotation.
3. **Signer views.** `lab_signer_authorization` and
   `lab_signer_crl_entry_proof` replace `ra_public_key` with
   `ra_public_keys BYTEA[]`. The signer accepts the request if any of those
   keys verifies it; an empty set verifies nothing.
4. **Compatibility.** `ra_system_key_lab` stays and returns the newest
   unretired key. A signer built before this change cannot read the new
   views and refuses every RA-backed intent (no silent acceptance); the
   signer and the migration are deployed together.

## Alternatives considered

- **Recording the verifying key with each request.** The submission
  functions would need a new parameter in three versions, and the key would
  still be the API's claim, which the signer re-verifies anyway. Matching by
  the recording time needs no change to the recorded evidence or to the
  submission path, and two candidate keys at most cost one extra
  verification.
- **Letting the owner update `ra_system.public_key_sec1`.** It breaks CRL
  publication, as described above.
- **Keeping retired keys valid for issuance.** A compromised key would then
  still get its pending requests signed after retirement.

## Consequences and open risks

- **Compromise response.** Retiring a key stops new requests and pending
  issuance under it. Revocations it signed while active stay listed; that is
  safe in direction (revoking more), but a stolen key could have revoked the
  RA's certificates before discovery. Disabling the RA stops everything.
- **The owner's clock and login.** Activation and retirement times come from
  the database clock; a compromised owner login can still register keys
  (unchanged since ADR-0025).
- **Replays across a retirement.** A replay of an accepted request signed by
  a key retired since is refused (401) instead of answered: the API checks
  the signature before the database finds the record.
- **No audit event for key changes.** The table itself is the record
  (append-only, dated); a dedicated event is open.

## Tests

- `tests/management_ra_key_rotation.sql` (new):
  - the first keys are backfilled, and a new RA gets key 1;
  - the API's roles cannot read or change the keys;
  - `ra_system.public_key_sec1` is frozen; other RA columns still change;
  - numbering and dating by the database; a third unretired key, a key born
    retired, and keys used by an approver or another RA (in `ra_system` or
    rotated) are refused; an officer cannot take a rotated RA key;
  - during the overlap both keys are usable, the single lookup gives the
    newest; retirement is dated by the database, happens once, and nothing
    else changes or is deleted; a retired key is no longer usable; a third
    key follows once one is retired; retiring all keys leaves none usable;
  - the signer's views expose `ra_public_keys BYTEA[]` to the signer only.

  Mutations checked by hand: dropping the frozen-column trigger, the
  append-only trigger, or the `retired_at IS NULL` filter of
  `ra_system_keys_lab` each fail the suite.
- `management_authorization_proofs.sql`: the signer view's key set.
- Signer unit tests: one of two candidate keys verifies; an empty set is
  refused.
- API HTTP test (67 tests), with real signatures and the in-process signer:
  - after a first RA revocation is on a CRL, the owner adds a second key;
  - a request signed by the new key is issued;
  - once key 1 is retired, a request it signs gets 401, and the replay of
    the new key's request answers 200;
  - a second issuance and revocation under the new key, then the worker's
    CRL renewal: the signer re-verifies the earlier revocation signed by the
    retired key and publishes.
- `lab_verify_issued_certificates` on the HTTP test's database reports no RA
  problem: the requests signed by the retired key, and those signed by the
  new one, both verify.
