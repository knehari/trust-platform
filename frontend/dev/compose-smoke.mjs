import assert from 'node:assert/strict';
import { claims, requiredEnv, signIn } from './keycloak-login.mjs';

const realm = 'http://127.0.0.1:8080/realms/trust-lab';
const api = 'http://127.0.0.1:8081';
const consoleOrigin = 'http://127.0.0.1:5173';
const allowedCa = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const hiddenCa = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const allowedRequest = '11111111-1111-4111-8111-000000000001';
const hiddenRequest = '11111111-1111-4111-8111-000000000002';
const allowedEvent = '33333333-3333-4333-8333-000000000001';
const hiddenEvent = '33333333-3333-4333-8333-000000000002';

const page = await fetch(consoleOrigin);
assert.equal(page.status, 200, 'console must serve over the published loopback port');

// A human sign-in through the Keycloak login form, with code + PKCE.
const session = await signIn(realm, 'lab-reader', requiredEnv('TRUST_LAB_PW_READER'));
assert.ifError(session.error);
const { access_token } = session;
assert.ok(access_token);
const { header: tokenHeader, payload } = claims(access_token);
assert.equal(tokenHeader.typ, 'at+jwt');
assert.equal(payload.azp, 'trust-console');
assert.equal(payload.sub, '7c1a0000-0000-4000-8000-000000000001');

const headers = { authorization: `Bearer ${access_token}` };
assert.equal((await fetch(`${api}/v1/cas`)).status, 401);
const scoped = await fetch(`${api}/v1/cas`, { headers });
assert.equal(scoped.status, 200);
const cas = await scoped.json();
assert.deepEqual(cas.map((ca) => ca.ca_id), [allowedCa]);
assert.equal((await fetch(`${api}/v1/cas/${hiddenCa}`, { headers })).status, 403);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}`, { headers })).status, 200);
const drafts = await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts`, { headers });
assert.equal(drafts.status, 200);
assert.deepEqual((await drafts.json()).map(draft => [draft.profile_id, draft.revision, draft.status]), [['server-lab', 1, 'DRAFT'], ['server-lab', 2, 'DRAFT']]);
const filteredDrafts = await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts?profile_id=server-lab`, { headers });
assert.equal(filteredDrafts.status, 200);
assert.deepEqual((await filteredDrafts.json()).map(draft => draft.revision), [1, 2]);
const newestDrafts = await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts?profile_id=server-lab&order=newest`, { headers });
assert.equal(newestDrafts.status, 200);
assert.deepEqual((await newestDrafts.json()).map(draft => draft.revision), [2, 1]);
const missingDrafts = await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts?profile_id=missing-profile`, { headers });
assert.equal(missingDrafts.status, 200);
assert.deepEqual(await missingDrafts.json(), []);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts?profile_id=Server-Lab`, { headers })).status, 400);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts?profile_id=server-lab&after=other-profile%7C1`, { headers })).status, 400);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts?profile_id=server-lab&order=invalid`, { headers })).status, 400);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts?order=newest`, { headers })).status, 400);
const draftDetail = await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts/server-lab/1`, { headers });
assert.equal(draftDetail.status, 200);
assert.match((await draftDetail.json()).snapshot_sha256, /^[0-9a-f]{64}$/);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts/server-lab/2`, { headers })).status, 200);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}/profile-drafts/server-lab/3`, { headers })).status, 404);
assert.equal((await fetch(`${api}/v1/cas/${hiddenCa}/profile-drafts`, { headers })).status, 403);
assert.equal((await fetch(`${api}/v1/cas/${hiddenCa}/profile-drafts?profile_id=hidden-lab`, { headers })).status, 403);
assert.equal((await fetch(`${api}/v1/cas/${hiddenCa}/profile-drafts/hidden-lab/1`, { headers })).status, 403);
for (const [kind, knownId, hiddenId, idField, sensitiveField] of [
  ['certificates', allowedRequest, hiddenRequest, 'request_id', 'certificate_der'],
  ['audit', allowedEvent, hiddenEvent, 'event_id', 'actor_id'],
]) {
  const base = `${api}/v1/cas/${allowedCa}/${kind}`;
  const list = await fetch(base, { headers });
  assert.equal(list.status, 200);
  const records = await list.json();
  assert.deepEqual(records.map((record) => record[idField]), [knownId]);
  assert.ok(records.every((record) => !(sensitiveField in record)));
  const detail = await fetch(`${base}/${knownId}`, { headers });
  assert.equal(detail.status, 200);
  assert.match(detail.headers.get('cache-control') ?? '', /no-store/);
  const record = await detail.json();
  assert.equal(record[idField], knownId);
  assert.ok(!(sensitiveField in record));
  assert.equal((await fetch(`${base}/${hiddenId}`, { headers })).status, 404);
  assert.equal((await fetch(`${api}/v1/cas/${hiddenCa}/${kind}/${hiddenId}`, { headers })).status, 403);
  assert.equal((await fetch(`${base}/not-a-uuid`, { headers })).status, 400);
}
console.log('Laboratory smoke passed: Keycloak sign-in with code+PKCE, scoped list/detail reads, and denials.');
