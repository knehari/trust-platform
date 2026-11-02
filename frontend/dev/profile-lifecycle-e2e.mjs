// Laboratory end-to-end check of profile draft authoring and submission
// (migration 0022, ADR-0010) through Keycloak sign-ins and the management
// API of the Compose stack. Run with .env.lab loaded, after compose-smoke.
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { clientCredentials, requiredEnv, signIn } from './keycloak-login.mjs';

const realm = 'http://127.0.0.1:8080/realms/trust-lab';
const api = 'http://127.0.0.1:8081';
const allowedCa = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const hiddenCa = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const profileId = `e2e-${randomUUID().slice(0, 8)}`;
const results = [];

async function token(username, envName) {
  const session = await signIn(realm, username, requiredEnv(envName));
  assert.ifError(session.error);
  return session.access_token;
}

async function post(path, accessToken, body, key = randomUUID()) {
  const response = await fetch(`${api}${path}`, {
    method: 'POST',
    headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json', 'idempotency-key': key },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, replayed: response.headers.get('idempotent-replayed') === 'true',
    body: text ? JSON.parse(text) : null, cacheControl: response.headers.get('cache-control') };
}

async function get(path, accessToken) {
  const response = await fetch(`${api}${path}`, { headers: { authorization: `Bearer ${accessToken}` } });
  return { status: response.status, body: response.ok ? await response.json() : null };
}

async function check(name, run) {
  await run();
  results.push(name);
  console.log(`ok - ${name}`);
}

const draft = (overrides = {}) => ({
  profile_id: profileId, display_name: 'End-to-end server proposal', policy_version: 'v1',
  max_validity_days: 90, max_dns_sans: 5, proposed_dns_zones: ['lab.invalid'],
  proposed_signature_suites: ['P256-SHA256'], ...overrides,
});
const base = `/v1/cas/${allowedCa}/profile-drafts`;

const author = await token('lab-author', 'TRUST_LAB_PW_AUTHOR');
const reader = await token('lab-reader', 'TRUST_LAB_PW_READER');
let first;
let second;

await check('an author records revision 1 and a replay returns it', async () => {
  const key = randomUUID();
  first = await post(base, author, draft(), key);
  assert.equal(first.status, 201);
  assert.equal(first.cacheControl, 'no-store');
  assert.deepEqual([first.body.revision, first.body.status, first.body.created_by],
    [1, 'DRAFT', '7c1a0000-0000-4000-8000-000000000011']);
  const replay = await post(base, author, draft(), key);
  assert.equal(replay.status, 200);
  assert.equal(replay.replayed, true);
  assert.equal(replay.body.snapshot_sha256, first.body.snapshot_sha256);
  assert.equal((await post(base, author, draft({ display_name: 'Changed' }), key)).status, 409);
});

await check('an editor without the reader role can write but not read', async () => {
  const editor = await token('lab-editor', 'TRUST_LAB_PW_EDITOR');
  second = await post(base, editor, draft({ display_name: 'Second revision', max_validity_days: 60 }));
  assert.equal(second.status, 201);
  assert.equal(second.body.revision, 2);
  assert.equal((await get(`${base}/${profileId}/2`, editor)).status, 403);
});

await check('readers, workloads and other authorities cannot write', async () => {
  assert.equal((await post(base, reader, draft())).status, 403);
  assert.equal((await post(`/v1/cas/${hiddenCa}/profile-drafts`, author, draft())).status, 403);
  const workload = await clientCredentials(realm, 'trust-lab-workload', requiredEnv('TRUST_LAB_WORKLOAD_SECRET'));
  assert.ifError(workload.error);
  assert.equal((await post(base, workload.access_token, draft())).status, 401);
});

await check('submission refuses a stale revision and an altered digest', async () => {
  assert.equal((await post(`${base}/${profileId}/1/submission`, author, { snapshot_sha256: first.body.snapshot_sha256 })).status, 409);
  assert.equal((await post(`${base}/${profileId}/2/submission`, author, { snapshot_sha256: first.body.snapshot_sha256 })).status, 409);
});

await check('the latest revision is submitted once, and readers see it', async () => {
  const key = randomUUID();
  const submitted = await post(`${base}/${profileId}/2/submission`, author, { snapshot_sha256: second.body.snapshot_sha256 }, key);
  assert.equal(submitted.status, 201);
  assert.equal(submitted.body.status, 'SUBMITTED');
  const replay = await post(`${base}/${profileId}/2/submission`, author, { snapshot_sha256: second.body.snapshot_sha256 }, key);
  assert.equal(replay.status, 200);
  assert.equal(replay.body.submitted_at, submitted.body.submitted_at);
  assert.equal((await post(`${base}/${profileId}/2/submission`, author, { snapshot_sha256: second.body.snapshot_sha256 })).status, 409);
  const detail = await get(`${base}/${profileId}/2`, reader);
  assert.equal(detail.status, 200);
  assert.deepEqual([detail.body.status, detail.body.submitted_at], ['SUBMITTED', submitted.body.submitted_at]);
  assert.equal((await get(`${base}/${profileId}/1`, reader)).body.status, 'DRAFT');
});

await check('a revision with syntax warnings cannot be submitted', async () => {
  const warned = await post(base, author, draft({ proposed_dns_zones: ['Not_A_Zone'] }));
  assert.equal(warned.status, 201);
  assert.deepEqual(warned.body.proposal_warnings, ['invalid_dns_zone']);
  const refused = await post(`${base}/${profileId}/${warned.body.revision}/submission`, author, { snapshot_sha256: warned.body.snapshot_sha256 });
  assert.equal(refused.status, 422);
  assert.equal((await get(`${base}/${profileId}/${warned.body.revision}`, reader)).body.status, 'DRAFT');
});

await check('each write left an audit event readers can see', async () => {
  const audit = await get(`/v1/cas/${allowedCa}/audit?order=newest`, reader);
  assert.equal(audit.status, 200);
  const types = audit.body.map(event => event.event_type);
  assert.ok(types.filter(type => type === 'profile.draft.created').length >= 3);
  assert.ok(types.includes('profile.draft.submitted'));
  assert.ok(audit.body.every(event => !('actor_id' in event)));
});

console.log(`Laboratory profile lifecycle suite passed: ${results.length} cases (profile ${profileId}).`);
