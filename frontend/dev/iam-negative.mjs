// Laboratory IAM negative-access suite for the Compose stack (criterion 5,
// first slice). Each case signs in through the Keycloak login form, or obtains
// a workload or foreign token, and checks that the management API refuses
// what that identity must not do. Run after compose-smoke.mjs with .env.lab
// loaded. Brute-force lockout runs last because it locks lab-outsider.
import assert from 'node:assert/strict';
import { authorizationCode, claims, clientCredentials, requiredEnv, signIn } from './keycloak-login.mjs';

const issuerOrigin = 'http://127.0.0.1:8080';
const realm = `${issuerOrigin}/realms/trust-lab`;
const foreignRealm = `${issuerOrigin}/realms/trust-lab-foreign`;
const api = 'http://127.0.0.1:8081';
const allowedCa = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const hiddenCa = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const results = [];

async function status(path, token, init = {}) {
  const headers = token ? { authorization: `Bearer ${token}` } : {};
  return (await fetch(`${api}${path}`, { ...init, headers })).status;
}

async function check(name, run) {
  await run();
  results.push(name);
  console.log(`ok - ${name}`);
}

async function human(username, envName) {
  const session = await signIn(realm, username, requiredEnv(envName));
  assert.ifError(session.error);
  return session;
}

await check('wrong password is refused by the login form', async () => {
  const outcome = await authorizationCode(realm, 'lab-reader', 'not-the-password-0000000000');
  assert.equal(outcome.code, undefined);
  assert.match(outcome.error, /invalid username or password/i);
});

await check('disabled user cannot sign in', async () => {
  const outcome = await authorizationCode(realm, 'lab-disabled', requiredEnv('TRUST_LAB_PW_DISABLED'));
  assert.equal(outcome.code, undefined);
  assert.match(outcome.error, /disabled/i);
});

await check('console client refuses the password grant (no login form bypass)', async () => {
  const response = await fetch(`${realm}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'trust-console', username: 'lab-reader',
      password: requiredEnv('TRUST_LAB_PW_READER'), scope: 'openid' }),
  });
  assert.ok([400, 401].includes(response.status), `password grant returned ${response.status}`);
});

await check('authenticated user without a role is refused (403)', async () => {
  const { access_token } = await human('lab-outsider', 'TRUST_LAB_PW_OUTSIDER');
  assert.equal(claims(access_token).payload.roles, undefined);
  assert.equal(await status('/v1/cas', access_token), 403);
  assert.equal(await status(`/v1/cas/${allowedCa}/certificates`, access_token), 403);
});

await check('profile editor role alone does not grant reads (least privilege)', async () => {
  const { access_token } = await human('lab-editor', 'TRUST_LAB_PW_EDITOR');
  assert.deepEqual(claims(access_token).payload.roles, ['trust-profile-editor']);
  assert.equal(await status('/v1/cas', access_token), 403);
  assert.equal(await status(`/v1/cas/${allowedCa}/profile-drafts`, access_token), 403);
});

await check('reader scoped to an ungranted CA sees nothing', async () => {
  const { access_token } = await human('lab-other-ca', 'TRUST_LAB_PW_OTHER_CA');
  assert.equal(await status(`/v1/cas/${allowedCa}`, access_token), 403);
  assert.ok([403, 404].includes(await status(`/v1/cas/${hiddenCa}`, access_token)));
  const list = await fetch(`${api}/v1/cas`, { headers: { authorization: `Bearer ${access_token}` } });
  assert.equal(list.status, 200);
  assert.deepEqual(await list.json(), []);
});

await check('workload client-credentials token is refused on human routes (401)', async () => {
  const workload = await clientCredentials(realm, 'trust-lab-workload', requiredEnv('TRUST_LAB_WORKLOAD_SECRET'));
  assert.ifError(workload.error);
  const { header, payload } = claims(workload.access_token);
  // Same issuer, audience, reader role, CA scope and database grant as a reader.
  assert.equal(header.typ, 'at+jwt');
  assert.equal(payload.azp, 'trust-lab-workload');
  assert.deepEqual(payload.roles, ['trust-ca-reader']);
  assert.deepEqual(payload.ca_ids, [allowedCa]);
  assert.equal(await status('/v1/cas', workload.access_token), 401);
  assert.equal(await status(`/v1/cas/${allowedCa}/audit`, workload.access_token), 401);
});

await check('workload with a wrong secret gets no token', async () => {
  const outcome = await clientCredentials(realm, 'trust-lab-workload', 'wrong-secret-000000000000000000');
  assert.ok(outcome.error);
});

await check('ID token presented as an access token is refused (401)', async () => {
  const { id_token } = await human('lab-reader', 'TRUST_LAB_PW_READER');
  assert.equal(claims(id_token).payload.aud, 'trust-console');
  assert.equal(await status('/v1/cas', id_token), 401);
});

await check('token from another realm of the same server is refused (401)', async () => {
  const foreign = await signIn(foreignRealm, 'foreign-reader', requiredEnv('TRUST_LAB_PW_FOREIGN'));
  assert.ifError(foreign.error);
  const { payload } = claims(foreign.access_token);
  // Same client name, audience, role and CA scope, and a database grant
  // under the foreign issuer: only the pinned issuer differs.
  assert.equal(payload.iss, foreignRealm);
  assert.equal(payload.azp, 'trust-console');
  assert.equal(await status('/v1/cas', foreign.access_token), 401);
});

await check('altered token signature or claims are refused (401)', async () => {
  const { access_token } = await human('lab-reader', 'TRUST_LAB_PW_READER');
  const [header, payload, signature] = access_token.split('.');
  const widened = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  widened.ca_ids = [allowedCa, hiddenCa];
  const forged = `${header}.${Buffer.from(JSON.stringify(widened)).toString('base64url')}.${signature}`;
  assert.equal(await status(`/v1/cas/${hiddenCa}`, forged), 401);
  const flipped = `${header}.${payload}.${signature.slice(0, -2)}${signature.at(-2) === 'A' ? 'B' : 'A'}${signature.at(-1)}`;
  assert.equal(await status('/v1/cas', flipped), 401);
});

await check('approvers are distinct, separately authenticated identities', async () => {
  const first = await human('lab-approver-1', 'TRUST_LAB_PW_APPROVER_1');
  const second = await human('lab-approver-2', 'TRUST_LAB_PW_APPROVER_2');
  const a = claims(first.access_token).payload;
  const b = claims(second.access_token).payload;
  assert.notEqual(a.sub, b.sub);
  assert.notEqual(a.sid, b.sid);
  assert.ok(a.roles.includes('trust-policy-approver') && b.roles.includes('trust-policy-approver'));
  // Neither approver can sign in with the other's password.
  const swapped = await authorizationCode(realm, 'lab-approver-1', requiredEnv('TRUST_LAB_PW_APPROVER_2'));
  assert.equal(swapped.code, undefined);
});

await check('no route accepts a write, whatever the role', async () => {
  const { access_token } = await human('lab-operator', 'TRUST_LAB_PW_OPERATOR');
  for (const path of ['/v1/cas', `/v1/cas/${allowedCa}/profile-drafts`]) {
    const code = await status(path, access_token, { method: 'POST' });
    assert.ok([404, 405].includes(code), `POST ${path} returned ${code}`);
  }
});

await check('users cannot edit their own CA scope or reach the account console', async () => {
  // Read-only inspection through the bootstrap administrator of the
  // disposable stack: the default role grants no account-console role, and
  // the user profile keeps unmanaged attributes such as ca_ids hidden and
  // read-only for users.
  const admin = await fetch(`${issuerOrigin}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'lab-admin',
      password: requiredEnv('TRUST_LAB_KC_ADMIN_PASSWORD') }),
  });
  assert.equal(admin.status, 200);
  const headers = { authorization: `Bearer ${(await admin.json()).access_token}` };
  const adminApi = `${issuerOrigin}/admin/realms/trust-lab`;
  const [account] = await (await fetch(`${adminApi}/clients?clientId=account`, { headers })).json();
  for (const user of ['7c1a0000-0000-4000-8000-000000000001', '7c1a0000-0000-4000-8000-000000000003']) {
    const accountRoles = await (await fetch(`${adminApi}/users/${user}/role-mappings/clients/${account.id}/composite`, { headers })).json();
    assert.deepEqual(accountRoles, []);
  }
  const profile = await (await fetch(`${adminApi}/users/profile`, { headers })).json();
  assert.ok(!profile.unmanagedAttributePolicy, `unmanaged attributes are ${profile.unmanagedAttributePolicy}`);
  assert.ok(!profile.attributes.some(attribute => attribute.name === 'ca_ids'));
});

await check('repeated wrong passwords lock the account temporarily', async () => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const outcome = await authorizationCode(realm, 'lab-outsider', `wrong-password-${attempt}-000000000`);
    assert.equal(outcome.code, undefined);
  }
  const locked = await authorizationCode(realm, 'lab-outsider', requiredEnv('TRUST_LAB_PW_OUTSIDER'));
  assert.equal(locked.code, undefined, 'the right password must be refused while the account is locked');
});

console.log(`Laboratory IAM negative suite passed: ${results.length} cases.`);
