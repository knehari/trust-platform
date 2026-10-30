import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

const issuer = 'http://127.0.0.1:8080';
const api = 'http://127.0.0.1:8081';
const consoleOrigin = 'http://127.0.0.1:5173';
const allowedCa = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const hiddenCa = 'ffffffff-ffff-4fff-8fff-ffffffffffff';

const page = await fetch(consoleOrigin);
assert.equal(page.status, 200, 'console must serve over the published loopback port');

const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const authorize = new URL(`${issuer}/authorize`);
for (const [key, value] of Object.entries({
  client_id: 'trust-console',
  redirect_uri: `${consoleOrigin}/auth/callback`,
  response_type: 'code',
  scope: 'openid profile trust-ca-read',
  state: 'compose-smoke',
  code_challenge_method: 'S256',
  code_challenge: challenge,
})) authorize.searchParams.set(key, value);

const redirect = await fetch(authorize, { redirect: 'manual' });
assert.equal(redirect.status, 302);
const callback = new URL(redirect.headers.get('location'));
assert.equal(callback.origin, consoleOrigin);
assert.equal(callback.searchParams.get('state'), 'compose-smoke');
const code = callback.searchParams.get('code');
assert.ok(code);

const exchange = await fetch(`${issuer}/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code', client_id: 'trust-console',
    redirect_uri: `${consoleOrigin}/auth/callback`, code, code_verifier: verifier,
  }),
});
assert.equal(exchange.status, 200);
const { access_token } = await exchange.json();
assert.ok(access_token);

const headers = { authorization: `Bearer ${access_token}` };
assert.equal((await fetch(`${api}/v1/cas`)).status, 401);
const scoped = await fetch(`${api}/v1/cas`, { headers });
assert.equal(scoped.status, 200);
const cas = await scoped.json();
assert.deepEqual(cas.map((ca) => ca.ca_id), [allowedCa]);
assert.equal((await fetch(`${api}/v1/cas/${hiddenCa}`, { headers })).status, 403);
assert.equal((await fetch(`${api}/v1/cas/${allowedCa}`, { headers })).status, 200);
console.log('Laboratory smoke passed: console, code+PKCE, scoped PostgreSQL reads, and denials.');
