// Laboratory helper: signs a test user in to the laboratory Keycloak realm
// through its real login form, with authorization code + PKCE, as the browser
// console does. It only parses Keycloak's own login page; it is not a general
// OIDC client and must not be used outside the disposable laboratory stack.
import { createHash, randomBytes } from 'node:crypto';

export const consoleOrigin = 'http://127.0.0.1:5173';
export const redirectUri = `${consoleOrigin}/auth/callback`;

function cookieJar() {
  const cookies = new Map();
  return {
    store(response) {
      for (const line of response.headers.getSetCookie()) {
        const [pair] = line.split(';');
        const index = pair.indexOf('=');
        if (index > 0) cookies.set(pair.slice(0, index).trim(), pair.slice(index + 1).trim());
      }
    },
    header() { return [...cookies].map(([name, value]) => `${name}=${value}`).join('; '); },
  };
}

function decodeEntities(value) {
  return value.replaceAll('&amp;', '&').replaceAll('&#x2F;', '/').replaceAll('&#47;', '/')
    .replaceAll('&quot;', '"').replaceAll('&#39;', "'");
}

// Returns {code} after a successful sign-in, or {error} with the page's
// visible outcome when Keycloak refuses it (wrong password, disabled user).
export async function authorizationCode(realmUrl, username, password, { clientId = 'trust-console', scope = 'openid profile' } = {}) {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const state = randomBytes(12).toString('base64url');
  const authorize = new URL(`${realmUrl}/protocol/openid-connect/auth`);
  for (const [key, value] of Object.entries({
    client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope, state,
    nonce: randomBytes(12).toString('base64url'), code_challenge_method: 'S256', code_challenge: challenge,
  })) authorize.searchParams.set(key, value);

  const jar = cookieJar();
  const page = await fetch(authorize, { redirect: 'manual' });
  jar.store(page);
  if (page.status !== 200) return { error: `authorize returned ${page.status}` };
  const html = await page.text();
  const action = html.match(/<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"/)?.[1];
  if (!action) return { error: 'no Keycloak login form' };

  const submitted = await fetch(decodeEntities(action), {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: jar.header() },
    body: new URLSearchParams({ username, password, credentialId: '' }),
  });
  if (submitted.status !== 302) {
    const body = await submitted.text();
    const message = body.match(/id="input-error"[^>]*>\s*([^<]+)/)?.[1]
      ?? body.match(/class="[^"]*kc-feedback-text[^"]*"[^>]*>\s*([^<]+)/)?.[1] ?? `status ${submitted.status}`;
    return { error: decodeEntities(message.trim()) };
  }
  const callback = new URL(submitted.headers.get('location'));
  if (`${callback.origin}${callback.pathname}` !== redirectUri) return { error: `unexpected redirect target ${callback.origin}${callback.pathname}` };
  if (callback.searchParams.get('state') !== state) return { error: 'state mismatch' };
  const code = callback.searchParams.get('code');
  if (!code) return { error: callback.searchParams.get('error') ?? 'no authorization code' };
  return { code, verifier, clientId };
}

export async function signIn(realmUrl, username, password, options) {
  const grant = await authorizationCode(realmUrl, username, password, options);
  if (grant.error) return grant;
  const exchange = await fetch(`${realmUrl}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', client_id: grant.clientId, redirect_uri: redirectUri,
      code: grant.code, code_verifier: grant.verifier,
    }),
  });
  if (exchange.status !== 200) return { error: `token exchange returned ${exchange.status}` };
  return exchange.json();
}

export async function clientCredentials(realmUrl, clientId, secret) {
  const response = await fetch(`${realmUrl}/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: secret }),
  });
  if (response.status !== 200) return { error: `client credentials returned ${response.status}` };
  return response.json();
}

export function claims(token) {
  const [header, payload] = token.split('.').slice(0, 2)
    .map(part => JSON.parse(Buffer.from(part, 'base64url').toString('utf8')));
  return { header, payload };
}

export function requiredEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set; load .env.lab (set -a; . ./.env.lab; set +a)`);
  return value;
}
