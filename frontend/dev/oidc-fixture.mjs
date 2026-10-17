// Loopback-only, auto-approved OIDC fixture. NO human authentication.
// Never bind this process to a public interface or use it for real users.
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';

const origin = 'http://127.0.0.1:8080';
const consoleOrigin = 'http://127.0.0.1:5173';
const redirectUri = `${consoleOrigin}/auth/callback`;
const caId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'ephemeral-lab', use: 'sig', alg: 'RS256' };
const pending = new Map();

function json(response, status, body) {
  response.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store',
    'access-control-allow-origin': consoleOrigin,
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'GET, POST, OPTIONS' });
  response.end(JSON.stringify(body));
}

function jwt(header, claims) {
  const base64url = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const body = `${base64url(header)}.${base64url(claims)}`;
  const signature = createSign('RSA-SHA256').update(body).end().sign(privateKey).toString('base64url');
  return `${body}.${signature}`;
}

function bad(response) { json(response, 400, { error: 'invalid_request' }); }

createServer(async (request, response) => {
  const url = new URL(request.url, origin);
  process.stdout.write(`${request.method} ${url.pathname}\n`);
  if (request.method === 'OPTIONS') { json(response, 200, {}); return; }
  if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
    json(response, 200, { issuer: origin, authorization_endpoint: `${origin}/authorize`,
      token_endpoint: `${origin}/token`, jwks_uri: `${origin}/jwks`,
      end_session_endpoint: `${origin}/logout`, response_types_supported: ['code'],
      subject_types_supported: ['public'], id_token_signing_alg_values_supported: ['RS256'],
      code_challenge_methods_supported: ['S256'] });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/jwks') { json(response, 200, { keys: [jwk] }); return; }
  if (request.method === 'GET' && url.pathname === '/authorize') {
    const q = url.searchParams;
    process.stdout.write(`authorize checks: client=${q.get('client_id') === 'trust-console'} redirect=${q.get('redirect_uri') === redirectUri} response=${q.get('response_type') === 'code'} pkce=${q.get('code_challenge_method') === 'S256' && !!q.get('code_challenge')} state=${!!q.get('state')} nonce=${!!q.get('nonce')} scope=${q.get('scope')?.includes('openid')}\n`);
    if (q.get('client_id') !== 'trust-console' || q.get('redirect_uri') !== redirectUri ||
        q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256' ||
        !q.get('code_challenge') || !q.get('state') ||
        !q.get('scope')?.includes('openid')) { bad(response); return; }
    const code = randomBytes(24).toString('base64url');
    pending.set(code, { challenge: q.get('code_challenge'), nonce: q.get('nonce'), expires: Date.now() + 60_000 });
    const next = new URL(redirectUri);
    next.searchParams.set('code', code);
    next.searchParams.set('state', q.get('state'));
    response.writeHead(302, { location: next.toString(), 'cache-control': 'no-store' });
    response.end();
    return;
  }
  if (request.method === 'POST' && url.pathname === '/token') {
    let raw = '';
    for await (const chunk of request) { raw += chunk; if (raw.length > 8192) { bad(response); return; } }
    const form = new URLSearchParams(raw);
    const code = form.get('code');
    const entry = pending.get(code);
    pending.delete(code);
    const verifier = form.get('code_verifier');
    const challenge = verifier && createHash('sha256').update(verifier).digest('base64url');
    if (form.get('grant_type') !== 'authorization_code' || form.get('client_id') !== 'trust-console' ||
        form.get('redirect_uri') !== redirectUri || !entry || entry.expires < Date.now() || challenge !== entry.challenge) {
      json(response, 400, { error: 'invalid_grant' }); return;
    }
    const now = Math.floor(Date.now() / 1000);
    const common = { iss: origin, sub: 'lab-operator', iat: now, nbf: now - 1, exp: now + 300 };
    const access_token = jwt({ alg: 'RS256', typ: 'at+jwt', kid: jwk.kid },
      { ...common, aud: 'trust-api', roles: ['trust-ca-reader'], ca_ids: [caId] });
    const id_token = jwt({ alg: 'RS256', typ: 'JWT', kid: jwk.kid },
      { ...common, aud: 'trust-console', ...(entry.nonce ? { nonce: entry.nonce } : {}), preferred_username: 'Lab Operator' });
    json(response, 200, { access_token, id_token, token_type: 'Bearer', expires_in: 300, scope: 'openid profile trust-ca-read' });
    return;
  }
  if (request.method === 'GET' && url.pathname === '/logout') {
    const next = url.searchParams.get('post_logout_redirect_uri');
    if (next !== consoleOrigin && next !== `${consoleOrigin}/`) { bad(response); return; }
    response.writeHead(302, { location: next, 'cache-control': 'no-store' }); response.end(); return;
  }
  json(response, 404, { error: 'not_found' });
}).listen(8080, '127.0.0.1', () => {
  process.stdout.write(`Disposable OIDC fixture listening on ${origin}\n`);
});
