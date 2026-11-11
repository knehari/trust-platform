// Laboratory sign-in diagnostic for one Keycloak account of the trust-lab
// realm. Keycloak answers "Invalid username or password" alike for a wrong
// password, a temporarily locked account and an unknown user; this tells them
// apart, with the laboratory administrator (lab-admin) and the passwords of
// the local .env.lab.
//
//   node frontend/dev/check-account.mjs lab-ra-officer            # diagnose
//   node frontend/dev/check-account.mjs lab-ra-officer --unlock   # and unlock
//
// Run from the repository root, with the stack up. It trusts the lab CA
// (.lab-keys/tls/ca.crt) whatever NODE_EXTRA_CA_CERTS says.
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const repository = fileURLToPath(new URL('../../', import.meta.url));
const caFile = join(repository, '.lab-keys', 'tls', 'ca.crt');
if (process.env.NODE_EXTRA_CA_CERTS !== caFile) {
  // Node reads NODE_EXTRA_CA_CERTS only at startup: run again with the lab CA.
  try {
    execFileSync(process.execPath, process.argv.slice(1), {
      stdio: 'inherit', env: { ...process.env, NODE_EXTRA_CA_CERTS: caFile },
    });
    process.exit(0);
  } catch (error) {
    process.exit(error.status ?? 1);
  }
}
const { signIn } = await import('./keycloak-login.mjs');

const [username, flag] = process.argv.slice(2);
if (!username || (flag && flag !== '--unlock')) {
  console.error('usage: node frontend/dev/check-account.mjs <username> [--unlock]');
  process.exit(2);
}
const env = Object.fromEntries(readFileSync(join(repository, '.env.lab'), 'utf8').split('\n')
  .filter(line => line.includes('=')).map(line => [line.slice(0, line.indexOf('=')), line.slice(line.indexOf('=') + 1)]));
// lab-ra-officer-2 -> TRUST_LAB_PW_RA_OFFICER_2
const variable = `TRUST_LAB_PW_${username.replace(/^lab-/, '').replace(/-/g, '_').toUpperCase()}`;
const base = 'https://127.0.0.1:8443';
const realm = `${base}/realms/trust-lab`;

const adminToken = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username: 'lab-admin',
    password: env.TRUST_LAB_KC_ADMIN_PASSWORD ?? '' }),
}).then(response => response.json()).then(body => body.access_token)
  .catch(error => { console.error(`Keycloak unreachable at ${base}: ${error.cause?.code ?? error.message}`); process.exit(1); });
if (!adminToken) {
  console.error('lab-admin cannot sign in: is .env.lab the one this stack was started with?');
  process.exit(1);
}
const admin = (path, method = 'GET') => fetch(`${base}/admin/realms/trust-lab${path}`,
  { method, headers: { authorization: `Bearer ${adminToken}` } });

const [user] = await admin(`/users?username=${encodeURIComponent(username)}&exact=true`).then(r => r.json());
if (!user) {
  console.log(`${username}: not in the trust-lab realm. The realm was imported by an older version;`);
  console.log('recreate the stack: scripts/lab/up.sh --reset');
  process.exit(1);
}
console.log(`${username}: exists, ${user.enabled ? 'enabled' : 'DISABLED'}` +
  (user.requiredActions?.length ? `, required actions: ${user.requiredActions.join(', ')}` : ''));
const lock = await admin(`/attack-detection/brute-force/users/${user.id}`).then(r => r.json());
console.log(`lockout: ${lock.disabled ? 'LOCKED' : 'not locked'}, ${lock.numFailures ?? 0} recent failure(s)`);
if (flag === '--unlock') {
  const status = (await admin(`/attack-detection/brute-force/users/${user.id}`, 'DELETE')).status;
  console.log(`unlock: ${status === 204 ? 'done' : `failed (${status})`}`);
}
if (!env[variable]) {
  console.log(`${variable} is not in .env.lab: run scripts/lab/init-env.sh, then scripts/lab/up.sh --reset`);
  process.exit(1);
}
const result = await signIn(realm, username, env[variable]);
if (result.error) {
  console.log(`sign-in with ${variable} from .env.lab: REFUSED (${result.error})`);
  console.log(lock.disabled && flag !== '--unlock'
    ? 'the account is locked: rerun with --unlock, then sign in with that password'
    : 'the realm holds another password than .env.lab: recreate the stack (scripts/lab/up.sh --reset)');
  process.exit(1);
}
console.log(`sign-in with ${variable} from .env.lab: OK`);
console.log(`In the browser, use exactly: grep '^${variable}=' .env.lab | cut -d= -f2`);
