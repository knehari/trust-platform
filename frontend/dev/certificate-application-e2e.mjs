// Laboratory end-to-end check of certificate applications (migration 0029,
// ADR-0016) on the lab issuing CA, through Keycloak sign-ins and the
// management API of the Compose stack. It creates that CA through the CA
// lifecycle (ADR-0013 to ADR-0014), lets the database owner provision grants
// on it (TRUST_LAB_OWNER_PSQL, a psql command line for the owner), activates
// a profile through the profile lifecycle (ADR-0010 to ADR-0012), then
// submits OpenSSL CSRs. Approved applications are issued by the lab signer
// (ADR-0017) and the certificates are checked with `openssl verify` against
// the root that create-lab-root.sh made. The certificate is then revoked
// (a requester asks, a registration officer approves; ADR-0018) and the
// signed CRLs are checked with `openssl crl -verify` and
// `openssl verify -crl_check`.
// Run on a fresh stack with .env.lab loaded, after the other suites.
import assert from 'node:assert/strict';
import { execFileSync, execSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomUUID, sign as signBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { requiredEnv, signIn } from './keycloak-login.mjs';

const realm = 'http://127.0.0.1:8080/realms/trust-lab';
const api = 'http://127.0.0.1:8081';
const repository = fileURLToPath(new URL('../../', import.meta.url));
const issuingCa = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const caName = 'Lab Issuing CA';
const results = [];
const ownerPsql = requiredEnv('TRUST_LAB_OWNER_PSQL');

async function token(username, envName) {
  const session = await signIn(realm, username, requiredEnv(envName));
  assert.ifError(session.error);
  return session.access_token;
}

async function send(method, path, accessToken, body, key = randomUUID()) {
  const headers = { authorization: `Bearer ${accessToken}` };
  if (body !== undefined) Object.assign(headers, { 'content-type': 'application/json', 'idempotency-key': key });
  const response = await fetch(`${api}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

async function check(label, run) {
  await run();
  results.push(label);
  console.log(`ok - ${label}`);
}

const sign = (keyName, claim) => execFileSync('openssl', ['dgst', '-sha256', '-sign', join(repository, '.lab-keys', `${keyName}.pem`)], { input: claim }).toString('base64');
const keys = mkdtempSync(join(tmpdir(), 'trust-csr-'));
// A CSR made the way an applicant would: OpenSSL, a fresh P-256 key that
// never leaves this temporary directory.
const keyOf = new Map();
function csr(commonName) {
  const key = join(keys, `${randomUUID()}.pem`);
  keyOf.set(commonName, key);
  return execFileSync('openssl', ['req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
    '-keyout', key, '-subj', `/CN=${commonName}`, '-config', '/dev/null'], { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
}

const admin = await token('lab-ca-admin', 'TRUST_LAB_PW_CA_ADMIN');
const caApprovers = [await token('lab-ca-approver-1', 'TRUST_LAB_PW_CA_APPROVER_1'), await token('lab-ca-approver-2', 'TRUST_LAB_PW_CA_APPROVER_2')];
const author = await token('lab-author', 'TRUST_LAB_PW_AUTHOR');
const approvers = [await token('lab-approver-1', 'TRUST_LAB_PW_APPROVER_1'), await token('lab-approver-2', 'TRUST_LAB_PW_APPROVER_2')];
const operator = await token('lab-operator', 'TRUST_LAB_PW_OPERATOR');
let applicationId;
let serial;
let issuedCertificate;
const issuingRoot = join(repository, '.lab-keys', 'ca', 'ca-root-lab-issuing-ca.crt');
const openssl = (args, input) => execFileSync('openssl', args, { input, stdio: ['pipe', 'pipe', 'pipe'] }).toString();
// stdout and stderr together, and whether OpenSSL succeeded.
const opensslOutcome = args => {
  const run = spawnSync('openssl', args, { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
  return { ok: run.status === 0, output: `${run.stdout}${run.stderr}` };
};
let crlNumber;

try {
  await check('the lab issuing CA is proposed with its identifier, attested, approved and activated', async () => {
    const proposed = await send('POST', '/v1/ca-proposals', admin, { display_name: caName, policy_version: 'v1', suite_id: 'ecdsa-p256-sha256', ca_id: issuingCa });
    assert.deepEqual([proposed.status, proposed.body.ca_id], [201, issuingCa], 'run on a fresh stack: the issuing CA already exists');
    const root = execFileSync('sh', ['scripts/lab/create-lab-root.sh', caName], { cwd: repository }).toString();
    const base = `/v1/ca-proposals/${issuingCa}`;
    assert.equal((await send('POST', `${base}/issuer-certificate`, admin, { certificate_pem: root })).status, 201);
    let digest;
    for (const [index, approver] of caApprovers.entries()) {
      const claim = await send('POST', `${base}/decision-claims`, approver, { decision: 'approve' });
      digest = /certificate_sha256=([0-9a-f]{64})/.exec(claim.body.claim)[1];
      assert.equal((await send('POST', `${base}/decisions`, approver, { decision: 'approve', issued_at: claim.body.issued_at,
        signature_der_base64: sign(`lab-ca-approver-${index + 1}`, claim.body.claim) })).status, 201);
    }
    const active = await send('POST', `${base}/activation`, admin, { certificate_sha256: digest });
    assert.deepEqual([active.status, active.body.lifecycle_status], [201, 'ACTIVE']);
  });

  await check('the owner provisions grants; a profile revision is approved and activated for the CA', async () => {
    execSync(`${ownerPsql} -v ca=${issuingCa} -f -`, { input: readFileSync(join(repository, 'scripts/lab/provision-issuing-ca.sql')), stdio: ['pipe', 'ignore', 'inherit'] });
    const base = `/v1/cas/${issuingCa}/profile-drafts`;
    const draft = await send('POST', base, author, { profile_id: 'server', display_name: 'Lab server certificates', policy_version: 'v1',
      max_validity_days: 90, max_dns_sans: 3, proposed_dns_zones: ['lab.invalid'], proposed_signature_suites: ['ecdsa-p256-sha256'] });
    assert.equal(draft.status, 201);
    const revision = `${base}/server/${draft.body.revision}`;
    assert.equal((await send('POST', `${revision}/submission`, author, { snapshot_sha256: draft.body.snapshot_sha256 })).status, 201);
    for (const [index, approver] of approvers.entries()) {
      const claim = await send('POST', `${revision}/decision-claims`, approver, { decision: 'approve' });
      assert.equal((await send('POST', `${revision}/decisions`, approver, { decision: 'approve', issued_at: claim.body.issued_at,
        signature_der_base64: sign(`lab-approver-${index + 1}`, claim.body.claim) })).status, 201);
    }
    const activated = await send('POST', `${revision}/activation`, operator, { snapshot_sha256: draft.body.snapshot_sha256 });
    assert.deepEqual([activated.status, activated.body.status], [201, 'ACTIVE']);
  });

  const requester = await token('lab-requester', 'TRUST_LAB_PW_REQUESTER');
  const officer = await token('lab-ra-officer', 'TRUST_LAB_PW_RA_OFFICER');
  const applications = `/v1/cas/${issuingCa}/certificate-applications`;
  // A registration officer's signed decision (ADR-0028): the database builds
  // the claim; the officer signs it with their own key, like OpenSSL would.
  async function decide(id, token, keyName, decision, reason) {
    const base = `${applications}/${id}`;
    const claim = await send('POST', `${base}/decision-claims`, token, { decision });
    if (claim.status !== 200) return claim;
    return send('POST', `${base}/decision`, token, { decision, reason, issued_at: claim.body.issued_at,
      signature_der_base64: sign(keyName, claim.body.claim) });
  }
  const apply = (commonName, names, days = 30, pem = csr(commonName)) => send('POST', applications, requester,
    { profile_id: 'server', csr_pem: pem, common_name: commonName, dns_names: names, validity_days: days });

  await check('a requester submits an OpenSSL CSR within the profile; other requests are refused', async () => {
    assert.equal((await send('POST', applications, officer, { profile_id: 'server', csr_pem: csr('a.lab.invalid'),
      common_name: 'a.lab.invalid', dns_names: ['a.lab.invalid'], validity_days: 30 })).status, 403);
    assert.equal((await apply('www.example.com', ['www.example.com'])).status, 422);
    assert.equal((await apply('www.lab.invalid', ['www.lab.invalid'], 91)).status, 422);
    const mismatched = await apply('www.lab.invalid', ['www.lab.invalid'], 30, csr('other.lab.invalid'));
    assert.deepEqual([mismatched.status, mismatched.body.reason], [422, 'SubjectMismatch']);
    const submitted = await apply('www.lab.invalid', ['www.lab.invalid', 'api.lab.invalid'], 90);
    assert.deepEqual([submitted.status, submitted.body.status, submitted.body.revision], [201, 'SUBMITTED', 1]);
    applicationId = submitted.body.application_id;
  });

  await check('a registration officer, not the requester, approves the exact application once with a signed decision', async () => {
    const decision = `${applications}/${applicationId}/decision`;
    assert.equal((await send('POST', `${applications}/${applicationId}/decision-claims`, requester, { decision: 'approve' })).status, 403);
    const claim = await send('POST', `${applications}/${applicationId}/decision-claims`, officer, { decision: 'approve' });
    assert.equal(claim.status, 200);
    assert.match(claim.body.claim, new RegExp(`^trust-platform/issuance-authorization/v1;decision=approve;ca=${issuingCa};application=${applicationId};`));
    assert.match(claim.body.claim, /;subject_cn=www\.lab\.invalid;dns_names=www\.lab\.invalid,api\.lab\.invalid;validity_days=90;extensions=;key=lab-ra-officer-p256;/);
    // Signed by another officer's key, or unsigned: refused, nothing recorded.
    for (const signature of [sign('lab-ra-officer-2', claim.body.claim), sign('lab-approver-1', claim.body.claim)]) {
      assert.equal((await send('POST', decision, officer, { decision: 'approve', reason: 'checked',
        issued_at: claim.body.issued_at, signature_der_base64: signature })).status, 422);
    }
    assert.equal((await send('POST', decision, officer, { decision: 'approve', reason: 'checked' })).status, 400);
    const approved = await decide(applicationId, officer, 'lab-ra-officer', 'approve', 'names and key checked');
    assert.deepEqual([approved.status, approved.body.status], [201, 'APPROVED']);
    assert.equal((await decide(applicationId, officer, 'lab-ra-officer', 'reject', 'again')).status, 409);
    const listed = await send('GET', applications, officer);
    const mine = listed.body.find(item => item.application_id === applicationId);
    assert.deepEqual([mine.status, mine.subject_cn, mine.dns_names], ['APPROVED', 'www.lab.invalid', ['www.lab.invalid', 'api.lab.invalid']]);
  });

  await check('the lab signer issues the approved application once; OpenSSL verifies it against the root', async () => {
    const issuance = `${applications}/${applicationId}/issuance`;
    const issued = await send('POST', issuance, requester, {});
    assert.deepEqual([issued.status, issued.body.status], [201, 'ISSUED']);
    serial = issued.body.serial_hex;
    issuedCertificate = join(keys, 'issued.crt');
    const certificate = issuedCertificate;
    writeFileSync(certificate, issued.body.certificate_pem);
    assert.equal(openssl(['verify', '-CAfile', issuingRoot, '-purpose', 'sslserver', certificate]).trim(), `${certificate}: OK`);
    const text = openssl(['x509', '-in', certificate, '-noout', '-subject', '-ext', 'subjectAltName,basicConstraints,extendedKeyUsage']);
    assert.match(text, /subject=CN\s?=\s?www\.lab\.invalid/);
    assert.match(text, /DNS:www\.lab\.invalid, DNS:api\.lab\.invalid/);
    assert.match(text, /CA:FALSE/);
    assert.match(text, /TLS Web Server Authentication/);
    // It names the CA's public latest-CRL route (ADR-0019).
    const points = openssl(['x509', '-in', certificate, '-noout', '-ext', 'crlDistributionPoints']);
    assert.match(points, new RegExp(`URI:${api}/v1/public/crls/${issuingCa}/latest\\.crl`));
    // The certificate carries the applicant's own key, never the CA's.
    const applicantKey = openssl(['pkey', '-in', keyOf.get('www.lab.invalid'), '-pubout']);
    assert.equal(openssl(['x509', '-in', certificate, '-noout', '-pubkey']), applicantKey);
    assert.equal(openssl(['x509', '-in', certificate, '-noout', '-serial']).trim().toLowerCase(), `serial=${serial}`);
    // Asking again never signs again.
    const again = await send('POST', issuance, officer, {});
    assert.deepEqual([again.status, again.body.status, again.body.certificate_pem], [200, 'ISSUED', null]);
    const listed = await send('GET', applications, officer);
    const mine = listed.body.find(item => item.application_id === applicationId);
    assert.deepEqual([mine.status, mine.certificate_serial_hex], ['ISSUED', serial]);
  });

  const crls = `/v1/cas/${issuingCa}/crls`;
  const publish = async () => {
    const published = await send('POST', crls, officer, {});
    assert.deepEqual([published.status, published.body.status], [201, 'PUBLISHED']);
    const file = join(keys, `crl-${published.body.crl_number}.pem`);
    writeFileSync(file, published.body.crl_pem);
    return { published, file };
  };

  await check('a registration officer publishes a CRL signed by the lab signer; OpenSSL verifies it and the certificate', async () => {
    assert.equal((await send('POST', crls, requester, {})).status, 403);
    const { published, file } = await publish();
    assert.equal(published.body.entry_count, 0);
    crlNumber = published.body.crl_number;
    const verified = opensslOutcome(['crl', '-in', file, '-CAfile', issuingRoot, '-noout', '-verify']);
    assert.ok(verified.ok && /verify OK/.test(verified.output), verified.output);
    const checked = opensslOutcome(['verify', '-crl_check', '-CAfile', issuingRoot, '-CRLfile', file, issuedCertificate]);
    assert.ok(checked.ok, checked.output);
    // OpenSSL itself downloads the CRL from the certificate's distribution
    // point, without a token.
    const downloaded = opensslOutcome(['verify', '-crl_check', '-crl_download', '-CAfile', issuingRoot, issuedCertificate]);
    assert.ok(downloaded.ok, downloaded.output);
    const status = await send('GET', `/v1/cas/${issuingCa}/crl-status`, officer);
    assert.deepEqual([status.body.latest_crl_number, status.body.renewal_due, status.body.expired], [crlNumber, false, false]);
  });

  await check('the requester asks for revocation, a registration officer approves it, and the next CRL revokes the certificate', async () => {
    const requests = `${applications}/${applicationId}/revocation-requests`;
    assert.equal((await send('POST', requests, requester, { reason_code: 2, reason: 'not an end-entity reason' })).status, 400);
    const requested = await send('POST', requests, requester, { reason_code: 1, reason: 'private key exposed' });
    assert.deepEqual([requested.status, requested.body.status], [201, 'REVOCATION_REQUESTED']);
    assert.equal((await send('POST', requests, officer, { reason_code: 4, reason: 'again' })).status, 409);
    // The officer signs the revocation decision (ADR-0029); the signer checks
    // that signature again before it lists the serial.
    const decision = `${requests}/${requested.body.revocation_id}/decision`;
    const claims = `${requests}/${requested.body.revocation_id}/decision-claims`;
    assert.equal((await send('POST', claims, requester, { decision: 'approve' })).status, 403);
    assert.equal((await send('POST', decision, officer, { decision: 'approve', reason: 'unsigned' })).status, 400);
    const claim = await send('POST', claims, officer, { decision: 'approve' });
    assert.equal(claim.status, 200);
    assert.match(claim.body.claim, new RegExp(`^trust-platform/revocation-authorization/v1;decision=approve;ca=${issuingCa};application=${applicationId};revocation=${requested.body.revocation_id};serial=${serial};reason_code=1;key=lab-ra-officer-p256;`));
    const signedBody = (keyName, text) => ({ decision: 'approve', reason: 'exposure confirmed', issued_at: claim.body.issued_at,
      signature_der_base64: sign(keyName, text) });
    assert.equal((await send('POST', decision, officer, signedBody('lab-ra-officer-2', claim.body.claim))).status, 422);
    const decided = await send('POST', decision, officer, signedBody('lab-ra-officer', claim.body.claim));
    assert.deepEqual([decided.status, decided.body.status], [201, 'REVOKED']);
    const listed = await send('GET', applications, officer);
    const mine = listed.body.find(item => item.application_id === applicationId);
    assert.deepEqual([mine.status, mine.revocation_reason_code], ['REVOKED', 1]);
    // The inventory reports the recorded revocation beside the issuance state (migration 0033).
    const inventory = await send('GET', `/v1/cas/${issuingCa}/certificates/by-serial/${serial}`, officer);
    assert.equal(inventory.status, 200);
    assert.equal(inventory.body.state, 'SIGNED');
    assert.equal(inventory.body.revocation_reason, 1);
    assert.match(inventory.body.revoked_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);

    const { published, file } = await publish();
    assert.deepEqual([published.body.crl_number > crlNumber, published.body.entry_count], [true, 1]);
    const verified = opensslOutcome(['crl', '-in', file, '-CAfile', issuingRoot, '-noout', '-verify']);
    assert.ok(verified.ok && /verify OK/.test(verified.output), verified.output);
    const text = openssl(['crl', '-in', file, '-noout', '-text']);
    assert.match(text, new RegExp(`Serial Number: ${serial.toUpperCase()}`));
    assert.match(text, /Key Compromise/);
    assert.match(text, new RegExp(`X509v3 CRL Number:\\s+${published.body.crl_number}`));
    const checked = opensslOutcome(['verify', '-crl_check', '-CAfile', issuingRoot, '-CRLfile', file, issuedCertificate]);
    assert.ok(!checked.ok && /certificate revoked/.test(checked.output), checked.output);
    const downloaded = opensslOutcome(['verify', '-crl_check', '-crl_download', '-CAfile', issuingRoot, issuedCertificate]);
    assert.ok(!downloaded.ok && /certificate revoked/.test(downloaded.output), downloaded.output);
    const unauthenticated = await fetch(`${api}/v1/public/crls/${issuingCa}/latest.crl`);
    assert.deepEqual([unauthenticated.status, unauthenticated.headers.get('content-type')], [200, 'application/pkix-crl']);
    // Readers list the CRLs and fetch the same DER the officer received.
    const list = await send('GET', crls, officer);
    assert.deepEqual(list.body.map(item => item.crl_number).slice(0, 2), [published.body.crl_number, crlNumber]);
    const der = await fetch(`${api}${crls}/${published.body.crl_number}`, { headers: { authorization: `Bearer ${officer}` } });
    assert.equal(der.headers.get('content-type'), 'application/pkix-crl');
    const derFile = join(keys, 'fetched.crl');
    writeFileSync(derFile, Buffer.from(await der.arrayBuffer()));
    assert.equal(openssl(['crl', '-inform', 'DER', '-in', derFile, '-outform', 'PEM']), openssl(['crl', '-in', file, '-outform', 'PEM']));
  });

  await check('a rejected application, or one never decided, is not issued', async () => {
    const rejected = await apply('old.lab.invalid', ['old.lab.invalid']);
    assert.equal(rejected.status, 201);
    const pending = await apply('new.lab.invalid', ['new.lab.invalid']);
    assert.equal(pending.status, 201);
    assert.equal((await decide(rejected.body.application_id, officer, 'lab-ra-officer', 'reject', 'not needed')).status, 201);
    assert.equal((await send('POST', `${applications}/${rejected.body.application_id}/issuance`, officer, {})).status, 409);
    assert.equal((await send('POST', `${applications}/${pending.body.application_id}/issuance`, requester, {})).status, 409);
  });

  await check('in the console, an officer signs the approval, then the revocation, outside the browser (ADR-0028, ADR-0029)', async () => {
    const submitted = await apply('console.lab.invalid', ['console.lab.invalid']);
    assert.equal(submitted.status, 201);
    const { chromium } = await import('playwright');
    const browser = await chromium.launch({ headless: true,
      ...(process.env.TRUST_E2E_CHROME_PATH ? { executablePath: process.env.TRUST_E2E_CHROME_PATH } : {}) });
    try {
      const page = await browser.newPage();
      page.setDefaultTimeout(15_000);
      await page.goto(`http://127.0.0.1:5173/?view=requests&ca=${issuingCa}`);
      await page.getByRole('button', { name: /Sign in with your organization/i }).click();
      await page.locator('#username').fill('lab-ra-officer');
      await page.locator('#password').fill(requiredEnv('TRUST_LAB_PW_RA_OFFICER'));
      await page.locator('#kc-login').click();
      const row = page.getByRole('row').filter({ hasText: 'console.lab.invalid' });
      await row.getByRole('button', { name: 'Review' }).click();
      await page.getByLabel('Decision reason for console.lab.invalid').fill('names and key checked in the console');
      await page.getByRole('button', { name: 'Prepare approval' }).click();
      const claim = await page.getByLabel('Decision claim for console.lab.invalid').inputValue();
      assert.match(claim, new RegExp(`^trust-platform/issuance-authorization/v1;decision=approve;ca=${issuingCa};application=${submitted.body.application_id};`));
      // A signature by another key is refused, and nothing is recorded.
      await page.getByLabel('Decision signature for console.lab.invalid').fill(sign('lab-ra-officer-2', claim));
      await page.getByRole('button', { name: 'Record approval' }).click();
      await page.getByRole('alert').filter({ hasText: 'does not verify with your registered key' }).waitFor();
      await page.getByLabel('Decision signature for console.lab.invalid').fill(sign('lab-ra-officer', claim));
      await page.getByRole('button', { name: 'Record approval' }).click();
      await page.getByRole('status').filter({ hasText: 'approved with your signed decision' }).waitFor();
    } finally {
      await browser.close();
    }
    const item = (await send('GET', applications, officer)).body.find(row => row.application_id === submitted.body.application_id);
    assert.equal(item.status, 'APPROVED');
    const issued = await send('POST', `${applications}/${submitted.body.application_id}/issuance`, officer, {});
    assert.deepEqual([issued.status, issued.body.status], [201, 'ISSUED']);

    // The requester asks to revoke it; the officer signs the revocation in the
    // console with the generic claim form (ADR-0029).
    const asked = await send('POST', `${applications}/${submitted.body.application_id}/revocation-requests`, requester,
      { reason_code: 4, reason: 'replaced by a new certificate' });
    assert.equal(asked.status, 201);
    const again = await chromium.launch({ headless: true,
      ...(process.env.TRUST_E2E_CHROME_PATH ? { executablePath: process.env.TRUST_E2E_CHROME_PATH } : {}) });
    try {
      const page = await again.newPage();
      page.setDefaultTimeout(15_000);
      await page.goto(`http://127.0.0.1:5173/?view=requests&ca=${issuingCa}`);
      await page.getByRole('button', { name: /Sign in with your organization/i }).click();
      await page.locator('#username').fill('lab-ra-officer');
      await page.locator('#password').fill(requiredEnv('TRUST_LAB_PW_RA_OFFICER'));
      await page.locator('#kc-login').click();
      await page.getByRole('tab', { name: /Revocation requested/ }).click();
      const row = page.getByRole('row').filter({ hasText: 'console.lab.invalid' });
      await row.getByRole('button', { name: 'Review revocation' }).click();
      await page.getByLabel('Revocation decision reason for console.lab.invalid').fill('superseded, checked');
      await page.getByRole('button', { name: 'Prepare revocation approval' }).click();
      const claim = await page.getByLabel('Revocation of console.lab.invalid claim').inputValue();
      assert.match(claim, new RegExp(`^trust-platform/revocation-authorization/v1;decision=approve;ca=${issuingCa};application=${submitted.body.application_id};revocation=${asked.body.revocation_id};serial=${issued.body.serial_hex};reason_code=4;`));
      await page.getByLabel('Revocation of console.lab.invalid signature').fill(sign('lab-ra-officer', claim));
      await page.getByRole('button', { name: 'Record revocation' }).click();
      await page.getByRole('status').filter({ hasText: 'revoked with your signed decision' }).waitFor();
    } finally {
      await again.close();
    }
    const revoked = (await send('GET', applications, officer)).body.find(row => row.application_id === submitted.body.application_id);
    assert.equal(revoked.status, 'REVOKED');
  });

  await check('an approval recorded without a signed proof is never signed (ADR-0028)', async () => {
    const unsigned = await apply('unsigned.lab.invalid', ['unsigned.lab.invalid']);
    assert.equal(unsigned.status, 201);
    const id = unsigned.body.application_id;
    // What a compromised API could still write: an approval with no officer
    // signature. The issuance is refused before any intent is journaled.
    execSync(`${ownerPsql} -f -`, { stdio: ['pipe', 'ignore', 'inherit'], input: `
      SELECT 1 FROM decide_certificate_application_lab('${realm}', '7c1a0000-0000-4000-8000-000000000016', '${issuingCa}',
        '${id}', 'approve', 'no signature', gen_random_uuid(), digest('unsigned', 'sha256'));` });
    const item = async () => (await send('GET', applications, officer)).body.find(row => row.application_id === id);
    assert.equal((await item()).status, 'APPROVED');
    assert.equal((await send('POST', `${applications}/${id}/issuance`, officer, {})).status, 409);
    assert.equal((await item()).status, 'APPROVED', 'no intent journaled, nothing to reconcile');
  });

  await check('two registration officers void an ambiguous issuance; the next CRL lists its serial (ADR-0020)', async () => {
    const officer2 = await token('lab-ra-officer-2', 'TRUST_LAB_PW_RA_OFFICER_2');
    const submitted = await apply('void.lab.invalid', ['void.lab.invalid']);
    assert.equal(submitted.status, 201);
    const id = submitted.body.application_id;
    assert.equal((await decide(id, officer, 'lab-ra-officer', 'approve', 'checked')).status, 201);
    // The database owner reproduces what the API records when the signer
    // times out: issuance started, intent journaled, outcome ambiguous.
    // The signer never sees this intent, so it is never claimed.
    const officerSubject = '7c1a0000-0000-4000-8000-000000000016';
    execSync(`${ownerPsql} -f -`, { stdio: ['pipe', 'ignore', 'inherit'], input: `
      SELECT 1 FROM begin_application_issuance_lab('${realm}', '${officerSubject}', '${issuingCa}', '${id}', gen_random_uuid(), digest('void', 'sha256'));
      SELECT 1 FROM record_application_signing_intent_lab('${realm}', '${officerSubject}', '${issuingCa}', '${id}', 'lab-signer:timeout', digest('void-tbs', 'sha256'));
      SELECT mark_application_signing_uncertain_lab('${realm}', '${officerSubject}', '${issuingCa}', '${id}');` });
    const item = async () => (await send('GET', applications, officer)).body.find(row => row.application_id === id);
    assert.equal((await item()).status, 'RECONCILIATION_REQUIRED');
    // Never re-signed.
    assert.equal((await send('POST', `${applications}/${id}/issuance`, officer, {})).status, 409);

    const reason = { reason: 'signer timed out; no claim recorded' };
    assert.equal((await send('POST', `${applications}/${id}/void-proposal`, requester, reason)).status, 403);
    const proposed = await send('POST', `${applications}/${id}/void-proposal`, officer, reason);
    assert.deepEqual([proposed.status, proposed.body.void_status, proposed.body.signer_claimed], [201, 'PROPOSED', false]);
    assert.equal((await send('POST', `${applications}/${id}/void-proposal`, officer2, reason)).status, 409);
    // The confirming officer signs (ADR-0029); the proposer cannot confirm.
    const confirmClaim = async token => send('POST', `${applications}/${id}/void-confirmation-claims`, token, {});
    const confirmBody = (claim, keyName) => ({ ...reason, issued_at: claim.body.issued_at, signature_der_base64: sign(keyName, claim.body.claim) });
    const own = await confirmClaim(officer);
    assert.equal((await send('POST', `${applications}/${id}/void-confirmation`, officer, confirmBody(own, 'lab-ra-officer'))).status, 403);
    assert.equal((await send('POST', `${applications}/${id}/void-confirmation`, officer2, reason)).status, 400);
    const voidClaim = await confirmClaim(officer2);
    assert.match(voidClaim.body.claim, new RegExp(`^trust-platform/void-authorization/v1;ca=${issuingCa};application=${id};serial=[0-9a-f]+;signer_claimed=false;key=lab-ra-officer-2-p256;`));
    const key = randomUUID();
    const body = confirmBody(voidClaim, 'lab-ra-officer-2');
    const voided = await send('POST', `${applications}/${id}/void-confirmation`, officer2, body, key);
    assert.deepEqual([voided.status, voided.body.status], [201, 'VOIDED']);
    const replay = await send('POST', `${applications}/${id}/void-confirmation`, officer2, body, key);
    assert.deepEqual([replay.status, replay.body.voided_at], [200, voided.body.voided_at]);
    const listed = await item();
    assert.deepEqual([listed.status, listed.void_status, listed.void_serial_hex, listed.void_proposed_by_reader],
      ['VOIDED', 'VOIDED', voided.body.serial_hex, true]);

    const { published, file } = await publish();
    const verified = opensslOutcome(['crl', '-in', file, '-CAfile', issuingRoot, '-noout', '-verify']);
    assert.ok(verified.ok && /verify OK/.test(verified.output), verified.output);
    const text = openssl(['crl', '-in', file, '-noout', '-text']);
    assert.match(text, new RegExp(`Serial Number: ${voided.body.serial_hex.toUpperCase()}`));
    assert.ok(published.body.entry_count >= 2, `entry count ${published.body.entry_count}`);
  });

  await check('a registered RA system obtains, then revokes, a certificate with requests it signs, without a user token (ADR-0025, ADR-0026)', async () => {
    // The RA's own key: ephemeral here, registered by the database owner.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicKey.export({ format: 'jwk' });
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    execSync(`${ownerPsql} -f -`, { input: `
      INSERT INTO ra_system (ra_id, display_name, public_key_sec1) VALUES ('lab-ra-e2e', 'E2E RA', '\\x${point.toString('hex')}');
      INSERT INTO ra_profile_grant (ra_id, ca_id, profile_id) VALUES ('lab-ra-e2e', '${issuingCa}', 'server');
      INSERT INTO management_role_grant (issuer, subject, ca_id, lifecycle_role)
        VALUES ('urn:trust-platform:ra', 'lab-ra-e2e', '${issuingCa}', 'certificate-requester');` });
    const csrDer = execFileSync('openssl', ['req', '-outform', 'DER'], { input: csr('ra.lab.invalid'), stdio: ['pipe', 'pipe', 'ignore'] });
    const text = value => { const bytes = Buffer.from(value, 'utf8'); const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length); return Buffer.concat([length, bytes]); };
    const uuidBytes = value => Buffer.from(value.replaceAll('-', ''), 'hex');
    // trust_pki_core::ra_request::ra_issuance_message, built independently.
    const body = (requestId, names, signedAt, key = privateKey, v2 = null, der = csrDer) => {
      const count = Buffer.alloc(4); count.writeUInt32BE(names.length);
      const validity = Buffer.alloc(4); validity.writeUInt32BE(30);
      const when = Buffer.alloc(8); when.writeBigInt64BE(BigInt(signedAt));
      const fields = [text('lab-ra-e2e'), uuidBytes(issuingCa), text('server'), uuidBytes(requestId),
        execFileSync('openssl', ['dgst', '-sha256', '-binary'], { input: der }), count, ...names.map(text), validity, when];
      // Version 2 (ADR-0028) also signs the subject CN and the extensions.
      const extensions = v2?.extensions ?? [];
      const extensionCount = Buffer.alloc(4); extensionCount.writeUInt32BE(extensions.length);
      const message = v2
        ? Buffer.concat([Buffer.from('trust-platform:ra-issuance-request:v2\0'), ...fields, text(v2.subject_cn), extensionCount, ...extensions.map(text)])
        : Buffer.concat([Buffer.from('trust-platform:ra-issuance-request:v1\0'), ...fields]);
      return { ra_id: 'lab-ra-e2e', request_id: requestId, profile_id: 'server', csr_der_base64: der.toString('base64'),
        dns_names: names, validity_days: 30, signed_at: signedAt, signature_der_base64: signBytes('sha256', message, key).toString('base64'),
        ...(v2 ? { subject_cn: v2.subject_cn, extensions } : {}) };
    };
    const post = async payload => {
      const response = await fetch(`${api}/v1/ra/cas/${issuingCa}/certificates`, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
      const raw = await response.text();
      return { status: response.status, body: raw ? JSON.parse(raw) : null };
    };
    const now = Math.floor(Date.now() / 1000);
    const requestId = randomUUID();
    const names = ['ra.lab.invalid', 'www.ra.lab.invalid'];
    const stranger = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
    assert.equal((await post(body(requestId, names, now, stranger))).status, 401, 'another key');
    assert.equal((await post(body(requestId, names, now - 900))).status, 401, 'a stale request');
    const issued = await post(body(requestId, names, now));
    assert.deepEqual([issued.status, issued.body.status], [201, 'ISSUED']);
    const file = join(keys, 'ra-issued.pem');
    writeFileSync(file, issued.body.certificate_pem);
    const verified = opensslOutcome(['verify', '-CAfile', issuingRoot, '-purpose', 'sslserver', '-verify_hostname', 'www.ra.lab.invalid', file]);
    assert.ok(verified.ok && /: OK/.test(verified.output), verified.output);
    const replay = await post(body(requestId, names, now));
    assert.deepEqual([replay.status, replay.body.certificate_sha256], [200, issued.body.certificate_sha256]);
    assert.equal((await post(body(requestId, ['ra.lab.invalid'], now))).status, 409, 'same id, other request');

    // Version 2: the CSR names "typo.lab.invalid"; the RA signs the subject it
    // validated and client authentication, once the owner allows it.
    const typoDer = execFileSync('openssl', ['req', '-outform', 'DER'], { input: csr('typo.lab.invalid'), stdio: ['pipe', 'pipe', 'ignore'] });
    const v2Names = ['ra2.lab.invalid', 'www.ra2.lab.invalid'];
    const v2 = { subject_cn: 'www.ra2.lab.invalid', extensions: ['client-auth'] };
    assert.equal((await post(body(randomUUID(), v2Names, now, privateKey, null, typoDer))).status, 422, 'v1 with a CSR naming another subject');
    assert.equal((await post(body(randomUUID(), v2Names, now, privateKey, v2, typoDer))).status, 422, 'client-auth not allowed yet');
    execSync(`${ownerPsql} -f -`, { input: `INSERT INTO profile_optional_extension (ca_id, profile_id, extension)
      VALUES ('${issuingCa}', 'server', 'client-auth') ON CONFLICT DO NOTHING;` });
    const corrected = await post(body(randomUUID(), v2Names, now, privateKey, v2, typoDer));
    assert.deepEqual([corrected.status, corrected.body.status], [201, 'ISSUED']);
    const correctedFile = join(keys, 'ra-corrected.pem');
    writeFileSync(correctedFile, corrected.body.certificate_pem);
    const correctedText = openssl(['x509', '-in', correctedFile, '-noout', '-subject', '-ext', 'extendedKeyUsage']);
    assert.match(correctedText, /subject=CN\s?=\s?www\.ra2\.lab\.invalid/);
    assert.match(correctedText, /TLS Web Server Authentication, TLS Web Client Authentication/);
    for (const purpose of ['sslserver', 'sslclient']) {
      const ok = opensslOutcome(['verify', '-CAfile', issuingRoot, '-purpose', purpose, correctedFile]);
      assert.ok(ok.ok && /: OK/.test(ok.output), `${purpose}: ${ok.output}`);
    }

    // The RA revokes it with a signed request (ADR-0026); the next CRL lists it.
    const serialBytes = Buffer.from(issued.body.serial_hex, 'hex');
    const reason = 'subscriber reported a key compromise';
    const revocation = (id, signedAt, key = privateKey) => {
      const length = Buffer.alloc(4); length.writeUInt32BE(serialBytes.length);
      const code = Buffer.alloc(2); code.writeUInt16BE(1);
      const when = Buffer.alloc(8); when.writeBigInt64BE(BigInt(signedAt));
      // trust_pki_core::ra_request::ra_revocation_message, built independently.
      const message = Buffer.concat([Buffer.from('trust-platform:ra-revocation-request:v1\0'), text('lab-ra-e2e'),
        uuidBytes(issuingCa), uuidBytes(id), length, serialBytes, code, text(reason), when]);
      return { ra_id: 'lab-ra-e2e', request_id: id, serial_hex: issued.body.serial_hex, reason_code: 1, reason,
        signed_at: signedAt, signature_der_base64: signBytes('sha256', message, key).toString('base64') };
    };
    const revoke = async payload => {
      const response = await fetch(`${api}/v1/ra/cas/${issuingCa}/revocations`, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });
      const raw = await response.text();
      return { status: response.status, body: raw ? JSON.parse(raw) : null };
    };
    // The owner turns on publication on revocation for this CA (ADR-0027):
    // nobody publishes by hand below.
    execSync(`${ownerPsql} -f -`, { input: `INSERT INTO ca_crl_policy (ca_id, publish_on_revocation) VALUES ('${issuingCa}', true)
      ON CONFLICT (ca_id) DO UPDATE SET publish_on_revocation = true, updated_at = clock_timestamp();` });
    const reader = await token('lab-ra-officer', 'TRUST_LAB_PW_RA_OFFICER');
    const before = (await send('GET', `/v1/cas/${issuingCa}/crl-status`, reader)).body;
    assert.deepEqual([before.publish_on_revocation, before.unpublished_entries], [true, 0]);
    const revocationId = randomUUID();
    assert.equal((await revoke(revocation(revocationId, now, stranger))).status, 401, 'revocation with another key');
    const revoked = await revoke(revocation(revocationId, now));
    assert.deepEqual([revoked.status, revoked.body.status], [201, 'REVOKED']);
    const again = await revoke(revocation(revocationId, now));
    assert.deepEqual([again.status, again.body.revoked_at], [200, revoked.body.revoked_at]);
    // The platform publishes the next CRL by itself, at once.
    const deadline = Date.now() + 30_000;
    let status;
    for (;;) {
      status = (await send('GET', `/v1/cas/${issuingCa}/crl-status`, reader)).body;
      if (status.latest_crl_number > before.latest_crl_number && status.unpublished_entries === 0) break;
      assert.ok(Date.now() < deadline, `no CRL published on revocation: ${JSON.stringify(status)}`);
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    // Relying parties fetch it from the public distribution point.
    const latest = await fetch(`${api}/v1/public/crls/${issuingCa}/latest.crl`);
    assert.equal(latest.status, 200);
    const crlDer = join(keys, 'on-revocation.crl');
    writeFileSync(crlDer, Buffer.from(await latest.arrayBuffer()));
    const crlFile = join(keys, 'on-revocation.pem');
    openssl(['crl', '-inform', 'DER', '-in', crlDer, '-out', crlFile]);
    const checked = opensslOutcome(['verify', '-crl_check', '-CAfile', issuingRoot, '-CRLfile', crlFile, file]);
    assert.ok(!checked.ok && /certificate revoked/.test(checked.output), checked.output);
  });

  await check('the API seals committed audit events into the tamper-evident chain (ADR-0022)', async () => {
    // A fresh token: the sealing pass may take up to the configured interval.
    const reader = await token('lab-ra-officer', 'TRUST_LAB_PW_RA_OFFICER');
    const path = `/v1/cas/${issuingCa}/audit?event_type=certificate.application.voided`;
    const deadline = Date.now() + 90_000;
    let events = [];
    for (;;) {
      const listed = await send('GET', path, reader);
      assert.equal(listed.status, 200);
      events = listed.body;
      assert.ok(events.length >= 1, 'the void was audited');
      assert.ok(events.every(event => typeof event.chain_sealed === 'boolean'), 'every event reports its seal');
      if (events.every(event => event.chain_sealed)) break;
      assert.ok(Date.now() < deadline, 'events still unsealed after 90 s: is TRUST_AUDIT_SEAL_INTERVAL_SECONDS set?');
      await new Promise(resolve => setTimeout(resolve, 2_000));
    }
    const detail = await send('GET', `/v1/cas/${issuingCa}/audit/${events[0].event_id}`, reader);
    assert.deepEqual([detail.status, detail.body.chain_sealed], [200, true]);
    // Readers learn only the flag, never the global sequence or hashes.
    assert.deepEqual(Object.keys(detail.body).sort(), ['ca_id', 'chain_sealed', 'decision', 'event_id', 'event_type', 'policy_version', 'recorded_at']);
  });

  await check('the lab signer signs a checkpoint of the sealed chain with its audit key (ADR-0023)', async () => {
    // Read as the database owner: checkpoints are not exposed to readers.
    const query = "SELECT count(*) || ':' || coalesce(max(c.seq), 0) || ':' || \
      coalesce(bool_and(c.chain_hash = l.chain_hash AND octet_length(c.key_id) = 32), false) \
      FROM audit_chain_checkpoint c JOIN audit_chain_link l USING (seq)";
    const deadline = Date.now() + 120_000;
    for (;;) {
      const [count, seq, matches] = execSync(`${ownerPsql} -At -f -`, { input: query }).toString().trim().split(':');
      if (Number(count) > 0) {
        assert.equal(matches, 'true', 'every checkpoint names its link hash');
        assert.ok(Number(seq) > 0);
        break;
      }
      assert.ok(Date.now() < deadline, 'no checkpoint after 120 s: is TRUST_AUDIT_CHECKPOINT_INTERVAL_SECONDS set and the signer given an audit key?');
      await new Promise(resolve => setTimeout(resolve, 3_000));
    }
  });
} finally {
  rmSync(keys, { recursive: true, force: true });
  rmSync(join(repository, '.lab-keys', 'ca', 'ca-root-lab-issuing-ca.pem'), { force: true });
  rmSync(issuingRoot, { force: true });
}

console.log(`Laboratory certificate application suite passed: ${results.length} cases (application ${applicationId}; certificate serial ${serial}, revoked; CRLs from ${crlNumber}).`);
