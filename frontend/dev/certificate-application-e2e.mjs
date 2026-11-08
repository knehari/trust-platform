// Laboratory end-to-end check of certificate applications (migration 0028,
// ADR-0016) on the lab issuing CA, through Keycloak sign-ins and the
// management API of the Compose stack. It creates that CA through the CA
// lifecycle (ADR-0013 to ADR-0014), lets the database owner provision grants
// on it (TRUST_LAB_OWNER_PSQL, a psql command line for the owner), activates
// a profile through the profile lifecycle (ADR-0010 to ADR-0012), then
// submits OpenSSL CSRs. Approved applications are issued by the lab signer
// (ADR-0017) and the certificates are checked with `openssl verify` against
// the root that create-lab-root.sh made.
// Run on a fresh stack with .env.lab loaded, after the other suites.
import assert from 'node:assert/strict';
import { execFileSync, execSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
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
const issuingRoot = join(repository, '.lab-keys', 'ca', 'ca-root-lab-issuing-ca.crt');
const openssl = (args, input) => execFileSync('openssl', args, { input, stdio: ['pipe', 'pipe', 'pipe'] }).toString();

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

  await check('a registration officer, not the requester, approves the exact application once', async () => {
    const decision = `${applications}/${applicationId}/decision`;
    assert.equal((await send('POST', decision, requester, { decision: 'approve', reason: 'self' })).status, 403);
    const approved = await send('POST', decision, officer, { decision: 'approve', reason: 'names and key checked' });
    assert.deepEqual([approved.status, approved.body.status], [201, 'APPROVED']);
    assert.equal((await send('POST', decision, officer, { decision: 'reject', reason: 'again' })).status, 409);
    const listed = await send('GET', applications, officer);
    const mine = listed.body.find(item => item.application_id === applicationId);
    assert.deepEqual([mine.status, mine.subject_cn, mine.dns_names], ['APPROVED', 'www.lab.invalid', ['www.lab.invalid', 'api.lab.invalid']]);
  });

  await check('the lab signer issues the approved application once; OpenSSL verifies it against the root', async () => {
    const issuance = `${applications}/${applicationId}/issuance`;
    const issued = await send('POST', issuance, requester, {});
    assert.deepEqual([issued.status, issued.body.status], [201, 'ISSUED']);
    serial = issued.body.serial_hex;
    const certificate = join(keys, 'issued.crt');
    writeFileSync(certificate, issued.body.certificate_pem);
    assert.equal(openssl(['verify', '-CAfile', issuingRoot, '-purpose', 'sslserver', certificate]).trim(), `${certificate}: OK`);
    const text = openssl(['x509', '-in', certificate, '-noout', '-subject', '-ext', 'subjectAltName,basicConstraints,extendedKeyUsage']);
    assert.match(text, /subject=CN\s?=\s?www\.lab\.invalid/);
    assert.match(text, /DNS:www\.lab\.invalid, DNS:api\.lab\.invalid/);
    assert.match(text, /CA:FALSE/);
    assert.match(text, /TLS Web Server Authentication/);
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

  await check('a rejected application, or one never decided, is not issued', async () => {
    const rejected = await apply('old.lab.invalid', ['old.lab.invalid']);
    assert.equal(rejected.status, 201);
    const pending = await apply('new.lab.invalid', ['new.lab.invalid']);
    assert.equal(pending.status, 201);
    const decision = `${applications}/${rejected.body.application_id}/decision`;
    assert.equal((await send('POST', decision, officer, { decision: 'reject', reason: 'not needed' })).status, 201);
    assert.equal((await send('POST', `${applications}/${rejected.body.application_id}/issuance`, officer, {})).status, 409);
    assert.equal((await send('POST', `${applications}/${pending.body.application_id}/issuance`, requester, {})).status, 409);
  });
} finally {
  rmSync(keys, { recursive: true, force: true });
  rmSync(join(repository, '.lab-keys', 'ca', 'ca-root-lab-issuing-ca.pem'), { force: true });
  rmSync(issuingRoot, { force: true });
}

console.log(`Laboratory certificate application suite passed: ${results.length} cases (application ${applicationId}; certificate serial ${serial}).`);
