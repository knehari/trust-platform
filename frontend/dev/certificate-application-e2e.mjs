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
    const decision = `${requests}/${requested.body.revocation_id}/decision`;
    assert.equal((await send('POST', decision, requester, { decision: 'approve', reason: 'self' })).status, 403);
    const decided = await send('POST', decision, officer, { decision: 'approve', reason: 'exposure confirmed' });
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
    const decision = `${applications}/${rejected.body.application_id}/decision`;
    assert.equal((await send('POST', decision, officer, { decision: 'reject', reason: 'not needed' })).status, 201);
    assert.equal((await send('POST', `${applications}/${rejected.body.application_id}/issuance`, officer, {})).status, 409);
    assert.equal((await send('POST', `${applications}/${pending.body.application_id}/issuance`, requester, {})).status, 409);
  });

  await check('two registration officers void an ambiguous issuance; the next CRL lists its serial (ADR-0020)', async () => {
    const officer2 = await token('lab-ra-officer-2', 'TRUST_LAB_PW_RA_OFFICER_2');
    const submitted = await apply('void.lab.invalid', ['void.lab.invalid']);
    assert.equal(submitted.status, 201);
    const id = submitted.body.application_id;
    assert.equal((await send('POST', `${applications}/${id}/decision`, officer, { decision: 'approve', reason: 'checked' })).status, 201);
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
    assert.equal((await send('POST', `${applications}/${id}/void-confirmation`, officer, reason)).status, 403);
    const key = randomUUID();
    const voided = await send('POST', `${applications}/${id}/void-confirmation`, officer2, reason, key);
    assert.deepEqual([voided.status, voided.body.status], [201, 'VOIDED']);
    const replay = await send('POST', `${applications}/${id}/void-confirmation`, officer2, reason, key);
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
} finally {
  rmSync(keys, { recursive: true, force: true });
  rmSync(join(repository, '.lab-keys', 'ca', 'ca-root-lab-issuing-ca.pem'), { force: true });
  rmSync(issuingRoot, { force: true });
}

console.log(`Laboratory certificate application suite passed: ${results.length} cases (application ${applicationId}; certificate serial ${serial}, revoked; CRLs from ${crlNumber}).`);
