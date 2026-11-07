import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PROFILE_EDITOR_ROLE, tokenRoles } from '../src/roles.ts';
import { parseProfileDraftForm } from '../src/profile-draft-form.ts';
import { compareProfileRevisions } from '../src/profile-compare.ts';

const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');

test('token roles are read from the access token payload, as a display hint only', () => {
  assert.deepEqual(tokenRoles(`${encode({ alg: 'RS256' })}.${encode({ roles: [PROFILE_EDITOR_ROLE, 3, 'trust-ca-reader'] })}.sig`),
    [PROFILE_EDITOR_ROLE, 'trust-ca-reader']);
  assert.deepEqual(tokenRoles('not-a-jwt'), []);
  assert.deepEqual(tokenRoles(`${encode({})}.${encode({ roles: 'trust-profile-editor' })}.sig`), []);
  assert.deepEqual(tokenRoles(`${encode({})}.!!!.sig`), []);
});

const fields = {
  profileId: 'server-lab', displayName: ' Server proposal ', policyVersion: 'v2',
  maxValidityDays: '60', maxDnsSans: '3', zones: 'lab.invalid, apps.lab.invalid', suites: 'P256-SHA256',
};

test('the revision form sends exactly the bounded request body', () => {
  assert.deepEqual(parseProfileDraftForm(fields), { input: {
    profile_id: 'server-lab', display_name: 'Server proposal', policy_version: 'v2',
    max_validity_days: 60, max_dns_sans: 3,
    proposed_dns_zones: ['lab.invalid', 'apps.lab.invalid'], proposed_signature_suites: ['P256-SHA256'],
  } });
  for (const altered of [
    { profileId: 'Server' }, { displayName: '' }, { displayName: 'x'.repeat(256) }, { policyVersion: 'v\u0007' },
    { maxValidityDays: '0' }, { maxValidityDays: '826' }, { maxValidityDays: '9.5' }, { maxDnsSans: '101' },
    { zones: ' ' }, { suites: Array(17).fill('S').join(',') },
  ]) assert.ok('error' in parseProfileDraftForm({ ...fields, ...altered }), JSON.stringify(altered));
});

test('comparison accepts recorded lifecycle states only', () => {
  const base = { ca_id: 'ca', profile_id: 'server-lab', display_name: 'S', policy_version: 'v1', max_validity_days: 90,
    max_dns_sans: 5, proposed_dns_zones: ['lab.invalid'], proposed_signature_suites: ['P256-SHA256'], created_by: 'e',
    created_at: '2026-10-24T12:00:00.000Z', submitted_at: null, proposal_warnings: [], snapshot_sha256: 'a'.repeat(64) };
  const first = { ...base, revision: 1, status: 'SUBMITTED', submitted_at: '2026-10-25T12:00:00.000Z' };
  const second = { ...base, revision: 2, status: 'DRAFT' };
  assert.ok(compareProfileRevisions(first, second).length > 0);
  assert.ok(compareProfileRevisions({ ...first, status: 'APPROVED', approval_count: 2 }, second).length > 0);
  assert.throws(() => compareProfileRevisions({ ...first, status: 'ACTIVE' }, second));
});
