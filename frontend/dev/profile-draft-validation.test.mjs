import assert from 'node:assert/strict';
import { test } from 'node:test';
import { requireProfileDraft, requireProfileDraftPage } from '../src/profile-draft-validation.ts';

const caId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const valid = {
  ca_id: caId, profile_id: 'server-lab', revision: 2,
  display_name: 'Laboratory server proposal', policy_version: 'v2',
  max_validity_days: 90, max_dns_sans: 5,
  proposed_dns_zones: ['lab.invalid'], proposed_signature_suites: ['P256-SHA256'],
  created_by: 'synthetic-editor', created_at: '2026-10-24T12:00:00.000Z',
  status: 'DRAFT', proposal_warnings: [], snapshot_sha256: 'a'.repeat(64),
};

test('profile proposal reads retain only allowed fields and exact identity', () => {
  const result = requireProfileDraft({ ...valid, private_key: 'must-not-copy' }, caId, { id: 'server-lab', revision: 2 });
  assert.deepEqual(result, valid);
  assert.deepEqual(requireProfileDraftPage([valid], caId), [valid]);
});

test('profile proposal reads reject scope, revision and malformed policy metadata', () => {
  for (const altered of [
    { ca_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff' },
    { profile_id: '../other' }, { revision: 0 }, { status: 'ACTIVE' },
    { proposed_dns_zones: null }, { proposed_signature_suites: [null] },
    { max_validity_days: -1 }, { proposal_warnings: 'none' },
    { snapshot_sha256: 'not-a-digest' }, { created_at: 'invalid' },
  ]) assert.throws(() => requireProfileDraft({ ...valid, ...altered }, caId));
  assert.throws(() => requireProfileDraft(valid, caId, { id: 'server-lab', revision: 1 }), /did not match/);
  assert.throws(() => requireProfileDraftPage([valid, { ...valid, status: 'ACTIVE' }], caId));
  assert.throws(() => requireProfileDraftPage(Array(101).fill(valid), caId), /invalid profile proposal page/);
});
