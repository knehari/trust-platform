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
  status: 'DRAFT', submitted_at: null, approval_count: 0, decided_at: null, activated_at: null, ended_at: null, proposal_warnings: [], snapshot_sha256: 'a'.repeat(64),
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
    { status: 'APPROVED' }, { submitted_at: '2026-10-25T12:00:00.000Z' },
    { status: 'SUBMITTED' }, { status: 'SUBMITTED', submitted_at: 'yesterday' },
  ]) assert.throws(() => requireProfileDraft({ ...valid, ...altered }, caId));
  assert.throws(() => requireProfileDraft(valid, caId, { id: 'server-lab', revision: 1 }), /did not match/);
  assert.throws(() => requireProfileDraftPage([valid, { ...valid, status: 'ACTIVE' }], caId));
  assert.throws(() => requireProfileDraftPage(Array(101).fill(valid), caId), /invalid profile proposal page/);
});

test('submitted revisions carry their submission time; drafts carry none', () => {
  const submitted = { ...valid, status: 'SUBMITTED', submitted_at: '2026-10-25T12:00:00.000Z' };
  assert.deepEqual(requireProfileDraft(submitted, caId), submitted);
  const { submitted_at: _omitted, ...withoutField } = valid;
  assert.equal(requireProfileDraft(withoutField, caId).submitted_at, null);
});

test('decided revisions carry consistent approval counts and decision times', () => {
  const submitted = { ...valid, status: 'SUBMITTED', submitted_at: '2026-10-25T12:00:00.000Z', approval_count: 1 };
  assert.deepEqual(requireProfileDraft(submitted, caId), submitted);
  const approved = { ...submitted, status: 'APPROVED', approval_count: 2, decided_at: '2026-10-26T12:00:00.000Z' };
  assert.deepEqual(requireProfileDraft(approved, caId), approved);
  const rejected = { ...submitted, status: 'REJECTED', approval_count: 1, decided_at: '2026-10-26T12:00:00.000Z' };
  assert.deepEqual(requireProfileDraft(rejected, caId), rejected);
  for (const altered of [
    { ...approved, approval_count: 1 }, { ...submitted, approval_count: 2 }, { ...approved, decided_at: null },
    { ...submitted, decided_at: '2026-10-26T12:00:00.000Z' }, { ...submitted, approval_count: 3 },
    { ...submitted, approval_count: -1 }, { ...submitted, approval_count: 1.5 }, { ...valid, status: 'ACTIVE' },
  ]) assert.throws(() => requireProfileDraft(altered, caId), JSON.stringify(altered));
});

test('activated revisions carry activation and end times consistent with their state', () => {
  const approved = { ...valid, status: 'APPROVED', submitted_at: '2026-10-25T12:00:00.000Z', approval_count: 2, decided_at: '2026-10-26T12:00:00.000Z' };
  const active = { ...approved, status: 'ACTIVE', activated_at: '2026-10-27T12:00:00.000Z' };
  const superseded = { ...active, status: 'SUPERSEDED', ended_at: '2026-10-28T12:00:00.000Z' };
  const retired = { ...superseded, status: 'RETIRED' };
  for (const row of [active, superseded, retired]) assert.deepEqual(requireProfileDraft(row, caId), row);
  for (const altered of [
    { ...active, activated_at: null }, { ...active, ended_at: '2026-10-28T12:00:00.000Z' },
    { ...superseded, ended_at: null }, { ...retired, approval_count: 1 }, { ...approved, activated_at: '2026-10-27T12:00:00.000Z' },
  ]) assert.throws(() => requireProfileDraft(altered, caId), JSON.stringify(altered));
});
