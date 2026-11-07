import assert from 'node:assert/strict';
import { test } from 'node:test';
import { profileDraftMetadataJson } from '../src/profile-draft-export.ts';

test('proposal metadata JSON includes the exact digest and excludes actor and private fields', () => {
  const draft = { ca_id: 'ca', profile_id: 'server-lab', revision: 2, status: 'DRAFT',
    display_name: 'Server proposal', policy_version: 'v1', max_validity_days: 90, max_dns_sans: 3,
    proposed_dns_zones: ['example.test'], proposed_signature_suites: ['ecdsa-p256'],
    proposal_warnings: ['advisory'], snapshot_sha256: 'a'.repeat(64), created_at: '2026-10-01T00:00:00Z',
    created_by: 'private-actor', private_key: 'never-export' };
  const json = profileDraftMetadataJson(draft);
  const parsed = JSON.parse(json);
  assert.equal(parsed.kind, 'trust-profile-proposal-metadata');
  assert.equal(parsed.snapshot_sha256, draft.snapshot_sha256);
  assert.deepEqual(parsed.advisory_syntax_warnings, ['advisory']);
  assert.equal(json.includes('private-actor'), false);
  assert.equal(json.includes('never-export'), false);
  assert.equal('created_by' in parsed, false);
});
