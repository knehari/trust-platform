import assert from 'node:assert/strict';
import test from 'node:test';
import { compareProfileRevisions, profileComparisonCsv, profileComparisonJson } from '../src/profile-compare.ts';

const base = {
  ca_id: 'allowed', profile_id: 'server-lab', revision: 1, status: 'DRAFT',
  display_name: 'Server', policy_version: 'v1', max_validity_days: 90, max_dns_sans: 5,
  proposed_dns_zones: ['lab.invalid'], proposed_signature_suites: ['P256-SHA256'],
  proposal_warnings: [], snapshot_sha256: 'a'.repeat(64), created_by: 'editor', created_at: '2026-10-01',
};

test('comparison orders revisions and identifies changed policy content', () => {
  const newer = { ...base, revision: 2, policy_version: 'v2', max_validity_days: 60,
    proposed_dns_zones: ['lab.invalid', 'apps.lab.invalid'], snapshot_sha256: 'b'.repeat(64) };
  const rows = compareProfileRevisions(newer, base);
  assert.deepEqual(rows.find(row => row.label === 'Policy version'), { label: 'Policy version', before: 'v1', after: 'v2', changed: true });
  assert.equal(rows.find(row => row.label === 'Maximum DNS SANs').changed, false);
  assert.equal(rows.find(row => row.label === 'Snapshot SHA-256').changed, true);
});

test('comparison rejects different authorities, profiles and revisions', () => {
  for (const other of [{ ...base, ca_id: 'hidden', revision: 2 }, { ...base, profile_id: 'other', revision: 2 }, base]) {
    assert.throws(() => compareProfileRevisions(base, other));
  }
});

test('comparison CSV exports only allowlisted fields and neutralizes spreadsheet formulas', () => {
  const older = { ...base, display_name: '=HYPERLINK("x")', private_key: 'never-export' };
  const newer = { ...base, revision: 2, display_name: 'Server', policy_version: 'v2', snapshot_sha256: 'b'.repeat(64) };
  const all = profileComparisonCsv(older, newer, false);
  const changed = profileComparisonCsv(older, newer, true);
  assert.match(all, /"'=HYPERLINK\(""x""\)"/);
  assert.match(all, /"Proposed signature suites"/);
  assert.equal(changed.includes('Proposed signature suites'), false);
  assert.equal(changed.includes('never-export'), false);
  assert.match(changed, /"allowed","server-lab","1","2"/);
});

test('comparison JSON follows the visible field filter and excludes actor identity', () => {
  const older = { ...base, private_key: 'never-export' };
  const newer = { ...base, revision: 2, policy_version: 'v2', snapshot_sha256: 'b'.repeat(64) };
  const all = JSON.parse(profileComparisonJson(newer, older, false));
  const changed = JSON.parse(profileComparisonJson(newer, older, true));
  assert.equal(changed.kind, 'trust-profile-proposal-comparison');
  assert.equal(changed.earlier_revision, 1);
  assert.equal(changed.later_revision, 2);
  assert.equal(changed.earlier_snapshot_sha256, older.snapshot_sha256);
  assert.ok(all.fields.length > changed.fields.length);
  assert.ok(changed.fields.every(row => row.changed));
  assert.equal(JSON.stringify(changed).includes('editor'), false);
  assert.equal(JSON.stringify(changed).includes('never-export'), false);
  assert.throws(() => profileComparisonJson(older, { ...newer, ca_id: 'hidden' }, true));
});
