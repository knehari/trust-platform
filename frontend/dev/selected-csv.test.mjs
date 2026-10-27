import assert from 'node:assert/strict';
import { test } from 'node:test';
import { auditCsv, certificateCsv, profileDraftCsv, MAX_CSV_ROWS } from '../src/selected-csv.ts';

const certificate = {
  ca_id: 'ca', request_id: 'request', serial_hex: '01', subject_cn: '=1+1',
  not_before: null, not_after: null, san_dns: ['a.example', '@bad.example'],
  fingerprint_sha256: 'a'.repeat(64), state: 'SIGNED', signed_at: '2026-10-01T00:00:00Z', published_at: null,
  certificate_der: 'never-export', private_key: 'never-export',
};

test('certificate CSV allowlists fields, escapes cells and neutralizes formulas', () => {
  const result = certificateCsv([{ ...certificate, subject_cn: '  =HYPERLINK("x")' }]);
  assert.match(result, /"'  =HYPERLINK\(""x""\)"/);
  assert.match(result, /"a\.example; @bad\.example"/);
  assert.equal(result.includes('never-export'), false);
  assert.equal(result.split('\r\n').length, 3);
});

test('audit CSV rejects empty or oversized selections and neutralizes formulas', () => {
  const event = { ca_id: 'ca', event_id: 'event', event_type: '+cmd', decision: 'allow', policy_version: null, recorded_at: '2026-10-01T00:00:00Z', raw_evidence: 'never-export' };
  assert.throws(() => auditCsv([]), /Select 1–100/);
  assert.throws(() => auditCsv(Array(MAX_CSV_ROWS + 1).fill(event)), /Select 1–100/);
  const result = auditCsv([event]);
  assert.match(result, /"'\+cmd"/);
  assert.equal(result.includes('never-export'), false);
});

test('profile proposal CSV exports an allowlist without actor identity and neutralizes formulas', () => {
  const proposal = { ca_id: 'ca', profile_id: 'server-lab', revision: 2, display_name: '=HYPERLINK("x")',
    policy_version: 'v1', max_validity_days: 90, max_dns_sans: 3, proposed_dns_zones: ['example.test'],
    proposed_signature_suites: ['ecdsa-p256'], proposal_warnings: ['warning'], snapshot_sha256: 'a'.repeat(64),
    created_at: '2026-10-01T00:00:00Z', status: 'DRAFT', created_by: 'private-actor', private_key: 'never-export' };
  assert.throws(() => profileDraftCsv([]), /Select 1–100/);
  assert.throws(() => profileDraftCsv(Array(MAX_CSV_ROWS + 1).fill(proposal)), /Select 1–100/);
  const result = profileDraftCsv([proposal]);
  assert.match(result, /"'=HYPERLINK\(""x""\)"/);
  assert.match(result, /"server-lab"/);
  assert.equal(result.includes('private-actor'), false);
  assert.equal(result.includes('never-export'), false);
});
