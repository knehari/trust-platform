import assert from 'node:assert/strict';
import { test } from 'node:test';
import { claimMatches } from '../src/application-claim.ts';

const ca = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const item = { application_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', subject_cn: 'www.lab.invalid',
  dns_names: ['www.lab.invalid', 'api.lab.invalid'], validity_days: 30 };
const claim = (decision = 'approve', overrides = {}) => {
  const f = { ca, application: item.application_id, subject_cn: item.subject_cn, dns_names: item.dns_names.join(','),
    validity_days: item.validity_days, ...overrides };
  return {
    decision, key_id: 'lab-ra-officer-p256', issued_at: '2026-11-11T10:00:00.000Z',
    claim: `trust-platform/issuance-authorization/v1;decision=${decision};ca=${f.ca};application=${f.application};profile=server;`
      + `revision=1;csr_sha256=${'ab'.repeat(32)};subject_cn=${f.subject_cn};dns_names=${f.dns_names};`
      + `validity_days=${f.validity_days};extensions=;key=lab-ra-officer-p256;issued_at=2026-11-11T10:00:00.000Z`,
  };
};

test('a claim for this exact application and decision is accepted', () => {
  assert.equal(claimMatches(claim(), 'approve', ca, item), true);
  assert.equal(claimMatches(claim('reject'), 'reject', ca, item), true);
});

test('a claim for other facts, another decision or another key is refused before signing', () => {
  assert.equal(claimMatches(claim('reject'), 'approve', ca, item), false);
  assert.equal(claimMatches(claim('approve', { ca: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' }), 'approve', ca, item), false);
  assert.equal(claimMatches(claim('approve', { subject_cn: 'evil.lab.invalid' }), 'approve', ca, item), false);
  assert.equal(claimMatches(claim('approve', { dns_names: 'www.lab.invalid' }), 'approve', ca, item), false);
  assert.equal(claimMatches(claim('approve', { validity_days: 90 }), 'approve', ca, item), false);
  assert.equal(claimMatches({ ...claim(), key_id: 'other-key' }, 'approve', ca, item), false);
  assert.equal(claimMatches({ ...claim(), claim: `${claim().claim}\nmore` }, 'approve', ca, item), false);
  assert.equal(claimMatches({ decision: 'approve' }, 'approve', ca, item), false);
});
