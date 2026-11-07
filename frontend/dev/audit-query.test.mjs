import assert from 'node:assert/strict';
import { test } from 'node:test';
import { prepareAuditQuery } from '../src/audit-query.ts';

const empty = { from: '', until: '', eventType: '', decision: '', policyVersion: '' };

test('audit exact filters use the API UTF-8 limit and reject interior controls', () => {
  for (const field of ['eventType', 'decision', 'policyVersion']) {
    assert.equal(prepareAuditQuery({ ...empty, [field]: '😀'.repeat(32) }).error, null);
    assert.match(prepareAuditQuery({ ...empty, [field]: '😀'.repeat(33) }).error, /128 UTF-8 bytes/u);
    assert.match(prepareAuditQuery({ ...empty, [field]: 'a\u0085b' }).error, /control characters/u);
  }
});

test('audit query normalizes Unicode whitespace and keeps exact fields', () => {
  const result = prepareAuditQuery({
    from: '2026-10-01', until: '2026-11-01', eventType: ' \u0085certificate.signed\u0085 ',
    decision: 'allow', policyVersion: 'v1',
  });
  assert.equal(result.error, null);
  const params = new URLSearchParams(result.query);
  assert.equal(params.get('event_type'), 'certificate.signed');
  assert.equal(params.get('decision'), 'allow');
  assert.equal(params.get('policy_version'), 'v1');
  assert.equal(params.get('from'), '2026-10-01T00:00:00.000Z');
  assert.equal(params.get('until'), '2026-11-01T00:00:00.000Z');
  assert.equal(prepareAuditQuery({ ...empty, from: '2026-11-01', until: '2026-10-01' }).query, null);
});
