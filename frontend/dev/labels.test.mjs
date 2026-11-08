import assert from 'node:assert/strict';
import { test } from 'node:test';
import { describeEvent, describeOutcome, humanizeStatus, relativeTime } from '../src/labels.ts';

test('status codes read as words, keeping acronyms', () => {
  assert.equal(humanizeStatus('KEY_ATTESTED'), 'Key attested');
  assert.equal(humanizeStatus('ACTIVE'), 'Active');
  assert.equal(humanizeStatus('CSR_VALIDATED'), 'CSR validated');
  assert.equal(humanizeStatus('NO_CRL'), 'No CRL yet');
  assert.equal(humanizeStatus('allow'), 'Allowed');
  assert.equal(humanizeStatus('deny'), 'Denied');
  assert.equal(humanizeStatus('persisted'), 'Persisted');
  assert.equal(humanizeStatus(''), '');
});

test('every audit event has a label and a category, known or not', () => {
  assert.deepEqual(describeEvent('crl.reconciliation_required'), { label: 'CRL needs reconciliation', category: 'crl', code: 'crl.reconciliation_required' });
  assert.equal(describeEvent('request.transition').category, 'request');
  assert.equal(describeEvent('certificate.application.submitted').category, 'request');
  assert.equal(describeEvent('certificate.revocation.requested').category, 'certificate');
  const unknown = describeEvent('signing.something_new');
  assert.equal(unknown.label, 'Something new');
  assert.equal(unknown.category, 'signing');
  assert.equal(describeEvent('mystery').category, 'other');
  assert.equal(describeEvent('mystery').label, 'Mystery');
});

test('the decision column is parsed into a typed outcome', () => {
  assert.deepEqual(describeOutcome('allow'), { kind: 'decision', status: 'allow' });
  assert.deepEqual(describeOutcome('SIGNING -> RECONCILIATION_REQUIRED'), { kind: 'transition', from: 'SIGNING', to: 'RECONCILIATION_REQUIRED' });
  assert.deepEqual(describeOutcome('created:8c6d2c6f-fc0f-4816-9b93-61c88e9d051c'), { kind: 'reference', status: 'created', reference: '8c6d2c6f-fc0f-4816-9b93-61c88e9d051c' });
  assert.deepEqual(describeOutcome('persisted'), { kind: 'result', status: 'persisted' });
  assert.deepEqual(describeOutcome('two words?'), { kind: 'text', text: 'two words?' });
});

test('relative times stay short and fall back to a date', () => {
  const now = new Date('2026-11-08T12:00:00Z');
  assert.equal(relativeTime('2026-11-08T11:59:40Z', now), 'just now');
  assert.equal(relativeTime('2026-11-08T11:55:00Z', now), '5 min ago');
  assert.equal(relativeTime('2026-11-08T09:00:00Z', now), '3 h ago');
  assert.equal(relativeTime('2026-11-07T10:00:00Z', now), 'yesterday');
  assert.equal(relativeTime('2026-11-05T12:00:00Z', now), '3 days ago');
  assert.equal(relativeTime('2026-11-15T12:00:00Z', now), new Date('2026-11-15T12:00:00Z').toLocaleDateString());
  assert.equal(relativeTime('2026-11-08T14:00:00Z', now), 'in 2 h');
  assert.equal(relativeTime('not a date', now), 'not a date');
});
