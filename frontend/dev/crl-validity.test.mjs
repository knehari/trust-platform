import assert from 'node:assert/strict';
import { test } from 'node:test';
import { crlElapsed, crlState } from '../src/crl-validity.ts';

const t = (iso) => Date.parse(iso);

test('a CRL is current only while it is the latest and before its next update', () => {
  assert.equal(crlState(12, 12, '2026-11-19T07:40:00Z', t('2026-11-14T00:00:00Z')), 'CURRENT');
  assert.equal(crlState(12, 12, '2026-11-19T07:40:00Z', t('2026-11-19T07:40:00Z')), 'EXPIRED');
  assert.equal(crlState(11, 12, '2026-11-30T00:00:00Z', t('2026-11-14T00:00:00Z')), 'SUPERSEDED');
  assert.equal(crlState(3, null, 'not a date', t('2026-11-14T00:00:00Z')), 'EXPIRED');
});

test('elapsed share is clamped and refuses missing or reversed dates', () => {
  const start = '2026-11-13T00:00:00Z';
  const end = '2026-11-17T00:00:00Z';
  assert.equal(crlElapsed(start, end, t('2026-11-14T00:00:00Z')), 0.25);
  assert.equal(crlElapsed(start, end, t('2026-11-01T00:00:00Z')), 0);
  assert.equal(crlElapsed(start, end, t('2026-12-01T00:00:00Z')), 1);
  assert.equal(crlElapsed(end, start, t('2026-11-14T00:00:00Z')), null);
  assert.equal(crlElapsed('', end, t('2026-11-14T00:00:00Z')), null);
});
