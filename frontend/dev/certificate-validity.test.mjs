import assert from 'node:assert/strict';
import { test } from 'node:test';
import { recordedValidityStatus } from '../src/certificate-validity.ts';

const interval = { not_before: '2026-10-20T00:00:00.000Z', not_after: '2026-10-22T00:00:00.000Z' };

test('recorded validity boundaries are inclusive at start and exclusive at end', () => {
  assert.equal(recordedValidityStatus(interval, Date.parse(interval.not_before) - 1), 'Not yet in period');
  assert.equal(recordedValidityStatus(interval, Date.parse(interval.not_before)), 'Within period');
  assert.equal(recordedValidityStatus(interval, Date.parse(interval.not_after) - 1), 'Within period');
  assert.equal(recordedValidityStatus(interval, Date.parse(interval.not_after)), 'Period ended');
});

test('missing or malformed metadata never implies a current certificate', () => {
  assert.equal(recordedValidityStatus({ not_before: null, not_after: null }, Date.now()), 'Not recorded');
  assert.equal(recordedValidityStatus({ not_before: 'invalid', not_after: interval.not_after }, Date.now()), 'Not recorded');
  assert.equal(recordedValidityStatus({ ...interval, not_after: interval.not_before }, Date.now()), 'Not recorded');
});
