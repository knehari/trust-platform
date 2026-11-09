import assert from 'node:assert/strict';
import { test } from 'node:test';
import { activityByDay, attentionEvents, certificateHealth, dayLabel, expiryBuckets, lifetimeElapsed } from '../src/dashboard.ts';

const now = Date.parse('2026-11-08T12:00:00Z');

test('expiry buckets count only future notAfter dates, week by week', () => {
  const buckets = expiryBuckets([
    { not_after: '2026-11-09T00:00:00Z' }, { not_after: '2026-11-20T00:00:00Z' },
    { not_after: '2026-11-01T00:00:00Z' }, { not_after: null }, { not_after: '2030-01-01T00:00:00Z' },
    { not_after: '2026-11-10T00:00:00Z', revoked_at: '2026-11-08T00:00:00Z' },
  ], now, 4);
  assert.deepEqual(buckets.map(bucket => bucket.count), [1, 1, 0, 0]);
});

test('activity is counted per UTC day with denials apart', () => {
  const days = activityByDay([
    { recorded_at: '2026-11-08T01:00:00Z', decision: 'allow' },
    { recorded_at: '2026-11-08T02:00:00Z', decision: 'deny' },
    { recorded_at: '2026-11-07T23:00:00Z', decision: 'SIGNING -> SIGNED' },
    { recorded_at: '2026-10-01T00:00:00Z', decision: 'allow' },
  ], now, 3);
  assert.deepEqual(days.map(day => [day.key, day.count, day.extra]), [['2026-11-06', 0, 0], ['2026-11-07', 1, 0], ['2026-11-08', 2, 1]]);
});

test('certificate health separates valid, expiring, expired and unknown', () => {
  const health = certificateHealth([
    { not_before: '2026-01-01T00:00:00Z', not_after: '2027-06-01T00:00:00Z' },
    { not_before: '2026-01-01T00:00:00Z', not_after: '2026-11-20T00:00:00Z' },
    { not_before: '2025-01-01T00:00:00Z', not_after: '2026-01-01T00:00:00Z' },
    { not_before: null, not_after: null },
  ], now);
  assert.deepEqual(health, { valid: 1, expiringSoon: 1, expired: 1, unknown: 1, revoked: 0 });
  const revoked = certificateHealth([{ not_before: '2026-01-01T00:00:00Z', not_after: '2027-06-01T00:00:00Z', revoked_at: '2026-11-01T00:00:00Z' }], now);
  assert.deepEqual(revoked, { valid: 0, expiringSoon: 0, expired: 0, unknown: 0, revoked: 1 });
});

test('lifetime elapsed is bounded and null when unknown', () => {
  assert.equal(lifetimeElapsed({ not_before: '2026-11-01T12:00:00Z', not_after: '2026-11-15T12:00:00Z' }, now), 0.5);
  assert.equal(lifetimeElapsed({ not_before: '2027-01-01T00:00:00Z', not_after: '2028-01-01T00:00:00Z' }, now), 0);
  assert.equal(lifetimeElapsed({ not_before: null, not_after: '2028-01-01T00:00:00Z' }, now), null);
});

test('attention counts recent denials and reconciliations only', () => {
  assert.deepEqual(attentionEvents([
    { recorded_at: '2026-11-08T10:00:00Z', decision: 'deny' },
    { recorded_at: '2026-11-08T10:00:00Z', decision: 'SIGNING -> RECONCILIATION_REQUIRED' },
    { recorded_at: '2026-10-01T10:00:00Z', decision: 'deny' },
  ], now), { denied: 1, reconciliation: 1 });
});

test('rows group under Today, Yesterday or a date', () => {
  const reference = new Date(2026, 10, 8, 12);
  assert.equal(dayLabel(new Date(2026, 10, 8, 1).toISOString(), reference), 'Today');
  assert.equal(dayLabel(new Date(2026, 10, 7, 23).toISOString(), reference), 'Yesterday');
  assert.notEqual(dayLabel(new Date(2026, 10, 1).toISOString(), reference), 'Today');
});
