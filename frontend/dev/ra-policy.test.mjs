import assert from 'node:assert/strict';
import { test } from 'node:test';
import { activeKeys, quotaUse, rotating, shortFingerprint } from '../src/ra-policy.ts';

test('quota use is bounded, warns from 80 % and stops at the quota', () => {
  assert.deepEqual(quotaUse(0, 100), { share: 0, tone: 'good', label: '0 / 100' });
  assert.equal(quotaUse(79, 100).tone, 'good');
  assert.equal(quotaUse(80, 100).tone, 'warn');
  assert.deepEqual(quotaUse(120, 100), { share: 1, tone: 'bad', label: '120 / 100' });
  assert.deepEqual(quotaUse(0, 0), { share: 1, tone: 'bad', label: 'Stopped (quota 0)' });
});

test('active keys are the unretired ones, newest first; two mean a rotation', () => {
  const keys = [
    { key_id: 1, sha256: 'aa', activated_at: '2026-01-01T00:00:00Z', retired_at: '2026-02-01T00:00:00Z' },
    { key_id: 2, sha256: 'bb', activated_at: '2026-01-15T00:00:00Z', retired_at: null },
    { key_id: 3, sha256: 'cc', activated_at: '2026-02-01T00:00:00Z', retired_at: null },
  ];
  assert.deepEqual(activeKeys(keys).map(key => key.key_id), [3, 2]);
  assert.equal(rotating(keys), true);
  assert.equal(rotating(keys.slice(0, 2)), false);
});

test('fingerprints are shortened into colon pairs', () => {
  assert.equal(shortFingerprint('A1B2C3D4E5F6A7B8'), 'a1:b2:c3:d4:e5:f6…');
  assert.equal(shortFingerprint('a1b2', 6), 'a1:b2');
});
