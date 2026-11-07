import assert from 'node:assert/strict';
import { test } from 'node:test';
import { requireExactRecord, requireScopedRows, visibleScopedRows } from '../src/scope.ts';

const rows = [{ ca_id: 'allowed', id: 1 }, { ca_id: 'hidden', id: 2 }];

test('a mixed-CA API page fails closed', () => {
  assert.throws(() => requireScopedRows(rows, 'allowed'), /outside the selected authority/);
  assert.deepEqual(requireScopedRows(rows.slice(0, 1), 'allowed'), rows.slice(0, 1));
});

test('old CA rows are hidden synchronously after selection changes', () => {
  assert.deepEqual(visibleScopedRows(rows, 'hidden'), rows.slice(1));
  assert.deepEqual(visibleScopedRows(rows, null), []);
});

test('exact detail rejects a scoped response for a different record', () => {
  const record = { ca_id: 'allowed', request_id: 'other' };
  assert.throws(() => requireExactRecord(record, 'allowed', 'request_id', 'requested'), /different record/);
  assert.throws(() => requireExactRecord(record, 'hidden', 'request_id', 'other'), /outside the selected authority/);
  assert.equal(requireExactRecord(record, 'allowed', 'request_id', 'other'), record);
});
