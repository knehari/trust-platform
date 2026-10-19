import assert from 'node:assert/strict';
import { test } from 'node:test';
import { requireScopedRows, visibleScopedRows } from '../src/scope.ts';

const rows = [{ ca_id: 'allowed', id: 1 }, { ca_id: 'hidden', id: 2 }];

test('a mixed-CA API page fails closed', () => {
  assert.throws(() => requireScopedRows(rows, 'allowed'), /outside the selected authority/);
  assert.deepEqual(requireScopedRows(rows.slice(0, 1), 'allowed'), rows.slice(0, 1));
});

test('old CA rows are hidden synchronously after selection changes', () => {
  assert.deepEqual(visibleScopedRows(rows, 'hidden'), rows.slice(1));
  assert.deepEqual(visibleScopedRows(rows, null), []);
});
