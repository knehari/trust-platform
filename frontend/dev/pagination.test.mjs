import assert from 'node:assert/strict';
import { test } from 'node:test';
import { appendUniquePage, requireAdvancingCursor } from '../src/pagination.ts';

test('overlapping pages append only new records in server order', () => {
  const current = [{ id: 'a' }, { id: 'b' }];
  const page = [{ id: 'b' }, { id: 'c' }, { id: 'c' }, { id: 'd' }];
  assert.deepEqual(appendUniquePage(current, page, row => row.id), [current[0], current[1], page[1], page[3]]);
});

test('a repeated cursor is rejected instead of inviting an endless load', () => {
  assert.throws(() => requireAdvancingCursor('same', 'same'), /repeated page cursor/);
  assert.equal(requireAdvancingCursor('old', 'new'), 'new');
  assert.equal(requireAdvancingCursor('old', null), null);
});
