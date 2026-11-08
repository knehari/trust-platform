import assert from 'node:assert/strict';
import { test } from 'node:test';
import { addWithin, headerState, toggleOne, toggleVisible } from '../src/selection.ts';

test('the header state reflects the visible rows only', () => {
  assert.equal(headerState([], ['a']), 'none');
  assert.equal(headerState(['a', 'b'], []), 'none');
  assert.equal(headerState(['a', 'b'], ['a', 'z']), 'some');
  assert.equal(headerState(['a', 'b'], ['b', 'a']), 'all');
});

test('the header checkbox selects every visible row, then clears them', () => {
  const all = toggleVisible(['a', 'b', 'c'], ['z'], 10);
  assert.deepEqual(all, ['z', 'a', 'b', 'c']);
  assert.deepEqual(toggleVisible(['a', 'b', 'c'], all, 10), ['z']);
  // A partial selection becomes complete rather than cleared.
  assert.deepEqual(toggleVisible(['a', 'b'], ['a'], 10), ['a', 'b']);
});

test('selections never exceed the export limit', () => {
  assert.deepEqual(addWithin(['a'], ['b', 'c', 'd'], 3), ['a', 'b', 'c']);
  assert.deepEqual(toggleVisible(['a', 'b', 'c'], [], 2), ['a', 'b']);
  assert.deepEqual(toggleOne('x', ['a', 'b'], 2), ['a', 'b']);
  assert.deepEqual(toggleOne('a', ['a', 'b'], 2), ['b']);
});
