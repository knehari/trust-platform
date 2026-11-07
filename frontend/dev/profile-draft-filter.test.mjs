import assert from 'node:assert/strict';
import { test } from 'node:test';
import { visibleProfileDrafts } from '../src/profile-draft-filter.ts';

test('warning triage filters only the already loaded proposal rows', () => {
  const rows = [
    { profile_id: 'clean', proposal_warnings: [] },
    { profile_id: 'warning', proposal_warnings: ['invalid zone'] },
  ];
  assert.deepEqual(visibleProfileDrafts(rows, false), rows);
  assert.deepEqual(visibleProfileDrafts(rows, true), [rows[1]]);
  assert.deepEqual(visibleProfileDrafts([], true), []);
});
