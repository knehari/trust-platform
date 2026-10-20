import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sortLoadedAuditEvents } from '../src/audit-sort.ts';

const rows = [
  { event_id: 'c', event_type: 'REVOKED', decision: 'DENIED' },
  { event_id: 'b', event_type: 'ISSUED', decision: 'APPROVED' },
  { event_id: 'a', event_type: 'REQUESTED', decision: 'PENDING' },
];

test('audit sorting only reorders loaded events without mutating server order', () => {
  assert.deepEqual(sortLoadedAuditEvents(rows, 'newest').map(row => row.event_id), ['c', 'b', 'a']);
  assert.deepEqual(sortLoadedAuditEvents(rows, 'oldest').map(row => row.event_id), ['a', 'b', 'c']);
  assert.deepEqual(sortLoadedAuditEvents(rows, 'type').map(row => row.event_id), ['b', 'a', 'c']);
  assert.deepEqual(sortLoadedAuditEvents(rows, 'decision').map(row => row.event_id), ['b', 'c', 'a']);
  assert.deepEqual(rows.map(row => row.event_id), ['c', 'b', 'a']);
});
