import assert from 'node:assert/strict';
import { test } from 'node:test';
import { requestActions } from '../src/request-actions.ts';

const base = { open_revocation_id: null, void_status: null, void_proposed_by_reader: null };

test('officers review submitted requests and revocations; requesters cannot decide', () => {
  assert.equal(requestActions({ ...base, status: 'SUBMITTED' }, false, true).formLabel, 'Review');
  assert.equal(requestActions({ ...base, status: 'SUBMITTED' }, true, false).formLabel, null);
  assert.equal(requestActions({ ...base, status: 'REVOCATION_REQUESTED', open_revocation_id: 'r' }, false, true).formLabel, 'Review revocation');
  assert.equal(requestActions({ ...base, status: 'REVOCATION_REQUESTED' }, false, true).formLabel, null);
});

test('issued certificates can be asked for revocation; approved ones issued', () => {
  assert.equal(requestActions({ ...base, status: 'ISSUED' }, true, false).formLabel, 'Revoke…');
  assert.equal(requestActions({ ...base, status: 'APPROVED' }, true, false).canIssue, true);
  assert.equal(requestActions({ ...base, status: 'APPROVED' }, false, false).canIssue, false);
});

test('a void is proposed by one officer and confirmed by another', () => {
  assert.equal(requestActions({ ...base, status: 'RECONCILIATION_REQUIRED' }, false, true).formLabel, 'Reconcile…');
  assert.equal(requestActions({ ...base, status: 'RECONCILIATION_REQUIRED', void_status: 'PROPOSED', void_proposed_by_reader: false }, false, true).formLabel, 'Review void');
  assert.equal(requestActions({ ...base, status: 'RECONCILIATION_REQUIRED', void_status: 'PROPOSED', void_proposed_by_reader: true }, false, true).formLabel, null);
  assert.equal(requestActions({ ...base, status: 'REVOKED' }, true, true).formLabel, null);
});
