import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readOnlyRoles } from '../src/roles.ts';

test('the console is read-only only without any recording role', () => {
  assert.equal(readOnlyRoles([]), true);
  assert.equal(readOnlyRoles(['trust-ca-reader']), true);
  assert.equal(readOnlyRoles(['trust-ca-reader', 'unknown-role']), true);
  for (const role of ['trust-profile-editor', 'trust-policy-approver', 'trust-ca-operator', 'trust-ca-administrator',
    'trust-ca-approver', 'trust-certificate-requester', 'trust-registration-officer']) {
    assert.equal(readOnlyRoles(['trust-ca-reader', role]), false, role);
  }
});
