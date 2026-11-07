import assert from 'node:assert/strict';
import { test } from 'node:test';
import { profileDraftListUrl, trimProfileFilterInput, validProfileDraftSearch, validProfilePolicyVersion } from '../src/profile-draft-query.ts';

test('profile search uses Unicode characters as the API does', () => {
  assert.equal(validProfileDraftSearch('😀😀'), true);
  assert.equal(validProfileDraftSearch('😀'.repeat(255)), true);
  assert.equal(validProfileDraftSearch('😀'.repeat(256)), false);
  assert.equal(validProfileDraftSearch('a'), false);
  assert.equal(validProfileDraftSearch('a\u0085b'), false);
});

test('profile policy version uses the database character limit and rejects controls', () => {
  assert.equal(validProfilePolicyVersion('v1'), true);
  assert.equal(validProfilePolicyVersion('😀'.repeat(128)), true);
  assert.equal(validProfilePolicyVersion('😀'.repeat(129)), false);
  assert.equal(validProfilePolicyVersion(''), false);
  assert.equal(validProfilePolicyVersion('v\u00851'), false);
});

test('profile filters trim the Unicode whitespace accepted by the API', () => {
  assert.equal(trimProfileFilterInput(' \u0085ab\u0085 '), 'ab');
  assert.equal(trimProfileFilterInput('v1\u0085'), 'v1');
});

test('unfiltered proposal URL omits the query and a cursor is encoded', () => {
  const filters = {
    profileFilter: '', profileOrder: 'oldest', searchTerm: '', policyFilter: '',
    fromFilter: '', untilFilter: '', minValidity: null, minSans: null,
  };
  assert.equal(profileDraftListUrl('authority-id', filters), '/v1/cas/authority-id/profile-drafts');
  assert.equal(profileDraftListUrl('authority-id', filters, 'server-lab|1'), '/v1/cas/authority-id/profile-drafts?after=server-lab%7C1');
});
