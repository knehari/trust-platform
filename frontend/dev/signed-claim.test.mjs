import assert from 'node:assert/strict';
import { test } from 'node:test';
import { signedClaimMatches } from '../src/signed-claim.ts';

const caId = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const applicationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const revocationId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const tail = ';key=lab-ra-officer-p256;issued_at=2026-11-11T10:00:00.000Z';
const value = claim => ({ decision: 'approve', key_id: 'lab-ra-officer-p256', issued_at: '2026-11-11T10:00:00.000Z', claim });
const revocation = (decision = 'approve', ca = caId, revocation = revocationId) =>
  `trust-platform/revocation-authorization/v1;decision=${decision};ca=${ca};application=${applicationId};revocation=${revocation};serial=0aff;reason_code=1${tail}`;

test('a revocation claim for this exact request and serial is accepted', () => {
  const subject = { caId, applicationId, revocationId, serialHex: '0AFF' };
  assert.equal(signedClaimMatches(value(revocation()), 'revocation', 'approve', subject), true);
  assert.equal(signedClaimMatches({ ...value(revocation('reject')), decision: 'reject' }, 'revocation', 'reject', subject), true);
});

test('claims of another kind, decision, record, serial or key are refused before signing', () => {
  const subject = { caId, applicationId, revocationId, serialHex: '0aff' };
  assert.equal(signedClaimMatches(value(revocation('reject')), 'revocation', 'approve', subject), false);
  assert.equal(signedClaimMatches(value(revocation('approve', 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee')), 'revocation', 'approve', subject), false);
  assert.equal(signedClaimMatches(value(revocation('approve', caId, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')), 'revocation', 'approve', subject), false);
  assert.equal(signedClaimMatches(value(revocation()), 'revocation', 'approve', { ...subject, serialHex: '0b00' }), false);
  assert.equal(signedClaimMatches({ ...value(revocation()), key_id: 'other' }, 'revocation', 'approve', subject), false);
  assert.equal(signedClaimMatches(value(revocation()), 'void', 'approve', subject), false);
  assert.equal(signedClaimMatches(value(`${revocation()}\nmore`), 'revocation', 'approve', subject), false);
});

test('a void confirmation claim names the application and serial', () => {
  const claim = `trust-platform/void-authorization/v1;ca=${caId};application=${applicationId};serial=0aff;signer_claimed=false${tail}`;
  const confirm = { ...value(claim), decision: 'confirm' };
  assert.equal(signedClaimMatches(confirm, 'void', 'confirm', { caId, applicationId, serialHex: '0aff' }), true);
  assert.equal(signedClaimMatches(confirm, 'void', 'confirm', { caId, applicationId: revocationId }), false);
});
