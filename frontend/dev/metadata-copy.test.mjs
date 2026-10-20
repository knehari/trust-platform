import assert from 'node:assert/strict';
import { test } from 'node:test';
import { auditMetadataJson, certificateMetadataJson } from '../src/metadata-copy.ts';

test('certificate JSON copies only approved metadata and preserves null CN', () => {
  const copied = JSON.parse(certificateMetadataJson({
    ca_id: 'ca', request_id: 'request', serial_hex: '010001', subject_cn: null,
    fingerprint_sha256: 'a'.repeat(64), state: 'SIGNED', signed_at: '2026-10-01T00:00:00Z', published_at: null,
    certificate_der: 'must-not-copy', private_key: 'must-not-copy',
  }));
  assert.deepEqual(Object.keys(copied), ['ca_id', 'request_id', 'serial_hex', 'subject_cn', 'fingerprint_sha256', 'state', 'signed_at', 'published_at']);
  assert.equal(copied.subject_cn, null);
  assert.equal(JSON.stringify(copied).includes('must-not-copy'), false);
});

test('audit JSON omits actor and raw evidence fields', () => {
  const copied = JSON.parse(auditMetadataJson({
    ca_id: 'ca', event_id: 'event', event_type: 'ISSUED', decision: 'APPROVED',
    policy_version: null, recorded_at: '2026-10-01T00:00:00Z',
    actor_id: 'must-not-copy', raw_evidence: 'must-not-copy',
  }));
  assert.deepEqual(Object.keys(copied), ['ca_id', 'event_id', 'event_type', 'decision', 'policy_version', 'recorded_at']);
  assert.equal(copied.policy_version, null);
  assert.equal(JSON.stringify(copied).includes('must-not-copy'), false);
});
