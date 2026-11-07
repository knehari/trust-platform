import assert from 'node:assert/strict';
import { test } from 'node:test';
import { filterLoadedCertificates } from '../src/certificate-filter.ts';

const certificates = [
  { ca_id: 'ca-1', subject_cn: 'paged-0001.lab.invalid', serial_hex: '010001', fingerprint_sha256: 'a'.repeat(64), request_id: 'request-1', state: 'SIGNED' },
  { ca_id: 'ca-1', subject_cn: null, serial_hex: '010002', fingerprint_sha256: 'b'.repeat(64), request_id: 'request-2', state: 'PUBLISHED' },
];

test('the loaded-row filter recognizes pasted serial formats', () => {
  for (const query of ['010001', '10001', '0x10001', '01:00:01']) {
    assert.deepEqual(filterLoadedCertificates(certificates, query), [certificates[0]], query);
  }
  assert.deepEqual(filterLoadedCertificates(certificates, '0x10003'), []);
});

test('the loaded-row filter keeps the existing metadata searches and never fetches more rows', () => {
  for (const query of ['paged-0001', 'request-1', 'AAAA', 'signed']) {
    assert.deepEqual(filterLoadedCertificates(certificates, query), [certificates[0]], query);
  }
  assert.deepEqual(filterLoadedCertificates(certificates, '  '), certificates);
  assert.deepEqual(filterLoadedCertificates([], '0x10001'), []);
});
