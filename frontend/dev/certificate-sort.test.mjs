import assert from 'node:assert/strict';
import { test } from 'node:test';
import { sortLoadedCertificates } from '../src/certificate-sort.ts';

const rows = [
  { request_id: 'c', serial_hex: '03', subject_cn: null },
  { request_id: 'b', serial_hex: '02', subject_cn: 'Zulu' },
  { request_id: 'a', serial_hex: '01', subject_cn: 'Alpha' },
];

test('sorting only reorders loaded certificates without mutating server order', () => {
  assert.deepEqual(sortLoadedCertificates(rows, 'newest').map(row => row.request_id), ['c', 'b', 'a']);
  assert.deepEqual(sortLoadedCertificates(rows, 'oldest').map(row => row.request_id), ['a', 'b', 'c']);
  assert.deepEqual(sortLoadedCertificates(rows, 'cn').map(row => row.request_id), ['a', 'b', 'c']);
  assert.deepEqual(sortLoadedCertificates(rows, 'serial').map(row => row.request_id), ['a', 'b', 'c']);
  assert.deepEqual(rows.map(row => row.request_id), ['c', 'b', 'a']);
});
