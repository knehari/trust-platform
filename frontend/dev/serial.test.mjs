import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalSerialHex } from '../src/serial.ts';

test('serial aliases map to the same DER-content value', () => {
  for (const input of ['010001', '10001', '0x10001', '0X10001', '01:00:01', '0x01:00:01', '00010001']) {
    assert.equal(canonicalSerialHex(input), '010001', input);
  }
  assert.equal(canonicalSerialHex('FF'), '00ff');
  assert.equal(canonicalSerialHex('80'), '0080');
  assert.equal(canonicalSerialHex('7f'), '7f');
});

test('invalid or oversized serials are rejected', () => {
  for (const input of ['', '0', '00', '0x', 'zz', '1::2', '1:00', '01:', '0xGG', '00000000000000000000000000000000000000000', 'ffffffffffffffffffffffffffffffffffffffff']) {
    assert.equal(canonicalSerialHex(input), null, input);
  }
});
