import assert from 'node:assert/strict';
import { test } from 'node:test';
import { normalizeLiteralPrefix, validLiteralPrefix } from '../src/literal-prefix.ts';

test('shared CA, CN and profile prefix checks count Unicode characters', () => {
  assert.equal(validLiteralPrefix('😀😀'), true);
  assert.equal(validLiteralPrefix('😀'.repeat(255)), true);
  assert.equal(validLiteralPrefix('😀'.repeat(256)), false);
  assert.equal(validLiteralPrefix('x'), false);
  assert.equal(validLiteralPrefix('a\u0085b'), false);
});

test('prefix normalization trims API whitespace before validation', () => {
  assert.equal(normalizeLiteralPrefix(' \u0085ab\u0085 '), 'ab');
  assert.equal(validLiteralPrefix(normalizeLiteralPrefix(' \u0085ab\u0085 ')), true);
});
