import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalUuid } from '../src/uuid.ts';

const id = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

test('common pasted UUID forms resolve to one exact identifier', () => {
  for (const input of [id, id.toUpperCase(), `{${id.toUpperCase()}}`, `urn:uuid:${id}`, `URN:UUID:{${id.toUpperCase()}}`, ` ${id} `]) {
    assert.equal(canonicalUuid(input), id, input);
  }
});

test('ambiguous or malformed UUIDs remain invalid', () => {
  for (const input of ['', 'eeee', `{${id}`, `${id}}`, `urn:uuid:urn:uuid:${id}`, `${id}/other`, `https://example.invalid/${id}`, '0x10001']) {
    assert.equal(canonicalUuid(input), null, input);
  }
});
