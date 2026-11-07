import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ApiError, apiGet } from '../src/api.ts';

test('failed reads expose a bounded server request ID for log correlation', async () => {
  const originalFetch = globalThis.fetch;
  const id = '12345-67890';
  globalThis.fetch = async () => new Response('{}', { status: 503, headers: { 'x-request-id': id } });
  try {
    await assert.rejects(apiGet('/v1/cas', 'test-token'), error =>
      error instanceof ApiError && error.status === 503 && error.requestId === id && error.message.includes(id));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('malformed request IDs are not reflected in UI errors', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response('{}', { status: 503, headers: { 'x-request-id': 'untrusted-id' } });
  try {
    await assert.rejects(apiGet('/v1/cas', 'test-token'), error =>
      error instanceof ApiError && error.requestId === null && !error.message.includes('untrusted-id'));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
