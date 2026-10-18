import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { checkApi } from './check-api-compat.mjs';

async function withServer(status, run) {
  const server = createServer((_request, response) => { response.writeHead(status).end(); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('accepts protected registered detail routes', () => withServer(401, checkApi));
test('detects an older API missing detail routes', () => withServer(404, async base => {
  await assert.rejects(checkApi(base), /Rebuild and restart trust-management-api/);
}));
test('does not mistake an unavailable API for a compatible one', () => withServer(503, async base => {
  await assert.rejects(checkApi(base), /returned 503/);
}));
