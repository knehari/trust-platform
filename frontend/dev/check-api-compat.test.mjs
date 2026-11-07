import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { checkApi } from './check-api-compat.mjs';

async function withServer(status, run) {
  const server = createServer((request, response) => {
    response.writeHead(typeof status === 'function' ? status(request.url) : status).end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

test('accepts protected registered detail routes', () => withServer(401, checkApi));
test('detects an older API missing the authority detail route', () => withServer(
  path => path === '/v1/cas/eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' ? 404 : 401,
  async base => { await assert.rejects(checkApi(base), /\/v1\/cas\/eeeeeeee.*missing \(404\)/); },
));
test('detects an older API missing detail routes', () => withServer(404, async base => {
  await assert.rejects(checkApi(base), /Rebuild and restart trust-management-api/);
}));
test('detects an older API missing serial lookup', () => withServer(
  path => path?.includes('/by-serial/') ? 404 : 401,
  async base => { await assert.rejects(checkApi(base), /by-serial\/010001.*missing \(404\)/); },
));
test('does not mistake an unavailable API for a compatible one', () => withServer(503, async base => {
  await assert.rejects(checkApi(base), /returned 503/);
}));
