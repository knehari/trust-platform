import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { profileDraftListUrl } from '../src/profile-draft-query.ts';

const root = new URL('../../', import.meta.url);
const read = path => readFileSync(new URL(path, root), 'utf8');

test('profile proposal query names agree across API, console and OpenAPI', () => {
  const spec = read('openapi/management-v1.yaml');
  const route = spec.split('  /v1/cas/{ca_id}/profile-drafts:\n')[1]
    ?.split('  /v1/cas/{ca_id}/profile-drafts/{profile_id}/{revision}:\n')[0];
  assert.ok(route, 'profile proposal route is documented');
  const documented = [...route.matchAll(/^ {10}name: ([a-z_]+)$/gm)].map(match => match[1]).sort();

  const rust = read('crates/management-api/src/main.rs');
  const query = rust.match(/struct ProfileDraftQuery \{([^}]+)\}/u)?.[1];
  assert.ok(query, 'profile proposal query struct exists');
  const accepted = [...query.matchAll(/^ {4}([a-z_]+): Option</gm)].map(match => match[1]).sort();

  const filters = {
    profileFilter: 'server-lab', profileOrder: 'newest', searchTerm: 'Laboratory',
    policyFilter: 'v2', fromFilter: '2026-10-01T00:00:00.000Z',
    untilFilter: '2026-11-01T00:00:00.000Z', minValidity: 60, minSans: 3,
  };
  const firstPage = new URL(profileDraftListUrl('authority-id', filters), 'http://localhost');
  const laterPage = new URL(profileDraftListUrl('authority-id', filters, 'server-lab|1'), 'http://localhost');
  const firstNames = [...firstPage.searchParams.keys()].sort();
  const laterNames = [...laterPage.searchParams.keys()].sort();
  const panel = read('frontend/src/ProfileDraftPanel.tsx');
  assert.match(panel, /apiGetPage<unknown>\(listUrl\(\),/u, 'initial request uses the shared URL builder');
  assert.match(panel, /apiGetPage<unknown>\(listUrl\(cursor\),/u, 'cursor request uses the shared URL builder');

  assert.deepEqual(documented, accepted, 'OpenAPI must describe every accepted query');
  assert.deepEqual(documented.filter(name => name !== 'after'), firstNames, 'first page must send each non-cursor query');
  assert.deepEqual(documented, laterNames, 'cursor pages must preserve every query');
  assert.equal(laterPage.searchParams.get('after'), 'server-lab|1');
  for (const name of firstNames) {
    assert.equal(laterPage.searchParams.get(name), firstPage.searchParams.get(name), `${name} must survive pagination`);
  }
});
