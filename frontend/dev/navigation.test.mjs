import assert from 'node:assert/strict';
import { test } from 'node:test';
import { navigationUrl, readNavigation } from '../src/navigation.ts';

const ca = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

test('view links round-trip a canonical CA without carrying credentials', () => {
  const url = navigationUrl('certificates', ca);
  assert.equal(url, `/?view=certificates&ca=${ca}`);
  assert.deepEqual(readNavigation(url.slice(1)), { section: 'certificates', caId: ca, detail: null });
  assert.deepEqual(readNavigation(`?view=audit&ca=%7B${ca.toUpperCase()}%7D`), { section: 'audit', caId: ca, detail: null });
  assert.deepEqual(readNavigation(navigationUrl('profiles', ca).slice(1)), { section: 'profiles', caId: ca, detail: null });
});

test('untrusted navigation values cannot become paths or authority IDs', () => {
  assert.deepEqual(readNavigation('?view=https://evil.invalid&ca=not-a-uuid&token=secret'), { section: 'overview', caId: null, detail: null });
  assert.deepEqual(readNavigation(`?ca=${ca}`), { section: 'authorities', caId: ca, detail: null });
  assert.equal(navigationUrl('overview', null), '/?view=overview');
  const destination = readNavigation(`?view=audit&ca=${ca}&token=secret`);
  const oidcState = navigationUrl(destination.section, destination.caId).slice(1);
  assert.equal(oidcState, `?view=audit&ca=${ca}`);
  assert.deepEqual(readNavigation(oidcState), destination);
});

test('detail links accept only a scoped, canonical UUID for the active view', () => {
  const id = '11111111-1111-4111-8111-000000000001';
  const detail = { kind: 'certificate', id };
  assert.deepEqual(readNavigation(navigationUrl('certificates', ca, detail).slice(1)), { section: 'certificates', caId: ca, detail });
  assert.equal(readNavigation(`?view=audit&ca=${ca}&certificate=${id}`).detail, null);
  assert.equal(readNavigation(`?view=certificates&ca=${ca}&certificate=../../secret`).detail, null);
  assert.equal(readNavigation(`?view=certificates&certificate=${id}`).detail, null);
});

test('profile revision links validate the slug, revision and CA before routing', () => {
  const detail = { kind: 'profile', id: 'server-lab', revision: 2 };
  assert.deepEqual(readNavigation(navigationUrl('profiles', ca, detail).slice(1)), { section: 'profiles', caId: ca, detail });
  for (const search of [
    `?view=profiles&ca=${ca}&profile=../hidden&revision=1`,
    `?view=profiles&ca=${ca}&profile=server-lab&revision=0`,
    `?view=profiles&ca=${ca}&profile=server-lab&revision=01`,
    `?view=profiles&ca=${ca}&profile=server-lab&revision=1000001`,
    `?view=certificates&ca=${ca}&profile=server-lab&revision=2`,
    '?view=profiles&profile=server-lab&revision=2',
  ]) assert.equal(readNavigation(search).detail, null, search);
});
