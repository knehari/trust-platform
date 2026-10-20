import assert from 'node:assert/strict';
import { test } from 'node:test';
import { navigationUrl, readNavigation } from '../src/navigation.ts';

const ca = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

test('view links round-trip a canonical CA without carrying credentials', () => {
  const url = navigationUrl('certificates', ca);
  assert.equal(url, `/?view=certificates&ca=${ca}`);
  assert.deepEqual(readNavigation(url.slice(1)), { section: 'certificates', caId: ca });
  assert.deepEqual(readNavigation(`?view=audit&ca=%7B${ca.toUpperCase()}%7D`), { section: 'audit', caId: ca });
});

test('untrusted navigation values cannot become paths or authority IDs', () => {
  assert.deepEqual(readNavigation('?view=https://evil.invalid&ca=not-a-uuid&token=secret'), { section: 'overview', caId: null });
  assert.deepEqual(readNavigation(`?ca=${ca}`), { section: 'authorities', caId: ca });
  assert.equal(navigationUrl('overview', null), '/?view=overview');
  const destination = readNavigation(`?view=audit&ca=${ca}&token=secret`);
  const oidcState = navigationUrl(destination.section, destination.caId).slice(1);
  assert.equal(oidcState, `?view=audit&ca=${ca}`);
  assert.deepEqual(readNavigation(oidcState), destination);
});
