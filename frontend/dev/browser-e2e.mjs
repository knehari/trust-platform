import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const origin = 'http://127.0.0.1:5173';
const allowedCa = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const hiddenCa = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const allowedRequest = '11111111-1111-4111-8111-000000000001';
const hiddenRequest = '11111111-1111-4111-8111-000000000002';
const allowedEvent = '33333333-3333-4333-8333-000000000001';
const expectedCn = process.env.TRUST_E2E_EXPECTED_CN ?? 'compose-allowed.lab.invalid';
const sanExpectedCn = process.env.TRUST_E2E_SAN_CN ?? 'paged-0102.lab.invalid';
const browser = await chromium.launch({
  headless: true,
  ...(process.env.TRUST_E2E_CHROME_PATH ? { executablePath: process.env.TRUST_E2E_CHROME_PATH } : {}),
});
const page = await browser.newPage({ acceptDownloads: true });
page.setDefaultTimeout(15_000);
page.on('response', response => {
  if (response.url().includes('/v1/cas/') && response.url().includes('/certificates?')) {
    console.log('Certificate page:', response.status(), new URL(response.url()).search);
  }
});

try {
  // A fresh browser must complete the actual OIDC code + PKCE redirect before
  // opening a scoped direct link. The synthetic DER never appears in the UI.
  await page.goto(`${origin}/?view=certificates&ca=${allowedCa}&certificate=${allowedRequest}`);
  await page.getByRole('button', { name: /Sign in with your organization/i }).click();
  const certificateDialog = page.getByRole('dialog', { name: 'Certificate detail' });
  await certificateDialog.waitFor();
  assert.equal(new URL(page.url()).searchParams.get('certificate'), allowedRequest);
  await certificateDialog.getByText(expectedCn).waitFor();
  await certificateDialog.getByText('Not recorded').first().waitFor();
  assert.equal((await certificateDialog.textContent()).includes('3000'), false);
  await certificateDialog.getByRole('button', { name: /Close certificate detail/i }).click();
  await certificateDialog.waitFor({ state: 'hidden' });

  // A 101-record CI fixture crosses the 100-row API page. The original Compose
  // record is on the older page and must remain reachable by a server CN query.
  const table = page.getByRole('table');
  await table.getByRole('row').nth(100).waitFor();
  await page.getByRole('button', { name: 'Load older certificates' }).click();
  await table.getByRole('row').nth(101).waitFor();
  if (!process.env.TRUST_E2E_SKIP_CN) {
    const cnSearch = page.getByLabel('Search CN prefix across this authority’s full certificate history');
    await cnSearch.fill(expectedCn.slice(0, -'.lab.invalid'.length));
    await cnSearch.locator('..').getByRole('button', { name: 'Search', exact: true }).click();
    await table.getByRole('button', { name: `View certificate for ${expectedCn}` }).waitFor();
    assert.equal(await table.getByRole('row').count(), 2);
  }

  if (!process.env.TRUST_E2E_SKIP_CSV) {
    await page.getByRole('checkbox', { name: /Select certificate .* for CSV export/i }).first().check();
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export selected CSV' }).click();
    const download = await downloadPromise;
    const stream = await download.createReadStream();
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    const content = Buffer.concat(chunks).toString('utf8');
    assert.ok(content.includes(process.env.TRUST_E2E_SKIP_CN ? '.lab.invalid' : expectedCn));
    assert.equal(content.includes('certificate_der'), false);
    assert.equal(content.includes('private-compose-actor'), false);
  }

  // Search the full history by DNS SAN, including a record beyond page one.
  if (!process.env.TRUST_E2E_SKIP_CN) {
    await page.getByRole('button', { name: 'Clear', exact: true }).click();
  }
  const sanSearch = page.getByLabel('Search exact DNS SAN across this authority’s full certificate history');
  await sanSearch.fill('PAGED-0102.LAB.INVALID');
  const sanPage = page.waitForResponse(response => response.status() === 200
    && response.url().includes('/certificates?')
    && new URL(response.url()).searchParams.get('san_dns') === 'PAGED-0102.LAB.INVALID');
  await page.getByRole('button', { name: 'Search SAN' }).click();
  await sanPage;
  await table.getByRole('button', { name: `View certificate for ${sanExpectedCn}` }).waitFor();
  await page.waitForFunction(() => document.querySelectorAll('table.certificate-table tr').length === 2);
  assert.equal(await table.getByRole('row').count(), 2);
  await table.getByRole('button', { name: `View certificate for ${sanExpectedCn}` }).click();
  await certificateDialog.getByText(sanExpectedCn).first().waitFor();
  await certificateDialog.getByText('RECORDED PERIOD', { exact: true }).waitFor();
  await certificateDialog.getByRole('button', { name: /Close certificate detail/i }).click();
  await certificateDialog.waitFor({ state: 'hidden' });

  // Historical rows without recorded X.509 dates are excluded by this server
  // filter. The synthetic fixture expires before 2028, but not before 2027.
  await page.getByRole('button', { name: 'Clear SAN' }).click();
  const expiryBefore = page.getByLabel('Recorded valid-until before this UTC date (exclusive)');
  await expiryBefore.fill('2028-01-01');
  const expiryPage = page.waitForResponse(response => response.status() === 200
    && response.url().includes('/certificates?')
    && new URL(response.url()).searchParams.get('not_after_before') === '2028-01-01T00:00:00.000Z');
  await page.getByRole('button', { name: 'Apply date' }).click();
  await expiryPage;
  await table.getByRole('button', { name: `View certificate for ${sanExpectedCn}` }).waitFor();
  await page.waitForFunction(() => document.querySelectorAll('table.certificate-table tr').length === 2);
  assert.equal(await table.getByRole('row').count(), 2);
  await expiryBefore.fill('2027-01-01');
  const emptyExpiryPage = page.waitForResponse(response => response.status() === 200
    && response.url().includes('/certificates?')
    && new URL(response.url()).searchParams.get('not_after_before') === '2027-01-01T00:00:00.000Z');
  await page.getByRole('button', { name: 'Apply date' }).click();
  await emptyExpiryPage;
  await page.getByText('No certificates recorded').waitFor();
  await page.getByRole('button', { name: 'Clear date' }).click();

  // Profile drafts are readable only under the signed and granted CA scope.
  await page.goto(`${origin}/?view=profiles&ca=${allowedCa}`);
  await page.getByRole('heading', { name: 'Laboratory server proposal' }).first().waitFor();
  await page.getByText('These proposals are not approved or active.').waitFor();
  await page.getByRole('button', { name: 'View proposal detail' }).first().click();
  const profileDialog = page.getByRole('dialog', { name: 'Revision 1' });
  await profileDialog.waitFor();
  await profileDialog.getByText('SNAPSHOT SHA-256').waitFor();
  assert.match(await profileDialog.textContent(), /[0-9a-f]{64}/);
  assert.equal(new URL(page.url()).searchParams.get('profile'), 'server-lab');
  assert.equal(new URL(page.url()).searchParams.get('revision'), '1');
  await profileDialog.getByRole('button', { name: 'Close proposal detail' }).click();
  await profileDialog.waitFor({ state: 'hidden' });
  await page.waitForFunction(() => !new URL(location.href).searchParams.has('profile'));
  assert.equal(new URL(page.url()).searchParams.has('profile'), false);
  await page.locator('#profile-draft-id-lookup').fill('Server-Lab');
  await page.getByRole('textbox', { name: 'Profile revision number' }).fill('2');
  await page.getByRole('button', { name: 'Find revision' }).click();
  await page.getByRole('alert').getByText('Enter a lowercase profile ID').waitFor();
  assert.equal(new URL(page.url()).searchParams.has('profile'), false);
  await page.locator('#profile-draft-id-lookup').fill('server-lab');
  const profileLookup = page.waitForResponse(response => response.status() === 200 && response.url().endsWith('/profile-drafts/server-lab/2'));
  await page.getByRole('button', { name: 'Find revision' }).click();
  await profileLookup;
  const lookedUpProfileDialog = page.getByRole('dialog', { name: 'Revision 2' });
  await lookedUpProfileDialog.waitFor();
  await lookedUpProfileDialog.getByRole('button', { name: 'Close proposal detail' }).click();
  await lookedUpProfileDialog.waitFor({ state: 'hidden' });
  await page.waitForFunction(() => !new URL(location.href).searchParams.has('profile'));
  await page.goto(`${origin}/?view=profiles&ca=${allowedCa}&profile=server-lab&revision=2`);
  const linkedProfileDialog = page.getByRole('dialog', { name: 'Revision 2' });
  await linkedProfileDialog.waitFor();
  await linkedProfileDialog.getByText('v2', { exact: true }).waitFor();
  await linkedProfileDialog.getByRole('button', { name: 'Close proposal detail' }).click();
  await linkedProfileDialog.waitFor({ state: 'hidden' });
  const freshPage = await browser.newPage();
  freshPage.setDefaultTimeout(15_000);
  await freshPage.goto(`${origin}/?view=profiles&ca=${allowedCa}&profile=server-lab&revision=2`);
  await freshPage.getByRole('button', { name: /Sign in with your organization/i }).click();
  await freshPage.getByRole('dialog', { name: 'Revision 2' }).waitFor();
  assert.equal(new URL(freshPage.url()).searchParams.get('profile'), 'server-lab');
  await freshPage.close();
  await page.getByRole('button', { name: 'Select for comparison' }).first().click();
  await page.getByRole('button', { name: 'Select for comparison' }).click();
  await page.getByRole('button', { name: 'Compare selected revisions' }).click();
  const comparison = page.getByRole('dialog', { name: 'Revision comparison' });
  await comparison.waitFor();
  await comparison.getByRole('row', { name: /Policy version v1 v2/ }).waitFor();
  await comparison.getByRole('button', { name: 'Close revision comparison' }).click();
  await comparison.waitFor({ state: 'hidden' });
  assert.equal(await page.getByText('Hidden laboratory proposal').count(), 0);
  await page.goto(`${origin}/?view=profiles&ca=${hiddenCa}&profile=hidden-lab&revision=1`);
  await page.getByRole('alert').first().waitFor();
  assert.equal(await page.getByText('Hidden laboratory proposal').count(), 0);
  assert.equal(await page.getByRole('dialog', { name: 'Revision 1' }).count(), 0);

  // The same browser session must deny a CA outside the signed scope. A forged
  // deep link must not surface the hidden certificate.
  await page.goto(`${origin}/?view=certificates&ca=${hiddenCa}&certificate=${hiddenRequest}`);
  await page.getByRole('alert').first().waitFor();
  assert.equal(await page.getByText('compose-hidden.lab.invalid').count(), 0);
  assert.equal(await page.getByRole('dialog', { name: 'Certificate detail' }).count(), 0);

  await page.goto(`${origin}/?view=audit&ca=${allowedCa}&event=${allowedEvent}`);
  const auditDialog = page.getByRole('dialog', { name: 'Audit event detail' });
  await auditDialog.waitFor();
  await auditDialog.getByText('certificate.signed').waitFor();
  assert.equal((await auditDialog.textContent()).includes('private-compose-actor'), false);
  await auditDialog.getByRole('button', { name: /Close audit event detail/i }).click();
  await auditDialog.waitFor({ state: 'hidden' });

  await page.getByRole('searchbox', { name: 'Exact decision' }).fill('allow');
  await page.getByRole('searchbox', { name: 'Exact policy version' }).fill('v1');
  await page.getByRole('button', { name: 'Apply' }).click();
  await page.getByText('Server filters are active for this authority’s full audit history.').waitFor();
  await page.getByRole('button', { name: 'Load older audit events' }).waitFor();
  await page.getByRole('searchbox', { name: 'Exact decision' }).fill('deny');
  await page.getByRole('button', { name: 'Apply' }).click();
  await page.getByText('No audit events recorded').waitFor();

  console.log(`Browser E2E passed: OIDC, scoped direct links, denial, pagination, dialogs, SAN search, recorded validity cutoff, audit decision/policy filters${process.env.TRUST_E2E_SKIP_CN ? '' : ', CN search'}${process.env.TRUST_E2E_SKIP_CSV ? '' : ', selected CSV'}.`);
} catch (error) {
  console.error('Browser E2E failed at', page.url());
  console.error((await page.locator('main').innerText()).slice(0, 1800));
  throw error;
} finally {
  await browser.close();
}
