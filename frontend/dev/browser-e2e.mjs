import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { labBrowserOptions } from './lab-browser.mjs';

const origin = 'http://127.0.0.1:5173';
const allowedCa = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const hiddenCa = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const allowedRequest = '11111111-1111-4111-8111-000000000001';
const hiddenRequest = '11111111-1111-4111-8111-000000000002';
const allowedEvent = '33333333-3333-4333-8333-000000000001';
const expectedCn = process.env.TRUST_E2E_EXPECTED_CN ?? 'compose-allowed.lab.invalid';
const sanExpectedCn = process.env.TRUST_E2E_SAN_CN ?? 'paged-0102.lab.invalid';
// Keycloak serves HTTPS: only the lab identity provider's key is accepted.
const browser = await chromium.launch(labBrowserOptions());
const readerPassword = process.env.TRUST_LAB_PW_READER;
if (!readerPassword) throw new Error('TRUST_LAB_PW_READER is not set; load .env.lab (set -a; . ./.env.lab; set +a)');

// Each new page is a new browser context, so each signs in through the
// laboratory Keycloak login form, as a person would.
async function signIn(target, username = 'lab-reader', password = readerPassword) {
  await target.getByRole('button', { name: /Sign in with your organization/i }).click();
  await target.locator('#username').fill(username);
  await target.locator('#password').fill(password);
  await target.locator('#kc-login').click();
}

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
  await signIn(page);
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
  // The full-history searches sit in a collapsed section; it stays open.
  await page.getByText('Search the full history', { exact: false }).click();
  if (!process.env.TRUST_E2E_SKIP_CN) {
    const cnSearch = page.getByLabel('CN prefix', { exact: true });
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
  const sanSearch = page.getByLabel('Exact DNS SAN', { exact: true });
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
  await certificateDialog.getByText('Recorded period', { exact: true }).waitFor();
  await certificateDialog.getByRole('button', { name: /Close certificate detail/i }).click();
  await certificateDialog.waitFor({ state: 'hidden' });

  // Historical rows without recorded X.509 dates are excluded by this server
  // filter. The synthetic fixture expires before 2028, but not before 2027.
  await page.getByRole('button', { name: 'Clear SAN' }).click();
  const expiryBefore = page.getByLabel('Valid until before (UTC, exclusive)');
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
  await page.getByRole('table', { name: 'Profile proposals' }).getByText('Laboratory server proposal', { exact: true }).first().waitFor();
  await page.getByRole('checkbox', { name: /Show proposals with advisory syntax warnings among loaded revisions only/ }).check();
  await page.getByText('No advisory syntax warnings in the loaded revisions.').waitFor();
  await page.getByRole('checkbox', { name: /Show proposals with advisory syntax warnings among loaded revisions only/ }).uncheck();
  await page.getByRole('table', { name: 'Profile proposals' }).getByText('Laboratory server proposal', { exact: true }).first().waitFor();
  await page.locator('#profile-draft-search').fill('server-lab');
  const proposalSearch = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('q') === 'server-lab');
  await page.getByRole('button', { name: 'Search proposals' }).click();
  await proposalSearch;
  await page.getByRole('table', { name: 'Profile proposals' }).getByText('Laboratory server proposal', { exact: true }).first().waitFor();
  await page.locator('#profile-draft-search').fill('hidden');
  const hiddenProposalSearch = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('q') === 'hidden');
  await page.getByRole('button', { name: 'Search proposals' }).click();
  await hiddenProposalSearch;
  await page.getByText('No proposals match “hidden”').waitFor();
  await page.getByRole('button', { name: 'Clear search' }).click();
  await page.getByRole('table', { name: 'Profile proposals' }).getByText('Laboratory server proposal', { exact: true }).first().waitFor();
  await page.getByText('Advanced filters (0 active)').click();
  await page.locator('#profile-draft-policy-filter').fill('v2');
  const policyFilterResponse = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('policy_version') === 'v2');
  await page.getByRole('button', { name: 'Filter policy' }).click();
  await policyFilterResponse;
  await page.getByText('server-lab · revision 2').waitFor();
  await page.getByRole('button', { name: 'Clear policy' }).click();
  await page.getByLabel('Recorded before UTC date').fill('2020-01-01');
  const recordedRangeResponse = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('until') === '2020-01-01T00:00:00.000Z');
  await page.getByRole('button', { name: 'Filter dates' }).click();
  await recordedRangeResponse;
  await page.getByText('No proposals match the active filters').waitFor();
  await page.getByRole('button', { name: 'Clear dates' }).click();
  await page.locator('#profile-draft-validity-filter').fill('91');
  const validityResponse = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('min_validity_days') === '91');
  await page.getByRole('button', { name: 'Filter validity' }).click();
  await validityResponse;
  await page.getByText('No proposals match the active filters').waitFor();
  await page.getByRole('button', { name: 'Clear validity' }).click();
  await page.locator('#profile-draft-san-filter').fill('6');
  const sanResponse = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('min_dns_sans') === '6');
  await page.getByRole('button', { name: 'Filter SAN limit' }).click();
  await sanResponse;
  await page.getByText('No proposals match the active filters').waitFor();
  await page.getByRole('button', { name: 'Clear SAN limit' }).click();
  await page.locator('#profile-draft-id-filter').fill('Server-Lab');
  await page.getByRole('button', { name: 'Filter revisions' }).click();
  await page.getByRole('alert').getByText('Enter a lowercase profile ID').waitFor();
  await page.locator('#profile-draft-id-filter').fill('missing-profile');
  const missingProfileFilter = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('profile_id') === 'missing-profile');
  await page.getByRole('button', { name: 'Filter revisions' }).click();
  await missingProfileFilter;
  await page.getByText('No revisions recorded for missing-profile').waitFor();
  await page.locator('#profile-draft-id-filter').fill('server-lab');
  const profileFilter = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('profile_id') === 'server-lab');
  await page.getByRole('button', { name: 'Filter revisions' }).click();
  await profileFilter;
  await page.getByRole('table', { name: 'Profile proposals' }).getByText('Laboratory server proposal', { exact: true }).first().waitFor();
  const newestProfilePage = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).searchParams.get('profile_id') === 'server-lab'
    && new URL(response.url()).searchParams.get('order') === 'newest');
  await page.getByRole('combobox', { name: 'Revision order' }).selectOption('newest');
  await newestProfilePage;
  await page.waitForFunction(() => document.querySelector('.profile-draft-row .mono')?.textContent?.includes('revision 2'));
  const unfilteredProfiles = page.waitForResponse(response => response.status() === 200
    && new URL(response.url()).pathname.endsWith('/profile-drafts')
    && !new URL(response.url()).searchParams.has('profile_id'));
  await page.getByRole('button', { name: 'Clear all advanced filters' }).click();
  await unfilteredProfiles;
  await page.getByText('Advanced filters (0 active)').waitFor();
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
  await signIn(freshPage);
  await freshPage.getByRole('dialog', { name: 'Revision 2' }).waitFor();
  assert.equal(new URL(freshPage.url()).searchParams.get('profile'), 'server-lab');
  await freshPage.close();
  const proposalTable = page.getByRole('table', { name: 'Profile proposals' });
  await proposalTable.getByRole('button', { name: 'Compare', exact: true, pressed: false }).first().click();
  await proposalTable.getByRole('button', { name: 'Compare', exact: true, pressed: false }).click();
  await page.getByRole('button', { name: 'Compare selected revisions' }).click();
  const comparison = page.getByRole('dialog', { name: 'Revision comparison' });
  await comparison.waitFor();
  await comparison.getByRole('row', { name: /Policy version v1 v2/ }).waitFor();
  await comparison.getByRole('checkbox', { name: 'Show changed fields only' }).check();
  assert.equal(await comparison.getByRole('row', { name: /Proposed signature suites/ }).count(), 0);
  const comparisonDownload = page.waitForEvent('download');
  await comparison.getByRole('button', { name: 'Export comparison CSV' }).click();
  assert.equal((await comparisonDownload).suggestedFilename(), 'trust-profile-comparison-server-lab-1-2.csv');
  await comparison.getByRole('checkbox', { name: 'Show changed fields only' }).uncheck();
  assert.equal(await comparison.getByRole('row', { name: /Proposed signature suites/ }).count(), 1);
  await comparison.getByRole('button', { name: 'Close revision comparison' }).click();
  await comparison.waitFor({ state: 'hidden' });
  await page.getByText('Advanced filters (0 active)').click();
  await page.locator('#profile-draft-id-filter').fill('missing-profile');
  await page.getByRole('button', { name: 'Filter revisions' }).click();
  await page.getByText('No revisions recorded for missing-profile').waitFor();
  for (const revision of [1, 2]) {
    await page.locator('#profile-draft-id-lookup').fill('server-lab');
    await page.getByRole('textbox', { name: 'Profile revision number' }).fill(String(revision));
    await page.getByRole('button', { name: 'Find revision' }).click();
    const exactDialog = page.getByRole('dialog', { name: `Revision ${revision}` });
    await exactDialog.waitFor();
    await exactDialog.getByRole('button', { name: 'Select for comparison' }).click();
    await exactDialog.getByRole('button', { name: 'Close proposal detail' }).click();
    await exactDialog.waitFor({ state: 'hidden' });
  }
  await page.getByRole('button', { name: 'Compare selected revisions' }).click();
  const exactComparison = page.getByRole('dialog', { name: 'Revision comparison' });
  await exactComparison.getByRole('row', { name: /Policy version v1 v2/ }).waitFor();
  assert.equal(new URL(page.url()).searchParams.get('compare_revision'), '2');
  await exactComparison.getByRole('button', { name: 'Copy comparison link' }).waitFor();
  await exactComparison.getByRole('button', { name: 'Close revision comparison' }).click();
  await exactComparison.waitFor({ state: 'hidden' });
  await page.waitForFunction(() => !new URL(location.href).searchParams.has('compare_revision'));
  const comparisonUrl = `${origin}/?view=profiles&ca=${allowedCa}&profile=server-lab&revision=1&compare_revision=2`;
  const sharedComparisonPage = await browser.newPage();
  sharedComparisonPage.setDefaultTimeout(15_000);
  await sharedComparisonPage.goto(comparisonUrl);
  await signIn(sharedComparisonPage);
  const sharedComparison = sharedComparisonPage.getByRole('dialog', { name: 'Revision comparison' });
  await sharedComparison.getByRole('row', { name: /Policy version v1 v2/ }).waitFor();
  assert.equal(new URL(sharedComparisonPage.url()).searchParams.get('compare_revision'), '2');
  await sharedComparisonPage.close();
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

  await page.getByText('Filter the full history', { exact: false }).click();
  await page.getByRole('searchbox', { name: 'Exact decision' }).fill('allow');
  await page.getByRole('searchbox', { name: 'Exact policy version' }).fill('v1');
  await page.getByRole('button', { name: 'Apply' }).click();
  await page.getByText('Server filters are active for this authority’s full audit history.').waitFor();
  await page.getByRole('button', { name: 'Load older audit events' }).waitFor();
  await page.getByRole('searchbox', { name: 'Exact decision' }).fill('deny');
  await page.getByRole('button', { name: 'Apply' }).click();
  await page.getByText('No audit events recorded').waitFor();

  // A reader is not offered profile changes. An author records a revision
  // through the console form and submits it; it becomes SUBMITTED, not
  // approved.
  await page.goto(`${origin}/?view=profiles&ca=${allowedCa}`);
  // The page title and the panel heading share this name: wait for both, so
  // the assertion below runs once the panel, where the button would be, is
  // rendered.
  await page.getByRole('heading', { name: 'Profile proposals', level: 1 }).waitFor();
  await page.getByRole('heading', { name: 'Profile proposals', level: 3 }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Propose a revision' }).count(), 0);
  if (process.env.TRUST_LAB_PW_AUTHOR) {
    const authorPage = await browser.newPage();
    authorPage.setDefaultTimeout(15_000);
    await authorPage.goto(`${origin}/?view=profiles&ca=${allowedCa}`);
    await signIn(authorPage, 'lab-author', process.env.TRUST_LAB_PW_AUTHOR);
    await authorPage.getByRole('button', { name: 'Propose a revision' }).click();
    const form = authorPage.getByRole('dialog', { name: 'Propose a profile revision' });
    const browserProfile = `browser-${Date.now().toString(36)}`;
    await form.getByLabel('Profile ID').fill(browserProfile);
    await form.getByLabel('Display name').fill('Browser server proposal');
    await form.getByLabel('Policy version').fill('v1');
    await form.getByLabel(/Proposed DNS zones/).fill('lab.invalid');
    await form.getByRole('button', { name: 'Record draft revision' }).click();
    const recorded = authorPage.getByRole('dialog', { name: 'Revision 1' });
    await recorded.waitFor();
    await recorded.locator('.ui-drawer-badges [data-status="DRAFT"]').waitFor();
    await recorded.getByRole('button', { name: 'Submit for approval' }).click();
    await recorded.locator('.ui-drawer-badges [data-status="SUBMITTED"]').waitFor();
    await recorded.getByText('This revision awaits approval.', { exact: false }).waitFor();
    assert.equal(await recorded.getByRole('button', { name: 'Submit for approval' }).count(), 0);
    await authorPage.getByRole('status').filter({ hasText: 'was submitted for approval' }).waitFor();
    await authorPage.close();

    // Two approvers sign the exact claim with their own laboratory keys
    // (generated by scripts/lab/init-env.sh), outside the browser.
    const keys = fileURLToPath(new URL('../../.lab-keys/', import.meta.url));
    for (const [index, expected] of [[1, 'SUBMITTED'], [2, 'APPROVED']]) {
      const approverPage = await browser.newPage();
      approverPage.setDefaultTimeout(15_000);
      await approverPage.goto(`${origin}/?view=profiles&ca=${allowedCa}&profile=${browserProfile}&revision=1`);
      await signIn(approverPage, `lab-approver-${index}`, process.env[`TRUST_LAB_PW_APPROVER_${index}`]);
      const detail = approverPage.getByRole('dialog', { name: 'Revision 1' });
      await detail.getByRole('button', { name: 'Prepare approval' }).click();
      const claim = await detail.getByLabel(/Claim to sign/).inputValue();
      assert.match(claim, /^trust-platform\/profile-decision\/v1;decision=approve;/);
      const signature = execFileSync('openssl', ['dgst', '-sha256', '-sign', `${keys}lab-approver-${index}.pem`], { input: claim }).toString('base64');
      await detail.getByLabel('Signature (base64, DER)').fill(signature);
      await detail.getByRole('button', { name: 'Record approval' }).click();
      await approverPage.getByRole('status').filter({ hasText: index === 1 ? 'was recorded (1/2)' : 'is now APPROVED' }).waitFor();
      await detail.locator(`.ui-drawer-badges [data-status="${expected}"]`).waitFor();
      await approverPage.close();
    }

    // An independent operator activates the approved revision, then retires it.
    const operatorPage = await browser.newPage();
    operatorPage.setDefaultTimeout(15_000);
    await operatorPage.goto(`${origin}/?view=profiles&ca=${allowedCa}&profile=${browserProfile}&revision=1`);
    await signIn(operatorPage, 'lab-operator', process.env.TRUST_LAB_PW_OPERATOR);
    const operated = operatorPage.getByRole('dialog', { name: 'Revision 1' });
    await operated.getByRole('button', { name: 'Activate this revision' }).click();
    await operatorPage.getByRole('status').filter({ hasText: 'is now ACTIVE' }).waitFor();
    await operated.getByRole('button', { name: 'Retire this revision' }).click();
    await operatorPage.getByRole('status').filter({ hasText: 'is now RETIRED' }).waitFor();
    assert.equal(await operated.getByRole('button', { name: /Activate|Retire/ }).count(), 0);
    await operatorPage.close();
  }

  // A CA administrator proposes a CA from the console and registers a root
  // generated outside the platform by OpenSSL; only the certificate is pasted.
  if (process.env.TRUST_LAB_PW_CA_ADMIN) {
    const adminPage = await browser.newPage();
    adminPage.setDefaultTimeout(15_000);
    await adminPage.goto(`${origin}/?view=authorities`);
    await signIn(adminPage, 'lab-ca-admin', process.env.TRUST_LAB_PW_CA_ADMIN);
    const panel = adminPage.getByRole('region', { name: 'CA proposals' });
    const rootName = `Browser Lab Root ${Date.now().toString(36)}`;
    await panel.getByLabel('Display name').fill(rootName);
    await panel.getByRole('button', { name: 'Propose this CA' }).click();
    const row = panel.getByRole('row').filter({ hasText: rootName });
    await row.getByText('Proposed', { exact: true }).waitFor();
    const repository = fileURLToPath(new URL('../../', import.meta.url));
    const pem = execFileSync('sh', ['scripts/lab/create-lab-root.sh', rootName], { cwd: repository }).toString();
    await row.getByLabel(/Certificate \(PEM\)/).fill(pem);
    await row.getByRole('button', { name: 'Register certificate' }).click();
    await panel.getByRole('row').filter({ hasText: rootName }).getByText('Key attested', { exact: true }).waitFor();

    // Two CA approvers sign the exact claim with their own laboratory keys,
    // outside the browser; then the administrator activates the CA.
    const keys = fileURLToPath(new URL('../../.lab-keys/', import.meta.url));
    for (const index of [1, 2]) {
      const approverPage = await browser.newPage();
      approverPage.setDefaultTimeout(15_000);
      await approverPage.goto(`${origin}/?view=authorities`);
      await signIn(approverPage, `lab-ca-approver-${index}`, process.env[`TRUST_LAB_PW_CA_APPROVER_${index}`]);
      const approverRow = approverPage.getByRole('region', { name: 'CA proposals' }).getByRole('row').filter({ hasText: rootName });
      await approverRow.getByRole('button', { name: 'Prepare CA approval' }).click();
      const claim = await approverRow.getByLabel(/CA claim to sign/).inputValue();
      assert.match(claim, /^trust-platform\/ca-decision\/v1;decision=approve;/);
      const signature = execFileSync('openssl', ['dgst', '-sha256', '-sign', `${keys}lab-ca-approver-${index}.pem`], { input: claim }).toString('base64');
      await approverRow.getByLabel('CA decision signature (base64, DER)').fill(signature);
      await approverRow.getByRole('button', { name: 'Record CA approval' }).click();
      await approverPage.getByRole('status').filter({ hasText: index === 1 ? 'was recorded (1/2)' : 'is now APPROVED' }).waitFor();
      await approverPage.close();
    }
    await adminPage.reload();
    const approvedRow = panel.getByRole('row').filter({ hasText: rootName });
    await approvedRow.getByRole('button', { name: 'Activate this CA' }).click();
    await adminPage.getByRole('status').filter({ hasText: 'is now an ACTIVE CA' }).waitFor();
    await panel.getByRole('row').filter({ hasText: rootName }).getByText('Active', { exact: true }).waitFor();

    // The administrator suspends the CA at once from the console.
    await panel.getByRole('row').filter({ hasText: rootName }).getByRole('button', { name: 'Operations' }).click();
    const activeRow = panel.getByRole('row').filter({ hasText: rootName });
    await activeRow.getByLabel(`Reason for ${rootName}`).fill('browser key review');
    await activeRow.getByRole('button', { name: 'Suspend this CA' }).click();
    await adminPage.getByRole('status').filter({ hasText: 'is now SUSPENDED' }).waitFor();
    await panel.getByRole('row').filter({ hasText: rootName }).getByText('Suspended', { exact: true }).first().waitFor();
    const slug = rootName.toLowerCase().replaceAll(' ', '-');
    rmSync(`${repository}.lab-keys/ca/ca-root-${slug}.pem`, { force: true });
    rmSync(`${repository}.lab-keys/ca/ca-root-${slug}.crt`, { force: true });
    await adminPage.close();
  }

  // Signing out ends the Keycloak session too: signing in again asks for the
  // password instead of reusing the identity provider's session cookie.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.getByRole('button', { name: /Sign in with your organization/i }).click();
  await page.locator('#password').waitFor();
  assert.equal(await page.locator('#kc-form-login').count(), 1);

  console.log(`Browser E2E passed: Keycloak sign-in and sign-out, ${process.env.TRUST_LAB_PW_AUTHOR ? 'profile draft recorded, submitted, approved by two signing approvers, activated and retired from the console, ' : ''}${process.env.TRUST_LAB_PW_CA_ADMIN ? 'CA proposed, its OpenSSL root registered, approved by two signing CA approvers, activated and suspended from the console, ' : ''}OIDC, scoped direct links, denial, pagination, dialogs, SAN search, recorded validity cutoff, audit decision/policy filters${process.env.TRUST_E2E_SKIP_CN ? '' : ', CN search'}${process.env.TRUST_E2E_SKIP_CSV ? '' : ', selected CSV'}.`);
} catch (error) {
  // Report every page still open (the reader page and, for example, the
  // approver page whose step failed), not only the first page: a dump of
  // the wrong page once hid a 401 that had signed the approver out.
  for (const open of browser.contexts().flatMap(context => context.pages())) {
    console.error('Browser E2E failed; open page:', open.url());
    console.error((await open.locator('body').innerText().catch(() => '(page text unavailable)')).slice(0, 1800));
  }
  throw error;
} finally {
  await browser.close();
}
