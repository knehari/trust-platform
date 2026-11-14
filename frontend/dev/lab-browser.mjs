// Chromium launch options for the laboratory suites (ADR-0033). Keycloak
// serves HTTPS with a certificate from the lab service CA, which the browser
// does not know. Instead of ignoring certificate errors in general, the
// browser accepts exactly the lab identity provider's key: its SPKI SHA-256
// is pinned with --ignore-certificate-errors-spki-list. Any other
// certificate error still fails.
import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const certificate = fileURLToPath(new URL('../../.lab-keys/tls/idp.crt', import.meta.url));

export function labIdpSpkiPin() {
  const spki = new X509Certificate(readFileSync(certificate)).publicKey.export({ type: 'spki', format: 'der' });
  return createHash('sha256').update(spki).digest('base64');
}

export function labBrowserOptions(extra = {}) {
  return {
    headless: true,
    ...(process.env.TRUST_E2E_CHROME_PATH ? { executablePath: process.env.TRUST_E2E_CHROME_PATH } : {}),
    ...extra,
    args: [...(extra.args ?? []), `--ignore-certificate-errors-spki-list=${labIdpSpkiPin()}`],
  };
}
