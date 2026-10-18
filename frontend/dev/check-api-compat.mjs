import { pathToFileURL } from 'node:url';

const ca = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const request = '11111111-1111-4111-8111-000000000001';
const event = '33333333-3333-4333-8333-000000000001';

export async function checkApi(base = 'http://127.0.0.1:8081') {
  const routes = [
    `/v1/cas/${ca}/certificates/${request}`,
    `/v1/cas/${ca}/audit/${event}`,
  ];
  for (const route of routes) {
    const response = await fetch(new URL(route, base), { signal: AbortSignal.timeout(5000) });
    if (response.status === 404) {
      throw new Error(`${route} is missing (404). Rebuild and restart trust-management-api from this checkout.`);
    }
    if (response.status !== 401) {
      throw new Error(`${route} returned ${response.status}; expected 401 for an unauthenticated request.`);
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  checkApi(process.env.TRUST_API_DEV_TARGET).then(
    () => console.log('Management API detail routes match this console checkout.'),
    error => { console.error(error.message); process.exitCode = 1; },
  );
}
