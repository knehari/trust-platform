import type { Certificate } from './api';

export function recordedValidityStatus(
  certificate: Pick<Certificate, 'not_before' | 'not_after'>,
  now: number,
): string {
  if (!certificate.not_before || !certificate.not_after) return 'Not recorded';
  const start = Date.parse(certificate.not_before);
  const end = Date.parse(certificate.not_after);
  if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end) return 'Not recorded';
  if (now < start) return 'Not yet in period';
  if (now >= end) return 'Period ended';
  return 'Within period';
}
