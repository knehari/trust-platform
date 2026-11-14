// Pure figures for the overview dashboard. They summarise the rows the
// console already loaded for the selected authority; they are not server
// totals, and the dashboard says so.
import type { AuditEvent, Certificate } from './api';
import { describeOutcome } from './labels.ts';

const DAY = 86_400_000;

export interface Bucket { key: string; start: number; end: number; count: number; extra: number }

function startOfUtcDay(time: number): number { return Math.floor(time / DAY) * DAY; }

/** Certificates whose recorded notAfter falls in each of the next `weeks` weeks. */
export function expiryBuckets(certificates: Pick<Certificate, 'not_after' | 'revoked_at'>[], now: number, weeks = 12): Bucket[] {
  const start = startOfUtcDay(now);
  const buckets: Bucket[] = Array.from({ length: weeks }, (_, index) => ({
    key: `w${index}`, start: start + index * 7 * DAY, end: start + (index + 1) * 7 * DAY, count: 0, extra: 0,
  }));
  for (const certificate of certificates) {
    if (certificate.revoked_at) continue;
    const end = certificate.not_after ? Date.parse(certificate.not_after) : NaN;
    if (!Number.isFinite(end) || end < now) continue;
    const bucket = buckets.find(item => end >= item.start && end < item.end);
    if (bucket) bucket.count += 1;
  }
  return buckets;
}

/** Audit events per UTC day over the last `days` days; `extra` counts denials. */
export function activityByDay(events: Pick<AuditEvent, 'recorded_at' | 'decision'>[], now: number, days = 14): Bucket[] {
  const today = startOfUtcDay(now);
  const buckets: Bucket[] = Array.from({ length: days }, (_, index) => {
    const start = today - (days - 1 - index) * DAY;
    return { key: new Date(start).toISOString().slice(0, 10), start, end: start + DAY, count: 0, extra: 0 };
  });
  for (const event of events) {
    const time = Date.parse(event.recorded_at);
    const bucket = buckets.find(item => time >= item.start && time < item.end);
    if (!bucket) continue;
    bucket.count += 1;
    if (event.decision === 'deny') bucket.extra += 1;
  }
  return buckets;
}

export interface CertificateHealth { valid: number; expiringSoon: number; expired: number; unknown: number; revoked: number }

/** Recorded-validity health of loaded certificates; `soonDays` marks renewals. */
export function certificateHealth(certificates: Pick<Certificate, 'not_before' | 'not_after' | 'revoked_at'>[], now: number, soonDays = 30): CertificateHealth {
  const health = { valid: 0, expiringSoon: 0, expired: 0, unknown: 0, revoked: 0 };
  for (const certificate of certificates) {
    // A recorded revocation outranks the validity period.
    if (certificate.revoked_at) { health.revoked += 1; continue; }
    const start = certificate.not_before ? Date.parse(certificate.not_before) : NaN;
    const end = certificate.not_after ? Date.parse(certificate.not_after) : NaN;
    if (!Number.isFinite(start) || !Number.isFinite(end)) health.unknown += 1;
    else if (end <= now) health.expired += 1;
    else if (end - now <= soonDays * DAY) health.expiringSoon += 1;
    else if (start <= now) health.valid += 1;
    else health.unknown += 1;
  }
  return health;
}

/** Share of the recorded lifetime already elapsed, 0–1, or null when unknown. */
export function lifetimeElapsed(certificate: Pick<Certificate, 'not_before' | 'not_after'>, now: number): number | null {
  const start = certificate.not_before ? Date.parse(certificate.not_before) : NaN;
  const end = certificate.not_after ? Date.parse(certificate.not_after) : NaN;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return null;
  return Math.min(1, Math.max(0, (now - start) / (end - start)));
}

/** Loaded audit events that ended in a denial or a reconciliation, newest window only. */
export function attentionEvents(events: Pick<AuditEvent, 'recorded_at' | 'decision'>[], now: number, days = 7): { denied: number; reconciliation: number } {
  let denied = 0;
  let reconciliation = 0;
  for (const event of events) {
    if (now - Date.parse(event.recorded_at) > days * DAY) continue;
    const outcome = describeOutcome(event.decision);
    if (outcome.kind === 'decision' && outcome.status === 'deny') denied += 1;
    if (outcome.kind === 'transition' && outcome.to === 'RECONCILIATION_REQUIRED') reconciliation += 1;
  }
  return { denied, reconciliation };
}

/** "Today", "Yesterday" or the local date, for grouping rows by day. */
export function dayLabel(value: string, now: Date): string {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return 'Unknown date';
  const key = (d: Date) => `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  if (key(date) === key(now)) return 'Today';
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (key(date) === key(yesterday)) return 'Yesterday';
  return date.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
}
