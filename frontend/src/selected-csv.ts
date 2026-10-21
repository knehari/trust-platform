import type { AuditEvent, Certificate } from './api';

export const MAX_CSV_ROWS = 100;

function cell(value: string | null): string {
  const text = value ?? '';
  const safe = /^[\s\uFEFF\u200B]*[=+\-@]/u.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}

function csv(header: string[], rows: (string | null)[][]): string {
  if (rows.length === 0 || rows.length > MAX_CSV_ROWS) throw new Error('Select 1–100 rows to export.');
  return [header, ...rows].map(row => row.map(cell).join(',')).join('\r\n') + '\r\n';
}

export function certificateCsv(rows: Certificate[]): string {
  return csv(
    ['ca_id', 'request_id', 'serial_hex', 'subject_cn', 'not_before', 'not_after', 'san_dns', 'fingerprint_sha256', 'state', 'signed_at', 'published_at'],
    rows.map(row => [row.ca_id, row.request_id, row.serial_hex, row.subject_cn, row.not_before, row.not_after, row.san_dns?.join('; ') ?? null, row.fingerprint_sha256, row.state, row.signed_at, row.published_at]),
  );
}

export function auditCsv(rows: AuditEvent[]): string {
  return csv(
    ['ca_id', 'event_id', 'event_type', 'decision', 'policy_version', 'recorded_at'],
    rows.map(row => [row.ca_id, row.event_id, row.event_type, row.decision, row.policy_version, row.recorded_at]),
  );
}
