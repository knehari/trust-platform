import type { AuditEvent } from './api';

export type AuditSort = 'newest' | 'oldest' | 'type' | 'decision';

export function sortLoadedAuditEvents(rows: AuditEvent[], order: AuditSort): AuditEvent[] {
  if (order === 'newest') return rows;
  if (order === 'oldest') return [...rows].reverse();
  return [...rows].sort((a, b) => {
    const comparison = order === 'type'
      ? a.event_type.localeCompare(b.event_type)
      : a.decision.localeCompare(b.decision);
    return comparison || a.event_id.localeCompare(b.event_id);
  });
}
