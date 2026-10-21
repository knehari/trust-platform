import { canonicalUuid } from './uuid.ts';

export type Section = 'overview' | 'authorities' | 'certificates' | 'audit';
export type DetailLink = { kind: 'certificate' | 'audit'; id: string };

export function readNavigation(search: string): { section: Section; caId: string | null; detail: DetailLink | null } {
  const params = new URLSearchParams(search);
  const view = params.get('view');
  const caId = canonicalUuid(params.get('ca') ?? '');
  const section: Section = view === 'authorities' || view === 'certificates' || view === 'audit' || view === 'overview'
    ? view : caId ? 'authorities' : 'overview';
  const certificateId = canonicalUuid(params.get('certificate') ?? '');
  const auditId = canonicalUuid(params.get('event') ?? '');
  const detail = caId && section === 'certificates' && certificateId
    ? { kind: 'certificate' as const, id: certificateId }
    : caId && section === 'audit' && auditId
      ? { kind: 'audit' as const, id: auditId }
      : null;
  return { section, caId, detail };
}

export function navigationUrl(section: Section, caId: string | null, detail: DetailLink | null = null): string {
  const params = new URLSearchParams({ view: section });
  if (caId) params.set('ca', caId);
  if (caId && detail?.kind === 'certificate' && section === 'certificates') params.set('certificate', detail.id);
  if (caId && detail?.kind === 'audit' && section === 'audit') params.set('event', detail.id);
  return `/?${params.toString()}`;
}
