import { canonicalUuid } from './uuid.ts';

export type Section = 'overview' | 'authorities' | 'profiles' | 'certificates' | 'audit';
export type DetailLink = { kind: 'certificate' | 'audit'; id: string } | { kind: 'profile'; id: string; revision: number };

export function readNavigation(search: string): { section: Section; caId: string | null; detail: DetailLink | null } {
  const params = new URLSearchParams(search);
  const view = params.get('view');
  const caId = canonicalUuid(params.get('ca') ?? '');
  const section: Section = view === 'authorities' || view === 'profiles' || view === 'certificates' || view === 'audit' || view === 'overview'
    ? view : caId ? 'authorities' : 'overview';
  const certificateId = canonicalUuid(params.get('certificate') ?? '');
  const auditId = canonicalUuid(params.get('event') ?? '');
  const profileId = params.get('profile') ?? '';
  const revisionText = params.get('revision') ?? '';
  const revision = /^(?:[1-9][0-9]{0,5})$/.test(revisionText) ? Number(revisionText) : null;
  const detail = caId && section === 'certificates' && certificateId
    ? { kind: 'certificate' as const, id: certificateId }
    : caId && section === 'audit' && auditId
      ? { kind: 'audit' as const, id: auditId }
      : caId && section === 'profiles' && /^[a-z][a-z0-9-]{1,63}$/.test(profileId) && revision !== null && revision <= 1_000_000
        ? { kind: 'profile' as const, id: profileId, revision }
        : null;
  return { section, caId, detail };
}

export function navigationUrl(section: Section, caId: string | null, detail: DetailLink | null = null): string {
  const params = new URLSearchParams({ view: section });
  if (caId) params.set('ca', caId);
  if (caId && detail?.kind === 'certificate' && section === 'certificates') params.set('certificate', detail.id);
  if (caId && detail?.kind === 'audit' && section === 'audit') params.set('event', detail.id);
  if (caId && detail?.kind === 'profile' && section === 'profiles') {
    params.set('profile', detail.id);
    params.set('revision', String(detail.revision));
  }
  return `/?${params.toString()}`;
}
