import { canonicalUuid } from './uuid.ts';
import { canonicalProfileRevision } from './profile-revision.ts';

export type Section = 'overview' | 'authorities' | 'profiles' | 'certificates' | 'audit';
export type DetailLink = { kind: 'certificate' | 'audit'; id: string } | { kind: 'profile'; id: string; revision: number; compareRevision?: number };

export function readNavigation(search: string): { section: Section; caId: string | null; detail: DetailLink | null } {
  const params = new URLSearchParams(search);
  const view = params.get('view');
  const caId = canonicalUuid(params.get('ca') ?? '');
  const section: Section = view === 'authorities' || view === 'profiles' || view === 'certificates' || view === 'audit' || view === 'overview'
    ? view : caId ? 'authorities' : 'overview';
  const certificateId = canonicalUuid(params.get('certificate') ?? '');
  const auditId = canonicalUuid(params.get('event') ?? '');
  const profile = canonicalProfileRevision(params.get('profile') ?? '', params.get('revision') ?? '');
  const hasComparison = params.has('compare_revision');
  const comparison = hasComparison && profile ? canonicalProfileRevision(profile.id, params.get('compare_revision') ?? '') : null;
  const detail = caId && section === 'certificates' && certificateId
    ? { kind: 'certificate' as const, id: certificateId }
    : caId && section === 'audit' && auditId
      ? { kind: 'audit' as const, id: auditId }
      : caId && section === 'profiles' && profile && (!hasComparison || (comparison && comparison.revision !== profile.revision))
        ? { kind: 'profile' as const, ...profile, ...(comparison ? { compareRevision: comparison.revision } : {}) }
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
    if (detail.compareRevision && detail.compareRevision !== detail.revision) params.set('compare_revision', String(detail.compareRevision));
  }
  return `/?${params.toString()}`;
}
