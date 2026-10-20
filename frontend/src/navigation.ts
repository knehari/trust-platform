import { canonicalUuid } from './uuid.ts';

export type Section = 'overview' | 'authorities' | 'certificates' | 'audit';

export function readNavigation(search: string): { section: Section; caId: string | null } {
  const params = new URLSearchParams(search);
  const view = params.get('view');
  const caId = canonicalUuid(params.get('ca') ?? '');
  const section: Section = view === 'authorities' || view === 'certificates' || view === 'audit' || view === 'overview'
    ? view : caId ? 'authorities' : 'overview';
  return { section, caId };
}

export function navigationUrl(section: Section, caId: string | null): string {
  const params = new URLSearchParams({ view: section });
  if (caId) params.set('ca', caId);
  return `/?${params.toString()}`;
}
