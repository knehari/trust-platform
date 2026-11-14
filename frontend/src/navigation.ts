import { canonicalUuid } from './uuid.ts';
import { canonicalProfileRevision } from './profile-revision.ts';

export type Section = 'overview' | 'authorities' | 'profiles' | 'requests' | 'certificates' | 'revocation' | 'channels' | 'audit';

const SECTIONS: readonly Section[] = ['overview', 'authorities', 'profiles', 'requests', 'certificates', 'revocation', 'channels', 'audit'];
export type DetailLink = { kind: 'certificate' | 'audit'; id: string } | { kind: 'profile'; id: string; revision: number; compareRevision?: number };

export function readNavigation(search: string): { section: Section; caId: string | null; detail: DetailLink | null } {
  const params = new URLSearchParams(search);
  const view = params.get('view');
  const caId = canonicalUuid(params.get('ca') ?? '');
  const section: Section = SECTIONS.find(known => known === view) ?? (caId ? 'authorities' : 'overview');
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

// The console's sections, grouped by the PKI component they belong to. Every
// section belongs to exactly one group; the order here is the sidebar order.
export type NavGroupId = 'supervision' | 'ca' | 'ra' | 'va';
export const NAV_GROUPS: readonly { id: NavGroupId; label: string; sections: readonly Section[] }[] = [
  { id: 'supervision', label: 'Supervision', sections: ['overview', 'audit'] },
  { id: 'ca', label: 'CA functions', sections: ['authorities', 'certificates', 'profiles'] },
  { id: 'ra', label: 'RA functions', sections: ['requests', 'channels'] },
  { id: 'va', label: 'VA functions', sections: ['revocation'] },
];

export function navGroupOf(section: Section): NavGroupId {
  return NAV_GROUPS.find(group => group.sections.includes(section))?.id ?? 'supervision';
}

// The groups that hold at least one visible section, each listing only its
// visible sections. Visibility is a display hint from the token's roles; the
// API still authorizes every request.
export function visibleNavGroups(visible: readonly Section[]): { id: NavGroupId; label: string; sections: Section[] }[] {
  return NAV_GROUPS
    .map(group => ({ id: group.id, label: group.label, sections: group.sections.filter(section => visible.includes(section)) }))
    .filter(group => group.sections.length > 0);
}
