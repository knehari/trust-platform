// Keep the existing profile-facing names while sharing the API's prefix rule.
export { normalizeLiteralPrefix as trimProfileFilterInput, validLiteralPrefix as validProfileDraftSearch } from './literal-prefix.ts';

export function validProfilePolicyVersion(value: string): boolean {
  const characters = [...value];
  return characters.length > 0
    && characters.length <= 128
    && !characters.some(character => /\p{Cc}/u.test(character));
}

export interface ProfileDraftListFilters {
  profileFilter: string;
  profileOrder: 'oldest' | 'newest';
  searchTerm: string;
  policyFilter: string;
  fromFilter: string;
  untilFilter: string;
  minValidity: number | null;
  minSans: number | null;
}

export function profileDraftListUrl(caId: string, filters: ProfileDraftListFilters, after?: string): string {
  const params = new URLSearchParams();
  if (after) params.set('after', after);
  if (filters.profileFilter) {
    params.set('profile_id', filters.profileFilter);
    params.set('order', filters.profileOrder);
  }
  if (filters.searchTerm) params.set('q', filters.searchTerm);
  if (filters.policyFilter) params.set('policy_version', filters.policyFilter);
  if (filters.fromFilter) params.set('from', filters.fromFilter);
  if (filters.untilFilter) params.set('until', filters.untilFilter);
  if (filters.minValidity !== null) params.set('min_validity_days', String(filters.minValidity));
  if (filters.minSans !== null) params.set('min_dns_sans', String(filters.minSans));
  return `/v1/cas/${encodeURIComponent(caId)}/profile-drafts${params.size ? `?${params}` : ''}`;
}
