import type { ProfileDraft } from './api';

export function visibleProfileDrafts(items: ProfileDraft[], warningsOnly: boolean): ProfileDraft[] {
  return warningsOnly ? items.filter(item => item.proposal_warnings.length > 0) : items;
}
