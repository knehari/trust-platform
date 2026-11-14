// Bulk selection of loaded rows for CSV export: every visible row, every
// row matching the active filter, or none, always within maxRows.

export type HeaderState = 'none' | 'some' | 'all';

export function headerState(visibleIds: string[], selected: string[]): HeaderState {
  if (visibleIds.length === 0) return 'none';
  const count = visibleIds.filter(id => selected.includes(id)).length;
  return count === 0 ? 'none' : count === visibleIds.length ? 'all' : 'some';
}

// The header checkbox: select every visible row (keeping earlier picks) or,
// when all are selected already, clear them.
export function toggleVisible(visibleIds: string[], selected: string[], maxRows: number): string[] {
  if (headerState(visibleIds, selected) === 'all') return selected.filter(id => !visibleIds.includes(id));
  return addWithin(selected, visibleIds, maxRows);
}

export function toggleOne(id: string, selected: string[], maxRows: number): string[] {
  return selected.includes(id) ? selected.filter(value => value !== id) : addWithin(selected, [id], maxRows);
}

export function addWithin(selected: string[], ids: string[], maxRows: number): string[] {
  const next = [...selected];
  for (const id of ids) {
    if (next.length >= maxRows) break;
    if (!next.includes(id)) next.push(id);
  }
  return next;
}
