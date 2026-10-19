export function requireScopedRows<T extends { ca_id: string }>(rows: T[], caId: string): T[] {
  if (rows.some(row => row.ca_id !== caId)) {
    throw new Error('The management API returned records outside the selected authority.');
  }
  return rows;
}

export function visibleScopedRows<T extends { ca_id: string }>(rows: T[], caId: string | null): T[] {
  return caId ? rows.filter(row => row.ca_id === caId) : [];
}
