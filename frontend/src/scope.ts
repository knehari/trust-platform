export function requireScopedRows<T extends { ca_id: string }>(rows: T[], caId: string): T[] {
  if (rows.some(row => row.ca_id !== caId)) {
    throw new Error('The management API returned records outside the selected authority.');
  }
  return rows;
}

export function visibleScopedRows<T extends { ca_id: string }>(rows: T[], caId: string | null): T[] {
  return caId ? rows.filter(row => row.ca_id === caId) : [];
}

export function requireExactRecord<T extends { ca_id: string }>(record: T, caId: string, field: keyof T, id: string): T {
  requireScopedRows([record], caId);
  if (record[field] !== id) {
    throw new Error('The management API returned a different record than requested.');
  }
  return record;
}
