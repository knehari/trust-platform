export function appendUniquePage<T>(current: T[], page: T[], id: (row: T) => string): T[] {
  const seen = new Set(current.map(id));
  const next = [...current];
  for (const row of page) {
    const key = id(row);
    if (!seen.has(key)) {
      seen.add(key);
      next.push(row);
    }
  }
  return next;
}

export function requireAdvancingCursor(cursor: string, next: string | null): string | null {
  if (next === cursor) throw new Error('The management API returned a repeated page cursor.');
  return next;
}
