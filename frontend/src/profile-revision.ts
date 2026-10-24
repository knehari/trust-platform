export function canonicalProfileId(profileId: string): boolean {
  return /^[a-z][a-z0-9-]{1,63}$/.test(profileId);
}

export function canonicalProfileRevision(profileId: string, revisionText: string): { id: string; revision: number } | null {
  if (!canonicalProfileId(profileId) || !/^(?:[1-9][0-9]{0,5}|1000000)$/.test(revisionText)) return null;
  const revision = Number(revisionText);
  return revision <= 1_000_000 ? { id: profileId, revision } : null;
}
