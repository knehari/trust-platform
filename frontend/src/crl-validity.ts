// The state and elapsed share of a published CRL's validity window, from the
// dates the API returned. Display only: relying parties check the CRL itself.
export type CrlState = 'CURRENT' | 'EXPIRED' | 'SUPERSEDED';

export function crlState(crlNumber: number, latestNumber: number | null, nextUpdate: string, now: number): CrlState {
  if (latestNumber !== null && crlNumber < latestNumber) return 'SUPERSEDED';
  const end = Date.parse(nextUpdate);
  return Number.isNaN(end) || now >= end ? 'EXPIRED' : 'CURRENT';
}

// Share of [thisUpdate, nextUpdate] elapsed at `now`, clamped to 0..1, or null
// when the dates are missing or out of order.
export function crlElapsed(thisUpdate: string, nextUpdate: string, now: number): number | null {
  const start = Date.parse(thisUpdate);
  const end = Date.parse(nextUpdate);
  if (Number.isNaN(start) || Number.isNaN(end) || end <= start) return null;
  return Math.min(1, Math.max(0, (now - start) / (end - start)));
}
