// The RA channel's policies as readers see them (migration 0049, ADR-0044).
// Display only: the database owner sets every value, and the server enforces
// the quotas, zones and keys on every signed request.

export interface RaKey {
  key_id: number;
  sha256: string;
  activated_at: string;
  retired_at: string | null;
}

export interface RaSystem {
  ra_id: string;
  display_name: string;
  enabled: boolean;
  profile_ids: string[];
  max_issuance_per_hour: number;
  max_revocation_per_hour: number;
  /** null: the profiles' own zones apply. */
  allowed_dns_zones: string[] | null;
  issuance_last_hour: number;
  revocation_last_hour: number;
  keys: RaKey[];
}

export interface ShortLivedProfile {
  profile_id: string;
  max_validity_days: number;
  updated_at: string;
}

export type QuotaTone = 'good' | 'warn' | 'bad';

/** How much of an hourly quota is used: a share (0–1) and a tone. */
export function quotaUse(used: number, max: number): { share: number; tone: QuotaTone; label: string } {
  if (max <= 0) return { share: 1, tone: 'bad', label: used > 0 ? `${used} / 0 · stopped` : 'Stopped (quota 0)' };
  const share = Math.min(1, Math.max(0, used / max));
  const tone: QuotaTone = used >= max ? 'bad' : share >= 0.8 ? 'warn' : 'good';
  return { share, tone, label: `${used} / ${max}` };
}

/** The keys that sign new requests now (unretired), newest first. */
export function activeKeys(keys: RaKey[]): RaKey[] {
  return keys.filter(key => key.retired_at === null).sort((a, b) => b.key_id - a.key_id);
}

/** A fingerprint shortened for a table, as OpenSSL-like colon pairs. */
export function shortFingerprint(sha256: string, pairs = 6): string {
  const hex = sha256.toLowerCase().replace(/[^0-9a-f]/g, '');
  return (hex.match(/../g) ?? []).slice(0, pairs).join(':') + (hex.length > pairs * 2 ? '…' : '');
}

/** Whether the RA is in a key rotation: two unretired keys. */
export function rotating(keys: RaKey[]): boolean {
  return activeKeys(keys).length > 1;
}
