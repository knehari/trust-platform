import { canonicalProfileId } from './profile-revision.ts';

export interface ProfileDraftInput {
  profile_id: string;
  display_name: string;
  policy_version: string;
  max_validity_days: number;
  max_dns_sans: number;
  proposed_dns_zones: string[];
  proposed_signature_suites: string[];
}

export interface ProfileDraftFields {
  profileId: string;
  displayName: string;
  policyVersion: string;
  maxValidityDays: string;
  maxDnsSans: string;
  zones: string;
  suites: string;
}

function listOf(raw: string): string[] {
  return raw.split(/[\s,]+/u).map(value => value.trim()).filter(Boolean);
}

function printable(value: string, max: number): boolean {
  return value.length >= 1 && [...value].length <= max && ![...value].some(char => /[\x00-\x1f\x7f]/u.test(char));
}

/**
 * Checks the form against the same bounds as the database before sending.
 * Returns the request body, or an error message for the person filling it.
 */
export function parseProfileDraftForm(fields: ProfileDraftFields): { input: ProfileDraftInput } | { error: string } {
  const profileId = fields.profileId.trim();
  if (!canonicalProfileId(profileId)) return { error: 'Enter a lowercase profile ID (2–64 letters, digits or hyphens, starting with a letter).' };
  const displayName = fields.displayName.trim();
  if (!printable(displayName, 255)) return { error: 'Enter a display name of 1–255 printable characters.' };
  const policyVersion = fields.policyVersion.trim();
  if (!printable(policyVersion, 128)) return { error: 'Enter a policy version of 1–128 printable characters.' };
  if (!/^\d{1,3}$/u.test(fields.maxValidityDays) || Number(fields.maxValidityDays) < 1 || Number(fields.maxValidityDays) > 825) {
    return { error: 'Enter a maximum validity from 1 to 825 days.' };
  }
  if (!/^\d{1,3}$/u.test(fields.maxDnsSans) || Number(fields.maxDnsSans) < 1 || Number(fields.maxDnsSans) > 100) {
    return { error: 'Enter a maximum of 1 to 100 DNS SANs.' };
  }
  const zones = listOf(fields.zones);
  if (zones.length < 1 || zones.length > 32 || zones.some(zone => zone.length > 253)) {
    return { error: 'Enter 1–32 DNS zones, separated by commas or spaces.' };
  }
  const suites = listOf(fields.suites);
  if (suites.length < 1 || suites.length > 16 || suites.some(suite => suite.length > 64)) {
    return { error: 'Enter 1–16 signature suite identifiers, separated by commas or spaces.' };
  }
  return { input: {
    profile_id: profileId, display_name: displayName, policy_version: policyVersion,
    max_validity_days: Number(fields.maxValidityDays), max_dns_sans: Number(fields.maxDnsSans),
    proposed_dns_zones: zones, proposed_signature_suites: suites,
  } };
}
