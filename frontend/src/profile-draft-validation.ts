import type { ProfileDraft } from './api';
import { canonicalProfileId } from './profile-revision.ts';

const LIFECYCLE_STATES: ProfileDraft['status'][] = ['DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'ACTIVE', 'SUPERSEDED', 'RETIRED'];
// States reached only after two approvals, and those that were activated.
const APPROVED_STATES = ['APPROVED', 'ACTIVE', 'SUPERSEDED', 'RETIRED'];
const ACTIVATED_STATES = ['ACTIVE', 'SUPERSEDED', 'RETIRED'];
const ENDED_STATES = ['SUPERSEDED', 'RETIRED'];

function timestamp(value: unknown): boolean {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value));
}

function stringArray(value: unknown, min: number, max: number): value is string[] {
  return Array.isArray(value) && value.length >= min && value.length <= max
    && value.every(item => typeof item === 'string');
}

function boundedUnicodeText(value: unknown, min: number, max: number): value is string {
  return typeof value === 'string' && [...value].length >= min && [...value].length <= max;
}

export function requireProfileDraft(value: unknown, caId: string, expected?: { id: string; revision: number }): ProfileDraft {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('The management API returned an invalid profile proposal.');
  }
  const row = value as Record<string, unknown>;
  if (row.ca_id !== caId) throw new Error('The management API returned a proposal outside the selected authority.');
  // Older API versions omit the decision fields; they mean no decision.
  const approvals = row.approval_count ?? 0;
  if (typeof row.profile_id !== 'string' || !canonicalProfileId(row.profile_id)
    || !Number.isInteger(row.revision) || (row.revision as number) < 1 || (row.revision as number) > 1_000_000
    || !LIFECYCLE_STATES.includes(row.status as ProfileDraft['status'])
    || (row.status === 'DRAFT' ? row.submitted_at !== null && row.submitted_at !== undefined : !timestamp(row.submitted_at))
    || !Number.isInteger(approvals) || (approvals as number) < 0 || (approvals as number) > 2
    || APPROVED_STATES.includes(row.status as string) !== (approvals === 2)
    || (APPROVED_STATES.includes(row.status as string) || row.status === 'REJECTED' ? !timestamp(row.decided_at)
      : row.decided_at !== null && row.decided_at !== undefined)
    || (ACTIVATED_STATES.includes(row.status as string) ? !timestamp(row.activated_at)
      : row.activated_at !== null && row.activated_at !== undefined)
    || (ENDED_STATES.includes(row.status as string) ? !timestamp(row.ended_at)
      : row.ended_at !== null && row.ended_at !== undefined)
    || typeof row.display_name !== 'string' || row.display_name.length < 1 || row.display_name.length > 255
    || typeof row.policy_version !== 'string' || row.policy_version.length < 1 || row.policy_version.length > 128
    || !Number.isInteger(row.max_validity_days) || (row.max_validity_days as number) < 1 || (row.max_validity_days as number) > 825
    || !Number.isInteger(row.max_dns_sans) || (row.max_dns_sans as number) < 1 || (row.max_dns_sans as number) > 100
    || !stringArray(row.proposed_dns_zones, 1, 32) || !stringArray(row.proposed_signature_suites, 1, 16)
    || !stringArray(row.proposal_warnings, 0, 6)
    || !boundedUnicodeText(row.created_by, 1, 256)
    || typeof row.created_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(row.created_at)
    || !Number.isFinite(Date.parse(row.created_at))
    || typeof row.snapshot_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(row.snapshot_sha256)) {
    throw new Error('The management API returned an invalid profile proposal.');
  }
  if (expected && (row.profile_id !== expected.id || row.revision !== expected.revision)) {
    throw new Error('The profile proposal detail did not match the linked revision.');
  }
  return {
    ca_id: caId,
    profile_id: row.profile_id,
    revision: row.revision as number,
    display_name: row.display_name as string,
    policy_version: row.policy_version as string,
    max_validity_days: row.max_validity_days as number,
    max_dns_sans: row.max_dns_sans as number,
    proposed_dns_zones: row.proposed_dns_zones,
    proposed_signature_suites: row.proposed_signature_suites,
    created_by: row.created_by as string,
    created_at: row.created_at as string,
    status: row.status as ProfileDraft['status'],
    submitted_at: row.status === 'DRAFT' ? null : row.submitted_at as string,
    approval_count: approvals as number,
    decided_at: APPROVED_STATES.includes(row.status as string) || row.status === 'REJECTED' ? row.decided_at as string : null,
    activated_at: ACTIVATED_STATES.includes(row.status as string) ? row.activated_at as string : null,
    ended_at: ENDED_STATES.includes(row.status as string) ? row.ended_at as string : null,
    proposal_warnings: row.proposal_warnings,
    snapshot_sha256: row.snapshot_sha256,
  };
}

export function requireProfileDraftPage(value: unknown, caId: string): ProfileDraft[] {
  if (!Array.isArray(value) || value.length > 100) {
    throw new Error('The management API returned an invalid profile proposal page.');
  }
  return value.map(row => requireProfileDraft(row, caId));
}
