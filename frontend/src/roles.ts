// Reads the role claim of the access token the console already holds, to
// decide which actions to offer. This is a display hint only: the
// management API verifies the token and the server-owned grants on every
// request, and refuses what the hint would wrongly offer.
export function tokenRoles(accessToken: string): string[] {
  const payload = accessToken.split('.')[1];
  if (!payload) return [];
  try {
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '='));
    const roles = (JSON.parse(json) as { roles?: unknown }).roles;
    return Array.isArray(roles) ? roles.filter((role): role is string => typeof role === 'string') : [];
  } catch {
    return [];
  }
}

export const PROFILE_EDITOR_ROLE = 'trust-profile-editor';
export const POLICY_APPROVER_ROLE = 'trust-policy-approver';
export const CA_OPERATOR_ROLE = 'trust-ca-operator';
export const CA_ADMINISTRATOR_ROLE = 'trust-ca-administrator';
export const CA_APPROVER_ROLE = 'trust-ca-approver';
export const CERTIFICATE_REQUESTER_ROLE = 'trust-certificate-requester';
export const REGISTRATION_OFFICER_ROLE = 'trust-registration-officer';

// Roles that offer at least one recording action in the console.
const WRITE_ROLES = [PROFILE_EDITOR_ROLE, POLICY_APPROVER_ROLE, CA_OPERATOR_ROLE, CA_ADMINISTRATOR_ROLE,
  CA_APPROVER_ROLE, CERTIFICATE_REQUESTER_ROLE, REGISTRATION_OFFICER_ROLE];

// Whether the console should present itself as read-only for these roles.
// A display hint like tokenRoles: the server still decides every request.
export function readOnlyRoles(roles: string[]): boolean {
  return !roles.some(role => WRITE_ROLES.includes(role));
}
