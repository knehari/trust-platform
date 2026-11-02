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
