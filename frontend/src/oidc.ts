import { UserManager, WebStorageStateStore } from 'oidc-client-ts';

const issuer = import.meta.env.VITE_OIDC_ISSUER as string | undefined;
const clientId = import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined;
const scope = (import.meta.env.VITE_OIDC_SCOPE as string | undefined) ?? 'openid profile trust-ca-read';

export const oidcConfigurationError = !issuer || !clientId
  ? 'OIDC test issuer and client ID are not configured.'
  : null;

export const userManager = oidcConfigurationError ? null : new UserManager({
  authority: issuer!,
  client_id: clientId!,
  redirect_uri: `${window.location.origin}/auth/callback`,
  post_logout_redirect_uri: window.location.origin,
  response_type: 'code',
  scope,
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  automaticSilentRenew: false,
  loadUserInfo: false,
});
