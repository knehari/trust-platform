# OIDC identity integration boundary

The management API accepts only signed RS256 `at+jwt` access tokens from one configured issuer and audience. It also requires an `azp` matching one of two distinct configured clients. The human client needs `trust-ca-reader`; the workload client needs `trust-ca-workload-reader`. A token carrying both reader roles is denied. Both need an explicit `ca_ids` UUID list, and each `(issuer, sub, ca_id)` needs a database-owner-managed reader grant. The API login remains a restricted reader. These checks protect read routes only.

| Configuration | Purpose |
| --- | --- |
| `TRUST_OIDC_ISSUER` | Exact HTTPS issuer URL; localhost HTTP is accepted for an isolated laboratory issuer. |
| `TRUST_OIDC_AUDIENCE` | Exact API audience in access tokens. |
| `TRUST_OIDC_HUMAN_CLIENT_ID` | Public console client using Authorization Code with PKCE. |
| `TRUST_OIDC_WORKLOAD_CLIENT_ID` | Separate confidential service client; its credential stays outside the browser and source tree. |
| `VITE_OIDC_ISSUER`, `VITE_OIDC_CLIENT_ID` | Browser issuer and human client ID; never put a client secret in a `VITE_` variable. |

For a [Keycloak](https://www.keycloak.org/docs/26.7.0/server_admin/) pilot, provision a dedicated realm, a public console client with strict redirect URI and PKCE S256, and a separate service-account client with only the needed read scope. Keycloak's [access-token-header option](https://www.keycloak.org/2025/04/keycloak-2620-released) must be enabled on both clients to issue `at+jwt`; its default `JWT` header is rejected here. Map the exact API audience, realm-controlled reader roles into the top-level `roles` array, and permitted CA UUIDs into `ca_ids`. Disable broad client scopes. Grant each actual issuer-qualified subject to only its CAs as the database owner. Test an unrelated CA and an ungranted subject for denial.

Provision maker and checker as different human accounts with independently verified authentication and distinct approval keys. The current API has no approval route, so it cannot yet enforce or demonstrate their separation. A service-account token must never be treated as a human approval. The [isolated Keycloak laboratory](iam-keycloak-lab.md) now exercises real sign-in for two humans and client credentials for the workload, inspects the resulting token claims, and verifies CA-scope and grant denials. The original disposable issuer in `compose.lab.yaml` still provides only fixture evidence. Transport, secret custody and IdP policy require a separate controlled-pilot review. Keycloak omits the optional `nbf` claim by default; the verifier still rejects future `nbf` values when present.
